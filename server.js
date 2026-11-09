
"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = 3000;
const ISSUER = "http://localhost:3000";
const CLIENT_ID = "my-client";
const REDIRECT_URI = "http://localhost:3001/callback";
const RESOURCE_AUDIENCE = "resource-server-a";
const LAB_USER_SUBJECT = "user-123";

const AUTH_CODE_TTL_SECONDS = 120;
const ACCESS_TOKEN_TTL_SECONDS = 600;
const ID_TOKEN_TTL_SECONDS = 300;

const SUPPORTED_SCOPES = new Set(["openid", "profile"]);

const PRIVATE_KEY_PATH = path.join(
  __dirname,
  "keys",
  "oidc-private.pem"
);

if (!fs.existsSync(PRIVATE_KEY_PATH)) {
  throw new Error(
    "OIDC private key not found: " + PRIVATE_KEY_PATH
  );
}

const privateKeyPromise = (async function () {
  const { importPKCS8 } = await import("jose");
  const pem = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
  return importPKCS8(pem, "RS256");
})();

const josePromise = import("jose");

// In-memory stores: entries disappear when the server restarts.
const authorizationCodes = new Map();
const accessTokens = new Map();

function sendJSON(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(JSON.stringify(payload));
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function parseFormBody(req) {
  return new Promise(function (resolve, reject) {
    let body = "";
    let size = 0;
    const maxSize = 16 * 1024;

    req.setEncoding("utf8");

    req.on("data", function (chunk) {
      size += Buffer.byteLength(chunk);

      if (size > maxSize) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }

      body += chunk;
    });

    req.on("end", function () {
      resolve(new URLSearchParams(body));
    });

    req.on("error", reject);
  });
}

function hasScope(scopeList, requiredScope) {
  return Array.isArray(scopeList) &&
    scopeList.includes(requiredScope);
}

function parseScopes(scopeString) {
  const requested = String(scopeString || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  return [...new Set(requested)];
}

function createCodeChallenge(codeVerifier) {
  return crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
}

function constantTimeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  return aBuffer.length === bBuffer.length &&
    crypto.timingSafeEqual(aBuffer, bBuffer);
}

// ========================================
// OIDC: ID Token Creation
// ========================================

async function createIdToken(codeData) {
  const { SignJWT } = await josePromise;
  const privateKey = await privateKeyPromise;

  const now = Math.floor(Date.now() / 1000);

  const payload = {
    auth_time: now
  };

  if (codeData.nonce) {
    payload.nonce = codeData.nonce;
  }

  const jwt = new SignJWT(payload)
    .setProtectedHeader({
      alg: "RS256",
      typ: "JWT"
    })
    .setIssuer(ISSUER)
    .setSubject(LAB_USER_SUBJECT)
    .setAudience(CLIENT_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + ID_TOKEN_TTL_SECONDS);

  return jwt.sign(privateKey);
}

// ========================================
// Authorization Endpoint
// GET /authorize
// ========================================

function handleAuthorize(req, res, url) {
  const clientId = url.searchParams.get("client_id");
  const responseType = url.searchParams.get("response_type");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const nonce = url.searchParams.get("nonce");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod =
    url.searchParams.get("code_challenge_method");

  const scopes = parseScopes(url.searchParams.get("scope"));

  // This lab supports exactly one preconfigured client.
  if (clientId !== CLIENT_ID) {
    return sendJSON(res, 400, {
      error: "invalid_client"
    });
  }

  if (responseType !== "code") {
    return sendJSON(res, 400, {
      error: "unsupported_response_type"
    });
  }

  if (redirectUri !== REDIRECT_URI) {
    return sendJSON(res, 400, {
      error: "invalid_request",
      error_description: "redirect_uri does not match the registered URI"
    });
  }

  if (!state) {
    return sendJSON(res, 400, {
      error: "invalid_request",
      error_description: "state is required by this lab"
    });
  }

  if (
    !codeChallenge ||
    codeChallengeMethod !== "S256"
  ) {
    return sendJSON(res, 400, {
      error: "invalid_request",
      error_description: "PKCE S256 is required"
    });
  }

  if (
    scopes.some(function (scope) {
      return !SUPPORTED_SCOPES.has(scope);
    })
  ) {
    return sendJSON(res, 400, {
      error: "invalid_scope"
    });
  }

  if (hasScope(scopes, "openid") && !nonce) {
    return sendJSON(res, 400, {
      error: "invalid_request",
      error_description: "nonce is required for this OIDC lab"
    });
  }

  const code = randomToken();
  const now = Date.now();

  authorizationCodes.set(code, {
    clientId: clientId,
    redirectUri: redirectUri,
    codeChallenge: codeChallenge,
    scope: scopes,
    nonce: nonce,
    createdAt: now,
    expiresAt: now + AUTH_CODE_TTL_SECONDS * 1000
  });

  const callbackUrl = new URL(redirectUri);
  callbackUrl.searchParams.set("code", code);
  callbackUrl.searchParams.set("state", state);

  console.log("\nAuthorization Code Issued");
  console.log("Client ID:", clientId);
  console.log("Scopes:", scopes.join(" ") || "(none)");
  console.log("PKCE Method: S256");
  console.log("Nonce supplied:", Boolean(nonce));
  console.log("Code value is not logged.");

  res.writeHead(302, {
    Location: callbackUrl.toString(),
    "Cache-Control": "no-store",
    "Pragma": "no-cache"
  });

  res.end();
}

// ========================================
// Token Endpoint
// POST /token
// ========================================

async function handleToken(req, res) {
  let form;

  try {
    form = await parseFormBody(req);
  } catch (error) {
    return sendJSON(res, 400, {
      error: "invalid_request"
    });
  }

  const grantType = form.get("grant_type");
  const code = form.get("code");
  const clientId = form.get("client_id");
  const redirectUri = form.get("redirect_uri");
  const codeVerifier = form.get("code_verifier");

  if (grantType !== "authorization_code") {
    return sendJSON(res, 400, {
      error: "unsupported_grant_type"
    });
  }

  if (!code || !clientId || !redirectUri || !codeVerifier) {
    return sendJSON(res, 400, {
      error: "invalid_request",
      error_description: "A required token request parameter is missing"
    });
  }

  const codeData = authorizationCodes.get(code);

  if (!codeData) {
    return sendJSON(res, 400, {
      error: "invalid_grant"
    });
  }

  // Authorization codes are single-use, including failed exchanges.
  authorizationCodes.delete(code);

  if (Date.now() > codeData.expiresAt) {
    return sendJSON(res, 400, {
      error: "invalid_grant",
      error_description: "Authorization code expired"
    });
  }

  if (
    clientId !== codeData.clientId ||
    clientId !== CLIENT_ID
  ) {
    return sendJSON(res, 400, {
      error: "invalid_grant"
    });
  }

  if (
    redirectUri !== codeData.redirectUri ||
    redirectUri !== REDIRECT_URI
  ) {
    return sendJSON(res, 400, {
      error: "invalid_grant"
    });
  }

  // RFC 7636: verify the S256 code challenge.
  const actualChallenge = createCodeChallenge(codeVerifier);

  if (
    !constantTimeStringEqual(
      actualChallenge,
      codeData.codeChallenge
    )
  ) {
    return sendJSON(res, 400, {
      error: "invalid_grant",
      error_description: "PKCE verification failed"
    });
  }

  const accessToken = randomToken();
  const now = Date.now();
  const expiresIn = ACCESS_TOKEN_TTL_SECONDS;

  accessTokens.set(accessToken, {
    active: true,
    client_id: clientId,
    username: LAB_USER_SUBJECT,
    sub: LAB_USER_SUBJECT,
    scope: codeData.scope.join(" "),
    aud: RESOURCE_AUDIENCE,
    iss: ISSUER,
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + expiresIn
  });

  const response = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    scope: codeData.scope.join(" ")
  };

  if (hasScope(codeData.scope, "openid")) {
    try {
      response.id_token = await createIdToken(codeData);
    } catch (error) {
      accessTokens.delete(accessToken);
      console.error("ID Token signing failed:", error.message);

      return sendJSON(res, 500, {
        error: "server_error",
        error_description: "Unable to create ID Token"
      });
    }
  }

  console.log("\n========================================");
  console.log("Token Issued");
  console.log("========================================");
  console.log("Client ID:", clientId);
  console.log("Access Token Audience:", RESOURCE_AUDIENCE);
  console.log("Scope:", codeData.scope.join(" ") || "(none)");
  console.log("ID Token Issued:", Boolean(response.id_token));
  console.log("Token values are not logged.");

  return sendJSON(res, 200, response);
}

// ========================================
// Token Introspection Endpoint
// POST /introspect
// ========================================

async function handleIntrospect(req, res) {
  let form;

  try {
    form = await parseFormBody(req);
  } catch (error) {
    return sendJSON(res, 400, {
      error: "invalid_request"
    });
  }

  const token = form.get("token");

  if (!token) {
    return sendJSON(res, 200, {
      active: false
    });
  }

  const tokenData = accessTokens.get(token);

  if (!tokenData || tokenData.exp <= Math.floor(Date.now() / 1000)) {
    accessTokens.delete(token);

    return sendJSON(res, 200, {
      active: false
    });
  }

  return sendJSON(res, 200, {
    active: true,
    client_id: tokenData.client_id,
    username: tokenData.username,
    sub: tokenData.sub,
    scope: tokenData.scope,
    aud: tokenData.aud,
    iss: tokenData.iss,
    iat: tokenData.iat,
    exp: tokenData.exp
  });
}

// ========================================
// HTTP Server
// ========================================

const server = http.createServer(async function (req, res) {
  const requestUrl = new URL(
    req.url,
    "http://localhost:" + PORT
  );

  try {
    if (req.method === "GET" && requestUrl.pathname === "/") {
      return sendJSON(res, 200, {
        service: "OAuth2/OIDC Authorization Server",
        issuer: ISSUER,
        endpoints: [
          "/authorize",
          "/token",
          "/introspect"
        ],
        supportedScopes: [...SUPPORTED_SCOPES],
        idTokenSigningAlgorithm: "RS256"
      });
    }

    if (
      req.method === "GET" &&
      requestUrl.pathname === "/authorize"
    ) {
      return handleAuthorize(req, res, requestUrl);
    }

    if (
      req.method === "POST" &&
      requestUrl.pathname === "/token"
    ) {
      return await handleToken(req, res);
    }

    if (
      req.method === "POST" &&
      requestUrl.pathname === "/introspect"
    ) {
      return await handleIntrospect(req, res);
    }

    return sendJSON(res, 404, {
      error: "not_found"
    });
  } catch (error) {
    console.error("Authorization Server error:", error.message);

    if (!res.headersSent) {
      return sendJSON(res, 500, {
        error: "server_error"
      });
    }

    res.end();
  }
});

server.listen(PORT, "0.0.0.0", function () {
  console.log("========================================");
  console.log("Authorization Server Running");
  console.log("Issuer:", ISSUER);
  console.log("Port:", PORT);
  console.log("Client ID:", CLIENT_ID);
  console.log("Resource Audience:", RESOURCE_AUDIENCE);
  console.log("Supported Scopes: openid, profile");
  console.log("ID Token Algorithm: RS256");
  console.log("Endpoints: /authorize, /token, /introspect");
  console.log("Token values are never logged.");
  console.log("========================================");
});

server.on("error", function (error) {
  console.error("Authorization Server failed:", error.message);
  process.exitCode = 1;
});
