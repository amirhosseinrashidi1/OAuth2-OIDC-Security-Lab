
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const CLIENT_ID = "my-client";
const REDIRECT_URI = "http://localhost:3001/callback";
const AUTHORIZATION_SERVER = "http://localhost:3000";
const RESOURCE_SERVER = "http://localhost:4000";
const ISSUER = "http://localhost:3000";
const PORT = 3001;

const PUBLIC_KEY_PATH = path.join(
  __dirname,
  "..",
  "keys",
  "oidc-public.pem"
);

const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
const josePromise = import("jose");

const publicKeyPromise = josePromise.then(({ importSPKI }) =>
  importSPKI(publicKeyPem, "RS256")
);

function generateRandomValue(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function createCodeChallenge(codeVerifier) {
  return crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
}

const state = generateRandomValue(32);
const nonce = generateRandomValue(32);
const codeVerifier = generateRandomValue(32);
const codeChallenge = createCodeChallenge(codeVerifier);

const authorizationUrl = new URL(
  AUTHORIZATION_SERVER + "/authorize"
);

authorizationUrl.searchParams.set("client_id", CLIENT_ID);
authorizationUrl.searchParams.set("response_type", "code");
authorizationUrl.searchParams.set("redirect_uri", REDIRECT_URI);
authorizationUrl.searchParams.set("state", state);
authorizationUrl.searchParams.set("nonce", nonce);
authorizationUrl.searchParams.set("code_challenge", codeChallenge);
authorizationUrl.searchParams.set("code_challenge_method", "S256");
authorizationUrl.searchParams.set("scope", "openid profile");

function requestJson(urlString, method, headers, body) {
  return new Promise(function (resolve, reject) {
    const url = new URL(urlString);

    const options = {
      hostname: url.hostname,
      port: Number(url.port),
      path: url.pathname + url.search,
      method: method,
      headers: headers || {}
    };

    const req = http.request(options, function (res) {
      let responseBody = "";

      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        responseBody += chunk;
      });

      res.on("end", function () {
        let data;

        try {
          data = JSON.parse(responseBody);
        } catch {
          reject(new Error("Server returned invalid JSON."));
          return;
        }

        resolve({
          statusCode: res.statusCode,
          data: data
        });
      });
    });

    req.on("error", reject);

    if (body) {
      req.write(body);
    }

    req.end();
  });
}

async function exchangeCodeForToken(code) {
  const tokenUrl = AUTHORIZATION_SERVER + "/token";

  const postData = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier
  }).toString();

  const result = await requestJson(
    tokenUrl,
    "POST",
    {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(postData)
    },
    postData
  );

  if (result.statusCode < 200 || result.statusCode >= 300) {
    throw new Error(
      "Token endpoint returned HTTP " + result.statusCode +
      ": " + (result.data.error_description || result.data.error || "unknown error")
    );
  }

  if (
    !result.data ||
    typeof result.data.access_token !== "string" ||
    !result.data.access_token
  ) {
    throw new Error("Token response did not contain an access token.");
  }

  if (
    typeof result.data.id_token !== "string" ||
    !result.data.id_token
  ) {
    throw new Error("OIDC token response did not contain an ID Token.");
  }

  return result.data;
}

async function validateIdToken(idToken, expectedNonce) {
  const { jwtVerify } = await josePromise;
  const publicKey = await publicKeyPromise;

  const result = await jwtVerify(idToken, publicKey, {
    issuer: ISSUER,
    audience: CLIENT_ID,
    algorithms: ["RS256"]
  });

  const claims = result.payload;

  if (typeof claims.sub !== "string" || !claims.sub) {
    throw new Error("ID Token validation failed: sub is missing.");
  }

  if (claims.nonce !== expectedNonce) {
    throw new Error("ID Token validation failed: nonce mismatch.");
  }

  return claims;
}

async function requestProfile(accessToken) {
  return requestJson(
    RESOURCE_SERVER + "/profile",
    "GET",
    {
      "Authorization": "Bearer " + accessToken,
      "Accept": "application/json"
    }
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sendHtml(res, statusCode, title, content) {
  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(
    "<!DOCTYPE html>" +
    "<html><head><meta charset='utf-8'>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'>" +
    "<title>" + escapeHtml(title) + "</title></head><body>" +
    content +
    "</body></html>"
  );
}

const server = http.createServer(async function (req, res) {
  const requestUrl = new URL(req.url, "http://localhost:" + PORT);

  if (req.method === "GET" && requestUrl.pathname === "/") {
    sendHtml(
      res,
      200,
      "OIDC Client Lab",
      "<h1>OpenID Connect Client Lab</h1>" +
      "<p>Authorization Code Flow with PKCE (S256)</p>" +
      "<p>Requested scopes: openid profile</p>" +
      "<p>ID Token algorithm: RS256</p>" +
      "<a href='" + escapeHtml(authorizationUrl.href) +
      "'>Start OIDC Login</a>"
    );
    return;
  }

  if (req.method === "GET" && requestUrl.pathname === "/callback") {
    const returnedState = requestUrl.searchParams.get("state");
    const code = requestUrl.searchParams.get("code");
    const oauthError = requestUrl.searchParams.get("error");

    if (oauthError) {
      sendHtml(
        res, 400, "Authorization Failed",
        "<h1>Authorization failed</h1><p>" +
        escapeHtml(oauthError) + "</p>"
      );
      return;
    }

    if (!returnedState || returnedState !== state) {
      sendHtml(
        res, 400, "State Validation Failed",
        "<h1>State validation failed</h1>"
      );
      return;
    }

    if (!code) {
      sendHtml(
        res, 400, "Authorization Code Missing",
        "<h1>Authorization code is missing</h1>"
      );
      return;
    }

    console.log("\nState validation successful.");
    console.log("Exchanging authorization code for tokens...");

    try {
      const tokenData = await exchangeCodeForToken(code);

      console.log("Token exchange successful.");
      console.log("Token Type:", tokenData.token_type || "unknown");
      console.log("Granted Scope:", tokenData.scope || "(none)");
      console.log("Access token and ID Token values will not be logged.");

      const idClaims = await validateIdToken(tokenData.id_token, nonce);

      console.log("ID Token signature: valid");
      console.log("ID Token issuer: valid");
      console.log("ID Token audience: valid");
      console.log("ID Token expiration: valid");
      console.log("ID Token nonce: valid");
      console.log("Authenticated subject:", idClaims.sub);

      console.log("Requesting /profile from Resource Server...");

      const profileResult = await requestProfile(tokenData.access_token);
      const profile = profileResult.data;

      console.log("Resource Server HTTP Status:", profileResult.statusCode);

      if (
        profileResult.statusCode >= 200 &&
        profileResult.statusCode < 300
      ) {
        console.log("Profile request successful.");

        const safeProfile = escapeHtml(
          JSON.stringify(profile, null, 2)
        );

        sendHtml(
          res,
          200,
          "OIDC Login Successful",
          "<h1>OIDC Login Successful</h1>" +
          "<p>State validation: successful</p>" +
          "<p>Authorization code exchange: successful</p>" +
          "<p>ID Token signature and claims: valid</p>" +
          "<p>Authenticated subject: " + escapeHtml(idClaims.sub) + "</p>" +
          "<p>Resource Server access: granted</p>" +
          "<h2>Profile API Response</h2>" +
          "<pre>" + safeProfile + "</pre>" +
          "<p>The Access Token and ID Token are not displayed.</p>" +
          "<p><a href='/'>Return to home</a></p>"
        );
        return;
      }

      const errorName = profile.error || "resource_access_failed";
      const errorDescription =
        profile.error_description ||
        "The Resource Server rejected the request.";

      console.log("Resource Server rejected the request:", errorName);

      sendHtml(
        res,
        profileResult.statusCode,
        "Resource Access Failed",
        "<h1>Resource Server access failed</h1>" +
        "<p>HTTP status: " + profileResult.statusCode + "</p>" +
        "<p>Error: " + escapeHtml(errorName) + "</p>" +
        "<p>Description: " + escapeHtml(errorDescription) + "</p>" +
        "<p>The token values are not displayed.</p>" +
        "<p><a href='/'>Return to home</a></p>"
      );
    } catch (error) {
      console.error("OIDC flow failed:", error.message);

      sendHtml(
        res,
        502,
        "OIDC Request Failed",
        "<h1>OIDC request failed</h1>" +
        "<p>" + escapeHtml(error.message) + "</p>" +
        "<p>Check that the Authorization Server and Resource Server are running.</p>" +
        "<p><a href='/'>Return to home</a></p>"
      );
    }

    return;
  }

  sendHtml(res, 404, "Not Found", "<h1>404 - Not Found</h1>");
});

server.listen(PORT, function () {
  console.log("========================================");
  console.log("OIDC Client Running");
  console.log("Client: http://localhost:" + PORT);
  console.log("Authorization Server: " + AUTHORIZATION_SERVER);
  console.log("Resource Server: " + RESOURCE_SERVER);
  console.log("PKCE Method: S256");
  console.log("Requested Scopes: openid profile");
  console.log("ID Token validation: RS256");
  console.log("Token values will not be logged.");
  console.log("========================================");
});
