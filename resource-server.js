const http = require("http");

const PORT = 4000;

const INTROSPECTION_URL = "http://localhost:3000/introspect";
const EXPECTED_AUDIENCE = "resource-server-b";
const REQUIRED_SCOPE = "profile";
const INTROSPECTION_TIMEOUT_MS = 5000;

// اختیاری: اگر سرور احراز هویت برای introspection کلاینت می‌خواهد
const INTROSPECTION_CLIENT_ID = process.env.INTROSPECTION_CLIENT_ID;
const INTROSPECTION_CLIENT_SECRET = process.env.INTROSPECTION_CLIENT_SECRET;

// ==================================================
// Helpers
// ==================================================

function sendJson(res, statusCode, body, extraHeaders = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function maskToken(token) {
  if (!token) return "";
  if (token.length <= 10) return "***";
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

function hasScope(tokenData, requiredScope) {
  if (typeof tokenData.scope !== "string") return false;
  return tokenData.scope.split(/\s+/).filter(Boolean).includes(requiredScope);
}

function hasAudience(tokenData, expectedAudience) {
  const { aud } = tokenData;
  if (!aud) return false;
  const audiences = Array.isArray(aud) ? aud : [aud];
  return audiences.includes(expectedAudience);
}

// ==================================================
// Token Introspection
// ==================================================

function introspectToken(token) {
  return new Promise((resolve, reject) => {
    const url = new URL(INTROSPECTION_URL);
    const postData = new URLSearchParams({ token }).toString();

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(postData),
      Accept: "application/json",
    };

    if (INTROSPECTION_CLIENT_ID && INTROSPECTION_CLIENT_SECRET) {
      const credentials = Buffer.from(
        `${INTROSPECTION_CLIENT_ID}:${INTROSPECTION_CLIENT_SECRET}`
      ).toString("base64");
      headers.Authorization = `Basic ${credentials}`;
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers,
        timeout: INTROSPECTION_TIMEOUT_MS,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          let data;
          try {
            data = JSON.parse(body);
          } catch {
            return reject(
              new Error("Invalid JSON response from introspection endpoint")
            );
          }

          if (res.statusCode !== 200) {
            return reject(
              new Error(`Introspection failed: ${JSON.stringify(data)}`)
            );
          }

          resolve(data);
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("Introspection request timed out"));
    });

    req.on("error", reject);

    req.write(postData);
    req.end();
  });
}

// ==================================================
// Resource Server
// ==================================================

const server = http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  // ==================================================
  // GET /profile
  // ==================================================

  if (req.method === "GET" && pathname === "/profile") {
    console.log("\n========================================");
    console.log("Resource Server: /profile");
    console.log("========================================");

    // ----------------------------------------------
    // 1. Authorization Header
    // ----------------------------------------------

    const authorization = req.headers.authorization;

    if (!authorization) {
      console.log("\nNO AUTHORIZATION HEADER");
      return sendJson(
        res,
        401,
        {
          error: "unauthorized",
          error_description: "Authorization header is required",
        },
        { "WWW-Authenticate": "Bearer" }
      );
    }

    // ----------------------------------------------
    // 2. Bearer Token
    // ----------------------------------------------

    const match = /^Bearer\s+(\S+)$/i.exec(authorization.trim());

    if (!match) {
      console.log("\nINVALID AUTHORIZATION HEADER");
      return sendJson(
        res,
        401,
        {
          error: "invalid_token",
          error_description: "Bearer token is required",
        },
        { "WWW-Authenticate": 'Bearer error="invalid_token"' }
      );
    }

    const token = match[1];
    console.log("\nExtracted Access Token (masked):", maskToken(token));

    // ----------------------------------------------
    // 3. Introspection
    // ----------------------------------------------

    console.log("\nCalling Authorization Server /introspect...");

    try {
      const tokenData = await introspectToken(token);

      console.log("\nIntrospection Response:");
      console.log(tokenData);

      // ------------------------------------------
      // 4. Token Validation
      // ------------------------------------------

      if (!tokenData.active) {
        console.log("\nTOKEN INVALID");
        return sendJson(
          res,
          401,
          {
            error: "invalid_token",
            error_description: "The access token is invalid or expired",
          },
          { "WWW-Authenticate": 'Bearer error="invalid_token"' }
        );
      }

      // ------------------------------------------
      // 4.1 Audience Validation
      // ------------------------------------------

      if (!hasAudience(tokenData, EXPECTED_AUDIENCE)) {
        console.log("\nINVALID AUDIENCE");
        console.log("Expected Audience:", EXPECTED_AUDIENCE);
        console.log("Token Audience:", tokenData.aud);
        return sendJson(
          res,
          401,
          {
            error: "invalid_token",
            error_description: "The access token audience is not valid for this resource server",
          },
          { "WWW-Authenticate": 'Bearer error="invalid_token"' }
        );
      }

      console.log("\nTOKEN VALID");

      // ------------------------------------------
      // 5. Scope Validation
      // ------------------------------------------

      console.log("Required Scope:", REQUIRED_SCOPE);
      console.log("Token Scope:", tokenData.scope);

      if (!hasScope(tokenData, REQUIRED_SCOPE)) {
        console.log("\nINSUFFICIENT SCOPE");
        console.log("ACCESS DENIED");
        return sendJson(
          res,
          403,
          {
            error: "insufficient_scope",
            error_description: "The access token does not have the required scope",
            required_scope: REQUIRED_SCOPE,
          },
          {
            "WWW-Authenticate": `Bearer error="insufficient_scope", scope="${REQUIRED_SCOPE}"`,
          }
        );
      }

      // ------------------------------------------
      // 6. Access Granted
      // ------------------------------------------

      console.log("\nSCOPE VALID");
      console.log("\nACCESS GRANTED");

      return sendJson(res, 200, {
        message: "Access granted",
        user: tokenData.username || tokenData.sub || "unknown",
        role: "user",
        client_id: tokenData.client_id,
        scope: tokenData.scope,
      });
    } catch (error) {
      console.error("\nTOKEN VALIDATION ERROR");
      console.error(error.message);

      return sendJson(res, 503, {
        error: "service_unavailable",
        error_description: "Authorization Server is unavailable",
      });
    }
  }

  // ==================================================
  // 404
  // ==================================================

  sendJson(res, 404, { error: "not_found" });
});

// ==================================================
// Start Resource Server
// ==================================================

server.listen(PORT, () => {
  console.log(`Resource Server running at http://localhost:${PORT}`);
  console.log(`Introspection Server: ${INTROSPECTION_URL}`);
  console.log(`Expected Audience: ${EXPECTED_AUDIENCE}`);
  console.log(`Required Scope for /profile: ${REQUIRED_SCOPE}`);
});
