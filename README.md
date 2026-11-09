# OAuth 2.0 & OpenID Connect Security Lab

A practical implementation of OAuth 2.0 and OpenID Connect (OIDC) from scratch using Node.js.

This project is designed as a hands-on security lab to explore authentication, authorization, token management, and security validation mechanisms in modern identity systems.

It demonstrates how an Authorization Server, an OIDC Client, and a Resource Server interact through OAuth 2.0 Authorization Code Flow with PKCE.

## Project Overview

The project implements a simplified OAuth 2.0 and OpenID Connect environment consisting of three main components:

- **Authorization Server (AS):** Handles authorization requests, authenticates the client flow, issues authorization codes, generates access tokens, and signs ID Tokens.
- **OIDC Client:** Initiates authentication requests, handles the authorization callback, exchanges authorization codes for tokens, and validates the authentication response.
- **Resource Server (RS):** Validates access tokens through token introspection and enforces audience and scope restrictions before providing protected resources.

## Architecture

```text
                  +----------------------+
                  |      User / Browser  |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  |      OIDC Client     |
                  |      Port: 3001      |
                  +----------+-----------+
                             |
                   Authorization Request
                   Authorization Code
                             |
                             v
                  +----------------------+
                  |  Authorization       |
                  |      Server          |
                  |      Port: 3000      |
                  +----------+-----------+
                             |
                   Access Token / ID Token
                             |
                +------------+-------------+
                |                          |
                v                          v
       +------------------+       +------------------+
       |  OIDC Client     |       | Resource Server  |
       |                  |       |   Port: 4000     |
       +------------------+       +--------+---------+
                                           |
                                    Token Introspection
                                           |
                                           v
                                  +------------------+
                                  | Authorization    |
                                  | Server           |
                                  +------------------+
```

## Implemented Features

### OAuth 2.0

- Authorization Code Grant Flow
- PKCE (Proof Key for Code Exchange) using S256
- State parameter validation
- Authorization code expiration
- One-time authorization code usage
- Access token generation
- Access token expiration
- Scope validation
- Token introspection

### OpenID Connect

- OpenID Connect authentication flow
- ID Token generation
- JWT-based ID Tokens
- RS256 digital signature
- Issuer (`iss`) validation
- Audience (`aud`) validation
- Expiration (`exp`) validation
- Nonce validation
- Subject (`sub`) identification

### Resource Server Security

- Access token validation through introspection
- Token active-status verification
- Audience validation
- Scope-based access control
- Protected resource endpoint
- HTTP 401 Unauthorized responses
- HTTP 403 Forbidden responses

## Technology Stack

- Node.js
- JavaScript
- OAuth 2.0
- OpenID Connect
- JSON Web Tokens (JWT)
- PKCE (S256)
- RSA / RS256
- JOSE library

## Project Structure

```text
OAuth2-OIDC-Security-Lab/
│
├── client/
│   └── client.js
│
├── keys/
│   └── oidc-public.pem
│
├── resource-server/
│   └── resource-server.js
│
├── server.js
├── package.json
├── package-lock.json
├── .gitignore
└── README.md
```

**Security note:** The private signing key (`oidc-private.pem`) is intentionally excluded from the repository.

## Requirements

- Node.js 20 or later
- npm
- OpenSSL

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/OAuth2-OIDC-Security-Lab.git
```

Navigate to the project directory:

```bash
cd OAuth2-OIDC-Security-Lab
```

Install dependencies:

```bash
npm install
```

## Security Key Setup

The Authorization Server requires an RSA private key to sign ID Tokens using RS256.

Generate a new private key:

```bash
openssl genpkey -algorithm RSA \
  -out keys/oidc-private.pem \
  -pkeyopt rsa_keygen_bits:2048
```

Generate the corresponding public key:

```bash
openssl pkey \
  -in keys/oidc-private.pem \
  -pubout \
  -out keys/oidc-public.pem
```

**Important:** Never upload or commit `oidc-private.pem` to GitHub. Keep private keys secure and local to your environment.

## Running the Project

Start each component in a separate terminal.

**1. Authorization Server**

```bash
node server.js
```

Runs on:

```text
http://localhost:3000
```

**2. OIDC Client**

```bash
node client/client.js
```

Runs on:

```text
http://localhost:3001
```

**3. Resource Server**

```bash
node resource-server/resource-server.js
```

Runs on:

```text
http://localhost:4000
```

## Security Testing

The lab includes practical security tests covering several OAuth 2.0 and OpenID Connect security mechanisms.

| Test Case | Expected Result |
|---|---|
| Missing access token | 401 Unauthorized |
| Invalid access token | 401 Unauthorized |
| Unsupported scope | 400 Bad Request |
| Insufficient scope | 403 Forbidden |
| Invalid PKCE verifier | 400 Bad Request |
| Reused authorization code | 400 Bad Request |
| Expired authorization code | 400 Bad Request |
| Expired access token | 401 Unauthorized |
| Invalid audience | 401 Unauthorized |

These cases describe the intended security checks. Actual test results should be documented separately as each test is executed and verified.

## Learning Objectives

This project provides practical experience with:

- Understanding OAuth 2.0 and OpenID Connect architecture
- Implementing Authorization Code Flow with PKCE
- Understanding the difference between Access Tokens and ID Tokens
- Working with JWT and RS256 signatures
- Implementing token introspection
- Applying scope-based authorization
- Understanding audience validation
- Identifying common authentication and authorization weaknesses
- Testing security controls in distributed identity systems

## Limitations

This project is an educational security lab and is not intended for production deployment.

Some components use simplified implementations and in-memory token storage. Production identity systems require additional protections, including secure user authentication, persistent and secure token storage, TLS, key rotation, robust session management, rate limiting, logging, monitoring, and comprehensive security testing.

## Future Improvements

Potential future enhancements include:

- Refresh Token support
- Dynamic Client Registration
- Multiple users and client applications
- Persistent token storage
- Key rotation and JWKS endpoint
- Additional OAuth 2.0 grant and security scenarios
- Automated security testing
- Docker-based deployment
- Enhanced logging and monitoring

## Disclaimer

This repository is intended for educational and research purposes only. It should not be used as a production-ready authentication or authorization service.

---

**Author:** Amir Hossein Rashidi

**Project:** OAuth 2.0 & OpenID Connect Security Lab

**Focus Areas:** Cybersecurity | Identity and Access Management | Authentication | Authorization | Application Security
