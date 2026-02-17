# StrongDM ID Examples

Example implementations showing how to integrate with [StrongDM ID](https://id.strongdm.ai) for agent authentication.

## What is StrongDM ID?

StrongDM ID is an identity service built for the agentic era. While it supports traditional OAuth/OIDC, its primary purpose is enabling **agents to authenticate, authorize, and trust other agents**.

Key capabilities:
- **Prove identity to other agents** - Sender-constrained tokens (DPoP) that can't be stolen
- **Carry proof of user delegation** - Tokens proving "User X gave me permission to do Y"
- **Enforce capability boundaries** - Cryptographically-enforced scopes
- **Spawn child agents with narrowed permissions** - Automatic scope narrowing
- **Maintain audit trails** - Every action logged with unique identity

## Examples

### [Flask Middleware](./examples/flask-middleware)

Python middleware for protecting Flask API endpoints.

```python
from flask import Flask
from strongdm_auth import StrongDMAuth

app = Flask(__name__)
auth = StrongDMAuth(app)

@app.route('/protected')
@auth.require_auth()
def protected():
    return "You're authenticated!"

@app.route('/admin')
@auth.require_scope('admin')
def admin():
    return "Admin only"
```

### [Next.js Middleware](./examples/nextjs-middleware)

TypeScript middleware for protecting Next.js API routes.

```typescript
// middleware.ts
const protectedRoutes = {
  "/api/protected": {},
  "/api/admin": { scopes: ["admin"] },
};
```

### [Go Middleware](./examples/go-middleware)

Go middleware for protecting `net/http` endpoints. Includes a client example for registration, token acquisition, and API calls.

```go
auth, _ := New(Config{Issuer: "https://id.strongdm.ai"}, log)

mux := http.NewServeMux()
mux.Handle("GET /protected", auth.RequireAuth(handler))
mux.Handle("GET /admin", auth.RequireScope("admin")(handler))
```

```bash
# Client: register, confirm, then call an API — all from the CLI
go run ./client register you@example.com
go run ./client confirm <enrollment_id> <poll_token> <code>
go run ./client call <client_id> <client_secret> http://localhost:8080/protected
```

### [DPoP Client](./examples/dpop-client)

Client-side DPoP proof generation in Python, Go (stdlib only), and TypeScript. Shows agents how to create sender-constrained tokens that can't be stolen or replayed.

```go
// Generate key, create proof, request DPoP-bound token — zero dependencies
privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
proof := createDPoPProof(privKey, "POST", tokenURL, "")
req.Header.Set("DPoP", proof)
```

### [SPIFFE Client](./examples/spiffe-client)

Workload identity via SPIFFE/SVID in Python, Go, and TypeScript. Fetch trust bundles and request JWT-SVIDs for service mesh authentication.

```bash
# Fetch trust bundle, get bearer token, request JWT-SVID
STRONGDM_CLIENT_ID=cli_xxx STRONGDM_CLIENT_SECRET=sec_xxx \
  python examples/spiffe-client/python/spiffe_client.py
```

## Getting Started

### 1. Register Your Agent

```bash
# Option 1: Root path (realm resolved from email domain)
curl -X POST https://id.strongdm.ai/register/agent \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@company.com",
    "agent_name": "my-agent",
    "requested_scopes": ["openid", "email"]
  }'

# Option 2: Realm-qualified path (explicit, preferred for multi-tenant)
curl -X POST https://id.strongdm.ai/realms/my-org/register/agent \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@company.com",
    "agent_name": "my-agent",
    "requested_scopes": ["openid", "email"]
  }'

# Human clicks email link, gets enrollment token
# Agent activates with the token
curl -X POST https://id.strongdm.ai/register/agent/activate \
  -H "Content-Type: application/json" \
  -d '{"enrollment_token": "pt_..."}'
```

### 2. Get Access Tokens

```bash
curl -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=openid email"
```

> **Note**: The token endpoint resolves your realm automatically from your `client_id`.
> The returned access token's `iss` claim will be realm-qualified
> (e.g., `https://id.strongdm.ai/realms/my-org`). Ensure your token validation
> accepts realm-qualified issuers.

### 3. Use the Examples

See individual example READMEs for setup instructions:

**Server-side (validate tokens):**
- [Flask Middleware](./examples/flask-middleware/README.md) — Python
- [Go Middleware](./examples/go-middleware/README.md) — Go
- [Next.js Middleware](./examples/nextjs-middleware/README.md) — TypeScript

**Client-side (acquire tokens):**
- [DPoP Client](./examples/dpop-client/README.md) — Sender-constrained tokens (Python, Go, TypeScript)
- [SPIFFE Client](./examples/spiffe-client/README.md) — Workload identity / JWT-SVID (Python, Go, TypeScript)

## Available Scopes

| Scope | Description | Access |
|-------|-------------|--------|
| `openid` | OpenID Connect identity | Any registered client |
| `email` | Access user email | Any registered client |
| `admin` | Administrative access | Superadmin only |

Additional scopes can be registered per-realm via the admin API. See the
[agent-instructions](https://id.strongdm.ai/.well-known/agent-instructions) for details.

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register/agent` | POST | Start agent enrollment |
| `/register/agent/activate` | POST | Activate with enrollment token |
| `/register/request` | POST | Start client self-registration |
| `/register/confirm` | POST | Complete self-registration |
| `/register/status/:id` | GET | Poll registration status |
| `/token` | POST | Get access token |
| `/realms/{name}/token` | POST | Realm-qualified token endpoint |
| `/introspect` | POST | Validate token |
| `/revoke` | POST | Token revocation (RFC 7009) |
| `/userinfo` | GET | OIDC userinfo (authenticated) |
| `/jwks` | GET | JSON Web Key Set |
| `/realms/{name}/jwks` | GET | Realm-qualified JWKS |
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/realms/{name}/.well-known/openid-configuration` | GET | Realm-qualified discovery |
| `/svid/jwt` | POST | Request JWT-SVID (authenticated) |
| `/.well-known/spiffe-trust-bundle` | GET | SPIFFE trust bundle (JWKS) |

### Token Response

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email"
}
```

## Documentation

- [Dialtone Demo](./DIALTONE-DEMO.md) - End-to-end walkthrough: register a client and get a DPoP-bound token
- [Use Cases](./USE-CASES.md) - 8 ways agents use identity (with code examples)
- [Agent Instructions](https://id.strongdm.ai/.well-known/agent-instructions) - Full reference for agents
- [Agent Patterns Cookbook](https://id.strongdm.ai/docs/agent-patterns/README.md) - Advanced implementation patterns
- [OIDC Discovery (root)](https://id.strongdm.ai/.well-known/openid-configuration) - Root-level OIDC metadata
- [OIDC Discovery (realm)](https://id.strongdm.ai/realms/{realm}/.well-known/openid-configuration) - Realm-qualified OIDC metadata (preferred)
- [JWKS](https://id.strongdm.ai/jwks) - Public keys for token verification

## Security Features

- **JWT Signature Verification** - Tokens signed with RS256/ES256/EdDSA
- **DPoP Support** - Sender-constrained tokens that can't be stolen/replayed
- **Token Introspection** - Real-time revocation checking
- **Scope Enforcement** - Cedar policy-based authorization
- **Short-Lived Tokens** - 1-hour expiry by default
