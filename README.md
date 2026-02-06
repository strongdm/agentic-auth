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
@auth.require_scope('pctl:read')
def admin():
    return "Admin only"
```

### [Next.js Middleware](./examples/nextjs-middleware)

TypeScript middleware for protecting Next.js API routes.

```typescript
// middleware.ts
const protectedRoutes = {
  "/api/protected": {},
  "/api/admin": { scopes: ["pctl:read"] },
};
```

## Getting Started

### 1. Register Your Agent

```bash
# Human sponsor initiates registration
curl -X POST https://id.strongdm.ai/register/agent \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@company.com",
    "agent_name": "my-agent",
    "requested_scopes": ["pctl:read"]
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
  -d "scope=pctl:read"
```

### 3. Use the Examples

See individual example READMEs for setup instructions:
- [Flask Middleware README](./examples/flask-middleware/README.md)
- [Next.js Middleware README](./examples/nextjs-middleware/README.md)

## Available Scopes

| Scope | Description | Domain Restriction |
|-------|-------------|-------------------|
| `pctl:read` | Read-only admin access | Any |

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register/agent` | POST | Start agent enrollment |
| `/register/agent/activate` | POST | Activate with enrollment token |
| `/token` | POST | Get access token |
| `/introspect` | POST | Validate token |
| `/jwks` | GET | JSON Web Key Set |
| `/.well-known/openid-configuration` | GET | OIDC discovery |

### Token Response

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "pctl:read"
}
```

## Documentation

- [Agent Instructions](https://id.strongdm.ai/.well-known/agent-instructions) - Getting started guide
- [OIDC Discovery](https://id.strongdm.ai/.well-known/openid-configuration) - Standard OIDC metadata
- [JWKS](https://id.strongdm.ai/jwks) - Public keys for token verification

## Security Features

- **JWT Signature Verification** - Tokens signed with RS256/ES256/EdDSA
- **DPoP Support** - Sender-constrained tokens that can't be stolen/replayed
- **Token Introspection** - Real-time revocation checking
- **Scope Enforcement** - Cedar policy-based authorization
- **Short-Lived Tokens** - 1-hour expiry by default
