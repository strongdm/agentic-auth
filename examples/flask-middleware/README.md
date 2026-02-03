# Flask Middleware for StrongDM ID

This example demonstrates how to protect Flask API endpoints using StrongDM ID (AI Principalis) authentication.

## Features

- JWT signature verification using JWKS
- Token introspection fallback
- Scope-based access control
- DPoP (Demonstrating Proof of Possession) support
- JWKS caching for performance

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Example App

```bash
# Basic usage
python app.py

# With custom configuration
STRONGDM_ISSUER=https://id.strongdm.ai \
STRONGDM_AUDIENCE=my-api \
python app.py
```

### 3. Test with a Token

First, get a token from StrongDM ID:

```bash
# Get an access token (you'll need valid client credentials)
TOKEN=$(curl -s -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=share:create share:list" | jq -r '.access_token')

# Call the protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/protected
```

## Usage in Your App

### Basic Authentication

```python
from flask import Flask
from strongdm_auth import StrongDMAuth

app = Flask(__name__)
auth = StrongDMAuth(app)

@app.route('/protected')
@auth.require_auth()
def protected():
    return "You're authenticated!"
```

### Scope-Based Access Control

```python
# Require a specific scope
@app.route('/admin')
@auth.require_scope('pctl:admin')
def admin():
    return "Admin only"

# Require at least one of multiple scopes
@app.route('/shares')
@auth.require_scope('share:list', 'share:create')
def list_shares():
    return "Shares list"

# Require ALL specified scopes
@app.route('/super-admin')
@auth.require_scope('pctl:admin', 'pctl:fuzz', require_all=True)
def super_admin():
    return "Super admin"
```

### Accessing Token Claims

```python
from flask import g

@app.route('/me')
@auth.require_auth()
def me():
    # Access raw claims
    claims = g.token_claims

    # Or use the helper
    agent = auth.get_current_agent()
    return {
        "subject": agent['subject'],
        "scopes": agent['scopes'],
    }
```

### With Token Introspection

Enable introspection for additional validation (useful for revocation checking):

```python
auth = StrongDMAuth(
    app,
    introspection_enabled=True,
    client_id="your_client_id",
    client_secret="your_client_secret",
)
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `issuer` | `https://id.strongdm.ai` | Token issuer URL |
| `audience` | `None` | Expected audience claim |
| `jwks_cache_ttl` | `900` (15 min) | JWKS cache TTL in seconds |
| `introspection_enabled` | `False` | Enable token introspection |
| `client_id` | `None` | Client ID (for introspection) |
| `client_secret` | `None` | Client secret (for introspection) |

## Environment Variables

```bash
STRONGDM_ISSUER=https://id.strongdm.ai
STRONGDM_AUDIENCE=my-api
STRONGDM_INTROSPECTION_ENABLED=true
STRONGDM_CLIENT_ID=cli_xxx
STRONGDM_CLIENT_SECRET=sec_xxx
PORT=5000
FLASK_DEBUG=true
```

## Available Scopes

See the [StrongDM ID documentation](https://id.strongdm.ai/.well-known/agent-instructions) for available scopes:

| Scope | Description |
|-------|-------------|
| `share:create` | Create share grants |
| `share:list` | List share grants |
| `share:revoke` | Revoke share grants |
| `share:use` | Use granted access |
| `pctl:read` | Read-only admin access |
| `pctl:admin` | Full admin access |

## Error Responses

The middleware returns standard HTTP error responses:

| Status | Meaning |
|--------|---------|
| `401` | Missing/invalid/expired token |
| `403` | Valid token but insufficient scope |
| `500` | Server configuration error |

Example error response:
```json
{
  "error": "Missing required scopes: pctl:admin"
}
```

## DPoP Support

For sender-constrained tokens, the middleware automatically validates DPoP proofs:

```bash
# Request with DPoP
curl -X GET http://localhost:5000/protected \
  -H "Authorization: DPoP $DPOP_TOKEN" \
  -H "DPoP: $DPOP_PROOF"
```

## Security Notes

1. **Always use HTTPS in production** - Bearer tokens can be intercepted over HTTP
2. **Set appropriate token TTLs** - Shorter is better for security
3. **Use DPoP for sensitive operations** - Prevents token theft
4. **Enable introspection for critical endpoints** - Catches revoked tokens
