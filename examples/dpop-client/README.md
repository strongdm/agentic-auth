# DPoP Client Examples

These examples show how to **create DPoP proofs** and use them to obtain sender-constrained tokens from StrongDM ID. DPoP (Demonstrating Proof of Possession, [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) binds tokens to a cryptographic key so they can't be stolen or replayed.

The middleware examples in this repo show how to **validate** DPoP tokens server-side. These examples show the **client side** — how an agent generates a key pair, creates DPoP proofs, and requests DPoP-bound tokens.

## How DPoP Works

```
Agent                                      StrongDM ID
  │                                            │
  │  1. Generate EC P-256 key pair             │
  │                                            │
  │  2. POST /token                            │
  │     Authorization: Basic (client creds)    │
  │     DPoP: <proof JWT signed with key>      │
  │     ──────────────────────────────────────►│
  │                                            │
  │  3. Response:                              │
  │     access_token (with cnf.jkt thumbprint) │
  │     token_type: "DPoP"                     │
  │  ◄──────────────────────────────────────── │
  │                                            │
  │  4. GET /api/resource                      │
  │     Authorization: DPoP <access_token>     │
  │     DPoP: <new proof for this request>     │
  │     ──────────────────────────────────────►│
  │                                            │
```

Key properties:
- The agent generates a fresh key pair (never leaves the agent)
- Each request includes a DPoP proof JWT signed with the private key
- The proof binds to the HTTP method, URL, and access token hash
- If someone steals the access token, they can't use it without the private key

## Examples

### Python

```bash
pip install jwcrypto httpx
python python/dpop_client.py
```

### Go (stdlib only — zero external dependencies)

```bash
cd go
go run main.go
```

### TypeScript

```bash
cd typescript
npm install
npx tsx dpop-client.ts
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRONGDM_ISSUER` | `https://id.strongdm.ai` | Token issuer (supports realm-qualified URLs like `https://id.strongdm.ai/realms/my-org`) |
| `STRONGDM_CLIENT_ID` | (required) | Your client ID |
| `STRONGDM_CLIENT_SECRET` | (required) | Your client secret |

## DPoP Proof Structure

The DPoP proof is a JWT with:

**Header:**
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

**Payload:**
```json
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "https://id.strongdm.ai/token",
  "iat": 1708000000,
  "ath": "sha256-hash-of-access-token"
}
```

The `ath` (access token hash) is only included when proving possession for an API call, not during the initial token request.

## When to Use DPoP

- **Laptop agents** (Pathway A) — keys stored in config files could be read by other processes
- **Untrusted environments** — anywhere a bearer token might be intercepted
- **High-security APIs** — when token theft would have serious consequences

For server-to-server calls in trusted infrastructure, bearer tokens with client_credentials are simpler and sufficient.
