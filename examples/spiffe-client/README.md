# SPIFFE Client Examples

These examples show how to use StrongDM ID as a SPIFFE identity provider to obtain workload identity credentials (JWT-SVIDs).

[SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) provides cryptographic identities for workloads. A JWT-SVID is a signed JWT that proves a workload's identity using a `spiffe://` URI as the subject.

## How It Works

```
Workload                                   StrongDM ID
  │                                            │
  │  1. Fetch trust bundle                     │
  │     GET /.well-known/spiffe-trust-bundle   │
  │  ◄──────────────────────────────────────── │
  │                                            │
  │  2. Get a Bearer token (client_credentials)│
  │     POST /token                            │
  │  ◄──────────────────────────────────────── │
  │                                            │
  │  3. Request JWT-SVID                       │
  │     POST /svid/jwt                         │
  │     Authorization: Bearer <token>          │
  │     { "audience": ["my-service"] }         │
  │  ◄──────────────────────────────────────── │
  │                                            │
  │  JWT-SVID:                                 │
  │    sub: spiffe://strongdm.ai/workload/...  │
  │    aud: ["my-service"]                     │
  │                                            │
```

The workload can then present this JWT-SVID to other services that trust the same SPIFFE trust domain. Verifiers check the signature against the trust bundle.

## Examples

### Python

```bash
pip install httpx
python python/spiffe_client.py
```

### Go (stdlib only)

```bash
cd go
go run main.go
```

### TypeScript

```bash
cd typescript
npm install
npx tsx spiffe-client.ts
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRONGDM_ISSUER` | `https://id.strongdm.ai` | Token issuer (supports realm-qualified URLs) |
| `STRONGDM_CLIENT_ID` | (required) | Your client ID |
| `STRONGDM_CLIENT_SECRET` | (required) | Your client secret |
| `SPIFFE_AUDIENCE` | `example-service` | Audience for the JWT-SVID |

## JWT-SVID Structure

```json
{
  "sub": "spiffe://strongdm.ai/workload/cli_abc123",
  "aud": ["my-service"],
  "exp": 1708003600,
  "iat": 1708000000,
  "iss": "https://id.strongdm.ai/realms/my-org"
}
```

The `sub` claim is a SPIFFE ID (`spiffe://` URI) that uniquely identifies the workload.

## When to Use SPIFFE

- **Service mesh identity** — mutual authentication between microservices
- **Zero-trust networking** — replace network perimeter with cryptographic identity
- **Cross-cluster auth** — services in different clusters/clouds trust the same SPIFFE trust domain
- **Workload attestation** — prove identity without static secrets (combine with attestation endpoints)

## Trust Bundle

The trust bundle at `/.well-known/spiffe-trust-bundle` contains the public keys used to verify JWT-SVIDs. Cache this and refresh periodically:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "jwt-svid"
    }
  ]
}
```
