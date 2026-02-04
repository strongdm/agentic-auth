# AgentKey

A Keybase-like public directory for AI agents, built with server-side Swift/Vapor, using id.strongdm.ai for authentication.

## Overview

AgentKey is a public directory where AI agents register their identities and **signing keys**. Other services can look up an agent and verify that messages/requests truly came from that agent by checking signatures against their registered public keys.

### How It Works

1. **Register Keys**: Agents register their Ed25519, RSA, or ECDSA public signing keys
2. **Sign Messages**: Agent A signs requests/messages with their private key
3. **Verify Signatures**: Service B looks up Agent A in AgentKey, fetches their public key, and verifies the signature
4. **Build Trust**: Add identity proofs (DNS, HTTP, GitHub) to establish verified status

## Requirements

- Swift 5.9+
- macOS 13+ or Linux

## Quick Start

1. **Clone and navigate to the project**:
   ```bash
   cd examples/agentkey
   ```

2. **Copy environment configuration**:
   ```bash
   cp .env.example .env
   ```

3. **Configure OAuth credentials** (edit `.env`):
   ```env
   STRONGDM_CLIENT_ID=cli_your_client_id
   STRONGDM_CLIENT_SECRET=sec_your_client_secret
   ```

4. **Build and run**:
   ```bash
   swift run App
   ```

5. **Visit** http://localhost:8080

## Project Structure

```
agentkey/
├── Package.swift           # Dependencies
├── Sources/App/
│   ├── entrypoint.swift    # Application entry point
│   ├── configure.swift     # App configuration
│   ├── routes.swift        # Route registration
│   │
│   ├── Auth/               # StrongDM authentication
│   │   ├── StrongDMAuth.swift
│   │   ├── StrongDMAuthMiddleware.swift
│   │   └── Models/
│   │       ├── TokenClaims.swift
│   │       └── AgentInfo.swift
│   │
│   ├── Controllers/
│   │   ├── API/            # JSON API controllers
│   │   │   ├── AgentAPIController.swift
│   │   │   ├── KeyAPIController.swift
│   │   │   └── VerifyAPIController.swift
│   │   └── Web/            # Web UI controllers
│   │       ├── HomeController.swift
│   │       ├── ProfileController.swift
│   │       ├── DashboardController.swift
│   │       └── AuthController.swift
│   │
│   ├── Models/             # Database models
│   │   ├── Agent.swift
│   │   ├── AgentPublicKey.swift
│   │   ├── AgentProof.swift
│   │   └── ActivityLog.swift
│   │
│   └── Migrations/         # Database migrations
│
├── Resources/Views/        # Leaf templates
├── Public/                 # Static assets (CSS, JS)
└── Tests/AppTests/
```

## API Reference

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agents` | List all public agents |
| GET | `/api/v1/agents/:id` | Get agent by ID |
| GET | `/api/v1/agents/subject/:subject` | Get agent by subject |
| GET | `/api/v1/agents/:id/keys` | List agent's public keys |
| POST | `/api/v1/verify` | Verify a signature |
| GET | `/health` | Health check |

### Protected Endpoints (requires Bearer token)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents` | Register new agent |
| PUT | `/api/v1/agents/:id` | Update agent (owner only) |
| DELETE | `/api/v1/agents/:id` | Delete agent (owner only) |
| POST | `/api/v1/agents/:id/keys` | Add public key |
| DELETE | `/api/v1/agents/:id/keys/:keyId` | Revoke key |
| GET | `/api/v1/agents/:id/activity` | View activity log |

### Signature Verification

```bash
# Verify a signature
curl -X POST https://agentkey.example.com/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "my-agent",
    "message": "Hello, World!",
    "signature": "base64-encoded-signature"
  }'

# Response
{
  "valid": true,
  "keyFingerprint": "aa:bb:cc:...",
  "agentSubject": "my-agent",
  "agentDisplayName": "My Agent",
  "verificationStatus": "verified"
}
```

### Register an Agent

```bash
curl -X POST https://agentkey.example.com/api/v1/agents \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "My AI Agent",
    "description": "A helpful assistant",
    "agentType": "assistant",
    "isPublic": true
  }'
```

### Add a Signing Key

```bash
curl -X POST https://agentkey.example.com/api/v1/agents/<id>/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "keyType": "ed25519",
    "label": "Production Key",
    "isPrimary": true
  }'
```

## Web UI

| Route | Description |
|-------|-------------|
| `/` | Landing page with featured agents |
| `/directory` | Browse all public agents |
| `/search?q=` | Search agents |
| `/@{subject}` | Public agent profile (Keybase-style URL) |
| `/verify` | Signature verification tool |
| `/dashboard` | Authenticated user dashboard |

## Authentication

### API Authentication
- Bearer tokens from id.strongdm.ai
- JWT verification via JWKS (15-minute cache)
- Optional: Token introspection fallback

### Web Authentication
- OAuth 2.0 flow with id.strongdm.ai
- Session cookies for authenticated state
- CSRF protection on forms

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STRONGDM_ISSUER` | Token issuer URL | `https://id.strongdm.ai` |
| `STRONGDM_AUDIENCE` | Expected token audience | - |
| `STRONGDM_CLIENT_ID` | OAuth client ID | - |
| `STRONGDM_CLIENT_SECRET` | OAuth client secret | - |
| `STRONGDM_CALLBACK_URL` | OAuth callback URL | `http://localhost:8080/auth/callback` |
| `STRONGDM_INTROSPECTION_ENABLED` | Enable token introspection | `false` |
| `DATABASE_URL` | PostgreSQL connection string | SQLite (dev) |

## Development

### Running Tests

```bash
swift test
```

### Building for Production

```bash
swift build -c release
```

### Database

- **Development**: SQLite (automatic, stored as `agentkey.sqlite`)
- **Production**: PostgreSQL (set `DATABASE_URL`)

Run migrations:
```bash
swift run App migrate
```

## Key Types Supported

- **Ed25519**: Modern, compact signatures (recommended)
- **RSA**: Traditional, widely supported
- **ECDSA**: Elliptic curve signatures

## Identity Proofs

Agents can add proofs to verify ownership of:

- **DNS**: Add TXT record `_agentkey.domain.com`
- **HTTP**: Host file at `/.well-known/agentkey.txt`
- **GitHub**: Create public gist with verification message
- **Twitter/X**: Post verification tweet

## License

See the repository root for license information.
