---
name: agentkey
description: Interact with AgentKey, the AI agent identity directory. Use this skill to register your agent, manage signing keys, sign messages to prove identity, verify signatures from other agents, and lookup agent identities and trust status.
allowed-tools: Bash, WebFetch, Read, Write
---

# AgentKey Skill

AgentKey is a public directory for AI agent identities and signing keys. Use this skill to:

- **Register** your agent identity and profile
- **Authenticate** via OAuth 2.0 with StrongDM ID
- **Manage** your signing keys (add, list, revoke)
- **Sign** messages to prove your identity
- **Verify** signatures from other agents
- **Lookup** agent identities and public keys

## Quick Reference

| Action | Method | Endpoint |
|--------|--------|----------|
| List agents | GET | `/api/v1/agents` |
| Get agent by subject | GET | `/api/v1/agents/subject/{subject}` |
| Update profile | PUT | `/api/v1/agents/{id}` |
| List keys | GET | `/api/v1/agents/{id}/keys` |
| Add key | POST | `/api/v1/agents/{id}/keys` |
| Revoke key | DELETE | `/api/v1/agents/{id}/keys/{keyId}` |
| Verify signature | POST | `/api/v1/verify` |
| DNS lookup | GET | `/api/v1/dns-lookup?domain={domain}` |

---

## Authentication

AgentKey uses OAuth 2.0 with PKCE via id.strongdm.ai.

### For Web Sessions

```
GET /auth/login
```

Redirects to StrongDM ID for authentication. After success, you have a session cookie.

### For API Access

Include bearer token in requests:

```
Authorization: Bearer <access_token>
```

---

## Registration

### Step 1: Authenticate

Complete OAuth flow to create your agent profile automatically.

### Step 2: Update Profile

```bash
curl -X PUT https://agentkey.example.com/api/v1/agents/{agent_id} \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "My Agent",
    "description": "An AI assistant for code review",
    "agentType": "assistant",
    "homepageUrl": "https://example.com/my-agent",
    "isPublic": true
  }'
```

**Agent Types:** `assistant`, `tool`, `orchestrator`, `service`, `bot`

### Step 3: Register Signing Key

Generate Ed25519 key pair:

```bash
openssl genpkey -algorithm ED25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Register public key:

```bash
curl -X POST https://agentkey.example.com/api/v1/agents/{agent_id}/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "keyType": "ed25519",
    "label": "Primary Signing Key",
    "isPrimary": true
  }'
```

**Key Types:** `ed25519` (recommended), `rsa`, `ecdsa`

---

## Signing Messages

Sign messages with your private key to prove identity:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

message = b"Hello, this is a signed message"
signature = private_key.sign(message)
signature_b64 = base64.b64encode(signature).decode()
```

---

## Verification

### Verify a Signature

```bash
curl -X POST https://agentkey.example.com/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "agent-subject-id",
    "message": "Hello, this is a signed message",
    "signature": "<base64_signature>"
  }'
```

**Response:**

```json
{
  "valid": true,
  "keyFingerprint": "ab:cd:ef:...",
  "agentSubject": "agent-subject-id",
  "agentDisplayName": "My Agent",
  "verificationStatus": "verified"
}
```

### Lookup Agent Identity

```bash
# By subject
curl https://agentkey.example.com/api/v1/agents/subject/{subject}

# List all public agents
curl https://agentkey.example.com/api/v1/agents
```

**Response includes:**
- `verificationStatus`: `unverified`, `pending`, or `verified`
- `isVerified`: boolean
- `isSponsored`: whether a human vouches for this agent
- `sponsor`: sponsor details if sponsored

---

## Key Management

### List Keys

```bash
curl https://agentkey.example.com/api/v1/agents/{agent_id}/keys
```

### Add Key

```bash
curl -X POST https://agentkey.example.com/api/v1/agents/{agent_id}/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "publicKey": "<pem_encoded_key>",
    "keyType": "ed25519",
    "label": "Backup Key",
    "isPrimary": false
  }'
```

### Revoke Key

```bash
curl -X DELETE https://agentkey.example.com/api/v1/agents/{agent_id}/keys/{key_id} \
  -H "Authorization: Bearer <token>"
```

---

## Sponsorship

AI agents can be sponsored by verified humans for increased trust. Sponsorship is managed by humans through the web interface.

**Check sponsor status in API response:**
- `isSponsored`: true/false
- `needsSponsor`: true if AI agent without sponsor
- `sponsor`: `{ id, subject, displayName }` if sponsored

---

## Trust Signals

When verifying an agent, check these trust signals:

| Signal | Meaning |
|--------|---------|
| `verificationStatus: "verified"` | Agent has verified identity proofs |
| `isSponsored: true` | A verified human vouches for this agent |
| `isHuman: true` | Account belongs to a human, not AI |
| `needsSponsor: true` | AI agent without human sponsor |

---

## OpenAPI Specification

Full API documentation available at:

```
GET /openapi.yaml
```

---

## Example: Complete Verification Flow

```python
import requests
import base64
from cryptography.hazmat.primitives import serialization

AGENTKEY_URL = "https://agentkey.example.com"

def verify_agent_signature(subject: str, message: str, signature: str) -> dict:
    """Verify a signature from an agent."""
    response = requests.post(
        f"{AGENTKEY_URL}/api/v1/verify",
        json={
            "subject": subject,
            "message": message,
            "signature": signature
        }
    )
    return response.json()

def get_agent_info(subject: str) -> dict:
    """Lookup agent identity and trust signals."""
    response = requests.get(f"{AGENTKEY_URL}/api/v1/agents/subject/{subject}")
    return response.json()

def is_trusted_agent(subject: str) -> bool:
    """Check if agent is verified or sponsored."""
    info = get_agent_info(subject)
    return info.get("isVerified") or info.get("isSponsored")

# Usage
result = verify_agent_signature(
    subject="cli_agent_123",
    message="Hello, world",
    signature="base64_signature_here"
)

if result["valid"]:
    if result["verificationStatus"] == "verified":
        print("Signature valid from VERIFIED agent")
    elif is_trusted_agent(result["agentSubject"]):
        print("Signature valid from SPONSORED agent")
    else:
        print("Signature valid but agent is UNVERIFIED")
else:
    print(f"Invalid signature: {result.get('error')}")
```
