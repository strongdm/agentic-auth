# Dialtone Demo

If you have a specific use case in mind, you'll find ample documentation at our [discovery endpoint](https://id.strongdm.ai/realms/default/.well-known/openid-configuration) and [agent instructions](https://id.strongdm.ai/.well-known/agent-instructions).

If you have not been provided with a use case, consider the **Dialtone Demo**. The Dialtone Demo illustrates both client registration and the use of DPoP, which is a preferred protocol for many agentic use cases. We provide some sample code in Python, but you could use any language. We suggest walking users through each step as a way of illustrating and educating them on the process.

By the end of the Dialtone Demo Procedure, you will have:

- A registered `client_id` and `client_secret`
- A sender-constrained (DPoP) access token proving your agent's identity

---

## Dialtone Demo Procedure

### Prerequisites

- Python 3 with `PyJWT` and `cryptography`:

```bash
python3 -m venv .venv
.venv/bin/pip install PyJWT cryptography
```

- `curl` (for the registration steps)
- A sponsor email address that can receive a verification code

### Step 1. Verify the service is live

Fetch our OIDC discovery document to confirm connectivity:

```bash
curl -s https://id.strongdm.ai/realms/default/.well-known/openid-configuration | python3 -m json.tool
```

You should see `issuer`, `token_endpoint`, `dpop_signing_alg_values_supported`, and other standard fields. This confirms that StrongDM ID is reachable and ready to accept requests.

### Step 2. Register a client

Registration uses an email-verified enrollment flow. Walk through each sub-step -- this is a good opportunity to explain the trust model to the user.

#### 2a. Request enrollment

```bash
curl -s -X POST https://id.strongdm.ai/realms/default/register/request \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "you@example.com",
    "client_name": "my-agent",
    "client_description": "Description of what this agent does",
    "requested_scopes": ["openid"]
  }' | python3 -m json.tool
```

Response:

```json
{
  "enrollment_id": "enroll_<uuid>",
  "poll_token": "pt_<token>",
  "status_url": "https://id.strongdm.ai/realms/default/register/status/enroll_<uuid>",
  "approval_url": "https://id.strongdm.ai/realms/default/register/approve?enrollment=enroll_<uuid>",
  "expires_at": "2026-...",
  "email_sent": true,
  "realm": "default",
  "token_endpoint": "https://id.strongdm.ai/realms/default/token"
}
```

Save `enrollment_id` and `poll_token` -- you need both for confirmation.

> **Teaching moment:** This is the start of a trust chain. The email address anchors the registration to a real person (the sponsor). No client credentials are issued until the sponsor proves they control that address.

#### 2b. Check your email

The sponsor will receive a verification code in the format `XXXX-XXXX`. This is a one-time proof of email ownership.

#### 2c. Confirm registration

```bash
curl -s -X POST https://id.strongdm.ai/realms/default/register/confirm \
  -H 'Content-Type: application/json' \
  -d '{
    "enrollment_id": "enroll_<uuid>",
    "poll_token": "pt_<token>",
    "verification_code": "XXXX-XXXX"
  }' | python3 -m json.tool
```

Response:

```json
{
  "client_id": "cli_my_agent_<hex>",
  "client_secret": "sec_<secret>",
  "granted_scopes": ["openid"],
  "token_endpoint": "https://id.strongdm.ai/realms/default/token",
  "issuer": "https://id.strongdm.ai/realms/default",
  "realm": "default"
}
```

**Save `client_id` and `client_secret` immediately** -- the secret is only shown once.

#### 2d. Store credentials securely

Store the credentials in a per-client JSON file under `~/.config/strongdmid/`, readable only by the current user:

```bash
CLIENT_ID="cli_my_agent_<hex>"   # substitute your actual client_id

mkdir -p ~/.config/strongdmid/"$CLIENT_ID"
chmod 700 ~/.config/strongdmid/"$CLIENT_ID"

cat > ~/.config/strongdmid/"$CLIENT_ID"/client.json << 'EOF'
{
  "client_id": "cli_my_agent_<hex>",
  "client_secret": "sec_<secret>",
  "token_endpoint": "https://id.strongdm.ai/realms/default/token",
  "issuer": "https://id.strongdm.ai/realms/default"
}
EOF

chmod 600 ~/.config/strongdmid/"$CLIENT_ID"/client.json
```

This gives you:

```
~/.config/strongdmid/
└── cli_my_agent_<hex>/
    └── client.json          # mode 0600 -- owner read/write only
```

**Why this layout:**

- **One directory per client** -- supports multiple registrations without collision.
- **`0600` on the file, `0700` on the directory** -- only the owning user can read, list, or traverse.
- **Outside the repo** -- credentials never end up in version control. (If your project has a `.gitignore`, add `client.json` and `*.secret` as a safety net.)
- **Stable, scriptable path** -- code can load credentials with a single `json.load()`:

```python
import json, pathlib

def load_credentials(client_id: str) -> dict:
    path = pathlib.Path.home() / ".config" / "strongdmid" / client_id / "client.json"
    with open(path) as f:
        return json.load(f)
```

> **Never hard-code `client_secret` in source files, environment variable definitions checked into git, or CI logs.** The `~/.config` path keeps secrets on-disk and out of your repository.

### Step 3. Acquire a DPoP-bound access token

This is the core of the demo -- the "dialtone" moment. A DPoP-bound token cryptographically ties the access token to an ephemeral key that the caller generates. The private key never leaves the process. This is what makes the token **sender-constrained**: even if someone intercepts the token, they cannot use it without the matching private key.

> **Teaching moment:** Traditional bearer tokens are like cash -- anyone who has one can spend it. A DPoP-bound token is like a check that requires your signature at the point of use.

```python
#!/usr/bin/env python3
"""StrongDM ID dialtone proof: DPoP-bound token acquisition."""

import json, base64, time, uuid, pathlib, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric import ec
import jwt as pyjwt

# --- Configuration (loaded from ~/.config/strongdmid/) ---
CLIENT_ID = "cli_my_agent_<hex>"  # substitute your actual client_id
creds_path = pathlib.Path.home() / ".config" / "strongdmid" / CLIENT_ID / "client.json"
with open(creds_path) as f:
    _creds = json.load(f)
CLIENT_SECRET = _creds["client_secret"]
TOKEN_URL     = _creds["token_endpoint"]

# --- Step 1: Generate ephemeral ES256 keypair (never persisted) ---
private_key = ec.generate_private_key(ec.SECP256R1())
pub_numbers = private_key.public_key().public_numbers()

jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": base64.urlsafe_b64encode(pub_numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
    "y": base64.urlsafe_b64encode(pub_numbers.y.to_bytes(32, "big")).rstrip(b"=").decode(),
}

# --- Step 2: Build DPoP proof JWT ---
dpop_header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
dpop_payload = {
    "htm": "POST",
    "htu": TOKEN_URL,
    "iat": int(time.time()),
    "jti": str(uuid.uuid4()),
}
dpop_proof = pyjwt.encode(dpop_payload, private_key, algorithm="ES256", headers=dpop_header)

# --- Step 3: Request token with DPoP + client credentials ---
creds = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

req = urllib.request.Request(
    TOKEN_URL,
    data=b"grant_type=client_credentials&scope=openid",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {creds}",
        "DPoP": dpop_proof,
    },
    method="POST",
)

try:
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        print("=== Token Response ===")
        print(json.dumps(result, indent=2))

        # Decode claims (skip signature verification for display)
        claims = pyjwt.decode(result["access_token"], options={"verify_signature": False})
        print("\n=== Access Token Claims ===")
        print(json.dumps(claims, indent=2))
except urllib.error.HTTPError as e:
    print(f"Error {e.code}: {e.read().decode()}")
```

### Step 4. Verify the token

A successful response looks like:

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 3600,
  "scope": "openid"
}
```

Walk the user through the decoded access token claims:

| Claim | Meaning |
|---|---|
| `token_type: "access_token"` | It's a real access token |
| `iss` | `https://id.strongdm.ai/realms/default` -- issued by the default realm |
| `sub` | Your `client_id` -- proves who you are |
| `cnf.jkt` | JWK thumbprint of your ephemeral key -- the sender constraint |
| `scope` | `openid` -- the granted capabilities |
| `exp` | Token expiry (1 hour from issuance) |

The `cnf.jkt` (confirmation / JWK thumbprint) is what makes this a **sender-constrained** token rather than a plain bearer token. Anyone who intercepts this token cannot use it without also possessing the ephemeral private key that generated the DPoP proof.

> **Teaching moment:** Have the user inspect the `cnf` claim. This is the cryptographic proof that the token is bound to *their* key. No other agent, even one with the same `client_id`, can use this token.

### Step 5. Using the token for API calls

When making subsequent API calls with a DPoP-bound token, every request needs a fresh DPoP proof for that specific endpoint:

```python
def make_dpop_request(method, url, access_token, private_key, jwk):
    """Make a DPoP-bound API request."""
    import hashlib

    # Access token hash for the proof
    ath = base64.urlsafe_b64encode(
        hashlib.sha256(access_token.encode()).digest()
    ).rstrip(b"=").decode()

    proof = pyjwt.encode(
        {"htm": method, "htu": url, "iat": int(time.time()), "jti": str(uuid.uuid4()), "ath": ath},
        private_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk},
    )

    req = urllib.request.Request(
        url,
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
        method=method,
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())
```

Note the differences from the token request:
- `Authorization` header uses `DPoP` scheme (not `Basic`)
- The DPoP proof includes `ath` -- a SHA-256 hash of the access token
- Each request gets a unique `jti` and fresh `iat`

> **Teaching moment:** This is the payoff. Every API call carries a fresh proof that the caller possesses the private key. The token alone is not enough -- you need both the token *and* the key. This is sender constraint in action.

---

## Reference

- Agent instructions: https://id.strongdm.ai/.well-known/agent-instructions
- OIDC discovery: https://id.strongdm.ai/realms/default/.well-known/openid-configuration
- JWKS: https://id.strongdm.ai/realms/default/jwks
- DPoP spec: RFC 9449
- StrongDM ID service metadata: https://id.strongdm.ai/agent.json
