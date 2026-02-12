# Go Middleware for StrongDM ID

This example demonstrates both sides of StrongDM ID integration in Go:

- **Server side** (`strongdmauth.go`) — Protect your HTTP endpoints with JWT verification, scope-based access control, and DPoP support.
- **Client side** (`client/`) — Register an OIDC client, get tokens, and call authenticated APIs.

## Features

- JWT signature verification using JWKS (auto-refreshed every 15 minutes)
- Token introspection fallback (catches revoked tokens)
- Scope-based access control (`RequireScope` / `RequireAllScopes`)
- DPoP (Demonstrating Proof of Possession) — sender-constrained tokens
- Standard `net/http` middleware — no framework dependency

## Quick Start

### 1. Register a Client

Every agent or service needs its own credentials. Register with id.strongdm.ai — a human approves via email, the agent gets a `client_id` and `client_secret`:

```bash
cd examples/go-middleware

# Start registration (sends verification email)
go run ./client register you@example.com

# Confirm with the emailed code
go run ./client confirm <enrollment_id> <poll_token> <CODE>
```

Save the returned `client_id` and `client_secret`.

### 2. Run the Example Server

```bash
go run .

# With custom configuration
STRONGDM_ISSUER=https://id.strongdm.ai \
STRONGDM_AUDIENCE=my-api \
go run .
```

### 3. Call Protected Endpoints

```bash
# Get a token
go run ./client token <client_id> <client_secret>

# Or with curl
TOKEN=$(curl -s -X POST https://id.strongdm.ai/token \
  -d "grant_type=client_credentials" \
  -d "client_id=CLI_ID" \
  -d "client_secret=CLI_SECRET" \
  -d "scope=openid" | jq -r '.access_token')

# Call the protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/protected

# Call the agent-info endpoint (shows full token claims)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/agent-info
```

Or do it all in one shot:

```bash
go run ./client call <client_id> <client_secret> http://localhost:8080/protected
```

## Server-Side Usage

### Protect Endpoints with Middleware

```go
auth, err := New(Config{
    Issuer: "https://id.strongdm.ai",
}, log)
defer auth.Close()

mux := http.NewServeMux()

// Any valid token
mux.Handle("GET /protected", auth.RequireAuth(handler))

// Require at least one of these scopes
mux.Handle("GET /admin", auth.RequireScope("admin")(handler))

// Require ALL of these scopes
mux.Handle("GET /sensitive", auth.RequireAllScopes("admin", "audit")(handler))
```

### Access Agent Info in Handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    agent := GetAgentInfo(r)

    fmt.Println(agent.Subject)   // "cli_my_agent_abc123"
    fmt.Println(agent.Scopes)    // ["openid", "admin"]
    fmt.Println(agent.ClientID)  // "cli_my_agent_abc123"
    fmt.Println(agent.Actor)     // "usr_sponsor" (if delegated)
    fmt.Println(agent.IssuedAt)  // 2026-02-12 22:57:00
    fmt.Println(agent.ExpiresAt) // 2026-02-12 23:57:00
}
```

### Token Introspection

Enable introspection for real-time revocation checking. This adds an extra HTTP call per request (cached 60s), but catches tokens that have been revoked since issuance:

```go
auth, err := New(Config{
    Issuer:               "https://id.strongdm.ai",
    IntrospectionEnabled: true,
    ClientID:             "cli_xxx",
    ClientSecret:         "sec_xxx",
}, log)
```

When introspection is enabled, tokens that fail JWT signature verification are checked against the `/introspect` endpoint as a fallback.

## Client-Side Usage

### Self-Registration

The registration flow is two steps: request (sends an email), then confirm (with the code from the email):

```go
import (
    "bytes"
    "encoding/json"
    "net/http"
)

// Step 1: Request registration.
body, _ := json.Marshal(map[string]any{
    "email":            "admin@example.com",
    "client_name":      "my-agent",
    "requested_scopes": []string{"openid"},
})
resp, _ := http.Post("https://id.strongdm.ai/register/request",
    "application/json", bytes.NewReader(body))

// Response: {"enrollment_id": "enroll_...", "poll_token": "pt_..."}

// Step 2: Confirm with email code.
body, _ = json.Marshal(map[string]any{
    "enrollment_id":     enrollmentID,
    "poll_token":        pollToken,
    "verification_code": code,
})
resp, _ = http.Post("https://id.strongdm.ai/register/confirm",
    "application/json", bytes.NewReader(body))

// Response: {"client_id": "cli_...", "client_secret": "sec_..."}
```

If your agent will use the authorization code flow (web login), include `redirect_uris`:

```go
body, _ := json.Marshal(map[string]any{
    "email":            "admin@example.com",
    "client_name":      "my-web-app",
    "requested_scopes": []string{"openid", "profile", "email"},
    "redirect_uris":    []string{"https://my-app.example.com/auth/callback"},
})
```

### Get a Token

For machine-to-machine use, `client_credentials` is the simplest grant type:

```go
import "net/url"

data := url.Values{
    "grant_type":    {"client_credentials"},
    "client_id":     {clientID},
    "client_secret": {clientSecret},
    "scope":         {"openid"},
}
resp, _ := http.PostForm("https://id.strongdm.ai/token", data)

// Response: {"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600}
```

For production services, use `golang.org/x/oauth2/clientcredentials` which handles token caching and refresh:

```go
import "golang.org/x/oauth2/clientcredentials"

cfg := &clientcredentials.Config{
    ClientID:     clientID,
    ClientSecret: clientSecret,
    TokenURL:     "https://id.strongdm.ai/token",
    Scopes:       []string{"openid"},
}

// cfg.Client(ctx) returns an *http.Client that automatically
// fetches and refreshes tokens.
httpClient := cfg.Client(ctx)
resp, _ := httpClient.Get("https://api.example.com/protected")
```

### Call an Authenticated API

```go
req, _ := http.NewRequest("GET", "https://api.example.com/protected", nil)
req.Header.Set("Authorization", "Bearer " + accessToken)
resp, _ := http.DefaultClient.Do(req)
```

## Configuration

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `Issuer` | `STRONGDM_ISSUER` | `https://id.strongdm.ai` | Token issuer URL |
| `Audience` | `STRONGDM_AUDIENCE` | (none) | Expected audience claim |
| `IntrospectionEnabled` | `STRONGDM_INTROSPECTION_ENABLED` | `false` | Enable introspection fallback |
| `ClientID` | `STRONGDM_CLIENT_ID` | (none) | Client ID (for introspection) |
| `ClientSecret` | `STRONGDM_CLIENT_SECRET` | (none) | Client secret (for introspection) |

## Error Responses

The middleware returns JSON error responses:

| Status | Meaning |
|--------|---------|
| `401` | Missing, invalid, or expired token |
| `403` | Valid token but insufficient scope |

```json
{"error": "requires one of: admin"}
```

## DPoP Support

[DPoP (RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449) binds tokens to a sender's key, preventing token theft. The middleware validates DPoP proofs automatically when the `Authorization` header uses the `DPoP` scheme:

```bash
curl -X GET http://localhost:8080/protected \
  -H "Authorization: DPoP $DPOP_TOKEN" \
  -H "DPoP: $DPOP_PROOF"
```

The proof JWT must contain:
- `htm` — HTTP method (e.g., `GET`)
- `htu` — Request URL
- `ath` — SHA-256 hash of the access token
- `jwk` — The sender's public key (in the JWS header)

## Project Structure

```
go-middleware/
├── strongdmauth.go    # Reusable auth middleware (~330 lines)
├── main.go            # Example server with protected routes
├── client/
│   └── main.go        # Client: register, get tokens, call APIs
├── go.mod
├── .env.example
└── README.md
```

## Dependencies

- [`lestrrat-go/jwx/v2`](https://github.com/lestrrat-go/jwx) — JWT, JWK, and JWS operations with built-in JWKS caching

## Security Notes

1. **Always use HTTPS in production** — Bearer tokens can be intercepted over plain HTTP.
2. **Use DPoP for sensitive operations** — Prevents stolen tokens from being replayed.
3. **Enable introspection for critical endpoints** — Catches revoked tokens between JWKS refreshes.
4. **Set an audience** — Prevents tokens issued for other services from being accepted.
5. **go-oidc note** — If you're using `coreos/go-oidc` instead, remember it defaults to RS256 only. Set `SupportedSigningAlgs` to accept ES256 and EdDSA.
