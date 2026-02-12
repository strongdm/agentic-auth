# Next.js Middleware for StrongDM ID

This example demonstrates how to protect Next.js API routes using StrongDM ID authentication with Edge Middleware.

## Features

- JWT signature verification using JWKS
- Edge middleware for low-latency auth
- Scope-based access control
- DPoP (Demonstrating Proof of Possession) support
- Token claims passed to route handlers via headers

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Create a `.env.local` file:

```bash
STRONGDM_ISSUER=https://id.strongdm.ai
STRONGDM_AUDIENCE=my-api  # Optional
```

### 3. Run the Development Server

```bash
npm run dev
```

### 4. Test with a Token

```bash
# Get an access token (you'll need valid client credentials)
TOKEN=$(curl -s -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=openid email" | jq -r '.access_token')

# Call a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/protected
```

## Project Structure

```
├── lib/
│   └── strongdm-auth.ts    # Auth library
├── middleware.ts            # Edge middleware configuration
└── app/
    └── api/
        ├── health/          # Public health check
        ├── protected/       # Basic auth required
        ├── agent-info/      # Shows token claims
        └── admin/           # Requires admin
```

## Middleware Configuration

Edit `middleware.ts` to configure protected routes:

```typescript
// Define your protected routes
const protectedRoutes: Record<string, RouteConfig> = {
  "/api/protected": {},                                    // Any valid token
  "/api/admin": { scopes: ["admin"] },                  // Admin only
  "/api/optional": { optional: true },                     // Auth optional
};

// Public routes (skip authentication)
const publicRoutes = ["/api/health", "/api/public"];
```

## Using Claims in Route Handlers

The middleware adds claims to request headers:

```typescript
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  // Get individual claims
  const subject = request.headers.get("x-strongdm-subject");
  const scopes = request.headers.get("x-strongdm-scopes")?.split(" ");

  // Or get full claims object
  const claimsHeader = request.headers.get("x-strongdm-claims");
  const claims = claimsHeader ? JSON.parse(claimsHeader) : null;

  return NextResponse.json({ subject, scopes });
}
```

## Using the Auth Library Directly

For more control, use the library in API routes:

```typescript
import { NextRequest, NextResponse } from "next/server";
import { StrongDMAuth, StrongDMAuthError } from "@/lib/strongdm-auth";

const auth = new StrongDMAuth();

export async function GET(request: NextRequest) {
  try {
    const claims = await auth.verifyRequest(
      request.headers.get("authorization"),
      request.headers.get("dpop"),
      request.method,
      request.url
    );

    // Check specific scopes
    auth.checkScopes(claims, ["admin"]);

    return NextResponse.json({ subject: claims.sub });
  } catch (error) {
    if (error instanceof StrongDMAuthError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode }
      );
    }
    throw error;
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRONGDM_ISSUER` | `https://id.strongdm.ai` | Token issuer URL |
| `STRONGDM_AUDIENCE` | - | Expected audience claim |
| `STRONGDM_INTROSPECTION_ENABLED` | `false` | Enable token introspection |
| `STRONGDM_CLIENT_ID` | - | Client ID (for introspection) |
| `STRONGDM_CLIENT_SECRET` | - | Client secret (for introspection) |

## API Endpoints

| Endpoint | Auth | Scopes | Description |
|----------|------|--------|-------------|
| `/api/health` | No | - | Health check |
| `/api/protected` | Yes | Any | Basic protected endpoint |
| `/api/agent-info` | Yes | Any | Returns token claims |
| `/api/admin` | Yes | admin | Admin operations |

## Error Responses

| Status | Meaning |
|--------|---------|
| `401` | Missing/invalid/expired token |
| `403` | Valid token but insufficient scope |

Example error:
```json
{
  "error": "Missing required scopes: admin"
}
```

## DPoP Support

For sender-constrained tokens:

```bash
curl -X GET http://localhost:3000/api/protected \
  -H "Authorization: DPoP $DPOP_TOKEN" \
  -H "DPoP: $DPOP_PROOF"
```

## Deployment Notes

- The middleware runs on the Edge runtime for low latency
- JWKS is cached for 15 minutes
- For high-security endpoints, enable introspection to check token revocation
- Always use HTTPS in production
