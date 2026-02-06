/**
 * Next.js Middleware for StrongDM ID Authentication
 *
 * This middleware protects API routes based on path patterns.
 * Configure which paths require authentication and which scopes are needed.
 */

import { NextRequest, NextResponse } from "next/server";
import { StrongDMAuth, StrongDMAuthError, TokenClaims } from "./lib/strongdm-auth";

// Configuration for protected routes
interface RouteConfig {
  /** Required scopes (at least one must match) */
  scopes?: string[];
  /** Require ALL scopes (default: false, meaning any scope matches) */
  requireAllScopes?: boolean;
  /** Allow unauthenticated access (useful for optional auth) */
  optional?: boolean;
}

// Define your protected routes here
const protectedRoutes: Record<string, RouteConfig> = {
  "/api/protected": {},
  "/api/agent-info": {},
  "/api/admin": { scopes: ["pctl:read"] },
};

// Public routes that skip authentication
const publicRoutes = ["/api/health", "/api/public"];

// Create auth instance
const auth = new StrongDMAuth({
  issuer: process.env.STRONGDM_ISSUER || "https://id.strongdm.ai",
  audience: process.env.STRONGDM_AUDIENCE,
});

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;

  // Skip public routes
  if (publicRoutes.some((route) => path.startsWith(route))) {
    return NextResponse.next();
  }

  // Check if this is a protected API route
  const routeConfig = Object.entries(protectedRoutes).find(([route]) =>
    path.startsWith(route)
  )?.[1];

  // If not a protected route, continue
  if (!routeConfig) {
    return NextResponse.next();
  }

  try {
    // Get auth headers
    const authHeader = request.headers.get("authorization");
    const dpopHeader = request.headers.get("dpop");

    // If auth is optional and no header provided, continue
    if (routeConfig.optional && !authHeader) {
      return NextResponse.next();
    }

    // Verify the token
    const claims = await auth.verifyRequest(
      authHeader,
      dpopHeader,
      request.method,
      request.url
    );

    // Check scopes if required
    if (routeConfig.scopes && routeConfig.scopes.length > 0) {
      auth.checkScopes(
        claims,
        routeConfig.scopes,
        routeConfig.requireAllScopes
      );
    }

    // Add claims to request headers for downstream handlers
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set("x-strongdm-claims", JSON.stringify(claims));
    requestHeaders.set("x-strongdm-subject", claims.sub);
    requestHeaders.set("x-strongdm-scopes", claims.scope || "");

    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
  } catch (error) {
    if (error instanceof StrongDMAuthError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode }
      );
    }

    console.error("Middleware auth error:", error);
    return NextResponse.json(
      { error: "Authentication failed" },
      { status: 401 }
    );
  }
}

// Configure which paths the middleware should run on
export const config = {
  matcher: [
    // Match all API routes
    "/api/:path*",
  ],
};
