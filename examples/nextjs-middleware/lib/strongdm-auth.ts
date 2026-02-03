/**
 * StrongDM ID Authentication Library for Next.js
 *
 * This library validates JWT tokens issued by StrongDM ID (https://id.strongdm.ai).
 * It supports:
 * - JWT signature verification using JWKS
 * - Token introspection fallback
 * - Scope-based access control
 * - DPoP token validation
 */

import * as jose from "jose";

export interface StrongDMAuthConfig {
  /** Token issuer URL (default: https://id.strongdm.ai) */
  issuer?: string;
  /** Expected audience claim (optional) */
  audience?: string;
  /** Enable token introspection fallback */
  introspectionEnabled?: boolean;
  /** Client ID for introspection */
  clientId?: string;
  /** Client secret for introspection */
  clientSecret?: string;
}

export interface TokenClaims {
  sub: string;
  iss: string;
  iat: number;
  exp: number;
  scope?: string;
  client_id?: string;
  azp?: string;
  act?: {
    sub: string;
  };
  cnf?: {
    jkt?: string;
  };
  [key: string]: unknown;
}

export interface AgentInfo {
  subject: string;
  scopes: string[];
  issuer: string;
  clientId?: string;
  actor?: {
    sub: string;
  };
}

export class StrongDMAuthError extends Error {
  constructor(
    message: string,
    public statusCode: number = 401
  ) {
    super(message);
    this.name = "StrongDMAuthError";
  }
}

// JWKS cache
let jwksCache: jose.JWTVerifyGetKey | null = null;
let jwksCacheExpiry = 0;
const JWKS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes

// Introspection cache
const introspectionCache = new Map<
  string,
  { result: TokenClaims; expiry: number }
>();
const INTROSPECTION_CACHE_TTL = 60 * 1000; // 1 minute

export class StrongDMAuth {
  private config: Required<
    Pick<StrongDMAuthConfig, "issuer"> &
      Omit<StrongDMAuthConfig, "issuer">
  >;

  constructor(config: StrongDMAuthConfig = {}) {
    this.config = {
      issuer: config.issuer || "https://id.strongdm.ai",
      audience: config.audience,
      introspectionEnabled: config.introspectionEnabled || false,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
    };
  }

  /**
   * Get the JWKS keyset for token verification.
   */
  private async getJWKS(): Promise<jose.JWTVerifyGetKey> {
    const now = Date.now();

    if (jwksCache && now < jwksCacheExpiry) {
      return jwksCache;
    }

    const jwksUrl = new URL("/jwks", this.config.issuer);
    jwksCache = jose.createRemoteJWKSet(jwksUrl);
    jwksCacheExpiry = now + JWKS_CACHE_TTL;

    return jwksCache;
  }

  /**
   * Extract the token from the Authorization header.
   */
  extractToken(authHeader: string | null): { type: string; token: string } {
    if (!authHeader) {
      throw new StrongDMAuthError("Missing Authorization header");
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2) {
      throw new StrongDMAuthError("Invalid Authorization header format");
    }

    const [type, token] = parts;
    const tokenType = type.toLowerCase();

    if (tokenType !== "bearer" && tokenType !== "dpop") {
      throw new StrongDMAuthError(`Unsupported token type: ${type}`);
    }

    return { type: tokenType, token };
  }

  /**
   * Verify a DPoP proof JWT.
   */
  async verifyDPoPProof(
    dpopProof: string,
    accessToken: string,
    method: string,
    url: string
  ): Promise<jose.JWTPayload> {
    // Decode header to get JWK
    const protectedHeader = jose.decodeProtectedHeader(dpopProof);

    if (protectedHeader.typ !== "dpop+jwt") {
      throw new StrongDMAuthError("Invalid DPoP proof: wrong typ");
    }

    if (!protectedHeader.jwk) {
      throw new StrongDMAuthError("Invalid DPoP proof: missing jwk");
    }

    // Import the JWK from the proof header
    const key = await jose.importJWK(protectedHeader.jwk as jose.JWK);

    // Verify the proof
    const { payload } = await jose.jwtVerify(dpopProof, key, {
      typ: "dpop+jwt",
    });

    // Verify required claims
    if (!payload.jti || !payload.htm || !payload.htu || !payload.iat) {
      throw new StrongDMAuthError("Invalid DPoP proof: missing required claims");
    }

    // Verify HTTP method
    if (payload.htm !== method) {
      throw new StrongDMAuthError("DPoP proof htm mismatch");
    }

    // Verify URI (without query string)
    const expectedHtu = url.split("?")[0];
    if (payload.htu !== expectedHtu) {
      throw new StrongDMAuthError("DPoP proof htu mismatch");
    }

    // Verify access token hash if present
    if (payload.ath) {
      const encoder = new TextEncoder();
      const data = encoder.encode(accessToken);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = new Uint8Array(hashBuffer);
      const expectedAth = jose.base64url.encode(hashArray);

      if (payload.ath !== expectedAth) {
        throw new StrongDMAuthError("DPoP proof ath mismatch");
      }
    }

    return payload;
  }

  /**
   * Verify a JWT token.
   */
  async verifyToken(
    token: string,
    tokenType: string,
    dpopProof?: string | null,
    method?: string,
    url?: string
  ): Promise<TokenClaims> {
    const jwks = await this.getJWKS();

    try {
      const { payload } = await jose.jwtVerify(token, jwks, {
        issuer: this.config.issuer,
        audience: this.config.audience,
      });

      // For DPoP tokens, verify the proof
      if (tokenType === "dpop") {
        if (!dpopProof) {
          throw new StrongDMAuthError("DPoP token requires DPoP proof header");
        }
        if (!method || !url) {
          throw new StrongDMAuthError(
            "DPoP verification requires method and url"
          );
        }

        await this.verifyDPoPProof(dpopProof, token, method, url);
      }

      return payload as TokenClaims;
    } catch (error) {
      if (error instanceof StrongDMAuthError) {
        throw error;
      }
      if (error instanceof jose.errors.JWTExpired) {
        throw new StrongDMAuthError("Token has expired");
      }
      if (error instanceof jose.errors.JWTClaimValidationFailed) {
        throw new StrongDMAuthError(`Token validation failed: ${error.message}`);
      }
      throw new StrongDMAuthError(`Invalid token: ${error}`);
    }
  }

  /**
   * Introspect a token using the introspection endpoint.
   */
  async introspectToken(token: string): Promise<TokenClaims> {
    // Check cache
    const cacheKey = await this.hashToken(token);
    const cached = introspectionCache.get(cacheKey);
    if (cached && Date.now() < cached.expiry) {
      return cached.result;
    }

    if (!this.config.clientId || !this.config.clientSecret) {
      throw new StrongDMAuthError(
        "Introspection requires client credentials",
        500
      );
    }

    const introspectionUrl = new URL("/introspect", this.config.issuer);
    const credentials = btoa(
      `${this.config.clientId}:${this.config.clientSecret}`
    );

    const response = await fetch(introspectionUrl.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({ token }),
    });

    if (!response.ok) {
      throw new StrongDMAuthError("Token introspection failed");
    }

    const result = await response.json();

    if (!result.active) {
      throw new StrongDMAuthError("Token is not active");
    }

    // Cache the result
    introspectionCache.set(cacheKey, {
      result,
      expiry: Date.now() + INTROSPECTION_CACHE_TTL,
    });

    return result as TokenClaims;
  }

  /**
   * Hash a token for cache key.
   */
  private async hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(token);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = new Uint8Array(hashBuffer);
    return jose.base64url.encode(hashArray).slice(0, 16);
  }

  /**
   * Verify authentication from request headers.
   */
  async verifyRequest(
    authHeader: string | null,
    dpopHeader?: string | null,
    method?: string,
    url?: string
  ): Promise<TokenClaims> {
    const { type, token } = this.extractToken(authHeader);

    // Try JWT verification first
    try {
      return await this.verifyToken(token, type, dpopHeader, method, url);
    } catch (error) {
      if (!this.config.introspectionEnabled) {
        throw error;
      }
    }

    // Fall back to introspection
    return await this.introspectToken(token);
  }

  /**
   * Check if claims have the required scopes.
   */
  checkScopes(
    claims: TokenClaims,
    requiredScopes: string[],
    requireAll: boolean = false
  ): void {
    const tokenScopes = new Set((claims.scope || "").split(" ").filter(Boolean));
    const required = new Set(requiredScopes);

    if (requireAll) {
      for (const scope of required) {
        if (!tokenScopes.has(scope)) {
          const missing = [...required].filter((s) => !tokenScopes.has(s));
          throw new StrongDMAuthError(
            `Missing required scopes: ${missing.join(", ")}`,
            403
          );
        }
      }
    } else {
      const hasAny = [...required].some((s) => tokenScopes.has(s));
      if (!hasAny) {
        throw new StrongDMAuthError(
          `Requires one of: ${[...required].join(", ")}`,
          403
        );
      }
    }
  }

  /**
   * Get agent info from token claims.
   */
  getAgentInfo(claims: TokenClaims): AgentInfo {
    return {
      subject: claims.sub,
      scopes: (claims.scope || "").split(" ").filter(Boolean),
      issuer: claims.iss,
      clientId: claims.client_id || claims.azp,
      actor: claims.act,
    };
  }
}

/**
 * Create a StrongDM auth instance with environment variables.
 */
export function createStrongDMAuth(): StrongDMAuth {
  return new StrongDMAuth({
    issuer: process.env.STRONGDM_ISSUER || "https://id.strongdm.ai",
    audience: process.env.STRONGDM_AUDIENCE,
    introspectionEnabled: process.env.STRONGDM_INTROSPECTION_ENABLED === "true",
    clientId: process.env.STRONGDM_CLIENT_ID,
    clientSecret: process.env.STRONGDM_CLIENT_SECRET,
  });
}
