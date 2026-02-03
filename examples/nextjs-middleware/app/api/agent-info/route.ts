import { NextRequest, NextResponse } from "next/server";
import { TokenClaims } from "@/lib/strongdm-auth";

export async function GET(request: NextRequest) {
  // Parse claims from middleware
  const claimsHeader = request.headers.get("x-strongdm-claims");
  if (!claimsHeader) {
    return NextResponse.json({ error: "No claims found" }, { status: 401 });
  }

  const claims: TokenClaims = JSON.parse(claimsHeader);

  return NextResponse.json({
    subject: claims.sub,
    issuer: claims.iss,
    scopes: (claims.scope || "").split(" ").filter(Boolean),
    clientId: claims.client_id || claims.azp,
    expiresAt: claims.exp,
    issuedAt: claims.iat,
    actor: claims.act, // Present if token is delegated
  });
}
