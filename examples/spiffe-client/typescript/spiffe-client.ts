/**
 * SPIFFE Client Example — TypeScript
 *
 * Demonstrates how to:
 * 1. Fetch the SPIFFE trust bundle from StrongDM ID
 * 2. Obtain a Bearer token via client_credentials
 * 3. Request a JWT-SVID (SPIFFE Verifiable Identity Document)
 * 4. Decode and inspect the JWT-SVID claims
 *
 * Requirements: npm install jose
 * Run: npx tsx spiffe-client.ts
 */

import * as jose from "jose";

const ISSUER = process.env.STRONGDM_ISSUER || "https://id.strongdm.ai";
const CLIENT_ID = process.env.STRONGDM_CLIENT_ID || "";
const CLIENT_SECRET = process.env.STRONGDM_CLIENT_SECRET || "";
const AUDIENCE = process.env.SPIFFE_AUDIENCE || "example-service";

/**
 * Fetch the SPIFFE trust bundle (JWKS for verifying SVIDs).
 */
async function fetchTrustBundle(): Promise<Record<string, unknown>> {
  const url = `${ISSUER}/.well-known/spiffe-trust-bundle`;
  console.log(`Fetching trust bundle from ${url}...`);

  const resp = await fetch(url);

  if (resp.status === 404) {
    console.log(
      "SPIFFE trust bundle endpoint not found (404) — SPIFFE may not be enabled"
    );
    return {};
  }

  if (!resp.ok) {
    throw new Error(`Trust bundle fetch failed: HTTP ${resp.status}`);
  }

  const bundle = (await resp.json()) as Record<string, unknown>;
  const keys = bundle.keys as unknown[];
  console.log(`Trust bundle contains ${keys?.length ?? 0} key(s)`);
  return bundle;
}

/**
 * Get a Bearer token via client_credentials grant.
 */
async function getBearerToken(): Promise<string> {
  const tokenUrl = `${ISSUER}/token`;
  const credentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${credentials}`,
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "openid",
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Token request failed: HTTP ${resp.status}: ${body}`);
  }

  const data = (await resp.json()) as { access_token: string };
  return data.access_token;
}

/**
 * Request a JWT-SVID from the SPIFFE endpoint.
 */
async function requestJWTSVID(
  bearerToken: string,
  audience: string[]
): Promise<Record<string, unknown>> {
  const svidUrl = `${ISSUER}/svid/jwt`;
  console.log(`\nRequesting JWT-SVID from ${svidUrl}...`);

  const resp = await fetch(svidUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${bearerToken}`,
    },
    body: JSON.stringify({ audience }),
  });

  if (resp.status === 404) {
    console.log(
      "JWT-SVID endpoint not found (404) — SPIFFE may not be enabled"
    );
    return {};
  }

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`SVID request failed: HTTP ${resp.status}: ${body}`);
  }

  return (await resp.json()) as Record<string, unknown>;
}

async function main() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error(
      "Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET environment variables"
    );
    process.exit(1);
  }

  // Step 1: Fetch trust bundle
  const bundle = await fetchTrustBundle();
  if (!bundle || !bundle.keys) {
    console.error("Cannot proceed without trust bundle");
    process.exit(1);
  }

  // Step 2: Get a Bearer token
  console.log(`\nGetting Bearer token from ${ISSUER}/token...`);
  const bearerToken = await getBearerToken();
  console.log(
    `Bearer token obtained (first 40 chars): ${bearerToken.slice(0, 40)}...`
  );

  // Step 3: Request a JWT-SVID
  const svidResponse = await requestJWTSVID(bearerToken, [AUDIENCE]);
  if (!svidResponse) {
    process.exit(1);
  }

  const svidToken =
    (svidResponse.svid as string) || (svidResponse.token as string);
  if (!svidToken) {
    console.error(
      `Unexpected response format: ${JSON.stringify(svidResponse, null, 2)}`
    );
    process.exit(1);
  }

  console.log(
    `JWT-SVID obtained (first 40 chars): ${svidToken.slice(0, 40)}...`
  );

  // Step 4: Decode and inspect claims
  const claims = jose.decodeJwt(svidToken);
  console.log(`\nJWT-SVID claims:`);
  console.log(`  sub (SPIFFE ID): ${claims.sub}`);
  console.log(`  aud:             ${claims.aud}`);
  console.log(`  iss:             ${claims.iss}`);
  console.log(`  exp:             ${claims.exp}`);

  if (typeof claims.sub === "string" && claims.sub.startsWith("spiffe://")) {
    console.log(`\n  Subject is a valid SPIFFE ID`);
  } else {
    console.log(`\n  WARNING: subject '${claims.sub}' is not a spiffe:// URI`);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
