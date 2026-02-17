/**
 * DPoP Client Example — TypeScript
 *
 * Demonstrates how to:
 * 1. Generate an EC P-256 key pair
 * 2. Create a DPoP proof JWT
 * 3. Request a DPoP-bound access token from StrongDM ID
 * 4. Make an authenticated API call with a fresh DPoP proof
 *
 * Requirements: npm install jose
 * Run: npx tsx dpop-client.ts
 */

import * as jose from "jose";

const ISSUER = process.env.STRONGDM_ISSUER || "https://id.strongdm.ai";
const CLIENT_ID = process.env.STRONGDM_CLIENT_ID || "";
const CLIENT_SECRET = process.env.STRONGDM_CLIENT_SECRET || "";

/**
 * Create a DPoP proof JWT.
 *
 * @param privateKey - The EC private key to sign the proof with
 * @param publicJwk - The corresponding public JWK (embedded in proof header)
 * @param method - HTTP method (e.g., "POST", "GET")
 * @param url - Target URL (without query string)
 * @param accessToken - If provided, includes an ath (access token hash) claim
 */
async function createDPoPProof(
  privateKey: CryptoKey,
  publicJwk: jose.JWK,
  method: string,
  url: string,
  accessToken?: string
): Promise<string> {
  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
  };

  // Include access token hash when proving possession for an API call
  if (accessToken) {
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(accessToken)
    );
    payload.ath = jose.base64url.encode(new Uint8Array(hash));
  }

  return new jose.SignJWT(payload)
    .setProtectedHeader({
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: publicJwk,
    })
    .sign(privateKey);
}

/**
 * Request a DPoP-bound access token using client_credentials grant.
 */
async function requestDPoPToken(
  privateKey: CryptoKey,
  publicJwk: jose.JWK,
  scope: string = "openid"
): Promise<Record<string, unknown>> {
  const tokenUrl = `${ISSUER}/token`;
  const proof = await createDPoPProof(privateKey, publicJwk, "POST", tokenUrl);
  const credentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${credentials}`,
      DPoP: proof,
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope,
    }),
  });

  // Handle DPoP nonce requirement
  if (resp.status === 400) {
    const body = await resp.json();
    if (body.error === "use_dpop_nonce") {
      const nonce = resp.headers.get("DPoP-Nonce");
      if (nonce) {
        console.log("Server requires DPoP nonce, retrying...");
        const retryProof = await createDPoPProof(
          privateKey,
          publicJwk,
          "POST",
          tokenUrl
        );
        const retryResp = await fetch(tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${credentials}`,
            DPoP: retryProof,
          },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            scope,
          }),
        });
        if (!retryResp.ok) {
          const errBody = await retryResp.text();
          throw new Error(`Token retry failed: HTTP ${retryResp.status}: ${errBody}`);
        }
        return retryResp.json();
      }
    }
    throw new Error(`Token request failed: ${JSON.stringify(body)}`);
  }

  if (!resp.ok) {
    const errBody = await resp.text();
    throw new Error(`Token request failed: HTTP ${resp.status}: ${errBody}`);
  }

  return resp.json();
}

/**
 * Make an API call with a DPoP-bound access token.
 */
async function callWithDPoP(
  url: string,
  accessToken: string,
  privateKey: CryptoKey,
  publicJwk: jose.JWK,
  method: string = "GET"
): Promise<Response> {
  const proof = await createDPoPProof(
    privateKey,
    publicJwk,
    method,
    url,
    accessToken
  );

  return fetch(url, {
    method,
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: proof,
    },
  });
}

async function main() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error(
      "Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET environment variables"
    );
    process.exit(1);
  }

  // Step 1: Generate a fresh EC P-256 key pair
  console.log("Generating EC P-256 key pair...");
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
  const publicJwk = await jose.exportJWK(publicKey);
  const thumbprint = await jose.calculateJwkThumbprint(publicJwk, "sha256");
  console.log(`JWK thumbprint: ${thumbprint}`);

  // Step 2: Request a DPoP-bound token
  console.log(`\nRequesting DPoP token from ${ISSUER}/token...`);
  const tokenResponse = await requestDPoPToken(privateKey, publicJwk);

  const accessToken = tokenResponse.access_token as string;
  const tokenType = tokenResponse.token_type as string;
  const expiresIn = tokenResponse.expires_in as number;

  console.log(`Token type: ${tokenType}`);
  console.log(`Expires in: ${expiresIn}s`);
  console.log(`Token (first 40 chars): ${accessToken.slice(0, 40)}...`);

  // Step 3: Verify the token has cnf.jkt matching our key
  const claims = jose.decodeJwt(accessToken);
  const cnf = claims.cnf as { jkt?: string } | undefined;
  if (cnf?.jkt) {
    console.log(`\nToken cnf.jkt: ${cnf.jkt}`);
    console.log(`Our thumbprint: ${thumbprint}`);
    if (cnf.jkt === thumbprint) {
      console.log("Thumbprint matches — token is bound to our key");
    } else {
      console.log("WARNING: thumbprint mismatch");
    }
  }

  // Step 4: Example API call (uncomment and set your URL)
  // const apiUrl = "https://your-api.example.com/protected";
  // console.log(`\nCalling ${apiUrl} with DPoP proof...`);
  // const resp = await callWithDPoP(apiUrl, accessToken, privateKey, publicJwk);
  // console.log(`Response: HTTP ${resp.status}`);
  // console.log(await resp.text());
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
