"""
DPoP Client Example — Python

Demonstrates how to:
1. Generate an EC P-256 key pair
2. Create a DPoP proof JWT
3. Request a DPoP-bound access token from StrongDM ID
4. Make an authenticated API call with a fresh DPoP proof

Requirements: pip install jwcrypto httpx
"""

import json
import os
import sys
import time
import uuid
import hashlib
import base64

import httpx
from jwcrypto import jwk, jwt as jwcrypto_jwt


def generate_dpop_key() -> jwk.JWK:
    """Generate a fresh EC P-256 key pair for DPoP proofs."""
    return jwk.JWK.generate(kty="EC", crv="P-256")


def create_dpop_proof(
    key: jwk.JWK,
    method: str,
    url: str,
    access_token: str | None = None,
) -> str:
    """
    Create a DPoP proof JWT.

    Args:
        key: The EC key pair to sign the proof with.
        method: HTTP method (e.g., "POST", "GET").
        url: The target URL (without query string).
        access_token: If provided, includes an ath (access token hash) claim.

    Returns:
        The signed DPoP proof JWT string.
    """
    # Public key for the JWK header (no private material)
    pub = json.loads(key.export_public())

    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": pub,
    }

    payload = {
        "jti": str(uuid.uuid4()),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
    }

    # Include access token hash when proving possession for an API call
    if access_token is not None:
        token_hash = hashlib.sha256(access_token.encode()).digest()
        payload["ath"] = base64.urlsafe_b64encode(token_hash).rstrip(b"=").decode()

    token = jwcrypto_jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)
    return token.serialize()


def jwk_thumbprint(key: jwk.JWK) -> str:
    """Compute the RFC 7638 JWK thumbprint (base64url-encoded SHA-256)."""
    return key.thumbprint()


def request_dpop_token(
    issuer: str,
    client_id: str,
    client_secret: str,
    key: jwk.JWK,
    scope: str = "openid",
) -> dict:
    """
    Request a DPoP-bound access token using client_credentials grant.

    Returns the full token response dict.
    """
    token_url = f"{issuer}/token"

    # Create the DPoP proof for the token request
    proof = create_dpop_proof(key, "POST", token_url)

    auth_value = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    with httpx.Client(timeout=30) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "scope": scope,
            },
            headers={
                "Authorization": f"Basic {auth_value}",
                "DPoP": proof,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        # Handle DPoP nonce requirement — server may respond with
        # use_dpop_nonce error and a DPoP-Nonce header
        if resp.status_code == 400:
            body = resp.json()
            if body.get("error") == "use_dpop_nonce":
                nonce = resp.headers.get("DPoP-Nonce")
                if nonce:
                    print(f"Server requires DPoP nonce, retrying...")
                    proof = create_dpop_proof(key, "POST", token_url)
                    resp = client.post(
                        token_url,
                        data={
                            "grant_type": "client_credentials",
                            "scope": scope,
                        },
                        headers={
                            "Authorization": f"Basic {auth_value}",
                            "DPoP": proof,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )

        if not resp.is_success:
            print(f"Token request failed: HTTP {resp.status_code}")
            print(resp.text)
            sys.exit(1)

        return resp.json()


def call_api_with_dpop(
    url: str,
    access_token: str,
    key: jwk.JWK,
    method: str = "GET",
) -> httpx.Response:
    """
    Make an API call with a DPoP-bound token.

    Each call needs a fresh DPoP proof bound to the specific method and URL.
    """
    proof = create_dpop_proof(key, method, url, access_token=access_token)

    with httpx.Client(timeout=30) as client:
        return client.request(
            method,
            url,
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": proof,
            },
        )


def main():
    issuer = os.environ.get("STRONGDM_ISSUER", "https://id.strongdm.ai")
    client_id = os.environ.get("STRONGDM_CLIENT_ID")
    client_secret = os.environ.get("STRONGDM_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET environment variables")
        sys.exit(1)

    # Step 1: Generate a fresh key pair
    print("Generating EC P-256 key pair...")
    key = generate_dpop_key()
    thumbprint = jwk_thumbprint(key)
    print(f"JWK thumbprint: {thumbprint}")

    # Step 2: Request a DPoP-bound token
    print(f"\nRequesting DPoP token from {issuer}/token...")
    token_response = request_dpop_token(issuer, client_id, client_secret, key)

    access_token = token_response["access_token"]
    token_type = token_response.get("token_type", "")
    expires_in = token_response.get("expires_in", 0)

    print(f"Token type: {token_type}")
    print(f"Expires in: {expires_in}s")
    print(f"Token (first 40 chars): {access_token[:40]}...")

    # Step 3: Verify the token has cnf.jkt matching our key
    # (Decode the JWT payload to check — don't verify signature here,
    # just inspect the claims)
    parts = access_token.split(".")
    if len(parts) == 3:
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        claims = json.loads(payload_bytes)
        cnf = claims.get("cnf", {})
        token_jkt = cnf.get("jkt", "")
        print(f"\nToken cnf.jkt: {token_jkt}")
        print(f"Our thumbprint: {thumbprint}")
        if token_jkt == thumbprint:
            print("Thumbprint matches — token is bound to our key")
        else:
            print("WARNING: thumbprint mismatch")

    # Step 4: Example API call (uncomment and set your API URL)
    # api_url = "https://your-api.example.com/protected"
    # print(f"\nCalling {api_url} with DPoP proof...")
    # resp = call_api_with_dpop(api_url, access_token, key)
    # print(f"Response: HTTP {resp.status_code}")
    # print(resp.text)


if __name__ == "__main__":
    main()
