"""
SPIFFE Client Example — Python

Demonstrates how to:
1. Fetch the SPIFFE trust bundle from StrongDM ID
2. Obtain a Bearer token via client_credentials
3. Request a JWT-SVID (SPIFFE Verifiable Identity Document)
4. Decode and inspect the JWT-SVID claims

Requirements: pip install httpx
"""

import base64
import json
import os
import sys

import httpx

TIMEOUT = 30.0


def fetch_trust_bundle(issuer: str) -> dict:
    """Fetch the SPIFFE trust bundle (JWKS for verifying SVIDs)."""
    url = f"{issuer}/.well-known/spiffe-trust-bundle"
    print(f"Fetching trust bundle from {url}...")

    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.get(url)
        if resp.status_code == 404:
            print("SPIFFE trust bundle endpoint not found (404) — SPIFFE may not be enabled")
            return {}
        resp.raise_for_status()
        bundle = resp.json()

    keys = bundle.get("keys", [])
    print(f"Trust bundle contains {len(keys)} key(s)")
    return bundle


def get_bearer_token(issuer: str, client_id: str, client_secret: str) -> str:
    """Get a Bearer token via client_credentials grant."""
    token_url = f"{issuer}/token"
    auth_value = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "scope": "openid",
            },
            headers={
                "Authorization": f"Basic {auth_value}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


def request_jwt_svid(issuer: str, bearer_token: str, audience: list[str]) -> dict:
    """
    Request a JWT-SVID from the SPIFFE endpoint.

    Args:
        issuer: The StrongDM ID issuer URL
        bearer_token: A valid Bearer token for authentication
        audience: List of audience identifiers for the JWT-SVID

    Returns:
        The JWT-SVID response including the SVID token
    """
    svid_url = f"{issuer}/svid/jwt"
    print(f"\nRequesting JWT-SVID from {svid_url}...")

    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.post(
            svid_url,
            json={"audience": audience},
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Content-Type": "application/json",
            },
        )

        if resp.status_code == 404:
            print("JWT-SVID endpoint not found (404) — SPIFFE may not be enabled")
            return {}

        resp.raise_for_status()
        return resp.json()


def decode_jwt_payload(token: str) -> dict:
    """Decode a JWT payload without signature verification (for inspection only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = base64.urlsafe_b64decode(parts[1] + "==")
    return json.loads(payload)


def main():
    issuer = os.environ.get("STRONGDM_ISSUER", "https://id.strongdm.ai")
    client_id = os.environ.get("STRONGDM_CLIENT_ID")
    client_secret = os.environ.get("STRONGDM_CLIENT_SECRET")
    audience = os.environ.get("SPIFFE_AUDIENCE", "example-service")

    if not client_id or not client_secret:
        print("Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET environment variables")
        sys.exit(1)

    # Step 1: Fetch trust bundle
    bundle = fetch_trust_bundle(issuer)
    if not bundle:
        print("Cannot proceed without trust bundle")
        sys.exit(1)

    # Step 2: Get a Bearer token
    print(f"\nGetting Bearer token from {issuer}/token...")
    bearer_token = get_bearer_token(issuer, client_id, client_secret)
    print(f"Bearer token obtained (first 40 chars): {bearer_token[:40]}...")

    # Step 3: Request a JWT-SVID
    svid_response = request_jwt_svid(issuer, bearer_token, [audience])
    if not svid_response:
        sys.exit(1)

    svid_token = svid_response.get("svid") or svid_response.get("token", "")
    if not svid_token:
        print(f"Unexpected response format: {json.dumps(svid_response, indent=2)}")
        sys.exit(1)

    print(f"JWT-SVID obtained (first 40 chars): {svid_token[:40]}...")

    # Step 4: Decode and inspect
    claims = decode_jwt_payload(svid_token)
    print(f"\nJWT-SVID claims:")
    print(f"  sub (SPIFFE ID): {claims.get('sub', '?')}")
    print(f"  aud:             {claims.get('aud', '?')}")
    print(f"  iss:             {claims.get('iss', '?')}")
    print(f"  exp:             {claims.get('exp', '?')}")

    # Verify the subject is a SPIFFE ID
    sub = claims.get("sub", "")
    if sub.startswith("spiffe://"):
        print(f"\n  Subject is a valid SPIFFE ID")
    else:
        print(f"\n  WARNING: subject '{sub}' is not a spiffe:// URI")


if __name__ == "__main__":
    main()
