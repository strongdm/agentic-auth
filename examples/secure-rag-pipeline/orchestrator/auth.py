"""StrongDM ID token management for the RAG pipeline.

Handles:
- Client credentials token acquisition with DPoP
- RFC 8693 token exchange for scope narrowing
- Token freshness checks
"""

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

# Configuration from environment
SDM_ISSUER = os.environ.get("SDM_ISSUER", "https://id.strongdm.ai/realms/default")
SDM_TOKEN_URL = f"{SDM_ISSUER}/token"


def _load_credentials(client_id: str) -> dict:
    """Load client credentials from the standard config path."""
    env_secret = os.environ.get("SDM_CLIENT_SECRET")
    if env_secret:
        return {
            "client_id": client_id,
            "client_secret": env_secret,
            "token_endpoint": SDM_TOKEN_URL,
            "issuer": SDM_ISSUER,
        }
    path = Path.home() / ".config" / "strongdmid" / client_id / "client.json"
    with open(path) as f:
        return json.load(f)


def _generate_dpop_keypair() -> tuple:
    """Generate an ephemeral ES256 keypair for DPoP proofs.

    Returns (private_key, jwk_dict).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(pub_numbers.x.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode(),
        "y": base64.urlsafe_b64encode(pub_numbers.y.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode(),
    }
    return private_key, jwk


def _build_dpop_proof(
    private_key, jwk: dict, method: str, url: str, access_token: str | None = None
) -> str:
    """Build a DPoP proof JWT (RFC 9449)."""
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    if access_token:
        ath = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        payload["ath"] = ath
    return pyjwt.encode(payload, private_key, algorithm="ES256", headers=headers)


class TokenManager:
    """Manages StrongDM ID tokens for the orchestrator."""

    def __init__(self, client_id: str):
        self.client_id = client_id
        self.creds = _load_credentials(client_id)
        self.private_key, self.jwk = _generate_dpop_keypair()
        self._token_cache: dict[str, tuple[str, float]] = {}

    def acquire_token(self, scopes: list[str]) -> str:
        """Acquire an access token via client_credentials grant with DPoP.

        Returns the access token string.
        """
        import urllib.request

        scope_str = " ".join(scopes)
        cache_key = scope_str
        if cache_key in self._token_cache:
            token, exp = self._token_cache[cache_key]
            if time.time() < exp - 60:
                return token

        dpop_proof = _build_dpop_proof(
            self.private_key, self.jwk, "POST", SDM_TOKEN_URL
        )
        auth = base64.b64encode(
            f"{self.creds['client_id']}:{self.creds['client_secret']}".encode()
        ).decode()

        req = urllib.request.Request(
            SDM_TOKEN_URL,
            data=f"grant_type=client_credentials&scope={scope_str}".encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {auth}",
                "DPoP": dpop_proof,
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())

        token = result["access_token"]
        expires_in = result.get("expires_in", 3600)
        self._token_cache[cache_key] = (token, time.time() + expires_in)
        return token

    def exchange_token(self, parent_token: str, target_scopes: list[str]) -> str:
        """Exchange a parent token for a scope-narrowed child token (RFC 8693).

        This is the core of the least-privilege model: the orchestrator takes
        its broad token and narrows it to only the scopes needed by a specific
        child agent.
        """
        import urllib.request

        scope_str = " ".join(target_scopes)
        dpop_proof = _build_dpop_proof(
            self.private_key, self.jwk, "POST", SDM_TOKEN_URL
        )

        body = (
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
            f"&subject_token={parent_token}"
            "&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
            "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
            f"&scope={scope_str}"
        )

        req = urllib.request.Request(
            SDM_TOKEN_URL,
            data=body.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": dpop_proof,
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        return result["access_token"]

    def make_authenticated_request(
        self, method: str, url: str, token: str, body: dict | None = None
    ) -> dict:
        """Make an authenticated request to an MCP server.

        Uses DPoP proof binding if the token is DPoP-bound, otherwise Bearer.
        """
        import urllib.request

        dpop_proof = _build_dpop_proof(
            self.private_key, self.jwk, method, url, access_token=token
        )

        headers = {
            "Authorization": f"DPoP {token}",
            "DPoP": dpop_proof,
            "Content-Type": "application/json",
        }

        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
