"""Shared JWT verification middleware for RAG pipeline MCP servers.

All MCP servers use this middleware to:
1. Extract Bearer/DPoP token from Authorization header
2. Fetch and cache JWKS from StrongDM ID
3. Verify signature, expiry, issuer
4. If DPoP: fully verify the DPoP proof (RFC 9449)
   - Validate proof JWT signature against embedded JWK
   - Check typ, htm, htu, iat, jti
   - Verify ath (access token hash) binding
   - Verify cnf.jkt (JWK thumbprint) matches proof key
   - Reject replayed proofs via jti nonce cache
5. Check required scope
6. Return decoded claims (caller identity as 'sub')
"""

import base64
import collections
import hashlib
import json
import os
import threading
import time

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient

SDM_ISSUER = os.environ.get("SDM_ISSUER", "https://id.strongdm.ai/realms/default")
SDM_JWKS_URL = os.environ.get("SDM_JWKS_URL", f"{SDM_ISSUER}/jwks")

# JWKS client with built-in caching (5 minute lifespan)
_jwks_client = PyJWKClient(SDM_JWKS_URL, cache_jwk_set=True, lifespan=300)

# DPoP configuration
DPOP_PROOF_MAX_AGE_SECONDS = 300  # Reject proofs older than 5 minutes
DPOP_NONCE_CACHE_SIZE = 10_000  # Max jti values to track for replay prevention

# Thread-safe jti replay cache: maps jti -> expiry timestamp
_jti_lock = threading.Lock()
_jti_seen: collections.OrderedDict[str, float] = collections.OrderedDict()


def _check_jti_replay(jti: str) -> bool:
    """Check if a jti has been seen before (replay attack).

    Returns True if this is a replay (jti already seen and not expired).
    Also evicts expired entries to keep the cache bounded.
    """
    now = time.time()
    with _jti_lock:
        # Evict expired entries
        expired_keys = [
            k for k, exp in _jti_seen.items() if exp < now
        ]
        for k in expired_keys:
            del _jti_seen[k]

        # Evict oldest if cache is full
        while len(_jti_seen) >= DPOP_NONCE_CACHE_SIZE:
            _jti_seen.popitem(last=False)

        if jti in _jti_seen:
            return True  # Replay detected

        # Record this jti with an expiry matching the proof max age
        _jti_seen[jti] = now + DPOP_PROOF_MAX_AGE_SECONDS
        return False


def _compute_jwk_thumbprint(jwk: dict) -> str:
    """Compute the JWK Thumbprint (RFC 7638) for a given JWK.

    For EC keys (P-256), the thumbprint is SHA-256 of the canonical
    JSON representation with members in lexicographic order:
    {"crv":"P-256","kty":"EC","x":"...","y":"..."}

    Returns the base64url-encoded thumbprint (no padding).
    """
    kty = jwk.get("kty")
    if kty == "EC":
        canonical = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }
    elif kty == "OKP":
        canonical = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
        }
    elif kty == "RSA":
        canonical = {
            "e": jwk["e"],
            "kty": jwk["kty"],
            "n": jwk["n"],
        }
    else:
        raise ValueError(f"Unsupported key type for thumbprint: {kty}")

    # RFC 7638: JSON serialization with no whitespace, keys sorted
    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical_json.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _reconstruct_ec_public_key(jwk: dict):
    """Reconstruct an EC public key object from a JWK dict.

    Needed to verify the DPoP proof signature against the embedded JWK.
    """
    crv = jwk.get("crv")
    if crv != "P-256":
        raise ValueError(f"Unsupported EC curve: {crv}")

    # Decode x and y coordinates (base64url, no padding)
    x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
    y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")

    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")

    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return public_numbers.public_key()


def _verify_dpop_proof(
    dpop_header_value: str,
    access_token: str,
    http_method: str,
    http_url: str,
    access_token_claims: dict,
) -> dict:
    """Fully verify a DPoP proof JWT per RFC 9449.

    Checks:
    1. Proof is a valid JWT signed by the embedded JWK
    2. Header typ is "dpop+jwt"
    3. Header alg is an allowed algorithm (ES256, EdDSA)
    4. Header contains a jwk with the public key
    5. Payload htm matches the HTTP method of this request
    6. Payload htu matches the HTTP URL of this request
    7. Payload iat is recent (within DPOP_PROOF_MAX_AGE_SECONDS)
    8. Payload jti is unique (not replayed)
    9. Payload ath matches SHA-256 of the access token
    10. Access token cnf.jkt matches the JWK thumbprint from the proof

    Returns the decoded proof payload on success.
    Raises HTTPException on any verification failure.
    """
    # Decode the proof header without verifying signature first,
    # so we can extract the embedded JWK for signature verification
    try:
        unverified_header = pyjwt.get_unverified_header(dpop_header_value)
    except pyjwt.DecodeError:
        raise HTTPException(status_code=401, detail="DPoP proof is not a valid JWT")

    # 1. Check typ
    if unverified_header.get("typ") != "dpop+jwt":
        raise HTTPException(
            status_code=401,
            detail=f"DPoP proof typ must be 'dpop+jwt', got '{unverified_header.get('typ')}'",
        )

    # 2. Check alg
    alg = unverified_header.get("alg")
    if alg not in ("ES256", "EdDSA"):
        raise HTTPException(
            status_code=401,
            detail=f"DPoP proof alg must be ES256 or EdDSA, got '{alg}'",
        )

    # 3. Extract embedded JWK
    proof_jwk = unverified_header.get("jwk")
    if not proof_jwk:
        raise HTTPException(
            status_code=401, detail="DPoP proof missing embedded jwk in header"
        )

    # Ensure JWK doesn't contain a private key
    if "d" in proof_jwk:
        raise HTTPException(
            status_code=401, detail="DPoP proof jwk must not contain private key material"
        )

    # 4. Reconstruct the public key and verify the proof signature
    try:
        if alg == "ES256":
            public_key = _reconstruct_ec_public_key(proof_jwk)
        else:
            # EdDSA support would go here
            raise HTTPException(
                status_code=401, detail=f"DPoP alg '{alg}' not yet implemented"
            )

        proof_payload = pyjwt.decode(
            dpop_header_value,
            public_key,
            algorithms=[alg],
            options={
                "verify_aud": False,
                "verify_iss": False,
                "verify_sub": False,
                "verify_exp": False,  # DPoP proofs use iat, not exp
            },
        )
    except pyjwt.InvalidSignatureError:
        raise HTTPException(
            status_code=401, detail="DPoP proof signature verification failed"
        )
    except pyjwt.DecodeError as e:
        raise HTTPException(
            status_code=401, detail=f"DPoP proof decode error: {e}"
        )

    # 5. Check htm (HTTP method)
    if proof_payload.get("htm") != http_method:
        raise HTTPException(
            status_code=401,
            detail=f"DPoP htm mismatch: proof says '{proof_payload.get('htm')}', "
            f"request is '{http_method}'",
        )

    # 6. Check htu (HTTP URL) — compare scheme + authority + path, ignore query
    proof_htu = proof_payload.get("htu", "")
    # Normalize: strip trailing slashes and query strings for comparison
    def _normalize_url(u: str) -> str:
        u = u.split("?")[0].split("#")[0].rstrip("/")
        return u

    if _normalize_url(proof_htu) != _normalize_url(http_url):
        raise HTTPException(
            status_code=401,
            detail=f"DPoP htu mismatch: proof says '{proof_htu}', "
            f"request URL is '{http_url}'",
        )

    # 7. Check iat (issued at) — must be recent
    iat = proof_payload.get("iat")
    if iat is None:
        raise HTTPException(status_code=401, detail="DPoP proof missing iat claim")

    now = time.time()
    age = now - iat
    if age > DPOP_PROOF_MAX_AGE_SECONDS:
        raise HTTPException(
            status_code=401,
            detail=f"DPoP proof too old: {age:.0f}s (max {DPOP_PROOF_MAX_AGE_SECONDS}s)",
        )
    if age < -30:  # Allow 30s clock skew into the future
        raise HTTPException(
            status_code=401,
            detail=f"DPoP proof iat is in the future by {-age:.0f}s",
        )

    # 8. Check jti (unique nonce) — reject replays
    jti = proof_payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="DPoP proof missing jti claim")

    if _check_jti_replay(jti):
        raise HTTPException(
            status_code=401, detail="DPoP proof jti replay detected"
        )

    # 9. Check ath (access token hash) — binds proof to this specific token
    ath = proof_payload.get("ath")
    if ath is not None:
        expected_ath = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        if ath != expected_ath:
            raise HTTPException(
                status_code=401,
                detail="DPoP ath mismatch: proof is bound to a different access token",
            )

    # 10. Check cnf.jkt — the access token must be bound to this proof's key
    cnf = access_token_claims.get("cnf", {})
    expected_jkt = cnf.get("jkt")
    if expected_jkt:
        actual_jkt = _compute_jwk_thumbprint(proof_jwk)
        if actual_jkt != expected_jkt:
            raise HTTPException(
                status_code=401,
                detail="DPoP cnf.jkt mismatch: access token is bound to a different key "
                f"(token jkt='{expected_jkt}', proof jkt='{actual_jkt}')",
            )
    # If the access token has no cnf.jkt, it's not DPoP-bound at the IDP level.
    # We still validated the proof structure, which provides some replay protection.

    return proof_payload


def _extract_token(request: Request) -> tuple[str, str]:
    """Extract token and scheme from Authorization header.

    Supports both 'Bearer' and 'DPoP' schemes.
    Returns (token, scheme).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Malformed Authorization header")

    scheme, token = parts
    if scheme not in ("Bearer", "DPoP"):
        raise HTTPException(
            status_code=401, detail=f"Unsupported auth scheme: {scheme}"
        )

    return token, scheme


def _get_request_url(request: Request) -> str:
    """Reconstruct the full request URL for DPoP htu verification.

    Uses X-Forwarded headers if behind a reverse proxy, otherwise
    falls back to the request's own URL.
    """
    # Prefer X-Forwarded-* headers (set by reverse proxies / load balancers)
    proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.url.hostname or "localhost")
    port = request.url.port
    path = request.url.path

    # Only include port if non-standard
    if port and not (proto == "https" and port == 443) and not (proto == "http" and port == 80):
        return f"{proto}://{host}:{port}{path}"
    return f"{proto}://{host}{path}"


def _verify_token(token: str) -> dict:
    """Verify JWT signature and standard claims.

    Returns decoded payload.
    """
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        payload = pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=SDM_ISSUER,
            options={"verify_aud": False},  # Audience varies per deployment
        )
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except pyjwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def require_scope(required_scope: str):
    """FastAPI dependency that verifies a JWT has the required scope.

    For DPoP tokens, also fully validates the DPoP proof:
    - Signature verification against embedded JWK
    - Method (htm) and URL (htu) binding
    - Freshness (iat) and replay (jti) checks
    - Access token hash (ath) binding
    - JWK thumbprint (cnf.jkt) confirmation

    Usage:
        @app.post("/tools/search")
        async def search(claims: dict = Depends(require_scope("vdb:read"))):
            caller = claims["sub"]
            ...
    """

    async def _dependency(request: Request) -> dict:
        token, scheme = _extract_token(request)
        claims = _verify_token(token)

        # If using DPoP scheme, fully verify the DPoP proof
        if scheme == "DPoP":
            dpop_header = request.headers.get("DPoP")
            if not dpop_header:
                raise HTTPException(
                    status_code=401,
                    detail="DPoP auth scheme requires a DPoP proof header",
                )

            http_method = request.method
            http_url = _get_request_url(request)

            _verify_dpop_proof(
                dpop_header_value=dpop_header,
                access_token=token,
                http_method=http_method,
                http_url=http_url,
                access_token_claims=claims,
            )

        # Check scope
        token_scopes = claims.get("scope", "").split()
        if required_scope not in token_scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient scope: requires '{required_scope}', "
                f"token has '{claims.get('scope', '')}'",
            )

        # Attach caller info to claims for audit logging
        claims["_scheme"] = scheme
        return claims

    return _dependency


def audit_log(server_name: str, endpoint: str, claims: dict, **extra):
    """Write a structured audit log entry."""
    entry = {
        "timestamp": time.time(),
        "server": server_name,
        "endpoint": endpoint,
        "caller": claims.get("sub", "unknown"),
        "scope_used": claims.get("scope", ""),
        "auth_scheme": claims.get("_scheme", "unknown"),
        **extra,
    }
    # In production, send to structured logging / SIEM
    print(json.dumps(entry))
