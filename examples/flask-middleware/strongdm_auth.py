"""
StrongDM ID Authentication Middleware for Flask

This middleware validates JWT tokens issued by StrongDM ID (https://id.strongdm.ai).
It supports:
- JWT signature verification using JWKS
- Token introspection fallback
- Scope-based access control
- DPoP token validation (optional)
"""

import time
import hashlib
import base64
import json
from functools import wraps
from typing import Optional, Callable

import jwt
import requests
from flask import Flask, request, g, jsonify, Response
from cachetools import TTLCache
from jwt import PyJWKClient, PyJWKClientError


class StrongDMAuthError(Exception):
    """Base exception for StrongDM auth errors."""
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class StrongDMAuth:
    """
    StrongDM ID authentication middleware for Flask.

    Usage:
        app = Flask(__name__)
        auth = StrongDMAuth(app)

        @app.route('/protected')
        @auth.require_auth()
        def protected():
            return f"Hello, {g.token_claims['sub']}"

        @app.route('/admin')
        @auth.require_scope('admin')
        def admin():
            return "Admin area"
    """

    DEFAULT_ISSUER = "https://id.strongdm.ai"

    def __init__(
        self,
        app: Optional[Flask] = None,
        issuer: str = DEFAULT_ISSUER,
        audience: Optional[str] = None,
        jwks_cache_ttl: int = 900,  # 15 minutes
        introspection_enabled: bool = False,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """
        Initialize the StrongDM auth middleware.

        Args:
            app: Flask application instance
            issuer: Token issuer URL (default: https://id.strongdm.ai)
            audience: Expected audience claim (optional)
            jwks_cache_ttl: JWKS cache TTL in seconds (default: 15 minutes)
            introspection_enabled: Enable token introspection fallback
            client_id: Client ID for introspection (required if introspection enabled)
            client_secret: Client secret for introspection (required if introspection enabled)
        """
        self.issuer = issuer.rstrip('/')
        self.audience = audience
        self.jwks_cache_ttl = jwks_cache_ttl
        self.introspection_enabled = introspection_enabled
        self.client_id = client_id
        self.client_secret = client_secret

        # JWKS clients keyed by issuer URL
        self._jwks_clients: dict[str, PyJWKClient] = {}

        # Cache for introspection results
        self._introspection_cache = TTLCache(maxsize=1000, ttl=60)

        # Discovery document cache
        self._discovery: Optional[dict] = None
        self._discovery_fetched_at: float = 0

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the middleware with a Flask app."""
        app.config.setdefault('STRONGDM_ISSUER', self.issuer)
        app.config.setdefault('STRONGDM_AUDIENCE', self.audience)

        # Register error handler
        @app.errorhandler(StrongDMAuthError)
        def handle_auth_error(error: StrongDMAuthError) -> tuple[Response, int]:
            return jsonify({"error": error.message}), error.status_code

    def _validate_issuer(self, token_issuer: str) -> None:
        """Validate that the token issuer is the base or a realm-qualified issuer."""
        if token_issuer == self.issuer:
            return
        if token_issuer.startswith(self.issuer + '/realms/'):
            return
        raise StrongDMAuthError("Invalid token issuer")

    def _get_jwks_client_for_issuer(self, issuer: str) -> PyJWKClient:
        """Get or create a JWKS client for the given issuer."""
        if issuer not in self._jwks_clients:
            jwks_uri = issuer.rstrip('/') + '/jwks'
            self._jwks_clients[issuer] = PyJWKClient(
                jwks_uri,
                cache_jwk_set=True,
                lifespan=self.jwks_cache_ttl
            )
        return self._jwks_clients[issuer]

    def _get_discovery(self) -> dict:
        """Fetch and cache the OIDC discovery document."""
        now = time.time()
        if self._discovery is None or (now - self._discovery_fetched_at) > 3600:
            discovery_url = f"{self.issuer}/.well-known/openid-configuration"
            resp = requests.get(discovery_url, timeout=10)
            resp.raise_for_status()
            self._discovery = resp.json()
            self._discovery_fetched_at = now
        return self._discovery

    def _extract_token(self) -> tuple[str, str]:
        """
        Extract the token from the Authorization header.

        Returns:
            Tuple of (token_type, token_value)
        """
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            raise StrongDMAuthError("Missing Authorization header")

        parts = auth_header.split(' ', 1)
        if len(parts) != 2:
            raise StrongDMAuthError("Invalid Authorization header format")

        token_type, token_value = parts
        token_type = token_type.lower()

        if token_type not in ('bearer', 'dpop'):
            raise StrongDMAuthError(f"Unsupported token type: {token_type}")

        return token_type, token_value

    @staticmethod
    def _jwk_thumbprint(jwk: dict) -> str:
        """Compute RFC 7638 SHA-256 JWK thumbprint."""
        kty = jwk.get("kty")
        if kty == "RSA":
            canonical_members = {"e": jwk.get("e"), "kty": kty, "n": jwk.get("n")}
        elif kty == "EC":
            canonical_members = {"crv": jwk.get("crv"), "kty": kty, "x": jwk.get("x"), "y": jwk.get("y")}
        elif kty == "OKP":
            canonical_members = {"crv": jwk.get("crv"), "kty": kty, "x": jwk.get("x")}
        elif kty == "oct":
            canonical_members = {"k": jwk.get("k"), "kty": kty}
        else:
            raise StrongDMAuthError("Invalid DPoP proof: unsupported JWK kty")

        if any(v is None for v in canonical_members.values()):
            raise StrongDMAuthError("Invalid DPoP proof: incomplete JWK for thumbprint")

        canonical = json.dumps(canonical_members, separators=(",", ":"), sort_keys=True).encode()
        digest = hashlib.sha256(canonical).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _verify_dpop_proof(self, dpop_proof: str, access_token: str) -> tuple[dict, str]:
        """
        Verify a DPoP proof JWT.

        Args:
            dpop_proof: The DPoP proof JWT from the DPoP header
            access_token: The access token being used

        Returns:
            The decoded DPoP proof claims
        """
        # Decode header without verification to get the JWK
        unverified_header = jwt.get_unverified_header(dpop_proof)

        if unverified_header.get('typ') != 'dpop+jwt':
            raise StrongDMAuthError("Invalid DPoP proof: wrong typ")

        jwk = unverified_header.get('jwk')
        if not jwk:
            raise StrongDMAuthError("Invalid DPoP proof: missing jwk")

        proof_jkt = self._jwk_thumbprint(jwk)

        # Verify the proof signature using the embedded JWK
        try:
            from jwt import PyJWK
            key = PyJWK.from_dict(jwk)
            claims = jwt.decode(
                dpop_proof,
                key.key,
                algorithms=['ES256', 'RS256', 'EdDSA'],
                options={"require": ["jti", "htm", "htu", "iat"]}
            )
        except jwt.InvalidTokenError as e:
            raise StrongDMAuthError(f"Invalid DPoP proof: {e}")

        # Verify the HTTP method and URI
        if claims.get('htm') != request.method:
            raise StrongDMAuthError("DPoP proof htm mismatch")

        # Reconstruct the expected URI
        expected_htu = request.url.split('?')[0]  # Remove query string
        if claims.get('htu') != expected_htu:
            raise StrongDMAuthError("DPoP proof htu mismatch")

        # Verify the access token hash (ath) if present
        if 'ath' in claims:
            expected_ath = base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b'=').decode()
            if claims['ath'] != expected_ath:
                raise StrongDMAuthError("DPoP proof ath mismatch")

        return claims, proof_jkt

    def _verify_token(self, token: str, token_type: str) -> dict:
        """
        Verify a JWT token.

        Args:
            token: The JWT token string
            token_type: 'bearer' or 'dpop'

        Returns:
            The decoded token claims
        """
        try:
            # Peek at unverified claims to determine the issuer and JWKS endpoint
            unverified = jwt.decode(token, options={"verify_signature": False}, algorithms=['RS256', 'ES256', 'EdDSA'])
            token_issuer = unverified.get('iss', '')
            self._validate_issuer(token_issuer)

            # Get the signing key from the token's issuer's JWKS endpoint
            jwks_client = self._get_jwks_client_for_issuer(token_issuer)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # Decode and verify the token
            options = {
                "require": ["exp", "iat", "sub"],
                "verify_exp": True,
                "verify_iat": True,
            }

            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=['RS256', 'ES256', 'EdDSA'],
                audience=self.audience,
                options=options,
            )

            # For DPoP tokens, verify the cnf/jkt claim matches the proof
            if token_type == 'dpop':
                dpop_proof = request.headers.get('DPoP')
                if not dpop_proof:
                    raise StrongDMAuthError("DPoP token requires DPoP proof header")

                # Verify the proof and bind it to token cnf.jkt.
                _, proof_jkt = self._verify_dpop_proof(dpop_proof, token)

                cnf = claims.get('cnf', {})
                token_jkt = cnf.get('jkt')
                if not token_jkt:
                    raise StrongDMAuthError("DPoP token missing cnf.jkt")
                if token_jkt != proof_jkt:
                    raise StrongDMAuthError(
                        "DPoP proof key thumbprint does not match token cnf.jkt"
                    )

            return claims

        except PyJWKClientError as e:
            raise StrongDMAuthError(f"Failed to fetch signing key: {e}")
        except jwt.ExpiredSignatureError:
            raise StrongDMAuthError("Token has expired")
        except jwt.InvalidAudienceError:
            raise StrongDMAuthError("Invalid token audience")
        except jwt.InvalidTokenError as e:
            raise StrongDMAuthError(f"Invalid token: {e}")

    def _introspect_token(self, token: str) -> dict:
        """
        Introspect a token using the introspection endpoint.

        Args:
            token: The token to introspect

        Returns:
            The introspection response
        """
        # Check cache first
        cache_key = hashlib.sha256(token.encode()).hexdigest()[:16]
        if cache_key in self._introspection_cache:
            return self._introspection_cache[cache_key]

        if not self.client_id or not self.client_secret:
            raise StrongDMAuthError(
                "Introspection requires client credentials",
                status_code=500
            )

        introspection_url = f"{self.issuer}/introspect"

        resp = requests.post(
            introspection_url,
            auth=(self.client_id, self.client_secret),
            data={"token": token},
            timeout=10,
        )

        if resp.status_code != 200:
            raise StrongDMAuthError("Token introspection failed")

        result = resp.json()

        # Cache the result
        self._introspection_cache[cache_key] = result

        return result

    def verify_request(self) -> dict:
        """
        Verify the current request's authentication.

        Returns:
            The decoded token claims

        Raises:
            StrongDMAuthError: If authentication fails
        """
        token_type, token = self._extract_token()

        # Try JWT verification first
        try:
            claims = self._verify_token(token, token_type)
            return claims
        except StrongDMAuthError:
            # Never allow DPoP proof failures to bypass sender-constrained validation.
            if not self.introspection_enabled or token_type == 'dpop':
                raise

        # Fall back to introspection
        result = self._introspect_token(token)

        if not result.get('active', False):
            raise StrongDMAuthError("Token is not active")

        return result

    def require_auth(self) -> Callable:
        """
        Decorator to require authentication for a route.

        Usage:
            @app.route('/protected')
            @auth.require_auth()
            def protected():
                return f"Hello, {g.token_claims['sub']}"
        """
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                claims = self.verify_request()
                g.token_claims = claims
                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def require_scope(self, *required_scopes: str, require_all: bool = False) -> Callable:
        """
        Decorator to require specific scopes.

        Args:
            required_scopes: The scopes required (at least one or all, depending on require_all)
            require_all: If True, all scopes are required. If False, at least one is required.

        Usage:
            @app.route('/admin')
            @auth.require_scope('admin')
            def admin():
                return "Admin area"

            @app.route('/restricted')
            @auth.require_scope('admin', require_all=True)
            def restricted():
                return "Restricted area"
        """
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                claims = self.verify_request()
                g.token_claims = claims

                # Get scopes from token
                token_scopes = set(claims.get('scope', '').split())
                required = set(required_scopes)

                if require_all:
                    if not required.issubset(token_scopes):
                        missing = required - token_scopes
                        raise StrongDMAuthError(
                            f"Missing required scopes: {', '.join(missing)}",
                            status_code=403
                        )
                else:
                    if not required.intersection(token_scopes):
                        raise StrongDMAuthError(
                            f"Requires one of: {', '.join(required)}",
                            status_code=403
                        )

                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def get_current_agent(self) -> Optional[dict]:
        """
        Get information about the currently authenticated agent.

        Returns:
            Dict with agent info or None if not authenticated
        """
        claims = getattr(g, 'token_claims', None)
        if not claims:
            return None

        return {
            'subject': claims.get('sub'),
            'scopes': claims.get('scope', '').split(),
            'issuer': claims.get('iss'),
            'client_id': claims.get('client_id') or claims.get('azp'),
            'actor': claims.get('act'),  # For delegated tokens
        }
