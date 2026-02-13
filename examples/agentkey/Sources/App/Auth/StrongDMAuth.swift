import Vapor
import JWT
import Foundation
import Crypto

/// StrongDM authentication service
/// Handles JWT verification via JWKS and optional token introspection
actor StrongDMAuth {
    /// Token issuer (e.g., https://id.strongdm.ai)
    let issuer: String

    /// Expected audience (optional)
    let audience: String?

    /// OAuth2 client ID for introspection
    let clientId: String?

    /// OAuth2 client secret for introspection
    let clientSecret: String?

    /// Whether introspection fallback is enabled
    let introspectionEnabled: Bool

    /// Cached JWKS
    private var jwks: JWKS?

    /// Cached signers
    private var signers: JWTSigners?

    /// JWKS cache expiry time
    private var jwksCacheExpiry: Date?

    /// JWKS cache TTL (15 minutes)
    private let jwksCacheTTL: TimeInterval = 15 * 60

    /// Introspection cache
    private var introspectionCache: [String: (result: TokenClaims, expiry: Date)] = [:]

    /// Introspection cache TTL (60 seconds)
    private let introspectionCacheTTL: TimeInterval = 60

    init(
        issuer: String,
        audience: String? = nil,
        clientId: String? = nil,
        clientSecret: String? = nil,
        introspectionEnabled: Bool = false
    ) {
        self.issuer = issuer
        self.audience = audience
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.introspectionEnabled = introspectionEnabled
    }

    /// Fetch JWKS from the issuer
    func fetchJWKS(client: Client) async throws {
        let jwksURL = URI(string: "\(issuer)/jwks")

        let response = try await client.get(jwksURL)

        guard response.status == .ok else {
            throw StrongDMAuthError.jwksFetchFailed("HTTP \(response.status.code)")
        }

        guard let body = response.body else {
            throw StrongDMAuthError.jwksFetchFailed("Empty response body")
        }

        let data = Data(buffer: body)
        self.jwks = try JSONDecoder().decode(JWKS.self, from: data)

        // Create signers from JWKS
        let newSigners = JWTSigners()
        try newSigners.use(jwks: self.jwks!)
        self.signers = newSigners

        self.jwksCacheExpiry = Date().addingTimeInterval(jwksCacheTTL)
    }

    /// Check if JWKS cache is valid
    private func isJWKSCacheValid() -> Bool {
        guard let expiry = jwksCacheExpiry else { return false }
        return Date() < expiry
    }

    /// Get the cached signers, refreshing if needed
    func getSigners(client: Client) async throws -> JWTSigners {
        if !isJWKSCacheValid() || signers == nil {
            try await fetchJWKS(client: client)
        }
        guard let signers = signers else {
            throw StrongDMAuthError.jwksFetchFailed("Signers not available")
        }
        return signers
    }

    /// Verify a JWT token
    func verifyToken(_ token: String, client: Client) async throws -> TokenClaims {
        do {
            // Try JWT verification first
            let signers = try await getSigners(client: client)
            let claims = try signers.verify(token, as: TokenClaims.self)

            // Verify issuer
            guard claims.iss.value == issuer else {
                throw StrongDMAuthError.invalidToken("Invalid issuer")
            }

            // Verify audience when configured.
            if let audience = audience {
                guard claims.audiences.contains(audience) else {
                    throw StrongDMAuthError.invalidToken("Invalid audience")
                }
            }

            return claims
        } catch let error as StrongDMAuthError {
            throw error
        } catch {
            // Fall back to introspection if enabled
            if introspectionEnabled {
                return try await introspectToken(token, client: client)
            }
            throw StrongDMAuthError.invalidToken(error.localizedDescription)
        }
    }

    /// Introspect a token using the introspection endpoint
    private func introspectToken(_ token: String, client: Client) async throws -> TokenClaims {
        guard let clientId = clientId, let clientSecret = clientSecret else {
            throw StrongDMAuthError.configurationError("Client credentials required for introspection")
        }

        // Check cache using SHA256 hash of token for stable cache key
        let tokenData = Data(token.utf8)
        let cacheKey = SHA256.hash(data: tokenData).compactMap { String(format: "%02x", $0) }.joined()
        if let cached = introspectionCache[cacheKey], Date() < cached.expiry {
            return cached.result
        }

        // Make introspection request
        let introspectionURL = URI(string: "\(issuer)/introspect")
        let credentials = Data("\(clientId):\(clientSecret)".utf8).base64EncodedString()

        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Basic \(credentials)")
        headers.add(name: .contentType, value: "application/x-www-form-urlencoded")

        let response = try await client.post(introspectionURL, headers: headers) { req in
            try req.content.encode(["token": token], as: .urlEncodedForm)
        }

        guard response.status == .ok else {
            throw StrongDMAuthError.introspectionFailed("HTTP \(response.status.code)")
        }

        struct IntrospectionResponse: Decodable {
            let active: Bool
            let sub: String?
            let iss: String?
            let exp: Int?
            let iat: Int?
            let aud: AudienceValue?
            let scope: String?
            let client_id: String?
        }

        let introspectionResult = try response.content.decode(IntrospectionResponse.self)

        guard introspectionResult.active else {
            throw StrongDMAuthError.invalidToken("Token is not active")
        }

        guard let sub = introspectionResult.sub else {
            throw StrongDMAuthError.invalidToken("Token missing subject")
        }

        if let audience = audience {
            guard introspectionResult.aud?.values.contains(audience) == true else {
                throw StrongDMAuthError.invalidToken("Invalid audience")
            }
        }

        // Build claims from introspection response
        let claims = TokenClaims(
            sub: SubjectClaim(value: sub),
            iss: IssuerClaim(value: introspectionResult.iss ?? issuer),
            iat: IssuedAtClaim(value: Date(timeIntervalSince1970: TimeInterval(introspectionResult.iat ?? 0))),
            exp: ExpirationClaim(value: Date(timeIntervalSince1970: TimeInterval(introspectionResult.exp ?? 0))),
            aud: introspectionResult.aud,
            scope: introspectionResult.scope,
            clientId: introspectionResult.client_id,
            azp: nil,
            act: nil,
            cnf: nil
        )

        // Cache the result
        introspectionCache[cacheKey] = (result: claims, expiry: Date().addingTimeInterval(introspectionCacheTTL))

        return claims
    }

    /// Clear expired introspection cache entries
    func cleanupIntrospectionCache() {
        let now = Date()
        introspectionCache = introspectionCache.filter { $0.value.expiry > now }
    }
}

/// StrongDM authentication errors
enum StrongDMAuthError: Error, AbortError {
    case jwksFetchFailed(String)
    case invalidToken(String)
    case introspectionFailed(String)
    case configurationError(String)
    case insufficientScope(String)

    var status: HTTPResponseStatus {
        switch self {
        case .jwksFetchFailed, .configurationError:
            return .internalServerError
        case .invalidToken, .introspectionFailed:
            return .unauthorized
        case .insufficientScope:
            return .forbidden
        }
    }

    var reason: String {
        switch self {
        case .jwksFetchFailed(let message):
            return "Failed to fetch JWKS: \(message)"
        case .invalidToken(let message):
            return "Invalid token: \(message)"
        case .introspectionFailed(let message):
            return "Token introspection failed: \(message)"
        case .configurationError(let message):
            return "Configuration error: \(message)"
        case .insufficientScope(let message):
            return "Insufficient scope: \(message)"
        }
    }
}
