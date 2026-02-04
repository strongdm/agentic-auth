import Vapor
import JWT

/// JWT claims from StrongDM ID tokens
struct TokenClaims: JWTPayload, Authenticatable {
    /// Subject (agent/user ID)
    let sub: SubjectClaim

    /// Issuer (https://id.strongdm.ai)
    let iss: IssuerClaim

    /// Issued at timestamp
    let iat: IssuedAtClaim

    /// Expiration timestamp
    let exp: ExpirationClaim

    /// Space-separated OAuth2 scopes
    let scope: String?

    /// OAuth2 client ID
    let clientId: String?

    /// Authorized party (alternative to client_id)
    let azp: String?

    /// Actor claim for delegated tokens
    let act: ActorClaim?

    /// Confirmation claim for DPoP
    let cnf: ConfirmationClaim?

    enum CodingKeys: String, CodingKey {
        case sub, iss, iat, exp, scope, azp, act, cnf
        case clientId = "client_id"
    }

    func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired()
    }

    /// Get scopes as an array
    var scopes: [String] {
        scope?.split(separator: " ").map(String.init) ?? []
    }

    /// Check if token has a specific scope
    func hasScope(_ requiredScope: String) -> Bool {
        scopes.contains(requiredScope)
    }

    /// Check if token has any of the required scopes
    func hasAnyScope(_ requiredScopes: [String]) -> Bool {
        let tokenScopes = Set(scopes)
        return requiredScopes.contains { tokenScopes.contains($0) }
    }

    /// Check if token has all required scopes
    func hasAllScopes(_ requiredScopes: [String]) -> Bool {
        let tokenScopes = Set(scopes)
        return requiredScopes.allSatisfy { tokenScopes.contains($0) }
    }

    /// Get the effective client ID
    var effectiveClientId: String? {
        clientId ?? azp
    }
}

/// Actor claim for delegated tokens
struct ActorClaim: Codable {
    let sub: String
}

/// Confirmation claim for DPoP tokens
struct ConfirmationClaim: Codable {
    /// JWK thumbprint
    let jkt: String?
}
