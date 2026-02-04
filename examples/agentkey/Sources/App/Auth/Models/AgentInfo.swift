import Vapor

/// Authenticated agent information extracted from token claims
struct AgentInfo: Content, Authenticatable {
    /// The agent's subject identifier from the token
    let subject: String

    /// OAuth2 scopes granted to this agent
    let scopes: [String]

    /// OAuth2 client ID (if present)
    let clientId: String?

    /// Whether this is a delegated token (has actor claim)
    let isDelegated: Bool

    /// The actor's subject (if delegated)
    let actorSubject: String?

    /// Initialize from token claims
    init(from claims: TokenClaims) {
        self.subject = claims.sub.value
        self.scopes = claims.scopes
        self.clientId = claims.effectiveClientId
        self.isDelegated = claims.act != nil
        self.actorSubject = claims.act?.sub
    }

    /// Check if agent has a specific scope
    func hasScope(_ scope: String) -> Bool {
        scopes.contains(scope)
    }

    /// Check if agent has any of the required scopes
    func hasAnyScope(_ requiredScopes: [String]) -> Bool {
        let agentScopes = Set(scopes)
        return requiredScopes.contains { agentScopes.contains($0) }
    }

    /// Check if agent has all required scopes
    func hasAllScopes(_ requiredScopes: [String]) -> Bool {
        let agentScopes = Set(scopes)
        return requiredScopes.allSatisfy { agentScopes.contains($0) }
    }
}

/// Request extension to access authenticated agent
extension Request {
    /// Get the authenticated agent info (throws if not authenticated)
    func requireAgent() throws -> AgentInfo {
        guard let agent = auth.get(AgentInfo.self) else {
            throw Abort(.unauthorized, reason: "Authentication required")
        }
        return agent
    }

    /// Get the authenticated agent info (returns nil if not authenticated)
    var agent: AgentInfo? {
        auth.get(AgentInfo.self)
    }
}
