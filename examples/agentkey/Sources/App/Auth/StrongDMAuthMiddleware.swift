import Vapor

/// Middleware for API routes requiring StrongDM authentication
struct StrongDMAuthMiddleware: AsyncMiddleware {
    /// Required scopes (at least one must be present)
    let requiredScopes: [String]

    /// Whether all scopes are required (vs any)
    let requireAllScopes: Bool

    init(scopes: [String] = [], requireAll: Bool = false) {
        self.requiredScopes = scopes
        self.requireAllScopes = requireAll
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Extract bearer token
        guard let authHeader = request.headers.bearerAuthorization else {
            throw Abort(.unauthorized, reason: "Missing Authorization header")
        }

        let token = authHeader.token

        // Verify token
        let claims = try await request.strongDMAuth.verifyToken(token, client: request.client)

        // Check scopes if required
        if !requiredScopes.isEmpty {
            if requireAllScopes {
                guard claims.hasAllScopes(requiredScopes) else {
                    let missing = requiredScopes.filter { !claims.hasScope($0) }
                    throw StrongDMAuthError.insufficientScope("Missing required scopes: \(missing.joined(separator: ", "))")
                }
            } else {
                guard claims.hasAnyScope(requiredScopes) else {
                    throw StrongDMAuthError.insufficientScope("Requires one of: \(requiredScopes.joined(separator: ", "))")
                }
            }
        }

        // Create agent info and store in request
        let agentInfo = AgentInfo(from: claims)
        request.auth.login(agentInfo)

        return try await next.respond(to: request)
    }
}

/// Middleware for web routes requiring session authentication
struct WebAuthMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Check for session
        guard let subject = request.session.data["subject"] else {
            // Redirect to login
            return request.redirect(to: "/auth/login?redirect=\(request.url.path)")
        }

        // Create agent info from session
        let scopes = request.session.data["scopes"]?.split(separator: " ").map(String.init) ?? []
        let sessionAgentInfo = SessionAgentInfo(
            subject: subject,
            scopes: scopes,
            displayName: request.session.data["displayName"]
        )
        request.auth.login(sessionAgentInfo)

        return try await next.respond(to: request)
    }
}

/// Session-based agent info for web UI
struct SessionAgentInfo: Authenticatable, Content {
    let subject: String
    let scopes: [String]
    let displayName: String?

    func hasScope(_ scope: String) -> Bool {
        scopes.contains(scope)
    }
}

/// Request extension for session agent
extension Request {
    var sessionAgent: SessionAgentInfo? {
        // First check if middleware already populated it
        if let agent = auth.get(SessionAgentInfo.self) {
            return agent
        }
        // Otherwise try to read from session directly (for public pages)
        guard let subject = session.data["subject"] else {
            return nil
        }
        let scopes = session.data["scopes"]?.split(separator: " ").map(String.init) ?? []
        return SessionAgentInfo(
            subject: subject,
            scopes: scopes,
            displayName: session.data["displayName"]
        )
    }

    func requireSessionAgent() throws -> SessionAgentInfo {
        guard let agent = sessionAgent else {
            throw Abort(.unauthorized, reason: "Authentication required")
        }
        return agent
    }
}

/// Scope requirement middleware factory
extension StrongDMAuthMiddleware {
    /// Create middleware requiring a specific scope
    static func requireScope(_ scope: String) -> StrongDMAuthMiddleware {
        StrongDMAuthMiddleware(scopes: [scope])
    }

    /// Create middleware requiring any of the specified scopes
    static func requireAnyScope(_ scopes: String...) -> StrongDMAuthMiddleware {
        StrongDMAuthMiddleware(scopes: scopes, requireAll: false)
    }

    /// Create middleware requiring all specified scopes
    static func requireAllScopes(_ scopes: String...) -> StrongDMAuthMiddleware {
        StrongDMAuthMiddleware(scopes: scopes, requireAll: true)
    }
}
