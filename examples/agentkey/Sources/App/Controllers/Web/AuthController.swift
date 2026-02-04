import Vapor
import Fluent
import Foundation
import Crypto

struct AuthController {
    /// Redirect to StrongDM OAuth login
    func login(req: Request) async throws -> Response {
        let redirectUri = req.query[String.self, at: "redirect"] ?? "/dashboard"

        // Store redirect URI in session
        req.session.data["redirect_after_login"] = redirectUri

        // Build OAuth authorization URL
        let issuer = Environment.get("STRONGDM_ISSUER") ?? "https://id.strongdm.ai"
        let clientId = Environment.get("STRONGDM_CLIENT_ID") ?? ""
        let callbackUrl = Environment.get("STRONGDM_CALLBACK_URL") ?? "http://localhost:9873/auth/callback"

        // Generate state for CSRF protection
        let state = UUID().uuidString
        req.session.data["oauth_state"] = state

        // Generate PKCE code verifier and challenge
        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(from: codeVerifier)
        req.session.data["pkce_code_verifier"] = codeVerifier

        var urlComponents = URLComponents(string: "\(issuer)/authorize")!
        urlComponents.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: callbackUrl),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]

        guard let authUrl = urlComponents.url else {
            throw Abort(.internalServerError, reason: "Failed to build authorization URL")
        }

        return req.redirect(to: authUrl.absoluteString)
    }

    /// OAuth callback handler
    func callback(req: Request) async throws -> Response {
        // Verify state
        guard let state = req.query[String.self, at: "state"],
              let expectedState = req.session.data["oauth_state"],
              state == expectedState else {
            throw Abort(.badRequest, reason: "Invalid state parameter")
        }

        // Clear state from session
        req.session.data["oauth_state"] = nil

        // Check for error
        if let error = req.query[String.self, at: "error"] {
            let description = req.query[String.self, at: "error_description"] ?? "Unknown error"
            throw Abort(.unauthorized, reason: "OAuth error: \(error) - \(description)")
        }

        // Get authorization code
        guard let code = req.query[String.self, at: "code"] else {
            throw Abort(.badRequest, reason: "Missing authorization code")
        }

        // Exchange code for tokens
        let tokens = try await exchangeCodeForTokens(code: code, req: req)

        // Verify and decode the ID token
        let claims = try await req.strongDMAuth.verifyToken(tokens.idToken, client: req.client)

        // Store session data
        req.session.data["subject"] = claims.sub.value
        req.session.data["scopes"] = claims.scope ?? ""
        req.session.data["access_token"] = tokens.accessToken

        // Get display name from claims if available
        // Note: This would require adding additional claims to TokenClaims struct

        // Log login activity if agent exists
        if let agent = try await Agent.query(on: req.db)
            .filter(\.$subject == claims.sub.value)
            .first() {
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.login
            )
        }

        // Redirect to original destination
        let redirectUri = req.session.data["redirect_after_login"] ?? "/dashboard"
        req.session.data["redirect_after_login"] = nil

        return req.redirect(to: redirectUri)
    }

    /// Logout
    func logout(req: Request) async throws -> Response {
        // Log logout activity if agent exists
        if let subject = req.session.data["subject"],
           let agent = try await Agent.query(on: req.db)
            .filter(\.$subject == subject)
            .first() {
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.logout
            )
        }

        // Clear session
        req.session.destroy()

        return req.redirect(to: "/?logged_out=1")
    }

    // MARK: - Helpers

    /// Exchange authorization code for tokens
    private func exchangeCodeForTokens(code: String, req: Request) async throws -> TokenResponse {
        let issuer = Environment.get("STRONGDM_ISSUER") ?? "https://id.strongdm.ai"
        let clientId = Environment.get("STRONGDM_CLIENT_ID") ?? ""
        let clientSecret = Environment.get("STRONGDM_CLIENT_SECRET") ?? ""
        let callbackUrl = Environment.get("STRONGDM_CALLBACK_URL") ?? "http://localhost:9873/auth/callback"

        // Get PKCE code verifier from session
        guard let codeVerifier = req.session.data["pkce_code_verifier"] else {
            throw Abort(.badRequest, reason: "Missing PKCE code verifier")
        }
        req.session.data["pkce_code_verifier"] = nil

        let tokenUrl = URI(string: "\(issuer)/token")

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/x-www-form-urlencoded")

        // Use Basic auth for client authentication
        let credentials = Data("\(clientId):\(clientSecret)".utf8).base64EncodedString()
        headers.add(name: .authorization, value: "Basic \(credentials)")

        let response = try await req.client.post(tokenUrl, headers: headers) { clientReq in
            try clientReq.content.encode([
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callbackUrl,
                "code_verifier": codeVerifier
            ], as: .urlEncodedForm)
        }

        guard response.status == .ok else {
            let body = response.body.map { String(buffer: $0) } ?? "No body"
            throw Abort(.unauthorized, reason: "Token exchange failed: \(body)")
        }

        return try response.content.decode(TokenResponse.self)
    }

    // MARK: - PKCE Helpers

    /// Generate a random code verifier for PKCE (43-128 characters)
    private func generateCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncodedString()
    }

    /// Generate code challenge from verifier using SHA256
    private func generateCodeChallenge(from verifier: String) -> String {
        let data = Data(verifier.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash).base64URLEncodedString()
    }
}

/// Token response from OAuth token endpoint
struct TokenResponse: Content {
    let accessToken: String
    let tokenType: String
    let expiresIn: Int?
    let refreshToken: String?
    let idToken: String
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case scope
    }
}

// MARK: - Base64URL Encoding Extension

extension Data {
    /// Encode data as base64url (RFC 4648) without padding
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
