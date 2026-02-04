import Vapor

func routes(_ app: Application) throws {
    // MARK: - Health Check

    app.get("health") { req -> HealthResponse in
        HealthResponse(status: "ok", timestamp: Date())
    }

    // MARK: - Web Routes (Public)

    let homeController = HomeController()
    app.get(use: homeController.index)
    app.get("directory", use: homeController.directory)
    app.get("search", use: homeController.search)
    app.get("verify", use: homeController.verifyPage)

    // Public agent profile (Keybase-style URL)
    let profileController = ProfileController()
    app.get(":subject", use: profileController.show)

    // MARK: - Auth Routes

    let authController = AuthController()
    app.get("auth", "login", use: authController.login)
    app.get("auth", "callback", use: authController.callback)
    app.get("auth", "logout", use: authController.logout)

    // MARK: - Dashboard Routes (Authenticated)

    let dashboardController = DashboardController()
    let dashboard = app.grouped("dashboard")
        .grouped(WebAuthMiddleware())

    dashboard.get(use: dashboardController.index)
    dashboard.get("profile", use: dashboardController.profile)
    dashboard.post("profile", use: dashboardController.updateProfile)
    dashboard.get("keys", use: dashboardController.keys)
    dashboard.post("keys", use: dashboardController.addKey)
    dashboard.post("keys", ":keyId", "revoke", use: dashboardController.revokeKey)
    dashboard.get("proofs", use: dashboardController.proofs)
    dashboard.post("proofs", use: dashboardController.addProof)
    dashboard.post("proofs", ":proofId", "verify", use: dashboardController.verifyProof)
    dashboard.get("activity", use: dashboardController.activity)

    // MARK: - API Routes

    let api = app.grouped("api", "v1")

    // Agent API
    let agentAPIController = AgentAPIController()
    api.get("agents", use: agentAPIController.index)
    api.get("agents", ":agentId", use: agentAPIController.show)
    api.get("agents", "subject", ":subject", use: agentAPIController.showBySubject)

    // Protected agent routes
    let protectedAgents = api.grouped("agents")
        .grouped(StrongDMAuthMiddleware())

    protectedAgents.post(use: agentAPIController.create)
    protectedAgents.put(":agentId", use: agentAPIController.update)
    protectedAgents.delete(":agentId", use: agentAPIController.delete)
    protectedAgents.post(":agentId", "sponsor", use: agentAPIController.sponsor)

    // Web-based sponsor route (session authenticated)
    app.grouped(WebAuthMiddleware())
        .post("sponsor", ":agentId", use: agentAPIController.sponsor)

    // Key API
    let keyAPIController = KeyAPIController()
    api.get("agents", ":agentId", "keys", use: keyAPIController.index)

    let protectedKeys = api.grouped("agents", ":agentId", "keys")
        .grouped(StrongDMAuthMiddleware())

    protectedKeys.post(use: keyAPIController.create)
    protectedKeys.delete(":keyId", use: keyAPIController.revoke)

    // Verify API
    let verifyAPIController = VerifyAPIController()
    api.post("verify", use: verifyAPIController.verify)

    // Activity API (protected)
    let activityAPI = api.grouped(StrongDMAuthMiddleware())
    activityAPI.get("agents", ":agentId", "activity", use: agentAPIController.activity)
}

struct HealthResponse: Content {
    let status: String
    let timestamp: Date
}
