import Vapor
import Fluent
import FluentSQLiteDriver
import FluentPostgresDriver
import Leaf
import JWT

public func configure(_ app: Application) async throws {
    // MARK: - Server Configuration

    // Set default port to 9873
    app.http.server.configuration.port = Int(Environment.get("PORT") ?? "9873") ?? 9873

    // MARK: - Environment Configuration

    // Load .env file in development
    if app.environment == .development {
        // Vapor automatically loads .env files
    }

    // MARK: - Database Configuration

    if let databaseURL = Environment.get("DATABASE_URL") {
        // Production: PostgreSQL
        try app.databases.use(.postgres(url: databaseURL), as: .psql)
    } else if app.environment == .testing {
        // Testing: In-memory SQLite
        app.databases.use(.sqlite(.memory), as: .sqlite)
    } else {
        // Development: SQLite file
        app.databases.use(.sqlite(.file("agentkey.sqlite")), as: .sqlite)
    }

    // MARK: - Session Configuration

    // Session middleware for web UI
    app.sessions.use(.fluent)

    // MARK: - Migrations

    app.migrations.add(SessionRecord.migration)
    app.migrations.add(CreateAgent())
    app.migrations.add(CreateAgentPublicKey())
    app.migrations.add(CreateAgentProof())
    app.migrations.add(CreateActivityLog())
    app.migrations.add(AddAgentSponsor())

    // Auto-migrate in development and testing
    if app.environment == .development || app.environment == .testing {
        try await app.autoMigrate()
    }

    // MARK: - Middleware

    // Serve static files from Public directory
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    // Session middleware
    app.middleware.use(app.sessions.middleware)

    // MARK: - Leaf Templating

    app.views.use(.leaf)
    app.leaf.cache.isEnabled = app.environment.isRelease

    // MARK: - JWT Configuration

    // Configure StrongDM auth service
    let issuer = Environment.get("STRONGDM_ISSUER") ?? "https://id.strongdm.ai"
    let audience = Environment.get("STRONGDM_AUDIENCE")

    // Fetch JWKS and configure JWT signers
    let strongDMAuth = StrongDMAuth(
        issuer: issuer,
        audience: audience,
        clientId: Environment.get("STRONGDM_CLIENT_ID"),
        clientSecret: Environment.get("STRONGDM_CLIENT_SECRET"),
        introspectionEnabled: Environment.get("STRONGDM_INTROSPECTION_ENABLED")?.lowercased() == "true"
    )

    // Store auth service in app storage
    app.storage[StrongDMAuthKey.self] = strongDMAuth

    // Fetch JWKS on startup
    try await strongDMAuth.fetchJWKS(client: app.client)
    app.logger.info("StrongDM JWKS fetched successfully from \(issuer)")

    // MARK: - Routes

    try routes(app)
}

// Storage key for StrongDM auth service
struct StrongDMAuthKey: StorageKey {
    typealias Value = StrongDMAuth
}

extension Application {
    var strongDMAuth: StrongDMAuth {
        get {
            guard let auth = storage[StrongDMAuthKey.self] else {
                fatalError("StrongDMAuth not configured. Call configure() first.")
            }
            return auth
        }
        set {
            storage[StrongDMAuthKey.self] = newValue
        }
    }
}

extension Request {
    var strongDMAuth: StrongDMAuth {
        application.strongDMAuth
    }
}
