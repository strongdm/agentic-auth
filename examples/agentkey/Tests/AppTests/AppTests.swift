@testable import App
import XCTVapor
import Testing

final class AppTests: XCTestCase {
    var app: Application!

    override func setUp() async throws {
        app = try await Application.make(.testing)
        try await configure(app)
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
    }

    // MARK: - Health Check

    func testHealthCheck() async throws {
        try await app.test(.GET, "health") { res async throws in
            XCTAssertEqual(res.status, .ok)

            struct HealthResponse: Content {
                let status: String
            }

            let health = try res.content.decode(HealthResponse.self)
            XCTAssertEqual(health.status, "ok")
        }
    }

    // MARK: - Public API

    func testListAgentsEmpty() async throws {
        try await app.test(.GET, "api/v1/agents") { res async throws in
            XCTAssertEqual(res.status, .ok)

            let agents = try res.content.decode([AgentResponse].self)
            XCTAssertEqual(agents.count, 0)
        }
    }

    func testAgentNotFound() async throws {
        let fakeId = UUID()
        try await app.test(.GET, "api/v1/agents/\(fakeId)") { res async in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    func testAgentBySubjectNotFound() async throws {
        try await app.test(.GET, "api/v1/agents/subject/nonexistent") { res async in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    // MARK: - Protected Endpoints

    func testCreateAgentUnauthorized() async throws {
        try await app.test(.POST, "api/v1/agents", beforeRequest: { req in
            try req.content.encode(CreateAgentRequest(
                displayName: "Test Agent",
                description: nil,
                agentType: nil,
                homepageUrl: nil,
                avatarUrl: nil,
                isPublic: nil
            ))
        }) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // MARK: - Verify Endpoint

    func testVerifyMissingParams() async throws {
        try await app.test(.POST, "api/v1/verify", beforeRequest: { req in
            try req.content.encode([
                "message": "test",
                "signature": "dGVzdA=="
            ])
        }) { res async in
            XCTAssertEqual(res.status, .badRequest)
        }
    }

    // MARK: - Web Pages

    func testHomePage() async throws {
        try await app.test(.GET, "/") { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains("AgentKey"))
        }
    }

    func testDirectoryPage() async throws {
        try await app.test(.GET, "/directory") { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains("Agent Directory"))
        }
    }

    func testSearchPage() async throws {
        try await app.test(.GET, "/search?q=test") { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains("Search Results"))
        }
    }

    func testVerifyPage() async throws {
        try await app.test(.GET, "/verify") { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains("Verify Signature"))
        }
    }

    // MARK: - Dashboard (requires auth)

    func testDashboardRedirectsToLogin() async throws {
        try await app.test(.GET, "/dashboard") { res async in
            XCTAssertEqual(res.status, .seeOther)
            XCTAssertTrue(res.headers.first(name: .location)?.contains("/auth/login") ?? false)
        }
    }

    // MARK: - Profile

    func testProfileNotFound() async throws {
        try await app.test(.GET, "/@nonexistent") { res async in
            XCTAssertEqual(res.status, .notFound)
        }
    }
}
