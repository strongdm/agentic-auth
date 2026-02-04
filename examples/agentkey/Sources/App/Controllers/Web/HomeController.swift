import Vapor
import Fluent
import Leaf

struct HomeController {
    /// Landing page with featured agents
    func index(req: Request) async throws -> View {
        // Get verified humans (human type with verified status)
        let verifiedHumans = try await Agent.query(on: req.db)
            .filter(\.$isPublic == true)
            .filter(\.$agentType == .human)
            .filter(\.$verificationStatus == .verified)
            .with(\.$sponsor)
            .sort(\.$createdAt, .descending)
            .limit(6)
            .all()

        // Get sponsored agents (non-human agents with a sponsor)
        let sponsoredAgents = try await Agent.query(on: req.db)
            .filter(\.$isPublic == true)
            .filter(\.$agentType != .human)
            .filter(\.$sponsor.$id != nil)
            .with(\.$sponsor)
            .sort(\.$createdAt, .descending)
            .limit(6)
            .all()

        // Get total counts
        let totalAgents = try await Agent.query(on: req.db)
            .filter(\.$isPublic == true)
            .count()

        let totalKeys = try await AgentPublicKey.query(on: req.db)
            .filter(\.$isRevoked == false)
            .count()

        let context = HomeContext(
            title: "AgentKey - AI Agent Identity Directory",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent,
            verifiedHumans: verifiedHumans.map { AgentResponse(from: $0) },
            sponsoredAgents: sponsoredAgents.map { AgentResponse(from: $0) },
            hasVerifiedHumans: !verifiedHumans.isEmpty,
            hasSponsoredAgents: !sponsoredAgents.isEmpty,
            stats: HomeStats(
                totalAgents: totalAgents,
                totalKeys: totalKeys
            )
        )

        return try await req.view.render("home", context)
    }

    /// Directory page with all public agents
    func directory(req: Request) async throws -> View {
        // Parse query parameters
        let page = (req.query[Int.self, at: "page"] ?? 1).clamped(to: 1...)
        let perPage = 20
        let search = req.query[String.self, at: "q"]
        let agentType = req.query[String.self, at: "type"]

        var query = Agent.query(on: req.db)
            .filter(\.$isPublic == true)

        // Apply search filter
        if let search = search, !search.isEmpty {
            query = query.group(.or) { group in
                group.filter(\.$displayName, .custom("LIKE"), "%\(search)%")
                group.filter(\.$subject, .custom("LIKE"), "%\(search)%")
                group.filter(\.$description, .custom("LIKE"), "%\(search)%")
            }
        }

        // Apply type filter
        if let type = agentType, let agentType = AgentType(rawValue: type) {
            query = query.filter(\.$agentType == agentType)
        }

        // Get total count for pagination
        let total = try await query.count()
        let totalPages = (total + perPage - 1) / perPage

        // Get paginated results
        let agents = try await query
            .with(\.$sponsor)
            .sort(\.$createdAt, .descending)
            .offset((page - 1) * perPage)
            .limit(perPage)
            .all()

        let context = DirectoryContext(
            title: "Agent Directory - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent,
            agents: agents.map { AgentResponse(from: $0) },
            search: search,
            agentType: agentType,
            agentTypes: AgentType.allCases.map { $0.rawValue },
            pagination: PaginationContext(
                currentPage: page,
                totalPages: totalPages,
                totalItems: total,
                hasNext: page < totalPages,
                hasPrevious: page > 1
            ),
            hasAgents: !agents.isEmpty
        )

        return try await req.view.render("directory", context)
    }

    /// Search results page
    func search(req: Request) async throws -> View {
        let query = req.query[String.self, at: "q"] ?? ""

        if query.isEmpty {
            return try await req.view.render("search", SearchContext(
                title: "Search - AgentKey",
                isAuthenticated: req.sessionAgent != nil,
                currentUser: req.sessionAgent,
                query: "",
                results: [],
                totalResults: 0
            ))
        }

        let agents = try await Agent.query(on: req.db)
            .filter(\.$isPublic == true)
            .group(.or) { group in
                group.filter(\.$displayName, .custom("LIKE"), "%\(query)%")
                group.filter(\.$subject, .custom("LIKE"), "%\(query)%")
                group.filter(\.$description, .custom("LIKE"), "%\(query)%")
            }
            .with(\.$sponsor)
            .sort(\.$createdAt, .descending)
            .limit(50)
            .all()

        let context = SearchContext(
            title: "Search Results - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent,
            query: query,
            results: agents.map { AgentResponse(from: $0) },
            totalResults: agents.count
        )

        return try await req.view.render("search", context)
    }

    /// Signature verification page
    func verifyPage(req: Request) async throws -> View {
        let context = VerifyPageContext(
            title: "Verify Signature - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent
        )

        return try await req.view.render("verify", context)
    }
}

// MARK: - View Contexts

struct HomeContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let verifiedHumans: [AgentResponse]
    let sponsoredAgents: [AgentResponse]
    let hasVerifiedHumans: Bool
    let hasSponsoredAgents: Bool
    let stats: HomeStats
}

struct HomeStats: Content {
    let totalAgents: Int
    let totalKeys: Int
}

struct DirectoryContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agents: [AgentResponse]
    let search: String?
    let agentType: String?
    let agentTypes: [String]
    let pagination: PaginationContext
    let hasAgents: Bool
}

struct PaginationContext: Content {
    let currentPage: Int
    let totalPages: Int
    let totalItems: Int
    let hasNext: Bool
    let hasPrevious: Bool
}

struct SearchContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let query: String
    let results: [AgentResponse]
    let totalResults: Int
}

struct VerifyPageContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
}

// MARK: - Helper Extensions

extension Comparable {
    func clamped(to range: PartialRangeFrom<Self>) -> Self {
        return max(self, range.lowerBound)
    }
}
