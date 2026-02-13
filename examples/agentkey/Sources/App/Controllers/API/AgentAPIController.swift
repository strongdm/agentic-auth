import Vapor
import Fluent

struct AgentAPIController {
    /// List all public agents
    func index(req: Request) async throws -> [AgentResponse] {
        let agents = try await Agent.query(on: req.db)
            .filter(\.$isPublic == true)
            .sort(\.$createdAt, .descending)
            .all()

        return agents.map { AgentResponse(from: $0) }
    }

    /// Get a single agent by ID
    func show(req: Request) async throws -> AgentResponse {
        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.query(on: req.db)
            .filter(\.$id == agentId)
            .with(\.$publicKeys)
            .first() else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check if agent is public or if requester is the owner
        if !agent.isPublic {
            if let agentInfo = req.agent {
                guard agentInfo.subject == agent.subject else {
                    throw Abort(.notFound, reason: "Agent not found")
                }
            } else {
                throw Abort(.notFound, reason: "Agent not found")
            }
        }

        return AgentResponse(from: agent, includeKeys: true)
    }

    /// Get an agent by subject
    func showBySubject(req: Request) async throws -> AgentResponse {
        guard let subject = req.parameters.get("subject") else {
            throw Abort(.badRequest, reason: "Missing subject parameter")
        }

        guard let agent = try await Agent.query(on: req.db)
            .filter(\.$subject == subject)
            .with(\.$publicKeys)
            .first() else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check visibility
        if !agent.isPublic {
            if let agentInfo = req.agent {
                guard agentInfo.subject == agent.subject else {
                    throw Abort(.notFound, reason: "Agent not found")
                }
            } else {
                throw Abort(.notFound, reason: "Agent not found")
            }
        }

        return AgentResponse(from: agent, includeKeys: true)
    }

    /// Create a new agent (requires authentication)
    func create(req: Request) async throws -> AgentResponse {
        let agentInfo = try req.requireAgent()

        // Validate request
        try CreateAgentRequest.validate(content: req)
        let createRequest = try req.content.decode(CreateAgentRequest.self)

        // Check if agent already exists
        if let _ = try await Agent.query(on: req.db)
            .filter(\.$subject == agentInfo.subject)
            .first() {
            throw Abort(.conflict, reason: "Agent already registered")
        }

        // Determine default agent type based on subject prefix
        let defaultAgentType: AgentType = agentInfo.subject.hasPrefix("usr_") ? .human : .assistant

        // Create agent
        let agent = Agent(
            subject: agentInfo.subject,
            displayName: createRequest.displayName,
            description: createRequest.description,
            agentType: createRequest.agentType ?? defaultAgentType,
            homepageUrl: createRequest.homepageUrl,
            avatarUrl: createRequest.avatarUrl,
            isPublic: createRequest.isPublic ?? true
        )

        try await agent.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.agentCreated
        )

        return AgentResponse(from: agent)
    }

    /// Update an agent (owner only)
    func update(req: Request) async throws -> AgentResponse {
        let agentInfo = try req.requireAgent()

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check ownership
        guard agent.subject == agentInfo.subject else {
            throw Abort(.forbidden, reason: "You can only update your own agent")
        }

        // Validate and decode request
        try UpdateAgentRequest.validate(content: req)
        let updateRequest = try req.content.decode(UpdateAgentRequest.self)

        // Update fields
        if let displayName = updateRequest.displayName {
            agent.displayName = displayName
        }
        if let description = updateRequest.description {
            agent.description = description
        }
        if let agentType = updateRequest.agentType {
            // Humans cannot change their agent type
            if agent.agentType != .human {
                agent.agentType = agentType
            }
        }
        if let homepageUrl = updateRequest.homepageUrl {
            agent.homepageUrl = homepageUrl
        }
        if let avatarUrl = updateRequest.avatarUrl {
            agent.avatarUrl = avatarUrl
        }
        if let isPublic = updateRequest.isPublic {
            agent.isPublic = isPublic
        }

        try await agent.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.profileUpdated
        )

        return AgentResponse(from: agent)
    }

    /// Delete an agent (owner only)
    func delete(req: Request) async throws -> HTTPStatus {
        let agentInfo = try req.requireAgent()

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check ownership
        guard agent.subject == agentInfo.subject else {
            throw Abort(.forbidden, reason: "You can only delete your own agent")
        }

        try await agent.delete(on: req.db)

        return .noContent
    }

    /// Get activity log for an agent (owner only)
    func activity(req: Request) async throws -> [ActivityLogResponse] {
        let agentInfo = try req.requireAgent()

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check ownership
        guard agent.subject == agentInfo.subject else {
            throw Abort(.forbidden, reason: "You can only view your own activity")
        }

        let logs = try await ActivityLog.query(on: req.db)
            .filter(\.$agent.$id == agentId)
            .sort(\.$createdAt, .descending)
            .limit(100)
            .all()

        return logs.map { ActivityLogResponse(from: $0) }
    }

    /// Sponsor an agent (set yourself as the sponsor)
    /// Works with both API authentication (req.agent) and web session (req.sessionAgent)
    func sponsor(req: Request) async throws -> Response {
        // Try API auth first, then session auth
        let sponsorSubject: String
        let usingSessionAuth: Bool
        if let agentInfo = req.agent {
            sponsorSubject = agentInfo.subject
            usingSessionAuth = false
        } else if let sessionAgent = req.sessionAgent {
            sponsorSubject = sessionAgent.subject
            usingSessionAuth = true
        } else {
            throw Abort(.unauthorized, reason: "Authentication required")
        }

        if usingSessionAuth {
            struct SponsorForm: Content {
                let csrfToken: String?

                enum CodingKeys: String, CodingKey {
                    case csrfToken = "_csrf"
                }
            }

            let form = try req.content.decode(SponsorForm.self)
            try req.validateCSRFToken(form.csrfToken)
        }

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let targetAgent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Cannot sponsor yourself
        guard targetAgent.subject != sponsorSubject else {
            throw Abort(.badRequest, reason: "You cannot sponsor yourself")
        }

        // Cannot sponsor if already sponsored
        guard targetAgent.$sponsor.id == nil else {
            throw Abort(.conflict, reason: "Agent is already sponsored")
        }

        // Find the sponsor's agent record
        guard let sponsorAgent = try await Agent.query(on: req.db)
            .filter(\.$subject == sponsorSubject)
            .first() else {
            throw Abort(.badRequest, reason: "You must have a registered agent to sponsor others")
        }

        // Set sponsor
        targetAgent.$sponsor.id = sponsorAgent.id

        try await targetAgent.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: targetAgent.id!,
            action: ActivityAction.agentSponsored,
            details: ["sponsor_subject": sponsorSubject]
        )

        // Redirect back to profile page (for web form submissions)
        return req.redirect(to: "/\(targetAgent.subject)")
    }
}
