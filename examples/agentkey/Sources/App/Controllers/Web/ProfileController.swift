import Vapor
import Fluent
import Leaf

struct ProfileController {
    /// Show public agent profile (Keybase-style URL: /@username)
    func show(req: Request) async throws -> View {
        guard let subject = req.parameters.get("subject") else {
            throw Abort(.badRequest, reason: "Missing subject")
        }

        guard let agent = try await Agent.query(on: req.db)
            .filter(\.$subject == subject)
            .with(\.$publicKeys)
            .with(\.$proofs)
            .with(\.$sponsor)
            .first() else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check if agent is public or if viewer is the owner
        if !agent.isPublic {
            if let sessionAgent = req.sessionAgent {
                guard sessionAgent.subject == agent.subject else {
                    throw Abort(.notFound, reason: "Agent not found")
                }
            } else {
                throw Abort(.notFound, reason: "Agent not found")
            }
        }

        // Get activity summary
        let recentActivity = try await ActivityLog.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .sort(\.$createdAt, .descending)
            .limit(5)
            .all()

        let isOwner = req.sessionAgent?.subject == agent.subject
        let canSponsor = req.sessionAgent != nil && !isOwner && agent.$sponsor.id == nil

        let activeKeys = agent.publicKeys.filter { !$0.isRevoked }
        let context = ProfileContext(
            title: "\(agent.displayName) (@\(agent.subject)) - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent,
            agent: AgentResponse(from: agent, includeKeys: true),
            publicKeys: activeKeys.map { PublicKeyResponse(from: $0) },
            hasPublicKeys: !activeKeys.isEmpty,
            proofs: agent.proofs.map { ProofResponse(from: $0) },
            hasProofs: !agent.proofs.isEmpty,
            recentActivity: recentActivity.map { ActivityLogResponse(from: $0) },
            hasRecentActivity: !recentActivity.isEmpty,
            isOwner: isOwner,
            canSponsor: canSponsor
        )

        return try await req.view.render("profile", context)
    }
}

// MARK: - View Contexts

struct ProfileContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let publicKeys: [PublicKeyResponse]
    let hasPublicKeys: Bool
    let proofs: [ProofResponse]
    let hasProofs: Bool
    let recentActivity: [ActivityLogResponse]
    let hasRecentActivity: Bool
    let isOwner: Bool
    let canSponsor: Bool
}
