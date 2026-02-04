import Vapor
import Fluent

/// Verification status for agents
enum VerificationStatus: String, Codable {
    case unverified
    case pending
    case verified
}

/// Type of agent
enum AgentType: String, Codable, CaseIterable {
    case human
    case assistant
    case tool
    case orchestrator
    case service
    case bot
}

/// Agent model representing a registered AI agent
final class Agent: Model, Content, @unchecked Sendable {
    static let schema = "agents"

    @ID(key: .id)
    var id: UUID?

    /// StrongDM ID subject (unique identifier)
    @Field(key: "subject")
    var subject: String

    /// Human-readable display name
    @Field(key: "display_name")
    var displayName: String

    /// Agent description/bio
    @OptionalField(key: "description")
    var description: String?

    /// Type of agent
    @Field(key: "agent_type")
    var agentType: AgentType

    /// Homepage/documentation URL
    @OptionalField(key: "homepage_url")
    var homepageUrl: String?

    /// Avatar/profile image URL
    @OptionalField(key: "avatar_url")
    var avatarUrl: String?

    /// Whether the agent is publicly discoverable
    @Field(key: "is_public")
    var isPublic: Bool

    /// Verification status
    @Field(key: "verification_status")
    var verificationStatus: VerificationStatus

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    /// Sponsor (parent agent who vouches for this agent)
    @OptionalParent(key: "sponsor_id")
    var sponsor: Agent?

    /// Relationship to public keys
    @Children(for: \.$agent)
    var publicKeys: [AgentPublicKey]

    /// Relationship to proofs
    @Children(for: \.$agent)
    var proofs: [AgentProof]

    /// Relationship to activity logs
    @Children(for: \.$agent)
    var activityLogs: [ActivityLog]

    init() {}

    init(
        id: UUID? = nil,
        subject: String,
        displayName: String,
        description: String? = nil,
        agentType: AgentType = .assistant,
        homepageUrl: String? = nil,
        avatarUrl: String? = nil,
        isPublic: Bool = true,
        verificationStatus: VerificationStatus = .unverified
    ) {
        self.id = id
        self.subject = subject
        self.displayName = displayName
        self.description = description
        self.agentType = agentType
        self.homepageUrl = homepageUrl
        self.avatarUrl = avatarUrl
        self.isPublic = isPublic
        self.verificationStatus = verificationStatus
    }
}

/// Sponsor info for display
struct SponsorInfo: Content {
    let id: UUID
    let subject: String
    let displayName: String
    let avatarLetter: String
}

/// Public response DTO for Agent
struct AgentResponse: Content {
    let id: UUID
    let subject: String
    let displayName: String
    let description: String?
    let agentType: AgentType
    let homepageUrl: String?
    let avatarUrl: String?
    let avatarLetter: String
    let isPublic: Bool
    let verificationStatus: VerificationStatus
    let isVerified: Bool
    let isHuman: Bool
    let isSponsored: Bool
    let needsSponsor: Bool
    let sponsor: SponsorInfo?
    let createdAt: Date?
    let updatedAt: Date?
    let publicKeys: [PublicKeyResponse]?

    init(from agent: Agent, includeKeys: Bool = false) {
        self.id = agent.id!
        self.subject = agent.subject
        self.displayName = agent.displayName
        self.description = agent.description
        self.agentType = agent.agentType
        self.homepageUrl = agent.homepageUrl
        self.avatarUrl = agent.avatarUrl
        self.avatarLetter = String(agent.displayName.prefix(1)).uppercased()
        self.isPublic = agent.isPublic
        self.verificationStatus = agent.verificationStatus
        self.isVerified = agent.verificationStatus == .verified
        self.isHuman = agent.agentType == .human
        self.createdAt = agent.createdAt
        self.updatedAt = agent.updatedAt

        // Check if agent has a sponsor
        if let sponsorAgent = agent.$sponsor.value, let s = sponsorAgent {
            self.isSponsored = true
            self.sponsor = SponsorInfo(
                id: s.id!,
                subject: s.subject,
                displayName: s.displayName,
                avatarLetter: String(s.displayName.prefix(1)).uppercased()
            )
        } else {
            self.isSponsored = false
            self.sponsor = nil
        }

        // Humans don't need sponsors, only AI agents do
        self.needsSponsor = agent.agentType != .human && !self.isSponsored

        if includeKeys, let keys = try? agent.$publicKeys.value {
            self.publicKeys = keys.filter { !$0.isRevoked }.map { PublicKeyResponse(from: $0) }
        } else {
            self.publicKeys = nil
        }
    }
}

/// Request DTO for creating an agent
struct CreateAgentRequest: Content, Validatable {
    let displayName: String
    let description: String?
    let agentType: AgentType?
    let homepageUrl: String?
    let avatarUrl: String?
    let isPublic: Bool?

    static func validations(_ validations: inout Validations) {
        validations.add("displayName", as: String.self, is: .count(1...100))
        validations.add("description", as: String?.self, is: .nil || .count(...500), required: false)
        validations.add("homepageUrl", as: String?.self, is: .nil || .url, required: false)
        validations.add("avatarUrl", as: String?.self, is: .nil || .url, required: false)
    }
}

/// Request DTO for updating an agent
struct UpdateAgentRequest: Content, Validatable {
    let displayName: String?
    let description: String?
    let agentType: AgentType?
    let homepageUrl: String?
    let avatarUrl: String?
    let isPublic: Bool?

    static func validations(_ validations: inout Validations) {
        validations.add("displayName", as: String?.self, is: .nil || .count(1...100), required: false)
        validations.add("description", as: String?.self, is: .nil || .count(...500), required: false)
        validations.add("homepageUrl", as: String?.self, is: .nil || .url, required: false)
        validations.add("avatarUrl", as: String?.self, is: .nil || .url, required: false)
    }
}
