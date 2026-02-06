import Vapor
import Fluent

/// Activity log model for tracking agent actions
final class ActivityLog: Model, Content, @unchecked Sendable {
    static let schema = "activity_logs"

    @ID(key: .id)
    var id: UUID?

    /// Reference to the agent
    @Parent(key: "agent_id")
    var agent: Agent

    /// Action performed (key_added, key_revoked, profile_updated, etc.)
    @Field(key: "action")
    var action: String

    /// Additional context as JSON
    @OptionalField(key: "details")
    var details: [String: String]?

    /// IP address of the request
    @OptionalField(key: "ip_address")
    var ipAddress: String?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {}

    init(
        id: UUID? = nil,
        agentId: UUID,
        action: String,
        details: [String: String]? = nil,
        ipAddress: String? = nil
    ) {
        self.id = id
        self.$agent.id = agentId
        self.action = action
        self.details = details
        self.ipAddress = ipAddress
    }
}

/// Activity log response DTO
struct ActivityLogResponse: Content {
    let id: UUID
    let action: String
    let details: [String: String]?
    let ipAddress: String?
    let createdAt: Date?

    init(from log: ActivityLog) {
        self.id = log.id!
        self.action = log.action
        self.details = log.details
        self.ipAddress = log.ipAddress
        self.createdAt = log.createdAt
    }
}

/// Common activity actions
enum ActivityAction {
    static let agentCreated = "agent_created"
    static let profileUpdated = "profile_updated"
    static let keyAdded = "key_added"
    static let keyRevoked = "key_revoked"
    static let proofAdded = "proof_added"
    static let proofVerified = "proof_verified"
    static let proofFailed = "proof_failed"
    static let proofRemoved = "proof_removed"
    static let verificationLost = "verification_lost"
    static let agentSponsored = "agent_sponsored"
    static let login = "login"
    static let logout = "logout"
}

/// Extension to log activities easily
extension Request {
    func logActivity(
        agentId: UUID,
        action: String,
        details: [String: String]? = nil
    ) async throws {
        let ipAddress = headers.first(name: .xForwardedFor) ?? remoteAddress?.ipAddress
        let log = ActivityLog(
            agentId: agentId,
            action: action,
            details: details,
            ipAddress: ipAddress
        )
        try await log.save(on: db)
    }
}
