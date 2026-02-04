import Vapor
import Fluent

/// Proof type for identity verification
enum ProofType: String, Codable, CaseIterable {
    case dns
    case github
}

/// Status of a proof
enum ProofStatus: String, Codable {
    case pending
    case verified
    case failed
    case expired
}

/// Agent proof model for identity verification (like Keybase proofs)
final class AgentProof: Model, Content, @unchecked Sendable {
    static let schema = "agent_proofs"

    @ID(key: .id)
    var id: UUID?

    /// Reference to the owning agent
    @Parent(key: "agent_id")
    var agent: Agent

    /// Type of proof (dns, http, github, twitter)
    @Field(key: "proof_type")
    var proofType: ProofType

    /// The claim being made (domain/username)
    @Field(key: "claim")
    var claim: String

    /// Where to find the proof (URL, DNS record, etc.)
    @Field(key: "proof_data")
    var proofData: String

    /// Current status of the proof
    @Field(key: "status")
    var status: ProofStatus

    /// When the proof was last verified
    @OptionalField(key: "verified_at")
    var verifiedAt: Date?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {}

    init(
        id: UUID? = nil,
        agentId: UUID,
        proofType: ProofType,
        claim: String,
        proofData: String,
        status: ProofStatus = .pending
    ) {
        self.id = id
        self.$agent.id = agentId
        self.proofType = proofType
        self.claim = claim
        self.proofData = proofData
        self.status = status
    }
}

/// Public response DTO for proof
struct ProofResponse: Content {
    let id: UUID
    let proofType: ProofType
    let claim: String
    let proofData: String
    let status: ProofStatus
    let isPending: Bool
    let isVerified: Bool
    let isFailed: Bool
    let verifiedAt: Date?
    let createdAt: Date?

    init(from proof: AgentProof) {
        self.id = proof.id!
        self.proofType = proof.proofType
        self.claim = proof.claim
        self.proofData = proof.proofData
        self.status = proof.status
        self.isPending = proof.status == .pending
        self.isVerified = proof.status == .verified
        self.isFailed = proof.status == .failed
        self.verifiedAt = proof.verifiedAt
        self.createdAt = proof.createdAt
    }
}

/// Request DTO for adding a proof
struct AddProofRequest: Content, Validatable {
    let proofType: ProofType
    let claim: String
    let proofData: String

    static func validations(_ validations: inout Validations) {
        validations.add("claim", as: String.self, is: .count(1...200))
        validations.add("proofData", as: String.self, is: .count(1...500))
    }
}
