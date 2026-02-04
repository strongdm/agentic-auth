import Vapor
import Fluent

/// Key type for signing keys
enum KeyType: String, Codable, CaseIterable {
    case ed25519
    case rsa
    case ecdsa
}

/// Key format
enum KeyFormat: String, Codable {
    case pem
    case jwk
}

/// Agent public key model for signature verification
final class AgentPublicKey: Model, Content, @unchecked Sendable {
    static let schema = "agent_public_keys"

    @ID(key: .id)
    var id: UUID?

    /// Reference to the owning agent
    @Parent(key: "agent_id")
    var agent: Agent

    /// SHA-256 fingerprint of the public key
    @Field(key: "fingerprint")
    var fingerprint: String

    /// Type of key (ed25519, rsa, ecdsa)
    @Field(key: "key_type")
    var keyType: KeyType

    /// The actual public key (PEM or JWK format)
    @Field(key: "public_key")
    var publicKey: String

    /// Format of the key
    @Field(key: "key_format")
    var keyFormat: KeyFormat

    /// User-provided label
    @OptionalField(key: "label")
    var label: String?

    /// Whether this is the primary signing key
    @Field(key: "is_primary")
    var isPrimary: Bool

    /// Whether the key has been revoked
    @Field(key: "is_revoked")
    var isRevoked: Bool

    /// When the key was revoked
    @OptionalField(key: "revoked_at")
    var revokedAt: Date?

    /// When the key expires
    @OptionalField(key: "expires_at")
    var expiresAt: Date?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {}

    init(
        id: UUID? = nil,
        agentId: UUID,
        fingerprint: String,
        keyType: KeyType,
        publicKey: String,
        keyFormat: KeyFormat = .pem,
        label: String? = nil,
        isPrimary: Bool = false,
        expiresAt: Date? = nil
    ) {
        self.id = id
        self.$agent.id = agentId
        self.fingerprint = fingerprint
        self.keyType = keyType
        self.publicKey = publicKey
        self.keyFormat = keyFormat
        self.label = label
        self.isPrimary = isPrimary
        self.isRevoked = false
        self.expiresAt = expiresAt
    }
}

/// Public response DTO for public key
struct PublicKeyResponse: Content {
    let id: UUID
    let fingerprint: String
    let keyType: KeyType
    let publicKey: String
    let keyFormat: KeyFormat
    let label: String?
    let isPrimary: Bool
    let isRevoked: Bool
    let revokedAt: Date?
    let expiresAt: Date?
    let createdAt: Date?

    init(from key: AgentPublicKey) {
        self.id = key.id!
        self.fingerprint = key.fingerprint
        self.keyType = key.keyType
        self.publicKey = key.publicKey
        self.keyFormat = key.keyFormat
        self.label = key.label
        self.isPrimary = key.isPrimary
        self.isRevoked = key.isRevoked
        self.revokedAt = key.revokedAt
        self.expiresAt = key.expiresAt
        self.createdAt = key.createdAt
    }
}

/// Request DTO for adding a public key
struct AddPublicKeyRequest: Content, Validatable {
    let publicKey: String
    let keyType: KeyType
    let keyFormat: KeyFormat?
    let label: String?
    let isPrimary: Bool?
    let expiresAt: Date?

    static func validations(_ validations: inout Validations) {
        validations.add("publicKey", as: String.self, is: !.empty)
        validations.add("label", as: String?.self, is: .nil || .count(1...100), required: false)
    }
}
