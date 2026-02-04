import Vapor
import Fluent
import Foundation

struct KeyAPIController {
    /// List all public keys for an agent
    func index(req: Request) async throws -> [PublicKeyResponse] {
        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
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

        let keys = try await AgentPublicKey.query(on: req.db)
            .filter(\.$agent.$id == agentId)
            .filter(\.$isRevoked == false)
            .sort(\.$isPrimary, .descending)
            .sort(\.$createdAt, .descending)
            .all()

        return keys.map { PublicKeyResponse(from: $0) }
    }

    /// Add a new public key (owner only)
    func create(req: Request) async throws -> PublicKeyResponse {
        let agentInfo = try req.requireAgent()

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check ownership
        guard agent.subject == agentInfo.subject else {
            throw Abort(.forbidden, reason: "You can only add keys to your own agent")
        }

        // Validate and decode request
        try AddPublicKeyRequest.validate(content: req)
        let addRequest = try req.content.decode(AddPublicKeyRequest.self)

        // Calculate fingerprint
        let fingerprint = calculateFingerprint(publicKey: addRequest.publicKey)

        // Check if key already exists
        if let _ = try await AgentPublicKey.query(on: req.db)
            .filter(\.$fingerprint == fingerprint)
            .first() {
            throw Abort(.conflict, reason: "Key already registered")
        }

        // If this is marked as primary, unset other primary keys
        if addRequest.isPrimary == true {
            try await AgentPublicKey.query(on: req.db)
                .filter(\.$agent.$id == agentId)
                .filter(\.$isPrimary == true)
                .set(\.$isPrimary, to: false)
                .update()
        }

        // Create the key
        let key = AgentPublicKey(
            agentId: agentId,
            fingerprint: fingerprint,
            keyType: addRequest.keyType,
            publicKey: addRequest.publicKey,
            keyFormat: addRequest.keyFormat ?? .pem,
            label: addRequest.label,
            isPrimary: addRequest.isPrimary ?? false,
            expiresAt: addRequest.expiresAt
        )

        try await key.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agentId,
            action: ActivityAction.keyAdded,
            details: [
                "keyId": key.id!.uuidString,
                "fingerprint": fingerprint,
                "keyType": addRequest.keyType.rawValue
            ]
        )

        return PublicKeyResponse(from: key)
    }

    /// Revoke a public key (owner only)
    func revoke(req: Request) async throws -> HTTPStatus {
        let agentInfo = try req.requireAgent()

        guard let agentId = req.parameters.get("agentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid agent ID")
        }

        guard let keyId = req.parameters.get("keyId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid key ID")
        }

        guard let agent = try await Agent.find(agentId, on: req.db) else {
            throw Abort(.notFound, reason: "Agent not found")
        }

        // Check ownership
        guard agent.subject == agentInfo.subject else {
            throw Abort(.forbidden, reason: "You can only revoke your own keys")
        }

        guard let key = try await AgentPublicKey.query(on: req.db)
            .filter(\.$id == keyId)
            .filter(\.$agent.$id == agentId)
            .first() else {
            throw Abort(.notFound, reason: "Key not found")
        }

        // Revoke the key
        key.isRevoked = true
        key.revokedAt = Date()
        key.isPrimary = false

        try await key.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agentId,
            action: ActivityAction.keyRevoked,
            details: [
                "keyId": keyId.uuidString,
                "fingerprint": key.fingerprint
            ]
        )

        return .noContent
    }

    /// Calculate SHA-256 fingerprint of a public key
    private func calculateFingerprint(publicKey: String) -> String {
        // Strip PEM headers if present and normalize
        var keyData = publicKey
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN EC PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END EC PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")

        // Calculate SHA-256 hash
        let data = Data(keyData.utf8)
        var hash = [UInt8](repeating: 0, count: 32)

        #if canImport(CommonCrypto)
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }
        #endif

        // Format as colon-separated hex pairs
        return hash.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

#if canImport(CommonCrypto)
import CommonCrypto
#endif
