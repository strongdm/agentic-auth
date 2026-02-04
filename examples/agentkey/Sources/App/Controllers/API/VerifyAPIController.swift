import Vapor
import Fluent
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

struct VerifyAPIController {
    /// Verify a signature against a registered agent's public key
    func verify(req: Request) async throws -> VerifyResponse {
        let verifyRequest = try req.content.decode(VerifyRequest.self)

        // Find the agent
        let agent: Agent?

        if let agentId = verifyRequest.agentId {
            agent = try await Agent.find(agentId, on: req.db)
        } else if let subject = verifyRequest.subject {
            agent = try await Agent.query(on: req.db)
                .filter(\.$subject == subject)
                .first()
        } else if let fingerprint = verifyRequest.keyFingerprint {
            // Find by key fingerprint
            guard let key = try await AgentPublicKey.query(on: req.db)
                .filter(\.$fingerprint == fingerprint)
                .filter(\.$isRevoked == false)
                .with(\.$agent)
                .first() else {
                return VerifyResponse(
                    valid: false,
                    error: "Key not found or revoked"
                )
            }
            agent = key.agent
        } else {
            throw Abort(.badRequest, reason: "Must provide agentId, subject, or keyFingerprint")
        }

        guard let agent = agent else {
            return VerifyResponse(
                valid: false,
                error: "Agent not found"
            )
        }

        // Get the key to verify with
        let key: AgentPublicKey?

        if let fingerprint = verifyRequest.keyFingerprint {
            key = try await AgentPublicKey.query(on: req.db)
                .filter(\.$agent.$id == agent.id!)
                .filter(\.$fingerprint == fingerprint)
                .filter(\.$isRevoked == false)
                .first()
        } else {
            // Use primary key or most recent non-revoked key
            key = try await AgentPublicKey.query(on: req.db)
                .filter(\.$agent.$id == agent.id!)
                .filter(\.$isRevoked == false)
                .sort(\.$isPrimary, .descending)
                .sort(\.$createdAt, .descending)
                .first()
        }

        guard let key = key else {
            return VerifyResponse(
                valid: false,
                error: "No valid key found for agent"
            )
        }

        // Check key expiration
        if let expiresAt = key.expiresAt, expiresAt < Date() {
            return VerifyResponse(
                valid: false,
                error: "Key has expired",
                keyFingerprint: key.fingerprint,
                agentSubject: agent.subject
            )
        }

        // Verify the signature
        let isValid = try verifySignature(
            message: verifyRequest.message,
            signature: verifyRequest.signature,
            publicKey: key.publicKey,
            keyType: key.keyType,
            keyFormat: key.keyFormat
        )

        return VerifyResponse(
            valid: isValid,
            error: isValid ? nil : "Signature verification failed",
            keyFingerprint: key.fingerprint,
            agentSubject: agent.subject,
            agentDisplayName: agent.displayName,
            verificationStatus: agent.verificationStatus
        )
    }

    /// Verify a signature using the appropriate algorithm
    private func verifySignature(
        message: String,
        signature: String,
        publicKey: String,
        keyType: KeyType,
        keyFormat: KeyFormat
    ) throws -> Bool {
        // Decode signature from base64
        guard let signatureData = Data(base64Encoded: signature) else {
            throw Abort(.badRequest, reason: "Invalid signature encoding (expected base64)")
        }

        let messageData = Data(message.utf8)

        // Note: In a production implementation, you would use CryptoKit or
        // a cryptography library to verify the signature based on key type.
        // This is a simplified implementation that demonstrates the structure.

        switch keyType {
        case .ed25519:
            return try verifyEd25519(message: messageData, signature: signatureData, publicKey: publicKey, format: keyFormat)
        case .rsa:
            return try verifyRSA(message: messageData, signature: signatureData, publicKey: publicKey, format: keyFormat)
        case .ecdsa:
            return try verifyECDSA(message: messageData, signature: signatureData, publicKey: publicKey, format: keyFormat)
        }
    }

    private func verifyEd25519(message: Data, signature: Data, publicKey: String, format: KeyFormat) throws -> Bool {
        #if canImport(CryptoKit)
        // Parse public key based on format
        let keyData: Data
        if format == .pem {
            keyData = try parsePEMPublicKey(publicKey)
        } else {
            // JWK format - would need to extract the key bytes
            throw Abort(.badRequest, reason: "JWK format not yet supported for Ed25519")
        }

        // Ed25519 public keys are 32 bytes, but PEM may include ASN.1 header
        // Strip the ASN.1 header if present (12 bytes for Ed25519)
        let rawKeyData: Data
        if keyData.count == 44 {
            // Has ASN.1 header, strip it
            rawKeyData = keyData.suffix(32)
        } else if keyData.count == 32 {
            rawKeyData = keyData
        } else {
            throw Abort(.badRequest, reason: "Invalid Ed25519 public key length: \(keyData.count) bytes")
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: rawKeyData)
        return key.isValidSignature(signature, for: message)
        #else
        // CryptoKit not available on this platform
        return false
        #endif
    }

    private func verifyRSA(message: Data, signature: Data, publicKey: String, format: KeyFormat) throws -> Bool {
        // RSA signature verification using Security framework
        // This is a placeholder - full implementation would use SecKeyVerifySignature
        #if os(macOS) || os(iOS)
        // Would use Security framework here
        return false
        #else
        return false
        #endif
    }

    private func verifyECDSA(message: Data, signature: Data, publicKey: String, format: KeyFormat) throws -> Bool {
        // ECDSA signature verification
        // This is a placeholder - full implementation would use CryptoKit or Security framework
        return false
    }

    private func parsePEMPublicKey(_ pem: String) throws -> Data {
        // Strip PEM headers and decode base64
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN ED25519 PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END ED25519 PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)

        guard let data = Data(base64Encoded: stripped) else {
            throw Abort(.badRequest, reason: "Invalid PEM encoding")
        }

        return data
    }
}

/// Request for signature verification
struct VerifyRequest: Content {
    /// The message that was signed
    let message: String

    /// The signature to verify (base64 encoded)
    let signature: String

    /// Agent ID to verify against (optional if subject or keyFingerprint provided)
    let agentId: UUID?

    /// Agent subject to verify against
    let subject: String?

    /// Specific key fingerprint to use
    let keyFingerprint: String?
}

/// Response from signature verification
struct VerifyResponse: Content {
    /// Whether the signature is valid
    let valid: Bool

    /// Error message if verification failed
    let error: String?

    /// Fingerprint of the key used for verification
    let keyFingerprint: String?

    /// Subject of the agent that owns the key
    let agentSubject: String?

    /// Display name of the agent
    let agentDisplayName: String?

    /// Verification status of the agent
    let verificationStatus: VerificationStatus?

    init(
        valid: Bool,
        error: String? = nil,
        keyFingerprint: String? = nil,
        agentSubject: String? = nil,
        agentDisplayName: String? = nil,
        verificationStatus: VerificationStatus? = nil
    ) {
        self.valid = valid
        self.error = error
        self.keyFingerprint = keyFingerprint
        self.agentSubject = agentSubject
        self.agentDisplayName = agentDisplayName
        self.verificationStatus = verificationStatus
    }
}
