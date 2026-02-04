import Vapor
import Fluent
import Leaf

struct DashboardController {
    /// Dashboard home
    func index(req: Request) async throws -> View {
        let sessionAgent = try req.requireSessionAgent()

        // Get or create agent record
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        // Get key count
        let keyCount = try await AgentPublicKey.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .filter(\.$isRevoked == false)
            .count()

        // Get proof count
        let proofCount = try await AgentProof.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .count()

        // Get recent activity
        let recentActivity = try await ActivityLog.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .sort(\.$createdAt, .descending)
            .limit(10)
            .all()

        let context = DashboardIndexContext(
            title: "Dashboard - AgentKey",
            isAuthenticated: true,
            currentUser: sessionAgent,
            agent: AgentResponse(from: agent),
            stats: DashboardStats(
                keyCount: keyCount,
                proofCount: proofCount,
                verificationStatus: agent.verificationStatus
            ),
            recentActivity: recentActivity.map { ActivityLogResponse(from: $0) },
            hasRecentActivity: !recentActivity.isEmpty
        )

        return try await req.view.render("dashboard/index", context)
    }

    /// Profile management page
    func profile(req: Request) async throws -> View {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        let context = DashboardProfileContext(
            title: "Edit Profile - AgentKey",
            isAuthenticated: true,
            currentUser: sessionAgent,
            agent: AgentResponse(from: agent),
            agentTypes: AgentType.allCases.map { $0.rawValue }
        )

        return try await req.view.render("dashboard/profile", context)
    }

    /// Update profile
    func updateProfile(req: Request) async throws -> Response {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        struct ProfileForm: Content {
            var displayName: String
            var description: String?
            var agentType: String
            var homepageUrl: String?
            var avatarUrl: String?
            var isPublic: String?
        }

        let form = try req.content.decode(ProfileForm.self)

        agent.displayName = form.displayName
        agent.description = form.description?.isEmpty == true ? nil : form.description
        // Humans cannot change their agent type
        if agent.agentType != .human {
            agent.agentType = AgentType(rawValue: form.agentType) ?? .assistant
        }
        agent.homepageUrl = form.homepageUrl?.isEmpty == true ? nil : form.homepageUrl
        agent.avatarUrl = form.avatarUrl?.isEmpty == true ? nil : form.avatarUrl
        agent.isPublic = form.isPublic == "on"

        try await agent.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.profileUpdated
        )

        return req.redirect(to: "/dashboard/profile?success=1")
    }

    /// Keys management page
    func keys(req: Request) async throws -> View {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        let keys = try await AgentPublicKey.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .sort(\.$isRevoked)
            .sort(\.$isPrimary, .descending)
            .sort(\.$createdAt, .descending)
            .all()

        let context = DashboardKeysContext(
            title: "Manage Keys - AgentKey",
            isAuthenticated: true,
            currentUser: sessionAgent,
            agent: AgentResponse(from: agent),
            keys: keys.map { PublicKeyResponse(from: $0) },
            keyTypes: KeyType.allCases.map { $0.rawValue },
            hasKeys: !keys.isEmpty
        )

        return try await req.view.render("dashboard/keys", context)
    }

    /// Add a new key
    func addKey(req: Request) async throws -> Response {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        struct KeyForm: Content {
            var publicKey: String
            var keyType: String
            var label: String?
            var isPrimary: String?
        }

        let form = try req.content.decode(KeyForm.self)

        guard let keyType = KeyType(rawValue: form.keyType) else {
            throw Abort(.badRequest, reason: "Invalid key type")
        }

        // Calculate fingerprint
        let fingerprint = calculateFingerprint(publicKey: form.publicKey)

        // Check if key already exists
        if let _ = try await AgentPublicKey.query(on: req.db)
            .filter(\.$fingerprint == fingerprint)
            .first() {
            return req.redirect(to: "/dashboard/keys?error=key_exists")
        }

        let isPrimary = form.isPrimary == "on"

        // If this is primary, unset others
        if isPrimary {
            try await AgentPublicKey.query(on: req.db)
                .filter(\.$agent.$id == agent.id!)
                .filter(\.$isPrimary == true)
                .set(\.$isPrimary, to: false)
                .update()
        }

        let key = AgentPublicKey(
            agentId: agent.id!,
            fingerprint: fingerprint,
            keyType: keyType,
            publicKey: form.publicKey,
            keyFormat: .pem,
            label: form.label?.isEmpty == true ? nil : form.label,
            isPrimary: isPrimary
        )

        try await key.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.keyAdded,
            details: [
                "fingerprint": fingerprint,
                "keyType": keyType.rawValue
            ]
        )

        return req.redirect(to: "/dashboard/keys?success=1")
    }

    /// Revoke a key
    func revokeKey(req: Request) async throws -> Response {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        guard let keyId = req.parameters.get("keyId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid key ID")
        }

        guard let key = try await AgentPublicKey.query(on: req.db)
            .filter(\.$id == keyId)
            .filter(\.$agent.$id == agent.id!)
            .first() else {
            throw Abort(.notFound, reason: "Key not found")
        }

        key.isRevoked = true
        key.revokedAt = Date()
        key.isPrimary = false

        try await key.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.keyRevoked,
            details: ["fingerprint": key.fingerprint]
        )

        return req.redirect(to: "/dashboard/keys?revoked=1")
    }

    /// Proofs management page
    func proofs(req: Request) async throws -> View {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        let proofs = try await AgentProof.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .sort(\.$createdAt, .descending)
            .all()

        let context = DashboardProofsContext(
            title: "Identity Proofs - AgentKey",
            isAuthenticated: true,
            currentUser: sessionAgent,
            agent: AgentResponse(from: agent),
            proofs: proofs.map { ProofResponse(from: $0) },
            hasProofs: !proofs.isEmpty,
            proofTypes: ProofType.allCases.map { $0.rawValue }
        )

        return try await req.view.render("dashboard/proofs", context)
    }

    /// Add a new proof
    func addProof(req: Request) async throws -> Response {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        struct ProofForm: Content {
            var proofType: String
            var claim: String
            var proofData: String
        }

        let form = try req.content.decode(ProofForm.self)

        guard let proofType = ProofType(rawValue: form.proofType) else {
            throw Abort(.badRequest, reason: "Invalid proof type")
        }

        let proof = AgentProof(
            agentId: agent.id!,
            proofType: proofType,
            claim: form.claim,
            proofData: form.proofData
        )

        try await proof.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.proofAdded,
            details: [
                "proofType": proofType.rawValue,
                "claim": form.claim
            ]
        )

        // Automatically try to verify proofs
        switch proofType {
        case .dns:
            try await verifyDNSProof(proof: proof, agent: agent, req: req)
        case .github:
            try await verifyGitHubProof(proof: proof, agent: agent, req: req)
        }

        return req.redirect(to: "/dashboard/proofs?success=1")
    }

    /// Verify a pending proof
    func verifyProof(req: Request) async throws -> Response {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        guard let proofId = req.parameters.get("proofId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid proof ID")
        }

        guard let proof = try await AgentProof.query(on: req.db)
            .filter(\.$id == proofId)
            .filter(\.$agent.$id == agent.id!)
            .first() else {
            throw Abort(.notFound, reason: "Proof not found")
        }

        switch proof.proofType {
        case .dns:
            try await verifyDNSProof(proof: proof, agent: agent, req: req)
        case .github:
            try await verifyGitHubProof(proof: proof, agent: agent, req: req)
        }

        return req.redirect(to: "/dashboard/proofs")
    }

    /// Verify a DNS proof by checking TXT records
    private func verifyDNSProof(proof: AgentProof, agent: Agent, req: Request) async throws {
        let domain = proof.claim
        let expectedValue = "agentkey-verify=\(agent.subject)"
        let txtRecordName = "_agentkey.\(domain)"

        // Use dig command to lookup TXT record
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/dig")
        process.arguments = ["+short", "TXT", txtRecordName]

        let pipe = Pipe()
        process.standardOutput = pipe

        try process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""

        // Check if the TXT record contains our expected value
        let verified = output.contains(expectedValue)

        if verified {
            proof.status = .verified
            proof.verifiedAt = Date()

            try await proof.save(on: req.db)

            // Update agent verification status if they have at least one verified proof
            if agent.verificationStatus != .verified {
                agent.verificationStatus = .verified
                try await agent.save(on: req.db)
            }

            // Log success
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofVerified,
                details: ["domain": domain]
            )
        } else {
            proof.status = .failed

            try await proof.save(on: req.db)

            // Log failure
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: ["domain": domain, "expected": expectedValue]
            )
        }
    }

    /// Verify a GitHub gist proof by fetching the gist content
    private func verifyGitHubProof(proof: AgentProof, agent: Agent, req: Request) async throws {
        let gistUrl = proof.proofData.trimmingCharacters(in: .whitespacesAndNewlines)
        let claimedUsername = proof.claim.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let expectedContent = "agentkey-verify=\(agent.subject)"

        // Extract username from gist URL and validate it matches the claim
        // URL format: https://gist.github.com/username/gistid or https://gist.githubusercontent.com/username/gistid/raw
        guard let url = URL(string: gistUrl) else {
            proof.status = .failed
            try await proof.save(on: req.db)
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: ["gist": gistUrl, "reason": "Invalid URL"]
            )
            return
        }

        // Get path components: ["username", "gistid"] or ["username", "gistid", "raw"]
        let pathComponents = url.pathComponents.filter { $0 != "/" }
        guard pathComponents.count >= 2 else {
            proof.status = .failed
            try await proof.save(on: req.db)
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: ["gist": gistUrl, "reason": "Could not parse username from URL"]
            )
            return
        }

        let urlUsername = pathComponents[0].lowercased()

        // Validate the username in the URL matches the claim
        if urlUsername != claimedUsername {
            proof.status = .failed
            try await proof.save(on: req.db)
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: [
                    "gist": gistUrl,
                    "reason": "Username mismatch",
                    "claimed": claimedUsername,
                    "url_username": urlUsername
                ]
            )
            return
        }

        // Convert gist URL to raw URL if needed
        // https://gist.github.com/username/gistid -> https://gist.githubusercontent.com/username/gistid/raw
        var rawUrl = gistUrl
        if gistUrl.contains("gist.github.com") && !gistUrl.contains("githubusercontent") {
            rawUrl = gistUrl.replacingOccurrences(of: "gist.github.com", with: "gist.githubusercontent.com")
        }
        if !rawUrl.hasSuffix("/raw") {
            rawUrl = rawUrl + "/raw"
        }

        // Fetch the gist content
        let response = try await req.client.get(URI(string: rawUrl))

        guard response.status == .ok,
              let body = response.body,
              let content = body.getString(at: 0, length: body.readableBytes) else {
            proof.status = .failed
            try await proof.save(on: req.db)
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: ["gist": gistUrl, "raw_url": rawUrl, "reason": "Could not fetch gist", "status": "\(response.status)"]
            )
            return
        }

        // Check if the gist contains our verification string or just the subject
        // Accept either "agentkey-verify=<subject>" or just the subject appearing in the content
        let verified = content.contains(expectedContent) || content.contains(agent.subject)

        if verified {
            proof.status = .verified
            proof.verifiedAt = Date()
            try await proof.save(on: req.db)

            // Update agent verification status
            if agent.verificationStatus != .verified {
                agent.verificationStatus = .verified
                try await agent.save(on: req.db)
            }

            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofVerified,
                details: ["github_username": proof.claim, "gist": gistUrl]
            )
        } else {
            proof.status = .failed
            try await proof.save(on: req.db)
            try await req.logActivity(
                agentId: agent.id!,
                action: ActivityAction.proofFailed,
                details: [
                    "github_username": proof.claim,
                    "gist": gistUrl,
                    "expected": expectedContent,
                    "reason": "Verification string not found in gist content"
                ]
            )
        }
    }

    /// Activity log page
    func activity(req: Request) async throws -> View {
        let sessionAgent = try req.requireSessionAgent()
        let agent = try await getOrCreateAgent(for: sessionAgent, on: req)

        let page = (req.query[Int.self, at: "page"] ?? 1).clamped(to: 1...)
        let perPage = 50

        let total = try await ActivityLog.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .count()

        let totalPages = (total + perPage - 1) / perPage

        let logs = try await ActivityLog.query(on: req.db)
            .filter(\.$agent.$id == agent.id!)
            .sort(\.$createdAt, .descending)
            .offset((page - 1) * perPage)
            .limit(perPage)
            .all()

        let context = DashboardActivityContext(
            title: "Activity Log - AgentKey",
            isAuthenticated: true,
            currentUser: sessionAgent,
            agent: AgentResponse(from: agent),
            activity: logs.map { ActivityLogResponse(from: $0) },
            pagination: PaginationContext(
                currentPage: page,
                totalPages: totalPages,
                totalItems: total,
                hasNext: page < totalPages,
                hasPrevious: page > 1
            ),
            hasActivity: !logs.isEmpty
        )

        return try await req.view.render("dashboard/activity", context)
    }

    // MARK: - Helpers

    /// Get or create agent for the session user
    private func getOrCreateAgent(for sessionAgent: SessionAgentInfo, on req: Request) async throws -> Agent {
        if let agent = try await Agent.query(on: req.db)
            .filter(\.$subject == sessionAgent.subject)
            .first() {
            return agent
        }

        // Determine default agent type based on subject prefix
        let defaultAgentType: AgentType = sessionAgent.subject.hasPrefix("usr_") ? .human : .assistant

        // Create new agent
        let agent = Agent(
            subject: sessionAgent.subject,
            displayName: sessionAgent.displayName ?? sessionAgent.subject,
            agentType: defaultAgentType
        )

        try await agent.save(on: req.db)

        // Log activity
        try await req.logActivity(
            agentId: agent.id!,
            action: ActivityAction.agentCreated
        )

        return agent
    }

    /// Calculate SHA-256 fingerprint of a public key
    private func calculateFingerprint(publicKey: String) -> String {
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

        let data = Data(keyData.utf8)
        var hash = [UInt8](repeating: 0, count: 32)

        #if canImport(CommonCrypto)
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }
        #endif

        return hash.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

#if canImport(CommonCrypto)
import CommonCrypto
#endif

// MARK: - View Contexts

struct DashboardIndexContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let stats: DashboardStats
    let recentActivity: [ActivityLogResponse]
    let hasRecentActivity: Bool
}

struct DashboardStats: Content {
    let keyCount: Int
    let proofCount: Int
    let verificationStatus: VerificationStatus
}

struct DashboardProfileContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let agentTypes: [String]
}

struct DashboardKeysContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let keys: [PublicKeyResponse]
    let keyTypes: [String]
    let hasKeys: Bool
}

struct DashboardProofsContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let proofs: [ProofResponse]
    let hasProofs: Bool
    let proofTypes: [String]
}

struct DashboardActivityContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
    let agent: AgentResponse
    let activity: [ActivityLogResponse]
    let pagination: PaginationContext
    let hasActivity: Bool
}
