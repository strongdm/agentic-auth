import Fluent

struct CreateAgentProof: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("agent_proofs")
            .id()
            .field("agent_id", .uuid, .required, .references("agents", "id", onDelete: .cascade))
            .field("proof_type", .string, .required)
            .field("claim", .string, .required)
            .field("proof_data", .string, .required)
            .field("status", .string, .required)
            .field("verified_at", .datetime)
            .field("created_at", .datetime)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("agent_proofs").delete()
    }
}
