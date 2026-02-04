import Fluent

struct CreateAgentPublicKey: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("agent_public_keys")
            .id()
            .field("agent_id", .uuid, .required, .references("agents", "id", onDelete: .cascade))
            .field("fingerprint", .string, .required)
            .field("key_type", .string, .required)
            .field("public_key", .string, .required)
            .field("key_format", .string, .required)
            .field("label", .string)
            .field("is_primary", .bool, .required)
            .field("is_revoked", .bool, .required)
            .field("revoked_at", .datetime)
            .field("expires_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "fingerprint")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("agent_public_keys").delete()
    }
}
