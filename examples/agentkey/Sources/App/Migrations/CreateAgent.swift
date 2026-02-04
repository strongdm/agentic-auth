import Fluent

struct CreateAgent: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("agents")
            .id()
            .field("subject", .string, .required)
            .field("display_name", .string, .required)
            .field("description", .string)
            .field("agent_type", .string, .required)
            .field("homepage_url", .string)
            .field("avatar_url", .string)
            .field("is_public", .bool, .required)
            .field("verification_status", .string, .required)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "subject")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("agents").delete()
    }
}
