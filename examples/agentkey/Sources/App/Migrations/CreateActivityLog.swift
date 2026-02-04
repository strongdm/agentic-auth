import Fluent

struct CreateActivityLog: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("activity_logs")
            .id()
            .field("agent_id", .uuid, .required, .references("agents", "id", onDelete: .cascade))
            .field("action", .string, .required)
            .field("details", .json)
            .field("ip_address", .string)
            .field("created_at", .datetime)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("activity_logs").delete()
    }
}
