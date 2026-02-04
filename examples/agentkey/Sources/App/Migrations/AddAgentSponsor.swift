import Fluent

struct AddAgentSponsor: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("agents")
            .field("sponsor_id", .uuid, .references("agents", "id", onDelete: .setNull))
            .update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("agents")
            .deleteField("sponsor_id")
            .update()
    }
}
