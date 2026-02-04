import Vapor
import Leaf

struct StaticPagesController {
    /// About page
    func about(req: Request) async throws -> View {
        let context = StaticPageContext(
            title: "About AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent
        )
        return try await req.view.render("about", context)
    }

    /// Privacy policy page
    func privacy(req: Request) async throws -> View {
        let context = StaticPageContext(
            title: "Privacy Policy - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent
        )
        return try await req.view.render("privacy", context)
    }

    /// Terms of service page
    func terms(req: Request) async throws -> View {
        let context = StaticPageContext(
            title: "Terms of Service - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent
        )
        return try await req.view.render("terms", context)
    }

    /// Key management documentation
    func keysDoc(req: Request) async throws -> View {
        let context = StaticPageContext(
            title: "Key Management Guide - AgentKey",
            isAuthenticated: req.sessionAgent != nil,
            currentUser: req.sessionAgent
        )
        return try await req.view.render("docs/keys", context)
    }

    /// Agent registration skill file (serves markdown as plaintext)
    func skillFile(req: Request) async throws -> Response {
        let filePath = req.application.directory.publicDirectory + "SKILL.md"

        guard FileManager.default.fileExists(atPath: filePath) else {
            throw Abort(.notFound, reason: "Skill file not found")
        }

        let content = try String(contentsOfFile: filePath, encoding: .utf8)

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/markdown; charset=utf-8")
        headers.add(name: .contentDisposition, value: "inline; filename=\"SKILL.md\"")

        return Response(
            status: .ok,
            headers: headers,
            body: .init(string: content)
        )
    }
}

// MARK: - View Contexts

struct StaticPageContext: Content {
    let title: String
    let isAuthenticated: Bool
    let currentUser: SessionAgentInfo?
}
