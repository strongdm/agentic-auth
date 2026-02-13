import Vapor
import Foundation

private let csrfSessionKey = "csrf_token"

/// CSRF helpers for session-authenticated web forms.
extension Request {
    /// Returns the current CSRF token or creates a new one for this session.
    func csrfToken() -> String {
        if let existing = session.data[csrfSessionKey] {
            return existing
        }

        var generator = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<bytes.count {
            bytes[i] = UInt8.random(in: 0...255, using: &generator)
        }
        let token = Data(bytes).base64URLEncodedString()
        session.data[csrfSessionKey] = token
        return token
    }

    /// Validates a submitted CSRF token against the session token.
    func validateCSRFToken(_ providedToken: String?) throws {
        guard let expected = session.data[csrfSessionKey],
              let provided = providedToken?.trimmingCharacters(in: .whitespacesAndNewlines),
              !provided.isEmpty,
              provided == expected else {
            throw Abort(.forbidden, reason: "Invalid CSRF token")
        }
    }
}

/// Fixed-window in-memory rate limiter for API endpoints.
actor FixedWindowRateLimiter {
    struct State {
        var count: Int
        var windowStart: Date
    }

    private var buckets: [String: State] = [:]
    private let limit: Int
    private let windowSeconds: TimeInterval

    init(limit: Int, windowSeconds: TimeInterval) {
        self.limit = limit
        self.windowSeconds = windowSeconds
    }

    func check(key: String, now: Date = Date()) -> (allowed: Bool, retryAfter: Int) {
        if buckets.count > 10_000 {
            let cutoff = now.addingTimeInterval(-windowSeconds)
            buckets = buckets.filter { $0.value.windowStart >= cutoff }
        }

        if var state = buckets[key] {
            if now.timeIntervalSince(state.windowStart) >= windowSeconds {
                state = State(count: 1, windowStart: now)
                buckets[key] = state
                return (true, Int(windowSeconds))
            }

            if state.count >= limit {
                let elapsed = now.timeIntervalSince(state.windowStart)
                let retry = max(1, Int(ceil(windowSeconds - elapsed)))
                return (false, retry)
            }

            state.count += 1
            buckets[key] = state
            let elapsed = now.timeIntervalSince(state.windowStart)
            let retry = max(1, Int(ceil(windowSeconds - elapsed)))
            return (true, retry)
        }

        buckets[key] = State(count: 1, windowStart: now)
        return (true, Int(windowSeconds))
    }
}

struct APIRateLimitMiddleware: AsyncMiddleware {
    private static let limiter = FixedWindowRateLimiter(limit: 100, windowSeconds: 60)
    private static let limitHeaderValue = "100"

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let ip = request.clientIPForRateLimit
        let check = await Self.limiter.check(key: ip)

        guard check.allowed else {
            let response = Response(status: .tooManyRequests)
            response.headers.contentType = .json
            response.headers.replaceOrAdd(name: "Retry-After", value: "\(check.retryAfter)")
            response.headers.replaceOrAdd(name: "X-RateLimit-Limit", value: Self.limitHeaderValue)
            response.headers.replaceOrAdd(name: "X-RateLimit-Remaining", value: "0")
            response.body = .init(string: "{\"error\":\"Rate limit exceeded\"}")
            return response
        }

        let response = try await next.respond(to: request)
        response.headers.replaceOrAdd(name: "X-RateLimit-Limit", value: Self.limitHeaderValue)
        return response
    }
}

private extension Request {
    var clientIPForRateLimit: String {
        if let forwarded = headers.first(name: .xForwardedFor)?
            .split(separator: ",")
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !forwarded.isEmpty {
            return forwarded
        }
        return remoteAddress?.ipAddress ?? "unknown"
    }
}
