import Foundation

enum DNSLookupError: Error {
    case timeout
}

/// Performs a bounded TXT lookup via `dig`.
func lookupTXTRecord(_ recordName: String, timeoutSeconds: TimeInterval = 3.0) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/dig")
    process.arguments = ["+time=2", "+tries=1", "+short", "TXT", recordName]

    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = Pipe()

    try process.run()

    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while process.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.05)
    }

    if process.isRunning {
        process.terminate()
        process.waitUntilExit()
        throw DNSLookupError.timeout
    }

    let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

/// Parses `dig +short TXT` output into normalized TXT values.
func parseTXTValues(from digOutput: String) -> [String] {
    digOutput
        .split(separator: "\n")
        .map { line in
            line
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\"", with: "")
        }
        .filter { !$0.isEmpty }
}
