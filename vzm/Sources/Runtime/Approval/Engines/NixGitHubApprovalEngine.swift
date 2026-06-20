import Foundation

final class NixGitHubApprovalEngine: BaseApprovalEngine {
    override var name: String { "NixGitHub" }

    private var approvedHeaders: [ProxyApprovalHeader]?

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/archive/[0-9a-f]{40}\.tar\.gz$"#),
        try! NSRegularExpression(pattern: #"^codeload\.github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/tar\.gz/[0-9a-f]{40}$"#),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 2 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            MaxRequestsApprovalGate.new(maxRequests: 256),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST" else {
            return .unknown
        }
        guard request.secrets.isEmpty else {
            return .unknown
        }
        guard request.body == nil else {
            return .unknown
        }
        guard request.method == "GET" else {
            return .unknown
        }
        guard urlMatches(request.url) else {
            return .unknown
        }

        if let approvedHeaders, request.headers == approvedHeaders, self.checkGates() {
            return .approved
        }

        return .canBeEngineApproved
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = request.headers
        super.onEngineApproved(request)
    }

    private func urlMatches(_ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)

        let range = NSRange(trimmed.startIndex..<trimmed.endIndex, in: trimmed)
        return Self.urlRegexes.contains { regex in
            regex.firstMatch(in: trimmed, range: range) != nil
        }
    }
}
