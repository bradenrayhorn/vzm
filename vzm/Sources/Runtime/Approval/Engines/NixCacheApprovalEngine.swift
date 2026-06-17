import Foundation

final class NixCacheApprovalEngine: BaseApprovalEngine {
    override var name: String { "NixCache" }

    private var approvedHeaders: [ProxyApprovalHeader]?

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^channels\.nixos\.org/flake-registry\.json$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/nix-cache-info$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/([0-9abcdfghijklmnpqrsvwxyz]{32})\.narinfo$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/nar/([0-9abcdfghijklmnpqrsvwxyz]{52})\.nar\.xz$"#),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 5 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            MaxRequestsApprovalGate.new(maxRequests: 16),
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
