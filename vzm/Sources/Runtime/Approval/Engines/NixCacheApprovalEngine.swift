import Foundation

final class NixCacheApprovalEngine: PatternApprovalEngine {
    override var name: String { "NixCache" }

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^channels\.nixos\.org/flake-registry\.json$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/nix-cache-info$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/([0-9abcdfghijklmnpqrsvwxyz]{32})\.narinfo$"#),
        try! NSRegularExpression(pattern: #"^cache\.nixos\.org/nar/([0-9abcdfghijklmnpqrsvwxyz]{52})\.nar\.(xz|zst)$"#),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 5 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 60),
        ])
    }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        request.type == "REQUEST"
            && request.secrets.isEmpty
            && request.body == nil
            && request.method == "GET"
            && urlMatches(regexes: Self.urlRegexes, request.url)
    }
}
