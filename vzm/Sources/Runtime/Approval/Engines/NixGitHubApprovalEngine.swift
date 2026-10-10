import Foundation

final class NixGitHubApprovalEngine: PatternApprovalEngine {
    override var name: String { "NixGitHub" }

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/archive/[0-9a-f]{40}\.tar\.gz$"#),
        try! NSRegularExpression(pattern: #"^codeload\.github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/tar\.gz/[0-9a-f]{40}$"#),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 2 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 60, maxRequests: 60),
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
