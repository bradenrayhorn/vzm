import Foundation

final class YarnPkgApprovalEngine: PatternApprovalEngine {
    override var name: String { "YarnPkg" }

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^yarnpkg\.com/latest-version$"#),
        try! NSRegularExpression(pattern: #"^classic\.yarnpkg\.com/latest-version$"#),
        try! NSRegularExpression(
            pattern: #"^registry\.yarnpkg\.com/(?:@[A-Za-z0-9._-]{1,128}(?:%2[fF]|/)[A-Za-z0-9._-]{1,128}|[A-Za-z0-9._-]{1,128})$"#
        ),
        try! NSRegularExpression(
            pattern: #"^registry\.yarnpkg\.com/(?:@[A-Za-z0-9._-]{1,128}/[A-Za-z0-9._-]{1,128}|[A-Za-z0-9._-]{1,128})/-/[A-Za-z0-9._-]{1,128}-[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.tgz$"#
        ),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 120, maxRequests: 2_000),
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
