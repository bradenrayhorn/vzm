import Foundation

final class YarnPkgApprovalEngine: BaseApprovalEngine {
    override var name: String { "YarnPkg" }

    private var approvedHeaders: Set<ProxyApprovalHeader>?

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
        guard urlMatches(regexes: Self.urlRegexes, request.url) else {
            return .unknown
        }

        if let approvedHeaders, Set(request.headers) == approvedHeaders, checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = Set(request.headers)
        super.onEngineApproved(request)
    }
}
