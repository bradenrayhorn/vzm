import Foundation

final class GradleDistributionApprovalEngine: PatternApprovalEngine {
    override var name: String { "GradleDistribution" }

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(
            pattern: #"^services\.gradle\.org/distributions/gradle-[0-9]{1,2}(?:\.[0-9]{1,2}){1,2}-(?:bin|all)\.zip$"#
        ),
        try! NSRegularExpression(
            pattern: #"^github\.com/gradle/gradle-distributions/releases/download/v[0-9]{1,2}(?:\.[0-9]{1,2}){1,2}/gradle-[0-9]{1,2}(?:\.[0-9]{1,2}){1,2}-(?:bin|all)\.zip$"#
        ),
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 8 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 60),
            RateLimitApprovalGate.new(windowSeconds: 60, maxRequests: 30),
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
