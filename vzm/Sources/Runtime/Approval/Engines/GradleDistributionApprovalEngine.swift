import Foundation

final class GradleDistributionApprovalEngine: BaseApprovalEngine {
    override var name: String { "GradleDistribution" }

    private var approvedHeaders: Set<ProxyApprovalHeader>?

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

        if let approvedHeaders, approvedHeaders.isSuperset(of: Set(request.headers)), checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        super.onEngineApproved(request)
    }
}
