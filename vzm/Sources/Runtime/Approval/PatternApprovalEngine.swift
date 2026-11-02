import Foundation

/// Read-only request patterns with an explicitly approved header baseline.
/// Matching and evaluation never establish consent.
class PatternApprovalEngine: BaseApprovalEngine {
    private var approvedHeaders: Set<ProxyApprovalHeader> = []

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        false
    }

    /// Headers requiring explicit consent after engine-specific protocol filtering.
    func headersForApproval(_ request: ProxyApprovalRequest) -> [ProxyApprovalHeader] {
        request.headers
    }

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        guard matches(request) else { return .notApplicable }
        if approvedHeaders.isSuperset(of: headersForApproval(request)) {
            return .approved
        }
        return .needsConsent(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders.formUnion(headersForApproval(request))
    }
}
