import Foundation

/// Read-only request patterns with an explicitly approved header baseline.
/// Matching and Auto eligibility never consume gates or establish consent.
class PatternApprovalEngine: BaseApprovalEngine {
    private var approvedHeaders: Set<ProxyApprovalHeader>?

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        false
    }

    override func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        matches(request) && (request.headers.isEmpty || headersWereApproved(request))
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard matches(request) else { return .unknown }

        if headersWereApproved(request), checkGates() {
            return .approved
        }
        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        super.onEngineApproved(request)
    }

    private func headersWereApproved(_ request: ProxyApprovalRequest) -> Bool {
        approvedHeaders?.isSuperset(of: Set(request.headers)) == true
    }
}
