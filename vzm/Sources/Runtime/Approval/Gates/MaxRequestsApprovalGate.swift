import Foundation

final class MaxRequestsApprovalGate: ApprovalGate {
    static func new(maxRequests: Int) -> ApprovalGateBuilder {
        { MaxRequestsApprovalGate(maxRequests: maxRequests) }
    }

    private let maxRequests: Int
    private var requestsSeen: Int = 0

    init(maxRequests: Int) {
        self.maxRequests = maxRequests
    }

    func canContinue() -> Bool {
        guard requestsSeen < maxRequests else {
            return false
        }

        requestsSeen += 1
        return true
    }
}
