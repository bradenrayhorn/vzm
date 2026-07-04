import Foundation

final class RateLimitApprovalGate: ApprovalGate {
    static func new(windowSeconds: TimeInterval, maxRequests: Int) -> ApprovalGateBuilder {
        { RateLimitApprovalGate(windowSeconds: windowSeconds, maxRequests: maxRequests) }
    }

    private let windowSeconds: TimeInterval
    private let maxRequests: Int
    private var requestsSeenAt: [Date] = []

    init(windowSeconds: TimeInterval, maxRequests: Int) {
        self.windowSeconds = windowSeconds
        self.maxRequests = maxRequests
    }

    func canContinue() -> Bool {
        let now = Date()
        requestsSeenAt.removeAll { now.timeIntervalSince($0) > windowSeconds }

        guard requestsSeenAt.count < maxRequests else {
            return false
        }

        requestsSeenAt.append(now)
        return true
    }
}
