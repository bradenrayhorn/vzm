import Foundation

final class IdleTimeoutApprovalGate: ApprovalGate {
    static func new(idleTimeoutSeconds: TimeInterval) -> ApprovalGateBuilder {
        { IdleTimeoutApprovalGate(idleTimeoutSeconds: idleTimeoutSeconds) }
    }

    private let idleTimeoutSeconds: TimeInterval
    private var lastSeen: Date

    init(idleTimeoutSeconds: TimeInterval) {
        self.idleTimeoutSeconds = idleTimeoutSeconds
        self.lastSeen = Date()
    }

    func canContinue() -> Bool {
        let now = Date()
        let isOpen = now.timeIntervalSince(lastSeen) <= idleTimeoutSeconds
        if isOpen {
            lastSeen = now
        }
        return isOpen
    }
}
