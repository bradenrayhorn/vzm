import Foundation

final class TimeWindowApprovalGate: ApprovalGate {
    static func new(durationSeconds: TimeInterval) -> ApprovalGateBuilder {
        { TimeWindowApprovalGate(durationSeconds: durationSeconds) }
    }

    private let deadline: Date

    init(durationSeconds: TimeInterval) {
        self.deadline = Date().addingTimeInterval(durationSeconds)
    }

    func canContinue() -> Bool {
        Date() <= deadline
    }
}
