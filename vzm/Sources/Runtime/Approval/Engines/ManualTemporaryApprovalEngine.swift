import Foundation

final class ManualTemporaryApprovalEngine: ApprovalEngine {
    static let shared = ManualTemporaryApprovalEngine()

    let name = "ApproveEverythingFor5Min"

    private let lock = NSLock()
    private var deadline: Date?

    private init() {}

    func activateForFiveMinutes() {
        lock.lock()
        deadline = Date().addingTimeInterval(5 * 60)
        lock.unlock()
    }

    func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        lock.lock()
        defer { lock.unlock() }

        guard let deadline else {
            return .unknown
        }

        if Date() <= deadline {
            return .approved
        }

        self.deadline = nil
        return .unknown
    }

    func onEngineApproved(_ request: ProxyApprovalRequest) {}
}
