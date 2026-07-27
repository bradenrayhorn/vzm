import Foundation

enum TemporaryApprovalDuration: CaseIterable, Identifiable {
    case oneMinute
    case fiveMinutes
    case tenMinutes
    case thirtyMinutes
    case oneHour

    var id: Self { self }

    var seconds: TimeInterval {
        switch self {
        case .oneMinute: 60
        case .fiveMinutes: 5 * 60
        case .tenMinutes: 10 * 60
        case .thirtyMinutes: 30 * 60
        case .oneHour: 60 * 60
        }
    }

    var label: String {
        switch self {
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .tenMinutes: "10 minutes"
        case .thirtyMinutes: "30 minutes"
        case .oneHour: "1 hour"
        }
    }
}

final class ManualTemporaryApprovalEngine: ApprovalEngine {
    static let shared = ManualTemporaryApprovalEngine()

    let name = "ApproveEverythingTemporarily"

    private let lock = NSLock()
    private var deadline: Date?

    private init() {}

    func activate(for duration: TemporaryApprovalDuration) {
        lock.lock()
        deadline = Date().addingTimeInterval(duration.seconds)
        lock.unlock()
    }

    func deactivate() {
        lock.lock()
        deadline = nil
        lock.unlock()
    }

    func currentDeadline() -> Date? {
        lock.lock()
        defer { lock.unlock() }
        return deadline
    }

    func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        lock.lock()
        defer { lock.unlock() }

        guard let deadline else {
            return .unknown
        }

        guard request.secrets.isEmpty else {
            return .unknown
        }

        guard request.type != "WEBSOCKET" else {
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
