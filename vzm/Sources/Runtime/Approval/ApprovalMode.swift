import Foundation

enum ApprovalMode: Equatable, Sendable {
    case `default`
    case auto
    case approveEverything(until: Date)

    var label: String {
        switch self {
        case .default: "Default"
        case .auto: "Auto"
        case .approveEverything: "Approve Everything"
        }
    }
}

/// Runtime-only policy shared by the menu and approval service.
/// Expiration is checked when reading, not just by the UI's timer.
final class ApprovalModeState: @unchecked Sendable {
    static let shared = ApprovalModeState()

    private let lock = NSLock()
    private var mode: ApprovalMode = .default

    func select(_ mode: ApprovalMode) {
        lock.lock()
        defer { lock.unlock() }
        self.mode = mode
    }

    func current(now: Date = Date()) -> ApprovalMode {
        lock.lock()
        defer { lock.unlock() }
        if case let .approveEverything(deadline) = mode, now >= deadline {
            mode = .default
        }
        return mode
    }
}
