import Foundation

enum ApprovalMode: Equatable, Sendable {
    case strict
    case auto
    case approveEverything(until: Date)
}

/// Runtime-only policy shared by the menu and approval service.
/// Expiration is checked when reading, not just by the UI's timer.
final class ApprovalModeState: @unchecked Sendable {
    static let shared = ApprovalModeState()

    private let lock = NSLock()
    private var mode: ApprovalMode = .auto
    private var allowSecrets = false

    func select(_ mode: ApprovalMode) {
        lock.lock()
        defer { lock.unlock() }
        self.mode = mode
        allowSecrets = false
    }

    func setAllowSecrets(_ enabled: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if case let .approveEverything(deadline) = mode, deadline > Date() {
            allowSecrets = enabled
        } else {
            allowSecrets = false
        }
    }

    func current(now: Date = Date()) -> ApprovalMode {
        policy(now: now).mode
    }

    func policy(now: Date = Date()) -> (mode: ApprovalMode, allowSecrets: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if case let .approveEverything(deadline) = mode, now >= deadline {
            mode = .auto
            allowSecrets = false
        }
        return (mode, allowSecrets)
    }
}
