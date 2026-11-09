import Foundation

enum EngineActivityGroup: String, CaseIterable, Identifiable, Sendable {
    case packages, containers, nix, llm, datadog, intellij

    var id: Self { self }

    var emoji: String {
        switch self {
        case .packages: "📦"
        case .containers: "🐳"
        case .nix: "❄️"
        case .llm: "🤖"
        case .datadog: "🐶"
        case .intellij: "💡"
        }
    }

    var title: String {
        switch self {
        case .packages: "Packages"
        case .containers: "Containers"
        case .nix: "Nix"
        case .llm: "LLM"
        case .datadog: "Datadog"
        case .intellij: "IntelliJ"
        }
    }
}

struct EngineActivitySnapshot: Equatable, Sendable {
    var lastApprovals: [EngineActivityGroup: TimeInterval] = [:]

    static let holdDuration: TimeInterval = 1
    static let fadeDuration: TimeInterval = 5
    static let idleOpacity = 0.3

    func intensity(for group: EngineActivityGroup, at time: TimeInterval) -> Double {
        guard let last = lastApprovals[group] else { return 0 }
        let elapsed = max(0, time - last)
        return min(1, max(0, 1 - (elapsed - Self.holdDuration) / Self.fadeDuration))
    }

    func opacity(for group: EngineActivityGroup, at time: TimeInterval) -> Double {
        Self.idleOpacity + (1 - Self.idleOpacity) * intensity(for: group, at: time)
    }
}

/// Bounded to one monotonic timestamp per group. No request data or per-approval UI tasks.
final class EngineActivityStore: @unchecked Sendable {
    static let shared = EngineActivityStore()

    private let lock = NSLock()
    private var running = false
    private var state = EngineActivitySnapshot()

    func start() {
        lock.lock()
        defer { lock.unlock() }
        state = EngineActivitySnapshot()
        running = true
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        running = false
        state = EngineActivitySnapshot()
    }

    func record(_ group: EngineActivityGroup, at time: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        lock.lock()
        defer { lock.unlock() }
        guard running else { return }
        state.lastApprovals[group] = max(state.lastApprovals[group] ?? time, time)
    }

    func snapshot() -> EngineActivitySnapshot {
        lock.lock()
        defer { lock.unlock() }
        return state
    }
}
