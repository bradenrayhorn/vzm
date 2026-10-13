import Foundation
import Observation

struct ProxyActivitySnapshot: Equatable, Sendable {
    var attemptsPerSecond: Double = 0
    var downloadMbps: Double = 0
    var uploadMbps: Double = 0
}

/// A bounded rolling window of published batches, with one-second resolution.
/// All timestamps must use the same clock (system uptime in production).
final class ProxyActivityMonitor: @unchecked Sendable {
    private struct Bucket {
        var tick: Int64 = -1
        var attempts: UInt64 = 0
        var downloadBytes: UInt64 = 0
        var uploadBytes: UInt64 = 0
    }

    static let windowSeconds: Double = 10
    private static let bucketCount = 10

    private let lock = NSLock()
    private var running = false
    private var buckets = Array(repeating: Bucket(), count: bucketCount)

    func start() {
        lock.lock()
        defer { lock.unlock() }
        buckets = Array(repeating: Bucket(), count: Self.bucketCount)
        running = true
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        running = false
        buckets = Array(repeating: Bucket(), count: Self.bucketCount)
    }

    /// Called once per publication, not once per traffic event.
    func record(
        attempts: UInt64 = 0,
        downloadBytes: UInt64 = 0,
        uploadBytes: UInt64 = 0,
        at time: TimeInterval
    ) {
        let tick = Int64(time.rounded(.down))
        let index = Int(tick % Int64(Self.bucketCount))
        guard index >= 0 else { return }

        lock.lock()
        defer { lock.unlock() }
        guard running else { return }
        // Concurrent callbacks can arrive out of order. Never replace a newer
        // bucket with an event that has already aged out of the window.
        guard buckets[index].tick <= tick else { return }
        if buckets[index].tick != tick {
            buckets[index] = Bucket(tick: tick)
        }
        buckets[index].attempts += attempts
        buckets[index].downloadBytes += downloadBytes
        buckets[index].uploadBytes += uploadBytes
    }

    func snapshot(at time: TimeInterval = ProcessInfo.processInfo.systemUptime) -> ProxyActivitySnapshot {
        let tick = Int64(time.rounded(.down))
        lock.lock()
        defer { lock.unlock() }
        guard running else { return ProxyActivitySnapshot() }

        var attempts: UInt64 = 0
        var downloadBytes: UInt64 = 0
        var uploadBytes: UInt64 = 0
        for bucket in buckets where bucket.tick >= 0 && bucket.tick <= tick
            && tick - bucket.tick < Int64(Self.bucketCount) {
            attempts += bucket.attempts
            downloadBytes += bucket.downloadBytes
            uploadBytes += bucket.uploadBytes
        }
        // Use the full window even at startup: pre-start time counts as idle.
        let bytesToMbps = 8 / Self.windowSeconds / 1_000_000
        return ProxyActivitySnapshot(
            attemptsPerSecond: Double(attempts) / Self.windowSeconds,
            downloadMbps: Double(downloadBytes) * bytesToMbps,
            uploadMbps: Double(uploadBytes) * bytesToMbps
        )
    }
}

@Observable
@MainActor
final class ProxyActivityCoordinator {
    static let shared = ProxyActivityCoordinator()

    private(set) var vmName: String?
    private(set) var snapshot: ProxyActivitySnapshot?
    private var refreshTask: Task<Void, Never>?

    func attach(monitor: ProxyActivityMonitor, vmName: String) {
        detach()
        self.vmName = vmName
        snapshot = monitor.snapshot()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(1))
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                self?.snapshot = monitor.snapshot()
            }
        }
    }

    func detach() {
        refreshTask?.cancel()
        refreshTask = nil
        vmName = nil
        snapshot = nil
    }
}
