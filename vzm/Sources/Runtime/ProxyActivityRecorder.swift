import Foundation
import NIOCore

/// All mutable state is confined to `eventLoop`. Channels must use that same
/// loop, so recording needs no locks or clock reads on the per-chunk path.
final class ProxyActivityRecorder: @unchecked Sendable {
    let eventLoop: EventLoop

    private let monitor: ProxyActivityMonitor
    private let clock: @Sendable () -> TimeInterval
    private var publishTask: RepeatedTask?
    private var attempts: UInt64 = 0
    private var downloadBytes: UInt64 = 0
    private var uploadBytes: UInt64 = 0

    init(
        eventLoop: EventLoop,
        monitor: ProxyActivityMonitor,
        clock: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.eventLoop = eventLoop
        self.monitor = monitor
        self.clock = clock
    }

    deinit {
        publishTask?.cancel()
    }

    func start() {
        eventLoop.preconditionInEventLoop()
        guard publishTask == nil else { return }
        monitor.start()
        publishTask = eventLoop.scheduleRepeatedTask(initialDelay: .seconds(1), delay: .seconds(1)) { [weak self] task in
            guard let self else {
                task.cancel()
                return
            }
            self.publish()
        }
    }

    func stop() {
        eventLoop.preconditionInEventLoop()
        publishTask?.cancel()
        publishTask = nil
        attempts = 0
        downloadBytes = 0
        uploadBytes = 0
        monitor.stop()
    }

    func recordAttempt() {
        eventLoop.preconditionInEventLoop()
        guard publishTask != nil else { return }
        attempts += 1
    }

    func recordUpload(bytes: Int) {
        eventLoop.preconditionInEventLoop()
        guard publishTask != nil, bytes > 0 else { return }
        uploadBytes += UInt64(bytes)
    }

    func recordDownload(bytes: Int) {
        eventLoop.preconditionInEventLoop()
        guard publishTask != nil, bytes > 0 else { return }
        downloadBytes += UInt64(bytes)
    }

    private func publish() {
        eventLoop.preconditionInEventLoop()
        // No invented traffic during idle periods, and no work on the monitor
        // until there is an actual batch to publish.
        guard attempts != 0 || downloadBytes != 0 || uploadBytes != 0 else { return }
        monitor.record(attempts: attempts, downloadBytes: downloadBytes, uploadBytes: uploadBytes, at: clock())
        attempts = 0
        downloadBytes = 0
        uploadBytes = 0
    }
}
