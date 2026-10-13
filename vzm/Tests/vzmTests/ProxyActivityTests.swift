import NIOCore
import NIOEmbedded
import XCTest
@testable import vzm

final class ProxyActivityTests: XCTestCase {
    func testRollingWindowAndIdleDecay() {
        let monitor = ProxyActivityMonitor()
        monitor.start()
        monitor.record(attempts: 120, downloadBytes: 10_000_000, at: 100)
        monitor.record(uploadBytes: 625_000, at: 105)

        XCTAssertEqual(monitor.snapshot(at: 105), ProxyActivitySnapshot(
            attemptsPerSecond: 12, downloadMbps: 8, uploadMbps: 0.5
        ))
        XCTAssertEqual(monitor.snapshot(at: 109.9).attemptsPerSecond, 12)
        XCTAssertEqual(monitor.snapshot(at: 110), ProxyActivitySnapshot(uploadMbps: 0.5))
        XCTAssertEqual(monitor.snapshot(at: 115), ProxyActivitySnapshot())
    }

    func testBucketsWrapWithoutRetainingOldTraffic() {
        let monitor = ProxyActivityMonitor()
        monitor.start()
        monitor.record(attempts: 1, at: 100)
        monitor.record(attempts: 1, at: 110)
        monitor.record(attempts: 1, at: 100) // Delayed batch must not overwrite newer data.
        XCTAssertEqual(monitor.snapshot(at: 110).attemptsPerSecond, 0.1)
        monitor.record(downloadBytes: 1_000_000, at: 1000)
        XCTAssertEqual(monitor.snapshot(at: 1000), ProxyActivitySnapshot(downloadMbps: 0.8))
        XCTAssertEqual(monitor.snapshot(at: 2000), ProxyActivitySnapshot())
    }

    func testStoppedAndRestartedMonitor() {
        let monitor = ProxyActivityMonitor()
        monitor.record(attempts: 1, at: 100)
        XCTAssertEqual(monitor.snapshot(at: 100), ProxyActivitySnapshot())
        monitor.start()
        monitor.record(attempts: 1, at: 100)
        monitor.stop()
        monitor.record(uploadBytes: 1_000_000, at: 101)
        XCTAssertEqual(monitor.snapshot(at: 101), ProxyActivitySnapshot())
        monitor.start()
        XCTAssertEqual(monitor.snapshot(at: 101), ProxyActivitySnapshot())
        monitor.record(attempts: 1, at: 101)
        XCTAssertEqual(monitor.snapshot(at: 101).attemptsPerSecond, 0.1)
    }

    func testConcurrentBatchPublication() {
        let monitor = ProxyActivityMonitor()
        monitor.start()
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in
            monitor.record(attempts: 1, uploadBytes: 1000, at: 100)
        }
        XCTAssertEqual(monitor.snapshot(at: 100), ProxyActivitySnapshot(
            attemptsPerSecond: 100, uploadMbps: 0.8
        ))
    }

    func testForwardingCountsEachDirectionOnce() throws {
        let loop = EmbeddedEventLoop()
        let clock = PublicationClock(loop: loop)
        let monitor = ProxyActivityMonitor()
        let recorder = ProxyActivityRecorder(eventLoop: loop, monitor: monitor, clock: { clock.read() })
        recorder.start()
        defer { recorder.stop() }
        let vm = EmbeddedChannel(loop: loop)
        let proxy = EmbeddedChannel(loop: loop)
        try vm.pipeline.addHandler(ForwardingHandler(peer: proxy, recordBytes: {
            recorder.recordUpload(bytes: $0)
        })).wait()
        try proxy.pipeline.addHandler(ForwardingHandler(peer: vm, recordBytes: {
            recorder.recordDownload(bytes: $0)
        })).wait()

        var upload = vm.allocator.buffer(capacity: 3)
        upload.writeBytes([1, 2, 3])
        _ = try vm.writeInbound(upload)
        XCTAssertEqual(try proxy.readOutbound(as: ByteBuffer.self), upload)
        var download = proxy.allocator.buffer(capacity: 5)
        download.writeBytes([4, 5, 6, 7, 8])
        _ = try proxy.writeInbound(download)
        XCTAssertEqual(try vm.readOutbound(as: ByteBuffer.self), download)
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
        XCTAssertEqual(clock.reads, 0)
        // Closing channels before publication must not discard their traffic.
        // finish() drains the shared loop's timers too, so close the channels directly.
        try vm.close().wait()
        loop.run() // Complete the deferred close callbacks without draining future timers.
        try vm.closeFuture.wait()
        try proxy.closeFuture.wait()
        loop.advanceTime(by: .seconds(1))
        let snapshot = monitor.snapshot(at: clock.time)
        XCTAssertEqual(snapshot.uploadMbps, 3 * 8 / 10 / 1_000_000.0, accuracy: 1e-12)
        XCTAssertEqual(snapshot.downloadMbps, 5 * 8 / 10 / 1_000_000.0, accuracy: 1e-12)
        XCTAssertEqual(snapshot.attemptsPerSecond, 0)
        XCTAssertEqual(clock.reads, 1)
        _ = try vm.finish(acceptAlreadyClosed: true)
        _ = try proxy.finish(acceptAlreadyClosed: true)
    }

    func testRecorderBatchesWithoutPerEventClockReads() {
        let loop = EmbeddedEventLoop()
        let clock = PublicationClock(loop: loop)
        let monitor = ProxyActivityMonitor()
        let recorder = ProxyActivityRecorder(eventLoop: loop, monitor: monitor, clock: { clock.read() })
        recorder.start()
        defer { recorder.stop() }
        for _ in 0..<1000 {
            recorder.recordAttempt()
            recorder.recordUpload(bytes: 1000)
            recorder.recordDownload(bytes: 2000)
        }
        XCTAssertEqual(clock.reads, 0)
        loop.advanceTime(by: .milliseconds(999))
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
        loop.advanceTime(by: .milliseconds(1))
        let expected = ProxyActivitySnapshot(attemptsPerSecond: 100, downloadMbps: 1.6, uploadMbps: 0.8)
        XCTAssertEqual(monitor.snapshot(at: clock.time), expected)
        XCTAssertEqual(clock.reads, 1)

        loop.advanceTime(by: .seconds(1))
        XCTAssertEqual(monitor.snapshot(at: clock.time), expected)
        XCTAssertEqual(clock.reads, 1) // Idle ticks don't read the clock or repeat the batch.
        recorder.recordAttempt()
        loop.advanceTime(by: .seconds(1))
        XCTAssertEqual(monitor.snapshot(at: clock.time).attemptsPerSecond, 100.1)
        XCTAssertEqual(clock.reads, 2)
        loop.advanceTime(by: .seconds(10))
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
    }

    func testRecorderIdleStopAndRestart() {
        let loop = EmbeddedEventLoop()
        let clock = PublicationClock(loop: loop)
        let monitor = ProxyActivityMonitor()
        let recorder = ProxyActivityRecorder(eventLoop: loop, monitor: monitor, clock: { clock.read() })
        recorder.recordAttempt() // Not started: ignored.
        recorder.start()
        defer { recorder.stop() }
        recorder.recordUpload(bytes: 0)
        recorder.recordDownload(bytes: -1)
        loop.advanceTime(by: .seconds(10))
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
        XCTAssertEqual(clock.reads, 0)

        recorder.recordAttempt()
        loop.advanceTime(by: .seconds(1))
        XCTAssertEqual(monitor.snapshot(at: clock.time).attemptsPerSecond, 0.1)
        recorder.recordUpload(bytes: 1000) // Pending batch must be discarded on stop.
        recorder.stop()
        recorder.recordAttempt() // Stopped: ignored.
        loop.advanceTime(by: .seconds(5))
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
        XCTAssertEqual(clock.reads, 1) // No publications after stop.

        recorder.start()
        recorder.start() // Idempotent: no extra timer or reset.
        loop.advanceTime(by: .seconds(1))
        XCTAssertEqual(monitor.snapshot(at: clock.time), ProxyActivitySnapshot())
        recorder.recordDownload(bytes: 1)
        loop.advanceTime(by: .seconds(1))
        XCTAssertEqual(clock.reads, 2)
        let snapshot = monitor.snapshot(at: clock.time)
        XCTAssertEqual(snapshot.downloadMbps, 0.0000008, accuracy: 1e-12)
        XCTAssertEqual(snapshot.uploadMbps, 0)
        XCTAssertEqual(snapshot.attemptsPerSecond, 0)
    }

    func testActivityLevelsAndThresholdBoundaries() {
        XCTAssertEqual(ProxyActivityLevel(rate: 0, mediumThreshold: 1, hyperactiveThreshold: 10), .idle)
        // Use unrounded rates: even traffic that formats as 0.0 is active.
        XCTAssertEqual(ProxyActivityLevel(rate: 0.001, mediumThreshold: 1, hyperactiveThreshold: 10), .active)
        XCTAssertEqual(ProxyActivityLevel(rate: 0.999, mediumThreshold: 1, hyperactiveThreshold: 10), .active)
        XCTAssertEqual(ProxyActivityLevel(rate: 1, mediumThreshold: 1, hyperactiveThreshold: 10), .medium)
        XCTAssertEqual(ProxyActivityLevel(rate: 9.999, mediumThreshold: 1, hyperactiveThreshold: 10), .medium)
        XCTAssertEqual(ProxyActivityLevel(rate: 10, mediumThreshold: 1, hyperactiveThreshold: 10), .hyperactive)
        XCTAssertEqual(ProxyActivityLevel(rate: 1000, mediumThreshold: 1, hyperactiveThreshold: 10), .hyperactive)
        XCTAssertEqual(ProxyActivityLevel.idle.litSegments, 0)
        XCTAssertEqual(ProxyActivityLevel.active.litSegments, 1)
        XCTAssertEqual(ProxyActivityLevel.medium.litSegments, 2)
        XCTAssertEqual(ProxyActivityLevel.hyperactive.litSegments, 3)
    }

    func testCombinedActivityUsesHighestIndividualMetric() {
        XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: nil), .idle)
        XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot()), .idle)

        // Each metric independently activates each level (OR, not AND).
        for (rate, expected): (Double, ProxyActivityLevel) in [(0.001, .active), (1, .medium), (10, .hyperactive)] {
            XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
                attemptsPerSecond: rate
            )), expected)
            XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
                downloadMbps: rate * 10
            )), expected)
            XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
                uploadMbps: rate * 10
            )), expected)
        }
        // Rates are not summed to reach a higher level.
        XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
            attemptsPerSecond: 0.9, downloadMbps: 9, uploadMbps: 9
        )), .active)
        XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
            attemptsPerSecond: 9, downloadMbps: 99, uploadMbps: 99
        )), .medium)
        XCTAssertEqual(ProxyActivityMenuBarLabel.level(for: ProxyActivitySnapshot(
            attemptsPerSecond: 0.1, downloadMbps: 10, uploadMbps: 100
        )), .hyperactive)
    }

    @MainActor
    func testCoordinatorLifecycle() {
        let monitor = ProxyActivityMonitor()
        monitor.start()
        let coordinator = ProxyActivityCoordinator()
        coordinator.attach(monitor: monitor, vmName: "dev")
        XCTAssertEqual(coordinator.vmName, "dev")
        XCTAssertEqual(coordinator.snapshot, ProxyActivitySnapshot())
        coordinator.attach(monitor: monitor, vmName: "build")
        XCTAssertEqual(coordinator.vmName, "build")
        coordinator.detach()
        XCTAssertNil(coordinator.vmName)
        XCTAssertNil(coordinator.snapshot)
    }
}

/// Test clock state, accessed only on the embedded event loop's test thread.
private final class PublicationClock: @unchecked Sendable {
    let loop: EmbeddedEventLoop
    private(set) var reads = 0

    init(loop: EmbeddedEventLoop) {
        self.loop = loop
    }

    var time: TimeInterval {
        Double(loop.now.uptimeNanoseconds) / 1_000_000_000
    }

    func read() -> TimeInterval {
        loop.preconditionInEventLoop()
        reads += 1
        return time
    }
}
