import NIOCore
import NIOEmbedded
import XCTest
@testable import vzm

private final class QueueObserver: DenyRule {
    let name = "Queue observer"
    private let lock = NSLock()
    private var callback: (ProxyApprovalRequest) -> Void = { _ in }
    var observed: (ProxyApprovalRequest) -> Void {
        get { lock.withLock { callback } }
        set { lock.withLock { callback = newValue } }
    }

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        observed(request)
        return false
    }
}

private actor ControlledPresenter {
    private(set) var presentations: [ApprovalPromptPresentation] = []
    private var continuation: CheckedContinuation<ApprovalCoordinatorResult, Never>?
    private var activeID: UUID?
    var onPresent: () -> Void = {}
    let cancellationResult: ApprovalCoordinatorResult

    init(cancellationResult: ApprovalCoordinatorResult = .deny) {
        self.cancellationResult = cancellationResult
    }

    func setOnPresent(_ callback: @escaping () -> Void) { onPresent = callback }

    func ask(_ request: ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult {
        let id = UUID()
        return await withTaskCancellationHandler {
            guard !Task.isCancelled else { return .deny }
            return await withCheckedContinuation {
                precondition(continuation == nil, "Prompts must not overlap")
                continuation = $0
                activeID = id
                presentations.append(request.presentation)
                onPresent()
            }
        } onCancel: {
            Task { await self.cancel(id: id) }
        }
    }

    private func cancel(id: UUID) {
        guard activeID == id else { return }
        resolve(cancellationResult)
    }

    func resolve(_ action: ApprovalCoordinatorResult) {
        let pending = continuation
        continuation = nil
        activeID = nil
        pending?.resume(returning: action)
    }
}

final class ApprovalQueueTests: XCTestCase {
    private var directory: URL!
    private var store: RecognizedElementStore!
    private var mode: ApprovalModeState!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = try RecognizedElementStore(directoryURL: directory)
        mode = ApprovalModeState()
        mode.select(.strict)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    private func request(_ path: String) -> ProxyApprovalRequest {
        ProxyApprovalRequest(id: UUID().uuidString, type: "REQUEST", domain: "example.com",
                             method: "GET", url: "example.com/\(path)", headers: [], secrets: [])
    }

    private func service(_ presenter: ControlledPresenter, observer: QueueObserver = QueueObserver(),
                         limit: Int = 64) throws -> ApprovalService {
        try ApprovalService(denyRules: [observer], engines: [], recognizedElementStore: store,
                            modeState: mode, maxPendingApprovals: limit,
                            promptUser: { await presenter.ask($0) })
    }

    private func enqueue(_ request: ProxyApprovalRequest, service: ApprovalService,
                         observer: QueueObserver) async -> Task<Bool, Never> {
        let evaluated = expectation(description: "Request evaluated: \(request.url)")
        observer.observed = { if $0.id == request.id { evaluated.fulfill() } }
        let task = Task { await service.askForApproval(request: request) }
        await fulfillment(of: [evaluated], timeout: 2)
        return task
    }

    func testDefaultLimitIncludesDisplayedPromptAndCancelledWaiterFreesCapacity() async throws {
        let presenter = ControlledPresenter()
        let observer = QueueObserver()
        let service = try service(presenter, observer: observer)
        let displayed = expectation(description: "First prompt displayed")
        await presenter.setOnPresent { displayed.fulfill() }
        let firstRequest = request("first")
        let first = Task { await service.askForApproval(request: firstRequest) }
        await fulfillment(of: [displayed], timeout: 2)

        var waiting: [Task<Bool, Never>] = []
        for index in 0..<63 {
            waiting.append(await enqueue(request("queued-\(index)"), service: service, observer: observer))
        }
        let overflow = await service.askForApproval(request: request("overflow"))
        XCTAssertFalse(overflow)
        waiting[0].cancel()
        let cancelled = await waiting.removeFirst().value
        XCTAssertFalse(cancelled)
        let replacement = await enqueue(request("replacement"), service: service, observer: observer)

        // Cancelling queued requests completes them without resolving the displayed prompt.
        for task in waiting { task.cancel() }
        for task in waiting {
            let result = await task.value
            XCTAssertFalse(result)
        }
        let presentations = await presenter.presentations
        XCTAssertEqual(presentations.count, 1)
        observer.observed = { _ in }
        let replacementShown = expectation(description: "Replacement admitted after cancellation")
        await presenter.setOnPresent { replacementShown.fulfill() }
        await presenter.resolve(.deny)
        let firstResult = await first.value
        XCTAssertFalse(firstResult)
        await fulfillment(of: [replacementShown], timeout: 2)
        await presenter.resolve(.approveOnce)
        let replacementResult = await replacement.value
        XCTAssertTrue(replacementResult)
    }

    func testCancellationPreservesFIFOAndReevaluatesQueuedRequests() async throws {
        let presenter = ControlledPresenter()
        let observer = QueueObserver()
        let service = try service(presenter, observer: observer, limit: 4)
        let firstShown = expectation(description: "First prompt displayed")
        await presenter.setOnPresent { firstShown.fulfill() }
        let firstRequest = request("first")
        let first = Task { await service.askForApproval(request: firstRequest) }
        await fulfillment(of: [firstShown], timeout: 2)
        let second = await enqueue(request("second"), service: service, observer: observer)
        let cancelled = await enqueue(request("cancelled"), service: service, observer: observer)
        let fourth = await enqueue(request("fourth"), service: service, observer: observer)
        observer.observed = { _ in }
        cancelled.cancel()
        let cancelledResult = await cancelled.value
        XCTAssertFalse(cancelledResult)

        let secondShown = expectation(description: "Second prompt displayed")
        await presenter.setOnPresent { secondShown.fulfill() }
        await presenter.resolve(.deny)
        await fulfillment(of: [secondShown], timeout: 2)
        // A later mode change must apply before the final queued request prompts.
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await presenter.resolve(.deny)
        let firstResult = await first.value
        let secondResult = await second.value
        let fourthResult = await fourth.value
        XCTAssertFalse(firstResult)
        XCTAssertFalse(secondResult)
        XCTAssertTrue(fourthResult)
        let presentations = await presenter.presentations
        XCTAssertEqual(presentations.count, 2)
        XCTAssertTrue(presentations[1].sections.contains { $0.text.contains("example.com/second") })
    }

    func testDisplayedCancellationCannotPersistConsentAndAdvancesQueue() async throws {
        // Deliberately return approval when cancelled to exercise the service's
        // post-prompt cancellation check, independently of the UI's deny result.
        let presenter = ControlledPresenter(cancellationResult: .approveOnce)
        let observer = QueueObserver()
        let service = try service(presenter, observer: observer)
        let firstShown = expectation(description: "First prompt displayed")
        await presenter.setOnPresent { firstShown.fulfill() }
        var r = request("cancelled")
        r.headers = [ProxyApprovalHeader(name: "User-Agent", value: "cancelled-agent")]
        let firstRequest = r
        let first = Task { await service.askForApproval(request: firstRequest) }
        await fulfillment(of: [firstShown], timeout: 2)
        let next = await enqueue(request("next"), service: service, observer: observer)
        observer.observed = { _ in }
        let nextShown = expectation(description: "Next prompt displayed")
        await presenter.setOnPresent { nextShown.fulfill() }
        first.cancel()
        let result = await first.value
        XCTAssertFalse(result)
        XCTAssertFalse(store.contains("example.com", type: .domain))
        XCTAssertFalse(store.contains("cancelled-agent", type: .userAgent))
        await fulfillment(of: [nextShown], timeout: 2)
        await presenter.resolve(.deny)
        let nextResult = await next.value
        XCTAssertFalse(nextResult)
    }

    func testCancellationRacingWithPromotionResolvesOnceAndReleasesTurn() async throws {
        let presenter = ControlledPresenter()
        let observer = QueueObserver()
        let service = try service(presenter, observer: observer, limit: 2)
        for iteration in 0..<25 {
            let shown = expectation(description: "Race prompt \(iteration)")
            await presenter.setOnPresent { shown.fulfill() }
            let firstRequest = request("first-\(iteration)")
            let first = Task { await service.askForApproval(request: firstRequest) }
            await fulfillment(of: [shown], timeout: 2)
            let queued = await enqueue(request("cancelled-\(iteration)"), service: service, observer: observer)
            observer.observed = { _ in }
            // The cancellation actor hop can race with finishApprovalTurn's
            // promotion. Either ordering must resolve the continuation once.
            queued.cancel()
            await presenter.resolve(.deny)
            let firstResult = await first.value
            let queuedResult = await queued.value
            XCTAssertFalse(firstResult)
            XCTAssertFalse(queuedResult)
        }
        let presentations = await presenter.presentations
        XCTAssertEqual(presentations.count, 25)
    }

    private func controlChannel(service: ApprovalService, completed: XCTestExpectation) async throws -> NIOAsyncTestingChannel {
        let channel = NIOAsyncTestingChannel()
        try await channel.eventLoop.submit {
            let recorder = ProxyActivityRecorder(eventLoop: channel.eventLoop, monitor: ProxyActivityMonitor())
            try channel.pipeline.syncOperations.addHandler(ApprovalControlHandler(activityRecorder: recorder, approve: {
                let result = await service.askForApproval(request: $0)
                completed.fulfill()
                return result
            }))
        }.get()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1234)).get()
        return channel
    }

    private func send(_ request: ProxyApprovalRequest, to channel: NIOAsyncTestingChannel) async throws {
        let data = try JSONEncoder().encode(request)
        // Exercise fragmented input as well as ignoring additional messages.
        _ = try await channel.writeInbound(ByteBuffer(bytes: data.prefix(10)))
        _ = try await channel.writeInbound(ByteBuffer(bytes: Array(data.dropFirst(10)) + [10] + Array(data) + [10]))
    }

    func testControlDisconnectCancelsQueuedAndDisplayedApprovals() async throws {
        let presenter = ControlledPresenter()
        let observer = QueueObserver()
        let service = try service(presenter, observer: observer, limit: 2)
        let firstDone = expectation(description: "Disconnected active caller completed")
        let first = try await controlChannel(service: service, completed: firstDone)
        let firstShown = expectation(description: "Socket prompt displayed")
        await presenter.setOnPresent { firstShown.fulfill() }
        try await send(request("first"), to: first)
        await fulfillment(of: [firstShown], timeout: 2)

        let queuedDone = expectation(description: "Disconnected queued caller completed")
        let queued = try await controlChannel(service: service, completed: queuedDone)
        let queuedRequest = request("queued")
        let queuedEvaluated = expectation(description: "Socket request queued")
        observer.observed = { if $0.id == queuedRequest.id { queuedEvaluated.fulfill() } }
        try await send(queuedRequest, to: queued)
        await fulfillment(of: [queuedEvaluated], timeout: 2)
        try await queued.close().get()
        await fulfillment(of: [queuedDone], timeout: 2)

        let nextDone = expectation(description: "Next socket caller completed")
        let next = try await controlChannel(service: service, completed: nextDone)
        let nextRequest = request("next")
        let nextEvaluated = expectation(description: "Replacement socket request queued")
        observer.observed = { if $0.id == nextRequest.id { nextEvaluated.fulfill() } }
        try await send(nextRequest, to: next)
        await fulfillment(of: [nextEvaluated], timeout: 2)
        observer.observed = { _ in }
        let nextShown = expectation(description: "Next socket prompt displayed")
        await presenter.setOnPresent { nextShown.fulfill() }
        try await first.close().get()
        await fulfillment(of: [firstDone, nextShown], timeout: 2)
        let firstOutput = try await first.readOutbound(as: ByteBuffer.self)
        let queuedOutput = try await queued.readOutbound(as: ByteBuffer.self)
        XCTAssertNil(firstOutput)
        XCTAssertNil(queuedOutput)
        XCTAssertFalse(store.contains("example.com", type: .domain))

        await presenter.resolve(.approveOnce)
        await fulfillment(of: [nextDone], timeout: 2)
        var output = try await next.waitForOutboundWrite(as: ByteBuffer.self)
        let response = try XCTUnwrap(output.readString(length: output.readableBytes))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any])
        XCTAssertEqual(json["id"] as? String, nextRequest.id)
        XCTAssertEqual(json["approved"] as? Bool, true)
        let presentations = await presenter.presentations
        XCTAssertEqual(presentations.count, 2)
        _ = try await first.finish(acceptAlreadyClosed: true)
        _ = try await queued.finish(acceptAlreadyClosed: true)
        _ = try await next.finish(acceptAlreadyClosed: true)
    }

    func testControlErrorCancelsDisplayedApproval() async throws {
        let presenter = ControlledPresenter()
        let service = try service(presenter)
        let done = expectation(description: "Errored socket caller completed")
        let channel = try await controlChannel(service: service, completed: done)
        let shown = expectation(description: "Prompt displayed before error")
        await presenter.setOnPresent { shown.fulfill() }
        try await send(request("error"), to: channel)
        await fulfillment(of: [shown], timeout: 2)
        channel.pipeline.fireErrorCaught(ChannelError.inputClosed)
        await fulfillment(of: [done], timeout: 2)
        let output = try await channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNil(output)
        _ = try await channel.finish(acceptAlreadyClosed: true)
    }

    func testAlreadyCancelledCallerDoesNotPromptOrConsumeCapacity() async throws {
        let presenter = ControlledPresenter()
        let service = try service(presenter, limit: 0)
        let r = request("cancelled")
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await service.askForApproval(request: r)
        }
        let result = await task.value
        XCTAssertFalse(result)
        let presentations = await presenter.presentations
        XCTAssertTrue(presentations.isEmpty)
        // Automatic decisions still work when no interactive capacity is available.
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        let automatic = await service.askForApproval(request: request("automatic"))
        XCTAssertTrue(automatic)
    }
}
