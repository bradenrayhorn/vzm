import XCTest
@testable import vzm

private actor PromptRecorder {
    private(set) var presentations: [ApprovalPromptPresentation] = []
    var action: ApprovalCoordinatorResult = .deny

    func setAction(_ action: ApprovalCoordinatorResult) { self.action = action }

    func ask(_ request: ApprovalCoordinatorRequest) -> ApprovalCoordinatorResult {
        presentations.append(request.presentation)
        return action
    }
}

private final class CountingGate: ApprovalGate {
    var checks = 0
    var isOpen = true

    func canContinue() -> Bool {
        checks += 1
        return isOpen
    }
}

private final class TestPatternEngine: PatternApprovalEngine {
    var onMatch: ((ProxyApprovalRequest) -> Void)?

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        onMatch?(request)
        return request.type == "REQUEST" && request.method == "GET"
            && request.body == nil && request.secrets.isEmpty
    }
}

private actor AsyncSignal {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        signaled = true
        let pending = waiters
        waiters = []
        pending.forEach { $0.resume() }
    }

    func wait() async {
        if signaled { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}

final class ApprovalTests: XCTestCase {
    private var directory: URL!
    private var store: RecognizedElementStore!
    private var mode: ApprovalModeState!
    private var prompts: PromptRecorder!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = try RecognizedElementStore(directoryURL: directory)
        mode = ApprovalModeState()
        prompts = PromptRecorder()
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    private func request(_ url: String = "cache.nixos.org/nix-cache-info", type: String = "REQUEST", method: String = "GET") -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            id: UUID().uuidString, type: type,
            domain: String(url.split(separator: "/").first ?? ""), method: method,
            url: url, headers: [], body: nil, secrets: []
        )
    }

    private func service(engines: [any ApprovalEngine]? = nil, denyEngines: [any ApprovalEngine]? = nil) throws -> ApprovalService {
        let prompts = self.prompts!
        return try ApprovalService(
            denyEngines: denyEngines, engines: engines, recognizedElementStore: store,
            modeState: mode, promptUser: { await prompts.ask($0) }
        )
    }

    private func assertDecision(_ service: ApprovalService, _ request: ProxyApprovalRequest, _ expected: Bool, file: StaticString = #filePath, line: UInt = #line) async {
        let result = await service.askForApproval(request: request)
        XCTAssertEqual(result, expected, file: file, line: line)
    }

    func testModeTransitionsAndExpiration() {
        let now = Date()
        XCTAssertEqual(mode.current(now: now), .default)
        mode.select(.auto)
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(100_000)), .auto)
        mode.select(.approveEverything(until: now.addingTimeInterval(60)))
        XCTAssertEqual(mode.current(now: now), .approveEverything(until: now.addingTimeInterval(60)))
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(60)), .default)
        mode.select(.approveEverything(until: now.addingTimeInterval(60)))
        mode.select(.auto)
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(61)), .auto)
        mode.select(.default)
        XCTAssertEqual(mode.current(), .default)
        XCTAssertEqual(ApprovalModeState().current(), .default)
    }

    func testAllEligiblePatternsAndRestrictions() {
        let patterns: [(PatternApprovalEngine, String, Bool)] = [
            (IntelliJApprovalEngine(), "download.jetbrains.com/jdk/feed/test.json", true),
            (GradleDistributionApprovalEngine(), "services.gradle.org/distributions/gradle-8.14-bin.zip", false),
            (MavenRepositoryApprovalEngine(), "repo.maven.apache.org/maven2/org/example/lib/1.0/lib-1.0.jar", true),
            (DockerHubApprovalEngine(), "registry-1.docker.io/v2/library/alpine/manifests/latest", true),
            (NixCacheApprovalEngine(), "cache.nixos.org/nix-cache-info", false),
            (NixGitHubApprovalEngine(), "github.com/NixOS/nix/archive/\(String(repeating: "a", count: 40)).tar.gz", false),
            (YarnPkgApprovalEngine(), "registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz", false),
        ]
        for (engine, url, supportsHead) in patterns {
            var r = request(url)
            XCTAssertTrue(engine.isEligibleForAuto(r), engine.name)
            if case .userApprovalRequired = engine.handle(r) {} else { XCTFail("Default needs consent: \(engine.name)") }
            r.method = "HEAD"
            XCTAssertEqual(engine.isEligibleForAuto(r), supportsHead, engine.name)
            r.method = "POST"
            XCTAssertFalse(engine.isEligibleForAuto(r), engine.name)
            r = request(url)
            r.body = ProxyApprovalBody(text: "payload", warning: "")
            XCTAssertFalse(engine.isEligibleForAuto(r), engine.name)
            r = request(url)
            r.secrets = ["TOKEN"]
            XCTAssertFalse(engine.isEligibleForAuto(r), engine.name)
            for type in ["CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
                XCTAssertFalse(engine.isEligibleForAuto(request(url, type: type)), engine.name)
            }
            XCTAssertFalse(engine.isEligibleForAuto(request("example.com/arbitrary")), engine.name)
        }
    }

    func testAutoDoesNotConsumeGatesOrDiscardExplicitSession() async throws {
        let gate = CountingGate()
        gate.isOpen = false
        let engine = TestPatternEngine(gateBuilders: [{ gate }])
        engine.onEngineApproved(request())
        let service = try service(engines: [engine])
        await assertDecision(service, request(), false)
        let checksBeforeAuto = gate.checks
        XCTAssertGreaterThan(checksBeforeAuto, 0)

        mode.select(.auto)
        for _ in 0..<5 { await assertDecision(service, request(), true) }
        XCTAssertEqual(gate.checks, checksBeforeAuto)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, request(), true)
        XCTAssertEqual(gate.checks, checksBeforeAuto)

        mode.select(.default)
        await assertDecision(service, request(), false)
        XCTAssertGreaterThan(gate.checks, checksBeforeAuto)
        gate.isOpen = true
        await assertDecision(service, request(), true)
    }

    func testAutoDoesNotActivateSessionOrPersistTrust() async throws {
        let service = try service()
        mode.select(.auto)
        await assertDecision(service, request(), true)
        XCTAssertFalse(store.contains("cache.nixos.org", type: .domain))
        mode.select(.default)
        await assertDecision(service, request(), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 1)
    }

    func testSafeAndKnownHeadersAreMaskedButNewHeadersPrompt() async throws {
        mode.select(.auto)
        let service = try service()
        var r = request()
        r.headers = [
            ProxyApprovalHeader(name: "Host", value: "cache.nixos.org"),
            ProxyApprovalHeader(name: "Accept", value: "*/*"),
            ProxyApprovalHeader(name: "User-Agent", value: "new-agent"),
        ]
        await assertDecision(service, r, false)
        XCTAssertFalse(store.contains("new-agent", type: .userAgent))
        try store.insert("new-agent", type: .userAgent)
        await assertDecision(service, r, true)
        r.headers.append(ProxyApprovalHeader(name: "X-Data", value: "unapproved"))
        await assertDecision(service, r, false)
    }

    func testExplicitEngineApprovalEstablishesAutoHeaderBaseline() async throws {
        let service = try service()
        mode.select(.auto)
        var r = request()
        r.headers = [ProxyApprovalHeader(name: "X-Data", value: "explicitly-approved")]
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, true)
        var unapprovedRequest = r
        unapprovedRequest.headers.append(ProxyApprovalHeader(name: "X-Unfamiliar", value: "data"))
        await assertDecision(service, unapprovedRequest, false)
        mode.select(.default)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
    }

    func testNewConnectAlwaysPromptsInEveryMode() async throws {
        let service = try service()
        var r = request("cache.nixos.org:443", type: "CONNECT", method: "CONNECT")
        r.domain = "cache.nixos.org"
        for selection in [ApprovalMode.default, .auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, r, false)
        }
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        XCTAssertTrue(store.contains(r.domain, type: .domain))
        await prompts.setAction(.deny)
        mode.select(.auto)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 4)
    }

    func testDeniedTrafficCannotBeApprovedByModes() async throws {
        let service = try service()
        for selection in [ApprovalMode.auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, request("telemetry.nextjs.org/collect"), false)
            await assertDecision(service, request("api.jetbrains.ai/test"), false)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testAutoExclusionsAndUnknownRequestsPrompt() async throws {
        mode.select(.auto)
        let service = try service()
        let requests = [
            request("pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar"),
            request("chatgpt.com/backend-api/codex/responses", type: "WEBSOCKET"),
            request("example.com:443", type: "TCP_CONNECT", method: "CONNECT"),
            request("example.com/repository", type: "GIT"),
            request("example.com/arbitrary"),
        ]
        for r in requests { await assertDecision(service, r, false) }
        var secretRequest = request()
        secretRequest.secrets = ["TOKEN"]
        await assertDecision(service, secretRequest, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, requests.count + 1)
    }

    func testQueuedRequestIsReevaluatedAfterModeChange() async throws {
        let promptStarted = AsyncSignal()
        let releasePrompt = AsyncSignal()
        let secondEvaluated = AsyncSignal()
        let engine = TestPatternEngine()
        let secondRequest = request()
        engine.onMatch = { r in
            if r.id == secondRequest.id {
                Task { await secondEvaluated.signal() }
            }
        }
        let prompts = self.prompts!
        let service = try ApprovalService(
            denyEngines: [], engines: [engine], recognizedElementStore: store,
            modeState: mode, promptUser: { request in
                await promptStarted.signal()
                await releasePrompt.wait()
                return await prompts.ask(request)
            }
        )
        let first = Task { await service.askForApproval(request: request()) }
        await promptStarted.wait()
        let second = Task { await service.askForApproval(request: secondRequest) }
        await secondEvaluated.wait()
        mode.select(.auto)
        await releasePrompt.signal()
        let firstResult = await first.value
        let secondResult = await second.value
        XCTAssertFalse(firstResult)
        XCTAssertTrue(secondResult)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 1)
    }

    func testApproveEverythingRetainsExclusionsAndExpiresToDefault() async throws {
        let service = try service()
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, request("example.com/arbitrary"), true)
        for type in ["GIT", "WEBSOCKET", "TCP_CONNECT"] {
            await assertDecision(service, request("example.com:443", type: type), false)
        }
        var r = request("example.com/arbitrary")
        r.secrets = ["TOKEN"]
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(-1)))
        await assertDecision(service, request(), false)
        XCTAssertEqual(mode.current(), .default)
    }
}
