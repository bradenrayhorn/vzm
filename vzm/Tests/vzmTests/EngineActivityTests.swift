import XCTest
@testable import vzm

final class EngineActivityTests: XCTestCase {
    @MainActor
    func testOverlayPreferenceDefaultsOnAndPersists() {
        let suite = "vzm-overlay-test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = EngineActivityStore()
        let coordinator = EngineActivityOverlayCoordinator(defaults: defaults, store: store)
        XCTAssertTrue(coordinator.isEnabled)

        coordinator.setEnabled(false)
        XCTAssertFalse(coordinator.isEnabled)
        coordinator.attach() // Disabled runtime must not start recording or create an overlay.
        store.record(.llm, at: 10)
        XCTAssertTrue(store.snapshot().lastApprovals.isEmpty)
        coordinator.detach()

        let restored = EngineActivityOverlayCoordinator(defaults: defaults, store: store)
        XCTAssertFalse(restored.isEnabled)
        restored.setEnabled(true) // No runtime: changing the setting must not start activity.
        store.record(.llm, at: 11)
        XCTAssertTrue(store.snapshot().lastApprovals.isEmpty)
        XCTAssertTrue(EngineActivityOverlayCoordinator(defaults: defaults, store: store).isEnabled)
    }

    func testHoldFadeAndIndependentGroups() {
        let store = EngineActivityStore()
        store.start()
        store.record(.packages, at: 100)
        let snapshot = store.snapshot()
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 100), 1)
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 100.5), 1)
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 101), 1)
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 103.5), 0.65, accuracy: 0.0001)
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 106), 0.3)
        XCTAssertEqual(snapshot.opacity(for: .packages, at: 200), 0.3)
        XCTAssertEqual(snapshot.opacity(for: .datadog, at: 100), 0.3)

        store.record(.packages, at: 104)
        store.record(.datadog, at: 102)
        XCTAssertEqual(store.snapshot().opacity(for: .packages, at: 105), 1)
        XCTAssertEqual(store.snapshot().opacity(for: .datadog, at: 105), 0.72, accuracy: 0.0001)
    }

    func testLifecycleAndConcurrentRecording() {
        let store = EngineActivityStore()
        store.record(.llm, at: 10)
        XCTAssertTrue(store.snapshot().lastApprovals.isEmpty)
        store.start()
        DispatchQueue.concurrentPerform(iterations: 1000) { tick in
            store.record(.llm, at: Double(tick))
        }
        XCTAssertEqual(store.snapshot().lastApprovals, [.llm: 999])
        store.stop()
        store.record(.llm, at: 1000)
        XCTAssertTrue(store.snapshot().lastApprovals.isEmpty)
        store.start()
        XCTAssertTrue(store.snapshot().lastApprovals.isEmpty)
    }

    func testAllProductionEngineMappings() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let recognized = try RecognizedElementStore(directoryURL: directory)
        let mappings: [(any ApprovalEngine, EngineActivityGroup?)] = [
            (NpmApprovalEngine(), .packages),
            (YarnPkgApprovalEngine(), .packages),
            (MavenRepositoryApprovalEngine(), .packages),
            (GradleDistributionApprovalEngine(), .packages),
            (AzureDevOpsNpmApprovalEngine(), .packages),
            (AzureDevOpsMavenApprovalEngine(recognizedElementStore: recognized), .packages),
            (DockerHubApprovalEngine(), .containers),
            (NixCacheApprovalEngine(), .nix),
            (NixGitHubApprovalEngine(), .nix),
            (ChatGPTApprovalEngine(), .llm),
            (OpenRouterApprovalEngine(), .llm),
            (DatadogApprovalEngine(recognizedElementStore: recognized), .datadog),
            (IntelliJApprovalEngine(), .intellij),
            (SecretRequestApprovalEngine(recognizedElementStore: recognized), nil),
            (ApproveForeverApprovalEngine(recognizedElementStore: recognized), nil),
        ]
        for (engine, expected) in mappings {
            XCTAssertEqual(engine.activityGroup, expected, engine.name)
        }
        XCTAssertEqual(EngineActivityGroup.allCases.count, 6)
        XCTAssertEqual(EngineActivityGroup.datadog.emoji, "🐶")
    }

    func testEngineConsentOnlyLightsSubsequentAutomaticApprovals() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let recognized = try RecognizedElementStore(directoryURL: directory)
        let activity = EngineActivityStore()
        activity.start()
        let service = try ApprovalService(
            denyRules: [], engines: [NpmApprovalEngine()], recognizedElementStore: recognized,
            modeState: ApprovalModeState(), engineActivity: activity,
            promptUser: { _ in .approveEngine }
        )
        let request = ProxyApprovalRequest(
            id: "npm-consent", type: "REQUEST", domain: "registry.npmjs.org",
            method: "GET", url: "registry.npmjs.org/package",
            headers: [.init(name: "X-Custom", value: "approved")], body: nil, secrets: []
        )
        let manual = await service.askForApproval(request: request)
        XCTAssertTrue(manual)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)
        let automatic = await service.askForApproval(request: request)
        XCTAssertTrue(automatic)
        XCTAssertEqual(Set(activity.snapshot().lastApprovals.keys), [.packages])
    }

    func testOnlyAutomaticMappedEngineApprovalsPublishActivity() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let recognized = try RecognizedElementStore(directoryURL: directory)
        let mode = ApprovalModeState()
        let activity = EngineActivityStore()
        let engine = ActivityTestEngine()
        let service = try ApprovalService(
            denyRules: [], engines: [engine], recognizedElementStore: recognized,
            modeState: mode, engineActivity: activity,
            promptUser: { _ in .approveOnce }
        )
        var request = ProxyApprovalRequest(
            id: "activity-test", type: "REQUEST", domain: "example.com",
            method: "GET", url: "example.com/test", headers: [], body: nil, secrets: []
        )
        func decide(_ expected: Bool) async {
            let decision = await service.askForApproval(request: request)
            XCTAssertEqual(decision, expected)
        }
        func reset() { activity.start() }

        reset()
        await decide(true)
        XCTAssertEqual(Set(activity.snapshot().lastApprovals.keys), [.packages])

        reset()
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await decide(true)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        reset()
        mode.select(.strict)
        await decide(true) // Manually approved, even though the engine would approve.
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        reset()
        mode.select(.auto)
        engine.result = .needsConsent(.default)
        await decide(true)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        engine.result = .denied
        await decide(false)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        engine.result = .notApplicable
        await decide(true)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        engine.result = .approved
        engine.group = nil
        await decide(true)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        engine.group = .packages
        request.type = "CONNECT"
        await decide(true) // Manual CONNECT approval establishes domain trust.
        await decide(true) // Known CONNECT domain shortcut.
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)

        let deniedService = try ApprovalService(
            denyRules: [ActivityTestDenyRule()], engines: [engine], recognizedElementStore: recognized,
            modeState: mode, engineActivity: activity,
            promptUser: { _ in XCTFail("Hard denials must not prompt"); return .approveOnce }
        )
        request.type = "REQUEST"
        let denied = await deniedService.askForApproval(request: request)
        XCTAssertFalse(denied)
        XCTAssertTrue(activity.snapshot().lastApprovals.isEmpty)
    }
}

private struct ActivityTestDenyRule: DenyRule {
    var name: String { "Test hard denial" }
    func shouldDeny(_ request: ProxyApprovalRequest) -> Bool { true }
}

private final class ActivityTestEngine: BaseApprovalEngine {
    var result: EngineEvaluation = .approved
    var group: EngineActivityGroup? = .packages
    override var activityGroup: EngineActivityGroup? { group }
    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation { result }
}
