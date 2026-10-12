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

    private func chatGPTRequest(accountID: String = "91691066-ac6c-4de7-b6cc-6e53b2ff7b34") -> ProxyApprovalRequest {
        var r = request("chatgpt.com/backend-api/codex/responses", type: "WEBSOCKET")
        r.headers = [ProxyApprovalHeader(name: "Chatgpt-Account-Id", value: accountID)]
        return r
    }

    private func azureMavenRequest(organization: String = "org", feed: String = "feed") -> ProxyApprovalRequest {
        var r = request("pkgs.dev.azure.com/\(organization)/_packaging/\(feed)/maven/v1/org/example/lib/1.0/lib-1.0.jar")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer {vzm:PAT}")]
        r.secrets = ["PAT"]
        return r
    }

    private func secretRequest() -> ProxyApprovalRequest {
        var r = request("build-cache.bushelops.com/auth/exchange/pat", method: "POST")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer {vzm:PAT}")]
        r.body = ProxyApprovalBody(text: "request payload", warning: "")
        r.secrets = ["PAT"]
        return r
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
            (NixGitHubApprovalEngine(), "api.github.com/repos/NixOS/nixpkgs/commits/nixos-26.05", false),
            (NixGitHubApprovalEngine(), "api.github.com/repos/NixOS/nixpkgs/commits/nixos-unstable", false),
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

    func testDockerHubPullSequenceInAuto() async throws {
        let service = try service(engines: [DockerHubApprovalEngine()])
        mode.select(.auto)
        let digest = String(repeating: "a", count: 64)
        for repository in ["library/mysql", "eqalpha/keydb"] {
            let urls = [
                "registry-1.docker.io/v2/\(repository)/manifests/8.4",
                "auth.docker.io/token?scope=repository%3A\(repository.replacingOccurrences(of: "/", with: "%2F"))%3Apull&service=registry.docker.io",
                "registry-1.docker.io/v2/\(repository)/manifests/sha256:\(digest)",
                "registry-1.docker.io/v2/\(repository)/referrers/sha256:\(digest)",
                "registry-1.docker.io/v2/\(repository)/blobs/sha256:\(digest)",
                "production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/\(digest)/data?Expires=1791820895&Signature=example~__&Key-Pair-Id=K2C9XPB6FLAKUF",
            ]
            for url in urls {
                for method in ["HEAD", "GET"] {
                    var r = request(url, method: method)
                    r.headers = [
                        ProxyApprovalHeader(name: "aUtHoRiZaTiOn", value: "Bearer \(UUID().uuidString)"),
                        ProxyApprovalHeader(name: "Accept", value: "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/json"),
                    ]
                    await assertDecision(service, r, true)
                }
            }
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testDockerHubHeaderConsentAndTokenRotation() {
        let engine = DockerHubApprovalEngine()
        var r = request("registry-1.docker.io/v2/library/mysql/manifests/8.4")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Basic arbitrary")]
        XCTAssertTrue(engine.isEligibleForAuto(r))
        if case .userApprovalRequired = engine.handle(r) {} else { XCTFail("Default needs engine consent") }

        r.headers.append(ProxyApprovalHeader(name: "X-Custom", value: "approved"))
        XCTAssertFalse(engine.isEligibleForAuto(r))
        engine.onEngineApproved(r)
        r.headers[0].value = "Bearer rotated-token"
        XCTAssertTrue(engine.isEligibleForAuto(r))
        if case .approved = engine.handle(r) {} else { XCTFail("Token rotation should retain consent") }
        r.headers[1].value = "changed"
        XCTAssertFalse(engine.isEligibleForAuto(r))
        if case .userApprovalRequired = engine.handle(r) {} else { XCTFail("Unknown headers need consent") }

        let otherEngine = NixCacheApprovalEngine()
        var other = request()
        other.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer token")]
        XCTAssertFalse(otherEngine.isEligibleForAuto(other))
    }

    func testDockerHubHeaderFilteringPreservesRestrictions() {
        let engine = DockerHubApprovalEngine()
        var r = request("registry-1.docker.io/v2/library/mysql/manifests/8.4")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "anything")]
        for mediaType in [
            "application/vnd.docker.distribution.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
            "APPLICATION/VND.OCI.IMAGE.INDEX.V1+JSON",
        ] {
            r.headers.append(ProxyApprovalHeader(name: "Accept", value: mediaType))
            XCTAssertTrue(engine.isEligibleForAuto(r))
            r.headers.removeLast()
        }
        for value in ["", "text/custom", "application/vnd.oci.image.index.v1+json,", "application/vnd.oci.image.index.v1+json; custom=value"] {
            var invalid = r
            invalid.headers.append(ProxyApprovalHeader(name: "Accept", value: value))
            XCTAssertFalse(engine.isEligibleForAuto(invalid))
        }
        var invalid = r
        invalid.secrets = ["TOKEN"]
        XCTAssertFalse(engine.isEligibleForAuto(invalid))
        invalid = r
        invalid.body = ProxyApprovalBody(text: "payload", warning: "")
        XCTAssertFalse(engine.isEligibleForAuto(invalid))
        invalid = r
        invalid.method = "POST"
        XCTAssertFalse(engine.isEligibleForAuto(invalid))
        for url in ["example.com/v2/library/mysql/manifests/8.4", "registry-1.docker.io/v2/library/mysql/blobs/uploads/"] {
            invalid = r
            invalid.url = url
            XCTAssertFalse(engine.isEligibleForAuto(invalid))
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
            azureMavenRequest(),
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

    func testChatGPTManualSessionApprovalRemembersAccountForEngineLifetime() async throws {
        mode.select(.auto)
        let service = try service()
        var r = chatGPTRequest()
        r.headers.append(ProxyApprovalHeader(name: "Authorization", value: "Bearer first-token"))
        await assertDecision(service, r, false)

        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
        XCTAssertEqual(presentations.last?.title, "ChatGPT session")

        await prompts.setAction(.deny)
        r.headers[0] = ProxyApprovalHeader(name: "cHaTgPt-AcCoUnT-iD", value: " \(r.headers[0].value) ")
        r.headers[1] = ProxyApprovalHeader(name: "Authorization", value: "Bearer rotated-token")
        await assertDecision(service, r, true)
        let presentationsAfterAuto = await prompts.presentations
        XCTAssertEqual(presentationsAfterAuto.count, 2)

        await assertDecision(service, chatGPTRequest(accountID: "another-account"), false)
        mode.select(.default)
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, r, false)

        // A fresh service/engine does not retain account trust.
        mode.select(.auto)
        let restartedService = try self.service()
        await assertDecision(restartedService, r, false)
        await assertDecision(service, r, true)
    }

    func testChatGPTDenyAndApproveOnceDoNotRememberAccount() async throws {
        mode.select(.auto)
        let service = try service()
        let r = chatGPTRequest()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
    }

    func testChatGPTMissingEmptyAndDuplicateAccountHeadersDoNotEstablishTrust() async throws {
        mode.select(.auto)
        let engine = ChatGPTApprovalEngine()
        let service = try service(engines: [engine])
        var missing = chatGPTRequest()
        missing.headers = []
        var duplicate = chatGPTRequest()
        duplicate.headers.append(ProxyApprovalHeader(name: "chatgpt-account-id", value: duplicate.headers[0].value))
        var conflicting = chatGPTRequest()
        conflicting.headers.append(ProxyApprovalHeader(name: "chatgpt-account-id", value: "another-account"))
        let requests = [missing, chatGPTRequest(accountID: " \n\t"), duplicate, conflicting]

        await prompts.setAction(.approveEngine)
        for r in requests { await assertDecision(service, r, true) }
        XCTAssertFalse(engine.isEligibleForAuto(chatGPTRequest()))
        XCTAssertFalse(engine.isEligibleForAuto(chatGPTRequest(accountID: "another-account")))

        // Even with a known account, ambiguous/missing headers must still prompt.
        engine.onEngineApproved(chatGPTRequest())
        await prompts.setAction(.deny)
        for r in requests { await assertDecision(service, r, false) }
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, requests.count * 2)
    }

    func testChatGPTKnownAccountDoesNotBypassSessionRestrictions() {
        let r = chatGPTRequest()
        let engine = ChatGPTApprovalEngine()
        engine.onEngineApproved(r)
        XCTAssertTrue(engine.isEligibleForAuto(r))
        var invalidRequests: [ProxyApprovalRequest] = []
        for type in ["REQUEST", "CONNECT", "TCP_CONNECT", "GIT"] {
            var invalid = r
            invalid.type = type
            invalidRequests.append(invalid)
        }
        var invalid = r
        invalid.method = "POST"
        invalidRequests.append(invalid)
        invalid = r
        invalid.body = ProxyApprovalBody(text: "payload", warning: "")
        invalidRequests.append(invalid)
        invalid = r
        invalid.secrets = ["TOKEN"]
        invalidRequests.append(invalid)
        for url in ["example.com/backend-api/codex/responses", "chatgpt.com/other", "chatgpt.com/backend-api/codex/responses?extra=1"] {
            invalid = r
            invalid.url = url
            invalidRequests.append(invalid)
        }
        for invalid in invalidRequests {
            XCTAssertFalse(engine.isEligibleForAuto(invalid))
            if case .unknown = engine.handle(invalid) {} else { XCTFail("Invalid session matched") }
        }
    }

    func testSecretRequestPermanentApprovalSurvivesRestartAndOnlyAppliesInAuto() async throws {
        let service = try service()
        let r = secretRequest()
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, r, false)

        store = try RecognizedElementStore(directoryURL: directory)
        let restartedService = try self.service()
        mode.select(.auto)
        var changed = r
        changed.headers = [ProxyApprovalHeader(name: "X-New-Header", value: "new value")]
        changed.body = ProxyApprovalBody(text: "different payload", warning: "different warning")
        await assertDecision(restartedService, changed, true)
        changed.headers = []
        changed.body = nil
        await assertDecision(restartedService, changed, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
    }

    func testSecretRequestDenyAndApproveOnceDoNotPersistRule() async throws {
        mode.select(.auto)
        let service = try service()
        let r = secretRequest()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        let restartedService = try self.service()
        await assertDecision(restartedService, r, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 4)
    }

    func testSecretRequestRuleMatchesExactMethodURLAndSecretSet() {
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        var r = secretRequest()
        r.secrets = ["PAT", "SECOND"]
        XCTAssertFalse(engine.isEligibleForAuto(r))
        engine.onEngineApproved(r)
        var reordered = r
        reordered.secrets = ["SECOND", "PAT", "PAT"]
        XCTAssertTrue(engine.isEligibleForAuto(reordered))

        var changed = r
        changed.method = "GET"
        XCTAssertFalse(engine.isEligibleForAuto(changed))
        changed.method = "post"
        XCTAssertFalse(engine.isEligibleForAuto(changed))
        for url in ["other.example/auth/exchange/pat", "build-cache.bushelops.com/auth/exchange/other", r.url + "?extra=1", r.url + "/"] {
            changed = r
            changed.url = url
            XCTAssertFalse(engine.isEligibleForAuto(changed))
        }
        for secrets in [["PAT"], ["SECOND"], ["PAT", "SECOND", "THIRD"], ["different"], ["pat", "SECOND"]] {
            changed = r
            changed.secrets = secrets
            XCTAssertFalse(engine.isEligibleForAuto(changed))
        }

        // Structured keys must not collide when secret names contain separators.
        r.secrets = ["a\nb", "c"]
        engine.onEngineApproved(r)
        changed = r
        changed.secrets = ["a", "b\nc"]
        XCTAssertFalse(engine.isEligibleForAuto(changed))
    }

    func testSecretRequestEngineExcludesOtherTypesAndInvalidRules() {
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        let r = secretRequest()
        engine.onEngineApproved(r)
        var invalidRequests: [ProxyApprovalRequest] = []
        for type in ["CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
            var invalid = r
            invalid.type = type
            invalidRequests.append(invalid)
        }
        var invalid = r
        invalid.method = ""
        invalidRequests.append(invalid)
        invalid = r
        invalid.url = ""
        invalidRequests.append(invalid)
        for secrets in [[String](), [""], [" \n\t"], ["PAT", ""]] {
            invalid = r
            invalid.secrets = secrets
            invalidRequests.append(invalid)
        }
        for invalid in invalidRequests {
            XCTAssertFalse(engine.isEligibleForAuto(invalid))
            if case .unknown = engine.handle(invalid) {} else { XCTFail("Invalid secret request matched") }
            engine.onEngineApproved(invalid)
        }
    }

    func testSecretRequestCustomPromptPreservesDetailsWarningsAndSafeActions() async throws {
        let service = try service()
        var r = secretRequest()
        r.headers.append(ProxyApprovalHeader(name: "Host", value: r.domain))
        r.body?.warning = "Body display warning"
        await assertDecision(service, r, false)
        let presentations = await prompts.presentations
        let presentation = try XCTUnwrap(presentations.first)
        XCTAssertEqual(presentation.title, "Secret access approval")
        XCTAssertTrue(presentation.warnings.contains("Warning: new domain."))
        XCTAssertTrue(presentation.warnings.contains("Body display warning"))
        XCTAssertTrue(presentation.warnings.contains {
            $0.contains("permanent approval to disk") && $0.contains("request body or other headers change")
        })
        XCTAssertEqual(presentation.sections.first { $0.title == "URL" }?.text, "POST \(r.url)")
        XCTAssertEqual(presentation.sections.first { $0.title == "Secrets" }?.text, "PAT")
        XCTAssertEqual(presentation.sections.first { $0.title == "Headers" }?.text, "Authorization: Bearer {vzm:PAT}")
        XCTAssertEqual(presentation.sections.first { $0.title == "Body" }?.text, r.body?.text)
        XCTAssertEqual(presentation.actions.map(\.id), [.deny, .approveEngine, .approveOnce])
        let permanent = try XCTUnwrap(presentation.actions.first { $0.id == .approveEngine })
        XCTAssertEqual(permanent.label, "♾️ Always allow in Auto")
        XCTAssertNil(permanent.keyboardShortcut)
        XCTAssertEqual(presentation.actions.first { $0.id == .approveOnce }?.keyboardShortcut, .defaultAction)
        XCTAssertEqual(presentation.actions.first { $0.id == .deny }?.keyboardShortcut, .cancelAction)
    }

    func testAzureMavenPromptTakesPrecedenceOverSecretRequestPrompt() async throws {
        let service = try service()
        await assertDecision(service, azureMavenRequest(), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.first?.title, "Outbound")
        XCTAssertEqual(presentations.first?.subtitle, "🚂 available: AzureDevOpsMaven")
        XCTAssertEqual(presentations.first?.actions.first { $0.id == .approveEngine }?.label, "🚂 Approve engine")
    }

    func testAzureMavenAutoReusesConsentAcrossFeedsInMemoryOnly() async throws {
        let service = try service()
        mode.select(.auto)
        let r = azureMavenRequest()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)

        var otherFeed = azureMavenRequest(organization: "another-org", feed: "another-feed")
        otherFeed.method = "HEAD"
        await assertDecision(service, otherFeed, true)
        mode.select(.default)
        await assertDecision(service, otherFeed, false)
        mode.select(.auto)
        await assertDecision(service, otherFeed, true)

        var changed = otherFeed
        changed.secrets.append("NEW_SECRET")
        await assertDecision(service, changed, false)
        changed = otherFeed
        changed.headers.append(ProxyApprovalHeader(name: "X-New", value: "new value"))
        await assertDecision(service, changed, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 5)

        store = try RecognizedElementStore(directoryURL: directory)
        let restartedService = try self.service()
        await assertDecision(restartedService, r, false)
        await assertDecision(restartedService, otherFeed, false)
    }

    func testAzureMavenDenyAndApproveOnceDoNotEstablishAutoConsent() async throws {
        mode.select(.auto)
        let service = try service()
        let r = azureMavenRequest()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        await assertDecision(service, azureMavenRequest(feed: "another-feed"), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 4)
    }

    func testAzureMavenAutoValidatesPatternHeadersAndSecretNames() {
        let engine = AzureDevOpsMavenApprovalEngine()
        var readOnly = azureMavenRequest()
        readOnly.headers = []
        readOnly.secrets = []
        XCTAssertTrue(engine.isEligibleForAuto(readOnly))
        let r = azureMavenRequest()
        XCTAssertFalse(engine.isEligibleForAuto(r))
        engine.onEngineApproved(r)
        XCTAssertTrue(engine.isEligibleForAuto(r))

        var another = azureMavenRequest(organization: "other", feed: "other")
        another.secrets = ["SECOND"]
        XCTAssertFalse(engine.isEligibleForAuto(another))
        engine.onEngineApproved(another)
        another.secrets = ["PAT", "SECOND", "PAT"]
        XCTAssertTrue(engine.isEligibleForAuto(another))
        another.secrets = ["pat"]
        XCTAssertFalse(engine.isEligibleForAuto(another))
        another = r
        another.headers = [ProxyApprovalHeader(name: "Authorization", value: "different value")]
        XCTAssertFalse(engine.isEligibleForAuto(another))

        var invalidRequests: [ProxyApprovalRequest] = []
        for type in ["CONNECT", "TCP_CONNECT", "WEBSOCKET", "GIT"] {
            var invalid = r
            invalid.type = type
            invalidRequests.append(invalid)
        }
        var invalid = r
        invalid.method = "POST"
        invalidRequests.append(invalid)
        invalid = r
        invalid.body = ProxyApprovalBody(text: "payload", warning: "")
        invalidRequests.append(invalid)
        for url in [
            "example.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar",
            r.url + "?extra=1", r.url + "#fragment",
            "pkgs.dev.azure.com/org/_packaging/feed/npm/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/other-1.0.jar",
            "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar.sha256",
        ] {
            invalid = r
            invalid.url = url
            invalidRequests.append(invalid)
        }
        for invalid in invalidRequests {
            XCTAssertFalse(engine.isEligibleForAuto(invalid))
            if case .unknown = engine.handle(invalid) {} else { XCTFail("Invalid Maven request matched") }
            var invalidConsent = invalid
            invalidConsent.secrets = ["UNAPPROVED"]
            engine.onEngineApproved(invalidConsent)
        }
        another = r
        another.secrets = ["UNAPPROVED"]
        XCTAssertFalse(engine.isEligibleForAuto(another))
    }

    func testAzureMavenAutoDoesNotConsumeGatesAndBypassesExhaustedSession() {
        let engine = AzureDevOpsMavenApprovalEngine()
        let r = azureMavenRequest()
        engine.onEngineApproved(r)
        for _ in 0..<200 { XCTAssertTrue(engine.isEligibleForAuto(r)) }
        for _ in 0..<120 {
            if case .approved = engine.handle(r) {} else { XCTFail("Auto consumed session gates") }
        }
        if case .userApprovalRequired = engine.handle(r) {} else { XCTFail("Rate limit was not enforced") }
        XCTAssertTrue(engine.isEligibleForAuto(r))
    }

    func testAzureMavenCanFallBackToExistingPermanentSecretRule() async throws {
        let r = azureMavenRequest()
        let secretEngine = SecretRequestApprovalEngine(recognizedElementStore: store)
        secretEngine.onEngineApproved(r)
        let service = try service()
        mode.select(.auto)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testSecretRequestRulesDoNotBypassDenyEnginesOrNewConnectConsent() async throws {
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        var blocked = secretRequest()
        blocked.domain = "telemetry.nextjs.org"
        blocked.url = "telemetry.nextjs.org/collect"
        engine.onEngineApproved(blocked)
        let service = try service()
        mode.select(.auto)
        await assertDecision(service, blocked, false)
        let deniedPresentations = await prompts.presentations
        XCTAssertTrue(deniedPresentations.isEmpty)

        engine.onEngineApproved(secretRequest())
        var connect = request("build-cache.bushelops.com:443", type: "CONNECT", method: "CONNECT")
        connect.domain = "build-cache.bushelops.com"
        await assertDecision(service, connect, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 1)
        XCTAssertEqual(presentations.first?.title, "Outbound")
    }

    func testSecretRequestStoreContainsOnlyRuleMetadata() throws {
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        engine.onEngineApproved(secretRequest())
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        XCTAssertEqual(files.count, 1)
        let data = try String(contentsOf: XCTUnwrap(files.first), encoding: .utf8)
        XCTAssertTrue(data.hasPrefix("autoApprovedSecretRequest\n"))
        XCTAssertTrue(data.contains("PAT"))
        XCTAssertTrue(data.contains("POST"))
        XCTAssertFalse(data.contains("Bearer"))
        XCTAssertFalse(data.contains("request payload"))
    }

    func testSecretRequestPersistenceFailureDoesNotGrantAutoApproval() throws {
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        try FileManager.default.removeItem(at: directory)
        try Data("not a directory".utf8).write(to: directory)
        engine.onEngineApproved(secretRequest())
        XCTAssertFalse(engine.isEligibleForAuto(secretRequest()))
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
