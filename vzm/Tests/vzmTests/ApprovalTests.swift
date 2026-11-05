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

private extension EngineEvaluation {
    var isApproved: Bool {
        if case .approved = self { return true }
        return false
    }
}

private final class DenyRuleObserver: DenyRule {
    let name = "Observer"
    private let matchResult: Bool
    private let onRequest: (ProxyApprovalRequest) -> Void

    init(matches: Bool = false, _ onRequest: @escaping (ProxyApprovalRequest) -> Void) {
        self.matchResult = matches
        self.onRequest = onRequest
    }

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        onRequest(request)
        return matchResult
    }
}

private final class TestPatternEngine: PatternApprovalEngine {
    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        return request.type == "REQUEST" && request.method == "GET"
            && request.body == nil && request.secrets.isEmpty
    }
}

private final class ApprovalEngineSpy: BaseApprovalEngine {
    private(set) var evaluationCount = 0
    private(set) var approvedRequests = 0
    private let result: EngineEvaluation

    init(result: EngineEvaluation = .approved) {
        self.result = result
        super.init()
    }

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        evaluationCount += 1
        return result
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedRequests += 1
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

    private func azureMavenRequest(organization: String = "org", project: String? = nil, feed: String = "feed") -> ProxyApprovalRequest {
        let prefix = project.map { "\(organization)/\($0)" } ?? organization
        var r = request("pkgs.dev.azure.com/\(prefix)/_packaging/\(feed)/maven/v1/org/example/lib/1.0/lib-1.0.jar")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer {vzm:PAT}")]
        r.secrets = ["PAT"]
        return r
    }

    private func azureNpmRequest(organization: String = "org", project: String? = nil, feed: String = "feed") -> ProxyApprovalRequest {
        let prefix = project.map { "\(organization)/\($0)" } ?? organization
        var r = request("pkgs.dev.azure.com/\(prefix)/_packaging/\(feed)/npm/registry/@scope%2fpackage")
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

    private func service(engines: [any ApprovalEngine]? = nil, denyRules: [any DenyRule]? = nil) throws -> ApprovalService {
        let prompts = self.prompts!
        return try ApprovalService(
            denyRules: denyRules, engines: engines, recognizedElementStore: store,
            modeState: mode, promptUser: { await prompts.ask($0) }
        )
    }

    private func assertDecision(_ service: ApprovalService, _ request: ProxyApprovalRequest, _ expected: Bool, file: StaticString = #filePath, line: UInt = #line) async {
        let result = await service.askForApproval(request: request)
        XCTAssertEqual(result, expected, file: file, line: line)
    }

    func testFirstConsentPromptWinsAndOnlyItsEngineRecordsConsent() async throws {
        func presentation(_ title: String) -> ApprovalPromptPresentation {
            ApprovalPromptPresentation(
                title: title, subtitle: nil, warnings: ["Engine warning"],
                sections: [ApprovalPromptSection(title: "Engine details", text: title)],
                actions: [
                    ApprovalPromptAction(id: .deny, label: "Deny", keyboardShortcut: .cancelAction),
                    ApprovalPromptAction(id: .approveEngine, label: "Remember", keyboardShortcut: .optionReturn),
                    ApprovalPromptAction(id: .approveOnce, label: "Once", keyboardShortcut: .defaultAction),
                ]
            )
        }
        let firstPrompt = presentation("First engine")
        let first = ApprovalEngineSpy(result: .needsConsent(.presentation(firstPrompt)))
        let second = ApprovalEngineSpy(result: .needsConsent(.presentation(presentation("Second engine"))))
        let unrelated = ApprovalEngineSpy(result: .notApplicable)
        let service = try service(engines: [first, second, unrelated])
        await prompts.setAction(.approveEngine)
        await assertDecision(service, request(), true)
        let presentations = await prompts.presentations
        let shown = try XCTUnwrap(presentations.first)
        XCTAssertEqual(presentations.count, 1)
        XCTAssertEqual(shown.title, firstPrompt.title)
        XCTAssertEqual(shown.sections.first?.text, "First engine")
        XCTAssertEqual(shown.warnings, ["Warning: new domain.", "Engine warning"])
        XCTAssertEqual(shown.actions.map(\.id), firstPrompt.actions.map(\.id))
        XCTAssertEqual(shown.actions.map(\.keyboardShortcut), firstPrompt.actions.map(\.keyboardShortcut))
        XCTAssertEqual(first.approvedRequests, 1)
        XCTAssertEqual(second.approvedRequests, 0)
        XCTAssertEqual(unrelated.approvedRequests, 0)
    }

    func testLaterApprovalOverridesEarlierConsentInAutoAndApproveEverythingFallback() async throws {
        let consent = ApprovalEngineSpy(result: .needsConsent(.default))
        let unrelated = ApprovalEngineSpy(result: .notApplicable)
        let approved = ApprovalEngineSpy()
        let service = try service(engines: [consent, unrelated, approved])
        for selection in [ApprovalMode.auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            // Secrets exclude this request from Approve Everything's broad approval.
            await assertDecision(service, secretRequest(), true)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
        for engine in [consent, unrelated, approved] {
            XCTAssertEqual(engine.approvedRequests, 0)
        }
        XCTAssertTrue(try store.elements(type: .autoApprovedSecretRequest).isEmpty)
        XCTAssertFalse(store.contains(secretRequest().domain, type: .domain))
    }

    func testTrackingRulePreservesDomainMatchingAcrossRequestTypes() {
        let rule = DenyTrackingRule()
        XCTAssertEqual(rule.name, "DenyTracking")
        for domain in ["telemetry.nextjs.org", "config.liquibase.com"] {
            for variant in [domain, domain.uppercased(), " \n\(domain)\t", domain + ".", domain + ":443"] {
                for type in ["REQUEST", "CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
                    var r = request(domain + "/collect", type: type)
                    r.domain = variant
                    XCTAssertTrue(rule.matches(r), "\(type): \(variant)")
                }
            }
        }
        for domain in ["example.com", "sub.telemetry.nextjs.org", "telemetry.nextjs.org.example.com", ""] {
            var r = request()
            r.domain = domain
            XCTAssertFalse(rule.matches(r), domain)
        }
    }

    func testJetBrainsRulePreservesDomainAndRequestOnlyPathMatching() {
        let rule = DenyJetBrainsOptionalServicesRule()
        XCTAssertEqual(rule.name, "DenyJetBrainsOptionalServices")
        for type in ["REQUEST", "CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
            var r = request("api.jetbrains.ai/test", type: type)
            r.domain = " API.JETBRAINS.AI:443 "
            XCTAssertTrue(rule.matches(r), type)
        }
        for url in [
            "frameworks.jetbrains.com/llm-config/config.json",
            "resources.jetbrains.com/storage/fus/config.json",
            "resources.jetbrains.com/storage/ap/fus/config.json",
        ] {
            var r = request(url)
            r.url = " \n" + url.uppercased() + "\t"
            XCTAssertTrue(rule.matches(r), url)
            for type in ["CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
                r.type = type
                XCTAssertFalse(rule.matches(r), "\(type): \(url)")
            }
        }
        for url in [
            "plugins.jetbrains.com/files/plugin.zip",
            "download.jetbrains.com/jdk/feed/test.json",
            "frameworks.jetbrains.com/remote-config/v2/update.json",
            "www.jetbrains.com/config/JetBrainsAccount.xml",
            "resources.jetbrains.com/storage/other/config.json",
            "example.com/llm-config/config.json",
        ] {
            XCTAssertFalse(rule.matches(request(url)), url)
        }
    }

    func testDenyDomainNormalizationPreservesOperationOrder() {
        let cases: [(any DenyRule, String)] = [
            (DenyTrackingRule(), "telemetry.nextjs.org"),
            (DenyTrackingRule(), "config.liquibase.com"),
            (DenyJetBrainsOptionalServicesRule(), "api.jetbrains.ai"),
        ]
        for (rule, domain) in cases {
            for (suffix, expected) in [
                ("", true), (".", true), (":443", true), (":443.", true),
                (".:443", false), ("..", false), (".example.com", false),
            ] {
                var r = request()
                r.domain = " \n" + domain.uppercased() + suffix + "\t"
                XCTAssertEqual(rule.matches(r), expected, "\(rule.name): \(r.domain)")
            }
        }
    }

    func testDenyRulesRunInOrderAndStopBeforeAnyApprovalInEveryMode() async throws {
        var calls: [String] = []
        let miss = DenyRuleObserver { _ in calls.append("miss") }
        let block = DenyRuleObserver(matches: true) { _ in calls.append("block") }
        let unreachable = DenyRuleObserver(matches: true) { _ in calls.append("unreachable") }
        let approval = ApprovalEngineSpy()
        let service = try service(engines: [approval], denyRules: [miss, block, unreachable])
        await prompts.setAction(.approveOnce)
        for selection in [ApprovalMode.auto, .strict, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            calls = []
            await assertDecision(service, request(), false)
            XCTAssertEqual(calls, ["miss", "block"])
        }
        XCTAssertEqual(approval.evaluationCount, 0)
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testModeTransitionsAndExpiration() {
        let now = Date()
        XCTAssertEqual(mode.current(now: now), .auto)
        mode.select(.strict)
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(100_000)), .strict)
        mode.select(.approveEverything(until: now.addingTimeInterval(60)))
        XCTAssertEqual(mode.current(now: now), .approveEverything(until: now.addingTimeInterval(60)))
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(60)), .auto)
        mode.select(.approveEverything(until: now.addingTimeInterval(60)))
        mode.select(.strict)
        XCTAssertEqual(mode.current(now: now.addingTimeInterval(61)), .strict)
        mode.select(.auto)
        XCTAssertEqual(mode.current(), .auto)
        XCTAssertEqual(ApprovalModeState().current(), .auto)
    }

    func testAcceptMediaTypesAndQualityValues() {
        let r = request()
        for value in [
            "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*",
            "*/*; q=0.2", "APPLICATION/JSON; Q=1.000", "text/html;q=0",
            "image/gif; q=0.001, image/jpeg; q=0.999, text/event-stream",
            "application/json; q=1", "application/json; q=0.", "application/json; q=1.",
            "application/vnd.npm.install-v1+json", "application/json ; q = 0.80",
            "application/json; q=2", "application/json; q=1.001", "application/json; q=.8",
            "application/json; q=123.456", "application/json; q=999", "application/json; q=000.999",
            "application/json; q=", "application/json; q=.",
        ] {
            var withHeader = r
            withHeader.headers = [ProxyApprovalHeader(name: "Accept", value: value)]
            XCTAssertTrue(ApprovalHeaderMasker.isSafe(withHeader.headers[0], in: r), value)
            XCTAssertTrue(ApprovalHeaderMasker.maskSafeHeaders(for: withHeader, knownUserAgents: []).isEmpty, value)
        }
        for value in [
            "", ",", "application/json,", ",application/json", "application/json,,*/*",
            "text/custom", "application/json, text/custom", "application/json; charset=utf-8",
            "application/json; q=-0.1", "application/json; q=+0.8", "application/json; q=0.1234",
            "application/json; q=1234", "application/json; q=12.34.56", "application/json; q=1e2",
            "application/json; q=NaN", "application/json; q=0.8; q=0.9",
            "application/json; q=0.8; custom=value", "application/json; q=0.8=extra",
            "application/json; q=\"0.8\"", "application/json;",
        ] {
            var withHeader = r
            withHeader.headers = [ProxyApprovalHeader(name: "Accept", value: value)]
            XCTAssertFalse(ApprovalHeaderMasker.isSafe(withHeader.headers[0], in: r), value)
            XCTAssertEqual(ApprovalHeaderMasker.maskSafeHeaders(for: withHeader, knownUserAgents: []), withHeader.headers, value)
        }
    }

    func testCloudflareBotCookieIsMasked() {
        for value in [
            "__cf_bm=abc123-1793051291.6056817-1.0.1.1-ABC_def.ghi",
            " \t__cf_bm=rotated-token_123.456 \t",
            "__cf_bm=a",
            "__cf_bm=" + String(repeating: "a", count: 512),
        ] {
            var r = request()
            r.headers = [ProxyApprovalHeader(name: " cOoKiE ", value: value)]
            XCTAssertTrue(ApprovalHeaderMasker.isSafe(r.headers[0], in: r), value)
            XCTAssertTrue(ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: []).isEmpty, value)
        }
    }

    func testOtherMixedAndMalformedCookiesRemainVisible() {
        for value in [
            "", "__cf_bm", "__cf_bm=", "__CF_BM=token", "__cf_bm_extra=token",
            "session=secret", "cf_clearance=secret",
            "__cf_bm=token; session=secret", "session=secret; __cf_bm=token",
            "__cf_bm=token; __cf_bm=other", "__cf_bm=token;", "__cf_bm=token,session=secret",
            "__cf_bm=token\r\nX-Data: secret", "__cf_bm=token with spaces",
            "__cf_bm=" + String(repeating: "a", count: 513),
        ] {
            var r = request()
            r.headers = [ProxyApprovalHeader(name: "Cookie", value: value)]
            XCTAssertFalse(ApprovalHeaderMasker.isSafe(r.headers[0], in: r), value)
            XCTAssertEqual(ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: []), r.headers, value)
        }
    }

    func testAcceptEncodingQualityValues() {
        let r = request()
        for value in [
            "zstd;q=1.0, gzip;q=0.8, deflate;q=0.5",
            "gzip", "BR; Q=1.000, gzip ; q = 0.8", "gzip;q=0, deflate",
        ] {
            let header = ProxyApprovalHeader(name: "Accept-Encoding", value: value)
            XCTAssertTrue(ApprovalHeaderMasker.isSafe(header, in: r), value)
        }
        for value in [
            "", "gzip,", "gzip,,br", "custom;q=0.8", "gzip;custom=value",
            "gzip;q=0.1234", "gzip;q=secret", "gzip;q=0.8;custom=value",
            "gzip;q=0.8;q=0.9", "gzip;q=0.8=extra", "gzip;",
        ] {
            let header = ProxyApprovalHeader(name: "Accept-Encoding", value: value)
            XCTAssertFalse(ApprovalHeaderMasker.isSafe(header, in: r), value)
        }
    }

    func testCommonAcceptMediaTypesAreMasked() {
        let types = [
            "text/plain", "application/octet-stream", "application/xhtml+xml", "application/xml", "text/xml",
            "image/png", "image/webp", "image/avif", "image/svg+xml", "image/x-icon",
            "text/css", "text/javascript", "application/javascript", "application/wasm",
            "application/pdf", "application/zip", "application/gzip",
            "application/problem+json", "application/vnd.api+json", "application/vnd.github+json",
            "application/rss+xml", "application/atom+xml",
        ]
        for mediaType in types {
            for value in [mediaType, "\(mediaType.uppercased()); q=0.8, */*; q=0.2"] {
                var r = request()
                r.headers = [ProxyApprovalHeader(name: "Accept", value: value)]
                XCTAssertTrue(ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: []).isEmpty, value)
            }
        }
        for value in [
            "application/vnd.some-secret+json", "application/custom+xml", "image/*", "text/*",
            "image/png; custom=secret", "application/pdf, application/vnd.some-secret+json",
        ] {
            var r = request()
            r.headers = [ProxyApprovalHeader(name: "Accept", value: value)]
            XCTAssertEqual(ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: []), r.headers, value)
        }
    }

    func testYarnVersionRedirectAndMetadataSequenceInAuto() async throws {
        mode.select(.auto)
        let service = try service()
        await assertDecision(service, request("yarnpkg.com/latest-version"), true)
        var redirected = request("classic.yarnpkg.com/latest-version")
        redirected.headers = [ProxyApprovalHeader(name: "Referer", value: "https://yarnpkg.com/latest-version")]
        await assertDecision(service, redirected, true)
        var metadata = request("registry.yarnpkg.com/@scope%2fpackage")
        metadata.headers = [ProxyApprovalHeader(name: "Accept", value: "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*")]
        await assertDecision(service, metadata, true)
        await assertDecision(service, request("registry.yarnpkg.com/picocolors/-/picocolors-1.1.1.tgz"), true)
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
        XCTAssertFalse(store.contains("classic.yarnpkg.com", type: .domain))

        for url in ["yarnpkg.com/latest-version", "registry.yarnpkg.com/package", "classic.yarnpkg.com/other"] {
            var invalid = request(url)
            invalid.headers = redirected.headers
            XCTAssertFalse(YarnPkgApprovalEngine().evaluate(invalid).isApproved, url)
        }
        for referer in ["https://example.com/latest-version", "https://yarnpkg.com/latest-version?data=secret", "http://yarnpkg.com/latest-version"] {
            redirected.headers[0].value = referer
            await assertDecision(service, redirected, false)
        }
        XCTAssertFalse(ApprovalHeaderMasker.isSafe(
            ProxyApprovalHeader(name: "Referer", value: "https://yarnpkg.com/latest-version"), in: redirected
        ))
    }

    func testSharedNpmPackagePathValidation() {
        let valid = [
            "package", "@scope/package", "@scope%2fpackage", "@scope%2Fpackage",
            "package/-/package-1.2.3.tgz", "@scope/package/-/package-1.2.3-beta.1+build.tgz",
        ]
        let invalid = [
            "", ".", "..", "@./package", "@scope/..", "package/", "/package",
            "@scope%252fpackage", "package%2fother", "@scope%2fpackage%2fother",
            "package/1.2.3", "-/v1/search", "-/npm/v1/security/advisories/bulk",
            "package/-/other-1.2.3.tgz", "@scope/package/-/other-1.2.3.tgz",
            "package/-/package-.tgz", "package/-/package-1.2.3.zip",
            "package/-/package-1.2.3.tgz/extra", "@scope%2fpackage/-/package-1.2.3.tgz",
            "package?data=secret", "package#fragment", "package/-/package-1.0.tgz?sig=secret",
            "../package", "package/../other", "%2e%2e", "package\nother",
            String(repeating: "a", count: 129),
        ]
        for path in valid + invalid {
            let expected = valid.contains(path)
            XCTAssertEqual(NpmPackageURL.isPackagePath(path), expected, path)
            XCTAssertEqual(NpmApprovalEngine().evaluate(request("registry.npmjs.org/\(path)")).isApproved, expected, path)
            XCTAssertEqual(YarnPkgApprovalEngine().evaluate(request("registry.yarnpkg.com/\(path)")).isApproved, expected, path)
            for prefix in ["org/_packaging/feed", "org/project/_packaging/feed"] {
                XCTAssertEqual(AzureDevOpsNpmApprovalEngine().evaluate(request("pkgs.dev.azure.com/\(prefix)/npm/registry/\(path)")).isApproved, expected, path)
            }
        }
        for url in [
            "example.com/package", "registry.npmjs.org.evil.com/package",
            "registry.npmjs.org:443/package", "user@registry.npmjs.org/package",
            "https://registry.npmjs.org/package",
        ] {
            XCTAssertFalse(NpmApprovalEngine().evaluate(request(url)).isApproved, url)
        }
    }

    func testObservedNpmAndAzureTarballsInAuto() async throws {
        mode.select(.auto)
        let service = try service()
        let publicPackages = [
            "@ai-sdk/provider-utils/-/provider-utils-4.0.33.tgz", "@ai-sdk/react/-/react-3.0.216.tgz",
            "@ai-sdk/provider/-/provider-3.0.12.tgz", "ai/-/ai-6.0.214.tgz",
            "@ai-sdk/gateway/-/gateway-3.0.139.tgz", "@opentelemetry/api/-/api-1.9.1.tgz",
            "js-yaml/-/js-yaml-4.3.2.tgz", "semver/-/semver-7.8.5.tgz",
            "@emnapi/runtime/-/runtime-1.11.3.tgz", "js-yaml/-/js-yaml-3.15.2.tgz",
            "@typescript-eslint/eslint-plugin/-/eslint-plugin-8.46.3.tgz",
            "@eslint-community/regexpp/-/regexpp-4.12.2.tgz",
            "@typescript-eslint/scope-manager/-/scope-manager-8.46.3.tgz",
            "@typescript-eslint/type-utils/-/type-utils-8.46.3.tgz", "@typescript-eslint/utils/-/utils-8.46.3.tgz",
            "@typescript-eslint/visitor-keys/-/visitor-keys-8.46.3.tgz", "graphemer/-/graphemer-1.4.0.tgz",
            "ignore/-/ignore-7.0.6.tgz", "@typescript-eslint/types/-/types-8.46.3.tgz",
            "@typescript-eslint/typescript-estree/-/typescript-estree-8.46.3.tgz",
            "@eslint-community/eslint-utils/-/eslint-utils-4.10.1.tgz",
            "@typescript-eslint/project-service/-/project-service-8.46.3.tgz",
            "@typescript-eslint/tsconfig-utils/-/tsconfig-utils-8.46.3.tgz",
            "@typescript-eslint/tsconfig-utils/-/tsconfig-utils-8.65.0.tgz",
            "@typescript-eslint/types/-/types-8.65.0.tgz", "fast-glob/-/fast-glob-3.3.3.tgz",
            "micromatch/-/micromatch-4.0.8.tgz", "@typescript-eslint/parser/-/parser-8.46.3.tgz",
            "typescript-eslint/-/typescript-eslint-8.46.3.tgz",
        ]
        for path in publicPackages {
            await assertDecision(service, request("registry.npmjs.org/\(path)"), true)
        }
        for path in [
            "@bushelpowered%2fbushel-web-offers",
            "@bushelpowered/bushel-interfaces/-/bushel-interfaces-2.0.63.tgz",
            "@bushelpowered/bushel-web-offers/-/bushel-web-offers-5.4.4.tgz",
            "@bushelpowered/design-system/-/design-system-0.3.1.tgz",
            "@bushelpowered/wallet-components/-/wallet-components-3.3.7.tgz",
            "@bushelpowered/bushel-interfaces/-/bushel-interfaces-1.6.2081.tgz",
            "@bushelpowered/design-system/-/design-system-0.2.4.tgz",
        ] {
            await assertDecision(service, request("pkgs.dev.azure.com/bushelpowered/_packaging/bushelpowered/npm/registry/\(path)"), true)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
        await assertDecision(service, request("p2ovsblobprodcus312.blob.core.windows.net/container/artifact.blob?sp=r"), false)
        await assertDecision(service, request("p2ovsblobprodcus312.blob.core.windows.net:443", type: "CONNECT", method: "CONNECT"), false)
    }

    func testNpmOrdinaryApprovalDoesNotEstablishHeaderConsent() async throws {
        let service = try service(engines: [NpmApprovalEngine()])
        var r = request("registry.npmjs.org/package")
        r.headers = [ProxyApprovalHeader(name: "X-Custom", value: "approved")]
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        r.url = "registry.npmjs.org/package/-/package-1.0.tgz"
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
        XCTAssertEqual(presentations.first?.subtitle, "🚂 available: Npm")
    }

    func testAzureNpmConsentScopePrecedenceAndRestart() async throws {
        mode.select(.auto)
        let service = try service()
        let r = azureNpmRequest()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)

        var another = azureNpmRequest(organization: "other", project: "project", feed: "another")
        another.method = "HEAD"
        await assertDecision(service, another, true)
        mode.select(.strict)
        await assertDecision(service, another, false)
        await assertDecision(service, r, false)
        var otherProject = azureNpmRequest(project: "project")
        await assertDecision(service, otherProject, false)
        mode.select(.auto)
        await assertDecision(service, otherProject, true)
        otherProject.headers.append(ProxyApprovalHeader(name: "X-New", value: "data"))
        await assertDecision(service, otherProject, false)
        another.secrets.append("NEW_SECRET")
        await assertDecision(service, another, false)
        another = r
        another.headers[0].value = "Bearer changed"
        await assertDecision(service, another, false)

        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.first?.subtitle, "🚂 available: AzureDevOpsNpm")
        XCTAssertEqual(presentations.first?.actions.first { $0.id == .approveEngine }?.label, "🚂 Approve engine")
        let restarted = try self.service()
        await assertDecision(restarted, r, false)
    }

    func testNpmEnginesRestrictionsAndExplicitHeaderConsent() {
        for engine in [NpmApprovalEngine(), AzureDevOpsNpmApprovalEngine()] as [any ApprovalEngine] {
            let url = engine.name == "Npm" ? "registry.npmjs.org/package" : "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/package"
            var r = request(url)
            XCTAssertTrue(engine.evaluate(r).isApproved)
            r.headers = [ProxyApprovalHeader(name: "X-Custom", value: "approved")]
            XCTAssertFalse(engine.evaluate(r).isApproved)
            engine.onEngineApproved(r)
            XCTAssertTrue(engine.evaluate(r).isApproved)
            r.headers[0].value = "changed"
            XCTAssertFalse(engine.evaluate(r).isApproved)
            if case .needsConsent = engine.evaluate(r) {} else { XCTFail("New header must prompt") }
            for type in ["CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
                let invalid = request(url, type: type)
                XCTAssertFalse(engine.evaluate(invalid).isApproved)
                if case .notApplicable = engine.evaluate(invalid) {} else { XCTFail("Wrong request type matched") }
            }
            for method in ["POST", "PUT", "DELETE", "PATCH"] {
                XCTAssertFalse(engine.evaluate(request(url, method: method)).isApproved)
            }
            r = request(url)
            r.body = ProxyApprovalBody(text: "payload", warning: "")
            XCTAssertFalse(engine.evaluate(r).isApproved)
            r = request(url)
            r.secrets = ["UNAPPROVED"]
            XCTAssertFalse(engine.evaluate(r).isApproved)
        }
        var credentialed = azureNpmRequest()
        let azure = AzureDevOpsNpmApprovalEngine()
        XCTAssertFalse(azure.evaluate(credentialed).isApproved)
        azure.onEngineApproved(credentialed)
        credentialed.secrets = ["PAT", "PAT"]
        XCTAssertTrue(azure.evaluate(credentialed).isApproved)
        credentialed.secrets = ["pat"]
        XCTAssertFalse(azure.evaluate(credentialed).isApproved)

        for url in [
            "example.com/org/_packaging/feed/npm/registry/package",
            "pkgs.dev.azure.com:443/org/_packaging/feed/npm/registry/package",
            "pkgs.dev.azure.com/org/_packaging/feed/npm/v1/package",
            "pkgs.dev.azure.com/org/_packaging/feed/maven/registry/package",
            "pkgs.dev.azure.com/org/_packaging//npm/registry/package",
            "pkgs.dev.azure.com/../_packaging/feed/npm/registry/package",
            "pkgs.dev.azure.com/org/../_packaging/feed/npm/registry/package",
            "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/package?data=secret",
        ] {
            var invalid = request(url)
            invalid.secrets = ["UNAPPROVED"]
            XCTAssertFalse(azure.evaluate(invalid).isApproved, url)
            if case .notApplicable = azure.evaluate(invalid) {} else { XCTFail("Invalid feed URL matched: \(url)") }
            azure.onEngineApproved(invalid)
        }
        credentialed = azureNpmRequest()
        credentialed.secrets = ["UNAPPROVED"]
        XCTAssertFalse(azure.evaluate(credentialed).isApproved)
    }

    func testHeaderConsentAccumulatesAndEmptyHeadersNeedNoConsent() {
        for (engine, url) in [
            (NpmApprovalEngine() as any ApprovalEngine, "registry.npmjs.org/package"),
            (AzureDevOpsNpmApprovalEngine() as any ApprovalEngine, "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/package"),
        ] {
            var r = request(url)
            XCTAssertTrue(engine.evaluate(r).isApproved)
            let first = ProxyApprovalHeader(name: "X-First", value: "approved")
            let second = ProxyApprovalHeader(name: "X-Second", value: "also approved")
            for header in [first, second] {
                r.headers = [header]
                if case .needsConsent = engine.evaluate(r) {} else { XCTFail("New headers need consent") }
                engine.onEngineApproved(r)
                XCTAssertTrue(engine.evaluate(r).isApproved)
            }
            r.headers = [first, second, first]
            XCTAssertTrue(engine.evaluate(r).isApproved)
            r.headers = []
            XCTAssertTrue(engine.evaluate(r).isApproved)
            r.headers = [ProxyApprovalHeader(name: first.name, value: "changed")]
            XCTAssertFalse(engine.evaluate(r).isApproved)
        }
    }

    func testAzureNpmHeaderAndSecretConsentAreIndependentAndRuntimeOnly() {
        let engine = AzureDevOpsNpmApprovalEngine()
        let url = "pkgs.dev.azure.com/org/_packaging/feed/npm/registry/package"
        var headerOnly = request(url)
        headerOnly.headers = [ProxyApprovalHeader(name: "X-Custom", value: "approved")]
        var secretOnly = request(url)
        secretOnly.secrets = ["PAT"]
        XCTAssertTrue(engine.evaluate(request(url)).isApproved)
        XCTAssertFalse(engine.evaluate(headerOnly).isApproved)
        XCTAssertFalse(engine.evaluate(secretOnly).isApproved)
        engine.onEngineApproved(headerOnly)
        XCTAssertTrue(engine.evaluate(headerOnly).isApproved)
        XCTAssertFalse(engine.evaluate(secretOnly).isApproved)
        engine.onEngineApproved(secretOnly)

        var combined = headerOnly
        combined.secrets = ["PAT", "PAT"]
        combined.url = "pkgs.dev.azure.com/other/project/_packaging/another/npm/registry/package"
        XCTAssertTrue(engine.evaluate(combined).isApproved)
        let fresh = AzureDevOpsNpmApprovalEngine()
        XCTAssertFalse(fresh.evaluate(combined).isApproved)
        XCTAssertTrue(fresh.evaluate(request(url)).isApproved)
        combined.secrets.append("NEW_SECRET")
        XCTAssertFalse(engine.evaluate(combined).isApproved)
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
            (NpmApprovalEngine(), "registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", false),
        ]
        for (engine, url, supportsHead) in patterns {
            var r = request(url)
            XCTAssertTrue(engine.evaluate(r).isApproved, engine.name)
            r.method = "HEAD"
            XCTAssertEqual(engine.evaluate(r).isApproved, supportsHead, engine.name)
            r.method = "POST"
            XCTAssertFalse(engine.evaluate(r).isApproved, engine.name)
            r = request(url)
            r.body = ProxyApprovalBody(text: "payload", warning: "")
            XCTAssertFalse(engine.evaluate(r).isApproved, engine.name)
            r = request(url)
            r.secrets = ["TOKEN"]
            XCTAssertFalse(engine.evaluate(r).isApproved, engine.name)
            for type in ["CONNECT", "TCP_CONNECT", "GIT", "WEBSOCKET"] {
                XCTAssertFalse(engine.evaluate(request(url, type: type)).isApproved, engine.name)
            }
            XCTAssertFalse(engine.evaluate(request("example.com/arbitrary")).isApproved, engine.name)
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

    func testDockerHubLayerDownloadHeadersInAuto() async throws {
        let service = try service(engines: [DockerHubApprovalEngine()])
        mode.select(.auto)
        let digest = "6dddcbf9098d2a4da10b4e38e4005483d63c3a2607dc0c465edd0f8499bb6cf3"
        let blob = "registry-1.docker.io/v2/library/mysql/blobs/sha256:\(digest)"
        for url in [
            blob,
            "production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/6d/\(digest)/data?Expires=1791820895&Signature=example~__&Key-Pair-Id=K2C9XPB6FLAKUF",
        ] {
            var r = request(url)
            r.headers = [
                ProxyApprovalHeader(name: "Accept-Encoding", value: "zstd;q=1.0, gzip;q=0.8, deflate;q=0.5"),
                ProxyApprovalHeader(name: "Accept", value: "application/vnd.oci.image.layer.v1.tar+gzip, */*"),
                ProxyApprovalHeader(name: "Baggage", value: "trigger=api"),
                ProxyApprovalHeader(name: "Referer", value: "https://\(blob)"),
            ]
            await assertDecision(service, r, true)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testDockerHubConfigAndAttestationBlobHeadersInAuto() async throws {
        let service = try service(engines: [DockerHubApprovalEngine()])
        mode.select(.auto)
        let digest = String(repeating: "a", count: 64)
        for mediaType in [
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.in-toto+json",
            "application/vnd.docker.container.image.v1+json",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
        ] {
            var r = request("registry-1.docker.io/v2/library/alpine/blobs/sha256:\(digest)")
            r.headers = [
                ProxyApprovalHeader(name: "Accept", value: "\(mediaType), */*"),
            ]
            await assertDecision(service, r, true)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testDockerHubLayerHeadersRemainNarrow() {
        let engine = DockerHubApprovalEngine()
        let digest = String(repeating: "a", count: 64)
        var r = request("registry-1.docker.io/v2/library/mysql/blobs/sha256:\(digest)")
        for url in [
            r.url,
            "registry-1.docker.io/v2/library/mysql/manifests/latest",
            "registry-1.docker.io/v2/library/mysql/referrers/sha256:\(digest)",
            "auth.docker.io/token?scope=repository%3Alibrary%2Fmysql%3Apull&service=registry.docker.io",
            "production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/\(digest)/data?Expires=1791820895&Signature=example~__&Key-Pair-Id=K2C9XPB6FLAKUF",
        ] {
            r.headers = [ProxyApprovalHeader(name: "Referer", value: "https://\(url)")]
            XCTAssertTrue(engine.evaluate(r).isApproved, url)
        }
        for (name, value) in [
            ("Baggage", "trigger=other"),
            ("Baggage", "trigger=api,secret=value"),
            ("Referer", "http://\(r.url)"),
            ("Referer", "https://example.com/v2/library/mysql/blobs/sha256:\(digest)"),
            ("Referer", "https://\(r.url)?secret=value"),
            ("Referer", "https://\(r.url)#secret"),
            ("Referer", "https://registry-1.docker.io/v2/library/mysql/blobs/uploads/"),
            ("Referer", "https://registry-1.docker.io/v2/library/mysql/blobs/sha256:invalid"),
        ] {
            r.headers = [ProxyApprovalHeader(name: name, value: value)]
            XCTAssertFalse(engine.evaluate(r).isApproved, value)
        }
        r = request("example.com/arbitrary")
        r.headers = [ProxyApprovalHeader(name: "Baggage", value: "trigger=api")]
        XCTAssertEqual(engine.headersForApproval(r), r.headers)
    }

    func testDockerHubHeaderConsentAndTokenRotation() {
        let engine = DockerHubApprovalEngine()
        var r = request("registry-1.docker.io/v2/library/mysql/manifests/8.4")
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Basic arbitrary")]
        XCTAssertTrue(engine.evaluate(r).isApproved)

        r.headers.append(ProxyApprovalHeader(name: "X-Custom", value: "approved"))
        XCTAssertFalse(engine.evaluate(r).isApproved)
        engine.onEngineApproved(r)
        r.headers[0].value = "Bearer rotated-token"
        XCTAssertTrue(engine.evaluate(r).isApproved)
        r.headers[1].value = "changed"
        XCTAssertFalse(engine.evaluate(r).isApproved)
        if case .needsConsent = engine.evaluate(r) {} else { XCTFail("Unknown headers need consent") }

        let otherEngine = NixCacheApprovalEngine()
        var other = request()
        other.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer token")]
        XCTAssertFalse(otherEngine.evaluate(other).isApproved)
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
            XCTAssertTrue(engine.evaluate(r).isApproved)
            r.headers.removeLast()
        }
        for value in ["", "text/custom", "application/vnd.oci.image.index.v1+json,", "application/vnd.oci.image.index.v1+json; custom=value", "application/vnd.in-toto+json, text/custom", "application/vnd.oci.image.config.v1+json; custom=value"] {
            var invalid = r
            invalid.headers.append(ProxyApprovalHeader(name: "Accept", value: value))
            XCTAssertFalse(engine.evaluate(invalid).isApproved)
        }
        var invalid = r
        invalid.secrets = ["TOKEN"]
        XCTAssertFalse(engine.evaluate(invalid).isApproved)
        invalid = r
        invalid.body = ProxyApprovalBody(text: "payload", warning: "")
        XCTAssertFalse(engine.evaluate(invalid).isApproved)
        invalid = r
        invalid.method = "POST"
        XCTAssertFalse(engine.evaluate(invalid).isApproved)
        for url in ["example.com/v2/library/mysql/manifests/8.4", "registry-1.docker.io/v2/library/mysql/blobs/uploads/"] {
            invalid = r
            invalid.url = url
            XCTAssertFalse(engine.evaluate(invalid).isApproved)
        }
    }

    func testAutoDoesNotPersistDomainTrust() async throws {
        let service = try service()
        mode.select(.auto)
        await assertDecision(service, request(), true)
        XCTAssertFalse(store.contains("cache.nixos.org", type: .domain))
        mode.select(.strict)
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
        mode.select(.strict)
        await assertDecision(service, r, false)
        mode.select(.auto)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
    }

    func testNewConnectAlwaysPromptsInEveryMode() async throws {
        let service = try service()
        var r = request("cache.nixos.org:443", type: "CONNECT", method: "CONNECT")
        r.domain = "cache.nixos.org"
        for selection in [ApprovalMode.strict, .auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, r, false)
        }
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        XCTAssertTrue(store.contains(r.domain, type: .domain))
        await prompts.setAction(.deny)
        for selection in [ApprovalMode.strict, .auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, r, true)
        }
        mode.select(.strict)
        await assertDecision(service, request(), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 5)
    }

    func testDeniedTrafficCannotBeApprovedByModes() async throws {
        let service = try service()
        for selection in [ApprovalMode.strict, .auto, .approveEverything(until: Date().addingTimeInterval(60))] {
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
        mode.select(.strict)
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, r, true)

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
        XCTAssertFalse(engine.evaluate(chatGPTRequest()).isApproved)
        XCTAssertFalse(engine.evaluate(chatGPTRequest(accountID: "another-account")).isApproved)

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
        XCTAssertTrue(engine.evaluate(r).isApproved)
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
            XCTAssertFalse(engine.evaluate(invalid).isApproved)
            if case .notApplicable = engine.evaluate(invalid) {} else { XCTFail("Invalid session matched") }
        }
    }

    func testSecretRequestPermanentApprovalSurvivesRestartButNotStrict() async throws {
        let service = try service()
        let r = secretRequest()
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, true)
        mode.select(.strict)
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, r, true)

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
        XCTAssertEqual(presentations.count, 2)
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
        XCTAssertFalse(engine.evaluate(r).isApproved)
        engine.onEngineApproved(r)
        var reordered = r
        reordered.secrets = ["SECOND", "PAT", "PAT"]
        XCTAssertTrue(engine.evaluate(reordered).isApproved)

        var changed = r
        changed.method = "GET"
        XCTAssertFalse(engine.evaluate(changed).isApproved)
        changed.method = "post"
        XCTAssertFalse(engine.evaluate(changed).isApproved)
        for url in ["other.example/auth/exchange/pat", "build-cache.bushelops.com/auth/exchange/other", r.url + "?extra=1", r.url + "/"] {
            changed = r
            changed.url = url
            XCTAssertFalse(engine.evaluate(changed).isApproved)
        }
        for secrets in [["PAT"], ["SECOND"], ["PAT", "SECOND", "THIRD"], ["different"], ["pat", "SECOND"]] {
            changed = r
            changed.secrets = secrets
            XCTAssertFalse(engine.evaluate(changed).isApproved)
        }

        // Structured keys must not collide when secret names contain separators.
        r.secrets = ["a\nb", "c"]
        engine.onEngineApproved(r)
        changed = r
        changed.secrets = ["a", "b\nc"]
        XCTAssertFalse(engine.evaluate(changed).isApproved)
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
            XCTAssertFalse(engine.evaluate(invalid).isApproved)
            if case .notApplicable = engine.evaluate(invalid) {} else { XCTFail("Invalid secret request matched") }
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

    func testMavenArtifactValidationAcceptsArtifactsAndChecksumSidecars() {
        let publicEngine = MavenRepositoryApprovalEngine()
        let azureEngine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        let publicPrefixes = ["repo.maven.apache.org/maven2/", "plugins.gradle.org/m2/"]
        let azurePrefix = "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/"
        for filename in ["lib-1.0.pom", "lib-1.0.module", "lib-1.0.jar", "lib-1.0-sources.jar"] {
            for suffix in ["", ".sha1", ".md5", ".sha256", ".sha512"] {
                for method in ["GET", "HEAD"] {
                    let path = "org/example/lib/1.0/" + filename + suffix
                    for prefix in publicPrefixes {
                        XCTAssertTrue(publicEngine.matches(request(prefix + path, method: method)), path)
                    }
                    let azure = request(azurePrefix + path, method: method)
                    if case .needsConsent = azureEngine.evaluate(azure) {} else { XCTFail(path) }
                }
            }
        }
        for path in [
            "org/example/lib/1.0/other-1.0.jar", "org/example/lib/1.0/lib-2.0.jar",
            "org/example/lib/1.0/lib-1.0.txt", "org/example/lib/1.0/lib-1.0.JAR",
            "org/example/lib/1.0/lib-1.0.jar.asc", "org/example/lib/1.0/lib-1.0.jar.sha999",
            "org/example/lib/1.0/lib-1.0.jar.sha1.sha1", "org//lib/1.0/lib-1.0.jar",
            "lib/1.0/lib-1.0.jar", "org/example/lib/1.0/", "/org/example/lib/1.0/lib-1.0.jar",
            "org/%65xample/lib/1.0/lib-1.0.jar", "org/example/lib/1.0/lib-1.0.jar?x=1",
            "org/example/lib/1.0/lib-1.0.jar#fragment",
        ] {
            for prefix in publicPrefixes {
                XCTAssertFalse(publicEngine.matches(request(prefix + path)), path)
            }
            if case .notApplicable = azureEngine.evaluate(request(azurePrefix + path)) {} else { XCTFail(path) }
        }
        for segment in [".", ".."] {
            for path in [
                "\(segment)/example/lib/1.0/lib-1.0.jar",
                "org/\(segment)/lib/1.0/lib-1.0.jar",
                "org/example/\(segment)/1.0/\(segment)-1.0.jar",
                "org/example/lib/\(segment)/lib-\(segment).jar",
            ] {
                for prefix in publicPrefixes {
                    XCTAssertFalse(publicEngine.matches(request(prefix + path)), path)
                }
                if case .notApplicable = azureEngine.evaluate(request(azurePrefix + path)) {} else { XCTFail(path) }
            }
        }
    }

    func testMavenRepositoryKeepsExactURLMatchingAndCrossRepositoryHeaderConsent() {
        let engine = MavenRepositoryApprovalEngine()
        var r = request("repo.maven.apache.org/maven2/org/example/lib/1.0/lib-1.0.jar")
        r.headers = [ProxyApprovalHeader(name: "X-Build", value: "build")]
        engine.onEngineApproved(r)
        r.url = "plugins.gradle.org/m2/org/example/lib/1.0/lib-1.0.jar"
        XCTAssertTrue(engine.evaluate(r).isApproved)
        r.headers[0].value = "changed"
        XCTAssertFalse(engine.evaluate(r).isApproved)

        let url = "repo.maven.apache.org/maven2/org/example/lib/1.0/lib-1.0.jar"
        XCTAssertTrue(engine.matches(request(" \n" + url + "\t")))
        for invalid in [
            url.replacingOccurrences(of: "repo.maven.apache.org", with: "REPO.MAVEN.APACHE.ORG"),
            url.replacingOccurrences(of: "repo.maven.apache.org", with: "repo.maven.apache.org:443"),
            "https://" + url,
        ] {
            XCTAssertFalse(engine.matches(request(invalid)), invalid)
        }
        var invalid = request(url)
        invalid.secrets = ["PAT"]
        XCTAssertFalse(engine.matches(invalid))
        invalid = request(url, method: "POST")
        XCTAssertFalse(engine.matches(invalid))
        invalid = request(url, type: "CONNECT")
        XCTAssertFalse(engine.matches(invalid))
        invalid = request(url)
        invalid.body = ProxyApprovalBody(text: "", warning: "")
        XCTAssertFalse(engine.matches(invalid))
    }

    func testGradlePluginArtifactValidationRetainsHashLayout() {
        let engine = MavenRepositoryApprovalEngine()
        let hash = String(repeating: "a", count: 32)
        let prefix = "plugins-artifacts.gradle.org/org/example/lib/1.0/"
        for ext in ["pom", "module", "jar"] {
            for suffix in ["", ".sha1", ".md5", ".sha256", ".sha512"] {
                XCTAssertTrue(engine.matches(request(prefix + hash + "/lib-1.0." + ext + suffix)))
            }
        }
        for segment in [".", ".."] {
            for path in [
                "org/\(segment)/lib/1.0/\(hash)/lib-1.0.jar",
                "org/example/\(segment)/1.0/\(hash)/\(segment)-1.0.jar",
                "org/example/lib/\(segment)/\(hash)/lib-\(segment).jar",
            ] {
                XCTAssertFalse(engine.matches(request("plugins-artifacts.gradle.org/" + path)), path)
            }
        }
        for path in [
            String(hash.dropLast()) + "/lib-1.0.jar", "not-a-hash/lib-1.0.jar",
            hash + "/other-1.0.jar", hash + "/lib-1.0.txt", "lib-1.0.jar",
            hash + "/other-1.0.jar.sha1", hash + "/lib-1.0.txt.sha1",
            hash + "/lib-1.0.jar.sha1.sha256", hash + "/lib-1.0.jar.sha999",
        ] {
            XCTAssertFalse(engine.matches(request(prefix + path)), path)
        }
    }

    func testAzureMavenPromptTakesPrecedenceOverSecretRequestPrompt() async throws {
        let service = try service()
        await assertDecision(service, azureMavenRequest(), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.first?.title, "Outbound")
        XCTAssertEqual(presentations.first?.subtitle, "🚂 available: AzureDevOpsMaven")
        XCTAssertEqual(presentations.first?.actions.first { $0.id == .approveEngine }?.label, "🚂 Approve engine")
        XCTAssertTrue(presentations.first?.warnings.contains { $0.contains("permanently") } == true)
        XCTAssertEqual(presentations.first?.sections.first { $0.title == "Feed" }?.text, "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/")
    }

    func testAzureMavenMultipleFeedsPersistButNeverBypassStrict() async throws {
        let service = try service()
        mode.select(.auto)
        let r = azureMavenRequest()
        var otherFeed = azureMavenRequest(organization: "another-org", project: "project", feed: "another-feed")
        otherFeed.method = "HEAD"
        for feed in [r, otherFeed] {
            await prompts.setAction(.deny)
            await assertDecision(service, feed, false)
            await prompts.setAction(.approveEngine)
            await assertDecision(service, feed, true)
        }
        await prompts.setAction(.deny)
        for selection in [ApprovalMode.auto, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, r, true)
            await assertDecision(service, otherFeed, true)
        }
        mode.select(.auto)
        var changed = otherFeed
        changed.secrets.append("NEW_SECRET")
        await assertDecision(service, changed, false)
        changed = otherFeed
        changed.headers.append(ProxyApprovalHeader(name: "X-New", value: "new value"))
        await assertDecision(service, changed, false)

        store = try RecognizedElementStore(directoryURL: directory)
        let restartedService = try self.service()
        for feed in [r, otherFeed] {
            await assertDecision(restartedService, feed, true)
        }
        mode.select(.strict)
        for feed in [r, otherFeed] {
            await assertDecision(restartedService, feed, false)
        }
    }

    func testAzureMavenConsentIsIsolatedByOrganizationProjectAndFeed() throws {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        let r = azureMavenRequest(project: "project")
        engine.onEngineApproved(r)
        for other in [
            azureMavenRequest(),
            azureMavenRequest(project: "other-project"),
            azureMavenRequest(project: "project", feed: "other-feed"),
            azureMavenRequest(organization: "other-org", project: "project"),
        ] {
            XCTAssertFalse(engine.evaluate(other).isApproved, other.url)
            if case .needsConsent = engine.evaluate(other) {} else { XCTFail(other.url) }
            var readOnly = other
            readOnly.headers = []
            readOnly.secrets = []
            XCTAssertFalse(engine.evaluate(readOnly).isApproved, other.url)
        }

        var other = azureMavenRequest(project: "other-project")
        other.headers = [ProxyApprovalHeader(name: "X-Other", value: "other")]
        other.secrets = ["OTHER"]
        engine.onEngineApproved(other)
        var changed = r
        changed.headers = other.headers
        changed.secrets = other.secrets
        XCTAssertFalse(engine.evaluate(changed).isApproved)
        changed = other
        changed.headers = r.headers
        changed.secrets = r.secrets
        XCTAssertFalse(engine.evaluate(changed).isApproved)

        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: try RecognizedElementStore(directoryURL: directory))
        XCTAssertTrue(restarted.evaluate(r).isApproved)
        XCTAssertTrue(restarted.evaluate(other).isApproved)
        XCTAssertFalse(restarted.evaluate(changed).isApproved)
    }

    func testAzureMavenUnauthenticatedFeedStillRequiresPersistedConsent() throws {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        var r = azureMavenRequest()
        r.headers = []
        r.secrets = []
        XCTAssertFalse(engine.evaluate(r).isApproved)
        engine.onEngineApproved(r)
        XCTAssertTrue(engine.evaluate(r).isApproved)
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        XCTAssertTrue(restarted.evaluate(r).isApproved)
        var other = r
        other.url = azureMavenRequest(project: "project").url
        XCTAssertFalse(restarted.evaluate(other).isApproved)
        r.secrets = ["NEW_SECRET"]
        XCTAssertFalse(restarted.evaluate(r).isApproved)
    }

    func testAzureMavenProjectScopedKotlinArtifacts() throws {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        let prefix = "pkgs.dev.azure.com/bushelpowered/bidl/_packaging/bidl/maven/v1/dev/bidl/kotlin-core-jvm/0.58/kotlin-core-jvm-0.58"
        var r = azureMavenRequest(organization: "bushelpowered", project: "bidl", feed: "bidl")
        r.url = prefix + ".module"
        XCTAssertFalse(engine.evaluate(r).isApproved)
        if case .needsConsent = engine.evaluate(r) {} else { XCTFail("Project feed did not match") }
        engine.onEngineApproved(r)
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: try RecognizedElementStore(directoryURL: directory))
        for ext in ["module", "jar", "pom", "jar.sha256"] {
            for method in ["GET", "HEAD"] {
                r.url = prefix + "." + ext
                r.method = method
                XCTAssertTrue(engine.evaluate(r).isApproved, r.url)
                XCTAssertTrue(restarted.evaluate(r).isApproved, r.url)
            }
        }
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
        XCTAssertTrue(try store.elements(type: .approvedAzureDevOpsMavenFeed).isEmpty)
        let restartedService = try self.service()
        await assertDecision(restartedService, r, false)
    }

    func testAzureMavenChecksumSidecarsRequireSupportedArtifacts() {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        let r = azureMavenRequest()
        engine.onEngineApproved(r)
        let prefix = "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/"
        for artifact in ["lib-1.0.pom", "lib-1.0.module", "lib-1.0.jar", "lib-1.0-sources.jar"] {
            for checksum in ["sha1", "md5", "sha256", "sha512"] {
                for method in ["GET", "HEAD"] {
                    var valid = r
                    valid.url = prefix + artifact + "." + checksum
                    valid.method = method
                    XCTAssertTrue(engine.evaluate(valid).isApproved, valid.url)
                }
            }
        }
        for filename in [
            "other-1.0.pom.sha1", "lib-2.0.jar.sha1", "lib-1.0.txt.sha1",
            "lib-1.0.sha1", "lib-1.0.pom.sha1.sha1", "lib-1.0.pom.sha256.sha1",
            "lib-1.0.jar.asc", "lib-1.0.jar.sha999",
        ] {
            var invalid = r
            invalid.url = prefix + filename
            XCTAssertFalse(engine.evaluate(invalid).isApproved, invalid.url)
            if case .notApplicable = engine.evaluate(invalid) {} else { XCTFail(invalid.url) }
        }
    }

    func testAzureMavenAutoValidatesPatternHeadersAndSecretNames() {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        var readOnly = azureMavenRequest()
        readOnly.headers = []
        readOnly.secrets = []
        XCTAssertFalse(engine.evaluate(readOnly).isApproved)
        let r = azureMavenRequest()
        XCTAssertFalse(engine.evaluate(r).isApproved)
        engine.onEngineApproved(r)
        XCTAssertTrue(engine.evaluate(r).isApproved)

        var another = azureMavenRequest()
        another.secrets = ["SECOND"]
        XCTAssertFalse(engine.evaluate(another).isApproved)
        engine.onEngineApproved(another)
        another.secrets = ["PAT", "SECOND", "PAT"]
        XCTAssertTrue(engine.evaluate(another).isApproved)
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        XCTAssertTrue(restarted.evaluate(another).isApproved)
        XCTAssertTrue(engine.evaluate(readOnly).isApproved)
        XCTAssertTrue(restarted.evaluate(readOnly).isApproved)
        another.secrets = ["pat"]
        XCTAssertFalse(engine.evaluate(another).isApproved)
        another = r
        another.headers = [ProxyApprovalHeader(name: "Authorization", value: "different value")]
        XCTAssertFalse(engine.evaluate(another).isApproved)

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
            "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar.sha999",
            "pkgs.dev.azure.com/org//_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/../_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/../project/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/project/_packaging/../maven/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/project/extra/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/project/_packaging/feed/maven/v1/org/example/lib/1.0/other-1.0.jar",
            "pkgs.dev.azure.com/org/project/_packaging/feed/maven/v1/org/example/lib/1.0/lib-1.0.jar?extra=1",
            "pkgs.dev.azure.com/org/project/_packaging/feed/maven/v1/../org/example/lib/1.0/lib-1.0.jar",
            "pkgs.dev.azure.com/org/_packaging/feed/maven/v1/org/./example/lib/1.0/lib-1.0.jar",
        ] {
            invalid = r
            invalid.url = url
            invalidRequests.append(invalid)
        }
        for invalid in invalidRequests {
            XCTAssertFalse(engine.evaluate(invalid).isApproved)
            if case .notApplicable = engine.evaluate(invalid) {} else { XCTFail("Invalid Maven request matched") }
            var invalidConsent = invalid
            invalidConsent.secrets = ["UNAPPROVED"]
            engine.onEngineApproved(invalidConsent)
        }
        another = r
        another.secrets = ["UNAPPROVED"]
        XCTAssertFalse(engine.evaluate(another).isApproved)
    }

    func testAzureMavenStoreDoesNotPersistHeaderValues() throws {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        var r = azureMavenRequest()
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer sensitive-token")]
        engine.onEngineApproved(r)
        let elements = try store.elements(type: .approvedAzureDevOpsMavenFeed)
        XCTAssertEqual(elements.count, 1)
        let metadata = try XCTUnwrap(elements.first)
        XCTAssertTrue(metadata.contains("PAT"))
        XCTAssertTrue(metadata.contains("_packaging"))
        XCTAssertFalse(metadata.contains("sensitive-token"))
        XCTAssertFalse(metadata.contains("Bearer"))
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        XCTAssertTrue(restarted.evaluate(r).isApproved)
        r.headers = [ProxyApprovalHeader(name: "Authorization", value: "Bearer changed-token")]
        XCTAssertFalse(restarted.evaluate(r).isApproved)
    }

    func testAzureMavenPersistenceFailureKeepsOnlyRuntimeConsent() throws {
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        try FileManager.default.removeItem(at: directory)
        try Data("not a directory".utf8).write(to: directory)
        let r = azureMavenRequest()
        engine.onEngineApproved(r)
        XCTAssertTrue(engine.evaluate(r).isApproved)
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        XCTAssertFalse(restarted.evaluate(r).isApproved)
    }

    func testRecognizedElementEnumerationValidatesMarkersAndTypes() throws {
        try store.insert("not valid JSON", type: .approvedAzureDevOpsMavenFeed)
        try store.insert("example.com", type: .domain)
        let engine = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        let r = azureMavenRequest()
        XCTAssertFalse(engine.evaluate(r).isApproved)
        engine.onEngineApproved(r)
        XCTAssertEqual(try store.elements(type: .approvedAzureDevOpsMavenFeed).count, 2)
        XCTAssertEqual(try store.elements(type: .domain), ["example.com"])
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        for file in files {
            let data = try Data(contentsOf: file)
            if String(decoding: data, as: UTF8.self).contains("_packaging") {
                try data.write(to: directory.appendingPathComponent("wrong-hash"))
                try Data("approvedAzureDevOpsMavenFeed\ncorrupted".utf8).write(to: file)
            }
        }
        XCTAssertEqual(try store.elements(type: .approvedAzureDevOpsMavenFeed), ["not valid JSON"])
        let restarted = AzureDevOpsMavenApprovalEngine(recognizedElementStore: store)
        XCTAssertFalse(restarted.evaluate(r).isApproved)
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
        XCTAssertFalse(engine.evaluate(secretRequest()).isApproved)
    }

    func testQueuedRequestIsReevaluatedAfterModeChange() async throws {
        mode.select(.strict)
        let promptStarted = AsyncSignal()
        let releasePrompt = AsyncSignal()
        let secondEvaluated = AsyncSignal()
        let engine = TestPatternEngine()
        let secondRequest = request()
        let observer = DenyRuleObserver { r in
            if r.id == secondRequest.id {
                Task { await secondEvaluated.signal() }
            }
        }
        let prompts = self.prompts!
        let service = try ApprovalService(
            denyRules: [observer], engines: [engine], recognizedElementStore: store,
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

    func testStrictPromptsForEveryRequestWithoutInvokingApprovalEngines() async throws {
        let engine = ApprovalEngineSpy()
        let service = try service(engines: [engine])
        mode.select(.strict)
        let requests = [
            request(),
            request("example.com/repository", type: "GIT"),
            chatGPTRequest(),
            secretRequest(),
            azureMavenRequest(),
            azureNpmRequest(),
        ]
        await prompts.setAction(.approveOnce)
        for r in requests {
            await assertDecision(service, r, true)
            await assertDecision(service, r, true)
            XCTAssertTrue(store.contains(r.domain, type: .domain))
        }
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, requests.count * 2)
        for presentation in presentations {
            XCTAssertEqual(presentation.actions.map(\.id), [.deny, .approveOnce])
            XCTAssertNil(presentation.subtitle)
        }
        XCTAssertEqual(engine.evaluationCount, 0)
        XCTAssertEqual(engine.approvedRequests, 0)
    }

    func testStrictLearnsDomainAndUserAgentButNotEngineConsent() async throws {
        let engine = NixCacheApprovalEngine()
        let service = try service(engines: [engine])
        var r = request()
        r.headers = [
            ProxyApprovalHeader(name: "User-Agent", value: "new-agent"),
            ProxyApprovalHeader(name: "X-Custom", value: "not consented"),
        ]
        r.body = ProxyApprovalBody(text: "payload", warning: "Body warning")
        r.secrets = ["TOKEN"]
        mode.select(.strict)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        XCTAssertTrue(store.contains("new-agent", type: .userAgent))
        XCTAssertTrue(store.contains(r.domain, type: .domain))
        XCTAssertTrue(try store.elements(type: .autoApprovedSecretRequest).isEmpty)
        let presentations = await prompts.presentations
        let presentation = try XCTUnwrap(presentations.first)
        XCTAssertTrue(presentation.warnings.contains("Body warning"))
        XCTAssertEqual(presentation.sections.first { $0.title == "Body" }?.text, "payload")
        XCTAssertEqual(presentation.sections.first { $0.title == "Secrets" }?.text, "TOKEN")
        XCTAssertTrue(presentation.sections.first { $0.title == "Headers" }?.text.contains("new-agent") == true)

        r.body = nil
        r.secrets = []
        mode.select(.auto)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        XCTAssertFalse(engine.evaluate(r).isApproved)
    }

    func testStrictConnectApprovalLearnsDomainAndUserAgent() async throws {
        mode.select(.strict)
        let service = try service()
        var r = request("example.com:443", type: "CONNECT", method: "CONNECT")
        r.domain = "example.com"
        r.headers = [ProxyApprovalHeader(name: "User-Agent", value: "connect-agent")]
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        XCTAssertTrue(store.contains(r.domain, type: .domain))
        XCTAssertTrue(store.contains("connect-agent", type: .userAgent))
        await prompts.setAction(.deny)
        await assertDecision(service, r, true)
        await assertDecision(service, request("example.com/request"), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
    }

    func testStrictReusesPersistedDomainsAndUserAgentsWithoutBypassingRequestPrompts() async throws {
        mode.select(.strict)
        let service = try service()
        var r = request()
        r.headers = [ProxyApprovalHeader(name: "User-Agent", value: "remembered-agent")]
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)

        store = try RecognizedElementStore(directoryURL: directory)
        let restarted = try self.service()
        await prompts.setAction(.deny)
        await assertDecision(restarted, r, false)
        var presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
        XCTAssertNil(presentations.last?.sections.first { $0.title == "Headers" })
        XCTAssertFalse(presentations.last?.warnings.contains("Warning: new domain.") == true)

        var connect = request(r.domain + ":443", type: "CONNECT", method: "CONNECT")
        connect.domain = r.domain
        await assertDecision(restarted, connect, true)
        mode.select(.auto)
        await assertDecision(restarted, r, true)
        presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)

        mode.select(.strict)
        r.headers[0].value = "unapproved-agent"
        await assertDecision(restarted, r, false)
        presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
        XCTAssertEqual(presentations.last?.sections.first { $0.title == "Headers" }?.text, "User-Agent: unapproved-agent")
        XCTAssertFalse(store.contains("unapproved-agent", type: .userAgent))
    }

    func testStrictDenialDoesNotLearnDomainOrUserAgent() async throws {
        mode.select(.strict)
        let service = try service()
        var r = request("new.example/request")
        r.headers = [ProxyApprovalHeader(name: "User-Agent", value: "denied-agent")]
        await assertDecision(service, r, false)
        XCTAssertFalse(store.contains(r.domain, type: .domain))
        XCTAssertFalse(store.contains("denied-agent", type: .userAgent))
        var connect = request(r.domain + ":443", type: "CONNECT", method: "CONNECT")
        connect.domain = r.domain
        await assertDecision(service, connect, false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
    }

    func testRawTCPAlwaysRequiresOneShotApprovalInEveryMode() async throws {
        let engine = ApprovalEngineSpy()
        let service = try service(engines: [engine])
        var r = request("example.com:443", type: "TCP_CONNECT", method: "CONNECT")
        r.domain = "example.com"
        try store.insert(r.domain, type: .domain)
        for selection in [ApprovalMode.auto, .strict, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await prompts.setAction(.approveOnce)
            await assertDecision(service, r, true)
            await prompts.setAction(.deny)
            await assertDecision(service, r, false)
        }
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 6)
        for presentation in presentations {
            XCTAssertEqual(presentation.actions.map(\.id), [.deny, .approveOnce])
            XCTAssertTrue(presentation.warnings.contains("Warning: raw TCP payload."))
        }
        XCTAssertEqual(engine.evaluationCount, 0)
        XCTAssertEqual(engine.approvedRequests, 0)
    }

    func testStrictCannotEstablishEngineConsent() async throws {
        mode.select(.strict)
        let service = try service()
        await prompts.setAction(.approveEngine)
        await assertDecision(service, secretRequest(), false)
        XCTAssertTrue(try store.elements(type: .autoApprovedSecretRequest).isEmpty)
        mode.select(.auto)
        await prompts.setAction(.deny)
        await assertDecision(service, secretRequest(), false)
    }

    func testSavedForeverRuleSurvivesRestartButNeverBypassesStrict() async throws {
        let service = try service()
        let r = request("example.com/arbitrary")
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, true)
        let restarted = try self.service()
        await assertDecision(restarted, r, true)
        mode.select(.strict)
        await assertDecision(restarted, r, false)
        mode.select(.auto)
        await assertDecision(restarted, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
    }

    func testKnownConnectCannotBypassHardDenialsInAnyMode() async throws {
        let service = try service()
        var r = request("telemetry.nextjs.org:443", type: "CONNECT", method: "CONNECT")
        r.domain = "telemetry.nextjs.org"
        try store.insert(r.domain, type: .domain)
        await prompts.setAction(.approveOnce)
        for selection in [ApprovalMode.auto, .strict, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selection)
            await assertDecision(service, r, false)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testQueuedRequestSwitchingToStrictIgnoresAvailableConsent() async throws {
        let promptStarted = AsyncSignal()
        let releasePrompt = AsyncSignal()
        let secondEvaluated = AsyncSignal()
        let engine = TestPatternEngine()
        var r = request()
        r.headers = [ProxyApprovalHeader(name: "X-Custom", value: "approved later")]
        var secondRequest = r
        secondRequest.id = UUID().uuidString
        let secondID = secondRequest.id
        let observer = DenyRuleObserver { request in
            if request.id == secondID {
                Task { await secondEvaluated.signal() }
            }
        }
        let prompts = self.prompts!
        let service = try ApprovalService(
            denyRules: [observer], engines: [engine], recognizedElementStore: store,
            modeState: mode, promptUser: { request in
                await promptStarted.signal()
                await releasePrompt.wait()
                return await prompts.ask(request)
            }
        )
        let firstRequest = r
        let first = Task { await service.askForApproval(request: firstRequest) }
        await promptStarted.wait()
        let queuedRequest = secondRequest
        let second = Task { await service.askForApproval(request: queuedRequest) }
        await secondEvaluated.wait()
        engine.onEngineApproved(r)
        mode.select(.strict)
        await releasePrompt.signal()
        let firstResult = await first.value
        let secondResult = await second.value
        XCTAssertFalse(firstResult)
        XCTAssertFalse(secondResult)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
        XCTAssertEqual(presentations.last?.actions.map(\.id), [.deny, .approveOnce])
    }

    func testApproveEverythingRetainsExclusionsAndExpiresToAuto() async throws {
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
        await assertDecision(service, request(), true)
        await assertDecision(service, request("example.com/arbitrary"), false)
        XCTAssertEqual(mode.current(), .auto)
    }
}
