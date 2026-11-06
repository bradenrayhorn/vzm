import XCTest
@testable import vzm

private actor OpenRouterPromptRecorder {
    private(set) var presentations: [ApprovalPromptPresentation] = []
    private var action: ApprovalCoordinatorResult = .deny

    func setAction(_ action: ApprovalCoordinatorResult) { self.action = action }

    func ask(_ request: ApprovalCoordinatorRequest) -> ApprovalCoordinatorResult {
        presentations.append(request.presentation)
        return action
    }
}

final class OpenRouterApprovalTests: XCTestCase {
    private var directory: URL!
    private var store: RecognizedElementStore!
    private var mode: ApprovalModeState!
    private var prompts: OpenRouterPromptRecorder!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = try RecognizedElementStore(directoryURL: directory)
        mode = ApprovalModeState()
        prompts = OpenRouterPromptRecorder()
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    // SDK headers captured locally from pi's OpenAI and Anthropic clients, plus
    // Node fetch's transport headers. Linux/arm64 values represent the guest.
    private func request(anthropic: Bool = false, secret: String = "OPENROUTER_API_KEY") -> ProxyApprovalRequest {
        var headers: [ProxyApprovalHeader] = [
            .init(name: "Host", value: "openrouter.ai"),
            .init(name: "Accept", value: "application/json"),
            .init(name: "Content-Type", value: "application/json"),
            .init(name: "User-Agent", value: "pi (linux 6.12.0; arm64)"),
            .init(name: "X-Session-Id", value: "01901234-1234-7123-8123-123456789abc"),
            .init(name: "X-Stainless-Lang", value: "js"),
            .init(name: "X-Stainless-OS", value: "Linux"),
            .init(name: "X-Stainless-Arch", value: "arm64"),
            .init(name: "X-Stainless-Runtime", value: "node"),
            .init(name: "X-Stainless-Runtime-Version", value: "v22.22.3"),
            .init(name: "X-Stainless-Package-Version", value: anthropic ? "0.129.0" : "7.19.0"),
            .init(name: "X-Stainless-Retry-Count", value: "0"),
            .init(name: "Connection", value: "keep-alive"),
            .init(name: "Accept-Language", value: "*"),
            .init(name: "Sec-Fetch-Mode", value: "cors"),
            .init(name: "Accept-Encoding", value: "gzip, deflate"),
            .init(name: "Content-Length", value: "367"),
        ]
        if anthropic {
            headers += [
                .init(name: "X-Api-Key", value: "{vzm:\(secret)}"),
                .init(name: "Anthropic-Version", value: "2023-06-01"),
                .init(name: "Anthropic-Dangerous-Direct-Browser-Access", value: "true"),
                .init(name: "X-Stainless-Timeout", value: "600"),
            ]
        } else {
            headers.append(.init(name: "Authorization", value: "Bearer {vzm:\(secret)}"))
        }
        return ProxyApprovalRequest(
            id: UUID().uuidString, type: "REQUEST", domain: "openrouter.ai", method: "POST",
            url: "openrouter.ai/api/v1/" + (anthropic ? "messages?beta=true" : "chat/completions"),
            headers: headers, body: .init(text: #"{"model":"example","messages":[],"stream":true}"#, warning: ""),
            secrets: [.init(name: secret, location: .authorizationHeader)]
        )
    }

    private func setting(_ request: ProxyApprovalRequest, _ name: String, _ value: String) -> ProxyApprovalRequest {
        var result = request
        result.headers.removeAll { $0.name.lowercased() == name.lowercased() }
        result.headers.append(.init(name: name, value: value))
        return result
    }

    private func assertApproved(_ engine: OpenRouterApprovalEngine, _ request: ProxyApprovalRequest,
                                file: StaticString = #filePath, line: UInt = #line) {
        if case .approved = engine.evaluate(request) {} else { XCTFail("Expected approval", file: file, line: line) }
    }

    private func assertConsent(_ engine: OpenRouterApprovalEngine, _ request: ProxyApprovalRequest,
                               file: StaticString = #filePath, line: UInt = #line) {
        if case .needsConsent = engine.evaluate(request) {} else { XCTFail("Expected consent", file: file, line: line) }
    }

    private func service() throws -> ApprovalService {
        let prompts = self.prompts!
        return try ApprovalService(recognizedElementStore: store, modeState: mode,
                                   promptUser: { await prompts.ask($0) })
    }

    private func assertDecision(_ service: ApprovalService, _ request: ProxyApprovalRequest, _ expected: Bool,
                                file: StaticString = #filePath, line: UInt = #line) async {
        let approved = await service.askForApproval(request: request)
        XCTAssertEqual(approved, expected, file: file, line: line)
    }

    func testBothProtocolsRequireExplicitConsentAndShareSecretConsent() {
        for anthropic in [false, true] {
            let engine = OpenRouterApprovalEngine()
            let r = request(anthropic: anthropic)
            assertConsent(engine, r)
            assertConsent(engine, r) // Evaluation alone must not establish consent.
            engine.onEngineApproved(r)
            assertApproved(engine, r)
            assertApproved(engine, request(anthropic: !anthropic))
            var withoutBeta = request(anthropic: true)
            withoutBeta.url = "openrouter.ai/api/v1/messages"
            assertApproved(engine, withoutBeta)
            assertConsent(OpenRouterApprovalEngine(), r)
        }
    }

    func testChangingBodiesSessionsAndOrdinaryMetadataRemainApproved() {
        let engine = OpenRouterApprovalEngine()
        engine.onEngineApproved(request())
        var changed = request(anthropic: true)
        changed.body = .init(text: "Different conversation and model", warning: "Display truncated")
        let values = [
            ("x-session-id", "12345678-1234-4234-8234-123456789abc"),
            ("x-stainless-package-version", "123.456.789-beta.1"),
            ("x-stainless-runtime-version", "v26.5.0"),
            ("x-stainless-os", "MacOS"),
            ("x-stainless-arch", "x64"),
            ("x-stainless-runtime", "bun"),
            ("x-stainless-retry-count", "2"),
            ("x-stainless-timeout", "1200"),
            ("content-length", "1234567"),
            ("anthropic-version", "2027-01-01"),
            ("anthropic-beta", "interleaved-thinking-2025-05-14, future-feature-2027-01-01"),
        ]
        for (name, value) in values { changed = setting(changed, name, value) }
        changed.headers = changed.headers.map { .init(name: $0.name.uppercased(), value: " \($0.value) ") }
        assertApproved(engine, changed)
        changed.headers.removeAll { $0.name == "X-SESSION-ID" }
        assertApproved(engine, changed) // Cache retention can disable session headers.
    }

    func testUnfamiliarHeadersAndValuesNeedConsentAndCanBeRemembered() {
        let engine = OpenRouterApprovalEngine()
        let r = request()
        engine.onEngineApproved(r)
        let unknownValues = [
            ("X-Custom", "example"), ("HTTP-Referer", "https://pi.dev"), ("X-Title", "pi"),
            ("X-Stainless-Future-Header", "anything"), ("X-Stainless-Lang", "python"),
            ("X-Stainless-Runtime", "unexpected"), ("X-Stainless-OS", "custom"),
            ("X-Stainless-Arch", "custom"), ("X-Stainless-Package-Version", "secret-data"),
            ("X-Stainless-Runtime-Version", "v1.2.3\nextra"),
            ("X-Stainless-Package-Version", "123456.0.0"),
            ("X-Stainless-Retry-Count", "101"), ("X-Stainless-Retry-Count", "-1"),
            ("X-Stainless-Timeout", "86401"), ("Content-Length", "1073741825"),
            ("Content-Length", "1e3"), ("X-Session-Id", "arbitrary-session-data"),
            ("Anthropic-Version", "not-a-date"), ("Anthropic-Dangerous-Direct-Browser-Access", "false"),
            ("Anthropic-Beta", ""), ("Anthropic-Beta", "feature,"),
            ("Anthropic-Beta", "feature with spaces"), ("Anthropic-Beta", String(repeating: "x", count: 129)),
            ("Anthropic-Beta", Array(repeating: "feature", count: 17).joined(separator: ",")),
            ("User-Agent", "a different client"),
        ]
        for (name, value) in unknownValues {
            assertConsent(engine, setting(r, name, value))
        }
        let custom = setting(r, "X-Custom", "example")
        engine.onEngineApproved(custom)
        assertApproved(engine, setting(r, "x-custom", "example"))
        assertConsent(engine, setting(r, "X-Custom", "different"))
    }

    func testContentTypeUsesOrdinaryHeaderConsentInsteadOfRestrictingMatching() {
        for anthropic in [false, true] {
            let engine = OpenRouterApprovalEngine()
            let r = request(anthropic: anthropic)
            engine.onEngineApproved(r)
            assertApproved(engine, r)

            var missing = r
            missing.headers.removeAll { $0.name == "Content-Type" }
            assertApproved(engine, missing)

            for value in ["application/json; charset=utf-8", "application/json; charset=\"UTF-8\"", "text/plain"] {
                assertApproved(engine, setting(r, "Content-Type", value))
            }

            let unfamiliar = setting(r, "Content-Type", "application/x-custom")
            assertConsent(engine, unfamiliar)
            engine.onEngineApproved(unfamiliar)
            assertApproved(engine, unfamiliar)

            var duplicate = r
            duplicate.headers.append(.init(name: "content-type", value: "application/json"))
            assertApproved(engine, duplicate)
        }
    }

    func testNewSecretsNeedConsentIncludingSecretsOutsideTheAuthHeader() {
        let engine = OpenRouterApprovalEngine()
        engine.onEngineApproved(request())
        let another = request(secret: "SECOND")
        assertConsent(engine, another)
        var extra = request()
        extra.secrets += ["SECOND", "SECOND"].map { .init(name: $0, location: .header) }
        assertConsent(engine, extra)
        engine.onEngineApproved(extra)
        assertApproved(engine, another)
        extra.secrets = ["SECOND", "OPENROUTER_API_KEY"].map { .init(name: $0, location: .header) }
        assertApproved(engine, extra)
        assertConsent(engine, request(secret: "openrouter_api_key"))
    }

    func testInvalidRequestsDoNotMatchOrEstablishConsent() {
        var invalid: [ProxyApprovalRequest] = []
        for url in [
            "example.com/api/v1/chat/completions", "openrouter.ai.example.com/api/v1/chat/completions",
            "openrouter.ai/api/v1/chat/completions/", "openrouter.ai/api/v1/chat/completions?beta=true",
            "openrouter.ai/api/v1/messages?beta=false", "openrouter.ai/api/v1/messages?beta=true&extra=1",
            "openrouter.ai/api/v1/messages#fragment", "openrouter.ai/api/v1/models",
            "openrouter.ai/api/v1/auth/keys", "openrouter.ai/api/v1/messages\nextra",
        ] {
            var r = request()
            r.url = url
            invalid.append(r)
        }
        for type in ["WEBSOCKET", "CONNECT", "TCP_CONNECT", "GIT"] {
            var r = request(); r.type = type; invalid.append(r)
        }
        for method in ["GET", "HEAD", "PUT", "DELETE"] {
            var r = request(); r.method = method; invalid.append(r)
        }
        var r = request(); r.body = nil; invalid.append(r)
        r = request(); r.secrets = []; invalid.append(r)
        r = request(); r.secrets = ["OTHER"].map { .init(name: $0, location: .header) }; invalid.append(r)
        r = request(); r.secrets.append(.init(name: " ", location: .header)); invalid.append(r)
        r = request(); r.headers.removeAll { $0.name == "Authorization" }; invalid.append(r)
        r = request(); r.headers.append(.init(name: "authorization", value: "Bearer {vzm:OPENROUTER_API_KEY}")); invalid.append(r)
        r = request(); r.headers.append(.init(name: "X-Api-Key", value: "{vzm:OPENROUTER_API_KEY}")); invalid.append(r)
        for value in ["Bearer real-token", "{vzm:OPENROUTER_API_KEY}", "Bearer {vzm:}",
                      "Bearer {vzm:OPENROUTER_API_KEY}suffix", "Bearer {vzm:OPENROUTER_API_KEY}{vzm:OTHER}"] {
            invalid.append(setting(request(), "Authorization", value))
        }
        invalid.append(setting(request(anthropic: true), "X-Api-Key", "Bearer {vzm:OPENROUTER_API_KEY}"))
        r = request(anthropic: true)
        r.headers.removeAll { $0.name == "X-Api-Key" }
        r.headers.append(.init(name: "Authorization", value: "Bearer {vzm:OPENROUTER_API_KEY}"))
        invalid.append(r)
        for r in invalid {
            let engine = OpenRouterApprovalEngine()
            if case .notApplicable = engine.evaluate(r) {} else { XCTFail("Invalid request matched: \(r.url)") }
            engine.onEngineApproved(r)
            assertConsent(engine, request())
            engine.onEngineApproved(request())
            if case .notApplicable = engine.evaluate(r) {} else { XCTFail("Consent bypassed matching") }
        }
    }

    func testDefaultServiceSelectsOpenRouterAndAutoApprovesUntilRestart() async throws {
        let service = try service()
        let r = request()
        await assertDecision(service, r, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 2)
        XCTAssertEqual(presentations.last?.title, "OpenRouter session")
        XCTAssertTrue(presentations.last?.warnings.contains { $0.contains("conversation content") } == true)
        XCTAssertTrue(presentations.last?.sections.contains { $0.title == "Secrets" && $0.text == "OPENROUTER_API_KEY (authorizationHeader)" } == true)
        XCTAssertEqual(presentations.last?.actions.first { $0.id == .approveEngine }?.keyboardShortcut, .optionReturn)
        XCTAssertTrue(try store.elements(type: .autoApprovedSecretRequest).isEmpty)

        await prompts.setAction(.deny)
        var changed = setting(request(anthropic: true), "Content-Type", "application/json; charset=utf-8")
        changed.body = .init(text: "next conversation", warning: "")
        await assertDecision(service, changed, true)
        let afterAuto = await prompts.presentations
        XCTAssertEqual(afterAuto.count, 2)
        await assertDecision(service, request(secret: "OTHER"), false)
        await assertDecision(service, setting(changed, "X-Unfamiliar", "value"), false)
        await assertDecision(service, setting(changed, "User-Agent", "another client"), false)

        mode.select(.strict)
        await assertDecision(service, r, false)
        mode.select(.approveEverything(until: Date().addingTimeInterval(60)))
        await assertDecision(service, changed, true)
        mode.select(.auto)
        let restarted = try self.service()
        await assertDecision(restarted, r, false)
        await assertDecision(service, r, true)
    }

    func testDenyAndApproveOnceDoNotEstablishSessionConsent() async throws {
        let service = try service()
        await assertDecision(service, request(), false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, request(), true)
        await prompts.setAction(.deny)
        await assertDecision(service, request(), false)
        let presentations = await prompts.presentations
        XCTAssertEqual(presentations.count, 3)
    }

    func testServiceRemembersExplicitlyApprovedUnfamiliarHeaders() async throws {
        let service = try service()
        await prompts.setAction(.approveEngine)
        await assertDecision(service, request(), true)
        await prompts.setAction(.deny)
        let custom = setting(request(), "X-Custom", "value")
        await assertDecision(service, custom, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, custom, true)
        await prompts.setAction(.deny)
        await assertDecision(service, custom, true)
        await assertDecision(service, setting(custom, "X-Custom", "changed"), false)
    }
}
