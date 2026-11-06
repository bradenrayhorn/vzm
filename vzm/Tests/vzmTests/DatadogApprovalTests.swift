import XCTest
@testable import vzm

private actor DatadogPromptRecorder {
    private(set) var presentations: [ApprovalPromptPresentation] = []
    private var action: ApprovalCoordinatorResult = .deny

    func setAction(_ action: ApprovalCoordinatorResult) { self.action = action }

    func ask(_ request: ApprovalCoordinatorRequest) -> ApprovalCoordinatorResult {
        presentations.append(request.presentation)
        return action
    }
}

private final class DatadogUnconditionalApprovalEngine: BaseApprovalEngine {
    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation { .approved }
}

final class DatadogApprovalTests: XCTestCase {
    private var directory: URL!
    private var store: RecognizedElementStore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = try RecognizedElementStore(directoryURL: directory)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    private func isolatedEngine() throws -> DatadogApprovalEngine {
        let isolatedStore = try RecognizedElementStore(directoryURL: directory.appendingPathComponent(UUID().uuidString))
        return DatadogApprovalEngine(recognizedElementStore: isolatedStore)
    }
    private func request(host: String = "api.datadoghq.com", secret: String = "datadog-pat") -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            id: UUID().uuidString, type: "REQUEST", domain: host, method: "POST",
            url: "\(host)/api/v2/logs/events/search",
            headers: [
                .init(name: "Host", value: host),
                .init(name: "Authorization", value: "Bearer {vzm:\(secret)}"),
                .init(name: "Accept", value: "application/json"),
                .init(name: "Content-Type", value: "application/json"),
                .init(name: "User-Agent", value: "pup/test"),
            ],
            body: .init(text: #"{"filter":{"query":"status:error"}}"#, warning: ""),
            secrets: [.init(name: secret, location: .authorizationHeader)]
        )
    }

    private func assertEvaluation(_ engine: DatadogApprovalEngine, _ request: ProxyApprovalRequest,
                                  _ expected: String, file: StaticString = #filePath, line: UInt = #line) {
        let actual: String
        switch engine.evaluate(request) {
        case .approved: actual = "approved"
        case .denied: actual = "denied"
        case .needsConsent: actual = "consent"
        case .notApplicable: actual = "notApplicable"
        }
        XCTAssertEqual(actual, expected, file: file, line: line)
    }

    private func assertDecision(_ service: ApprovalService, _ request: ProxyApprovalRequest, _ expected: Bool,
                                file: StaticString = #filePath, line: UInt = #line) async {
        let approved = await service.askForApproval(request: request)
        XCTAssertEqual(approved, expected, file: file, line: line)
    }

    func testApprovalRequiresExplicitConsentAndSurvivesRestart() {
        let engine = DatadogApprovalEngine(recognizedElementStore: store)
        let r = request()
        assertEvaluation(engine, r, "consent")
        assertEvaluation(engine, r, "consent")
        engine.onEngineApproved(r)
        assertEvaluation(engine, r, "approved")
        let restarted = DatadogApprovalEngine(recognizedElementStore: store)
        assertEvaluation(restarted, r, "approved")
        assertEvaluation(restarted, request(secret: "unapproved-pat"), "consent")
    }

    func testAllowsArbitraryMethodsPathsBodiesAndWhitelistedHeaders() {
        let engine = DatadogApprovalEngine(recognizedElementStore: store)
        engine.onEngineApproved(request())
        for method in ["GET", "POST", "DELETE"] {
            var r = request()
            r.method = method
            r.url = "api.datadoghq.com/arbitrary/path?query=changing-content"
            r.body = .init(text: "arbitrary content", warning: "Request body is too large to show.")
            r.headers += [
                .init(name: "Accept-Encoding", value: "zstd,gzip"),
                .init(name: "Content-Encoding", value: "gzip"),
            ]
            r.headers = r.headers.map {
                .init(name: $0.name.uppercased(), value: " \($0.value) ")
            }
            // Multiple references to the same name still represent one credential.
            r.secrets.append(r.secrets[0])
            assertEvaluation(engine, r, "approved")
            r.body = nil
            assertEvaluation(engine, r, "approved")
        }
    }

    func testUnknownVisibleHeadersCannotReuseOrEstablishConsent() throws {
        for name in ["X-Custom", "Cookie", "Proxy-Authorization"] {
            let engine = try isolatedEngine()
            var r = request()
            r.headers.append(.init(name: name, value: "unexpected"))
            assertEvaluation(engine, r, "notApplicable")
            engine.onEngineApproved(r)
            assertEvaluation(engine, request(), "consent")
            engine.onEngineApproved(request())
            assertEvaluation(engine, r, "notApplicable")
        }
    }

    func testInvalidRequestsNeverMatchOrEstablishConsent() throws {
        var invalid: [ProxyApprovalRequest] = []
        for host in ["api.datadoghq.com.evil.example", "app.datadoghq.com", "api.datadoghq.eu", "evil.example"] {
            invalid.append(request(host: host))
        }
        for url in [
            "api.datadoghq.com.evil.example/api/v2/users", "api.datadoghq.com@evil.example/api/v2/users",
            "api.datadoghq.com:443/api/v2/users", "https://api.datadoghq.com/api/v2/users",
            "api.datadoghq.com", "evil.example/api/v2/users",
        ] {
            var r = request(); r.url = url; invalid.append(r)
        }
        for type in ["CONNECT", "TCP_CONNECT", "WEBSOCKET", "GIT"] {
            var r = request(); r.type = type; invalid.append(r)
        }
        var r = request(); r.method = ""; invalid.append(r)
        r = request(); r.secrets = []; invalid.append(r)
        r = request(); r.secrets = [.init(name: "OTHER", location: .authorizationHeader)]; invalid.append(r)
        r = request(); r.secrets.append(.init(name: "OTHER", location: .authorizationHeader)); invalid.append(r)
        r = request(); r.headers.removeAll { $0.name == "Authorization" }; invalid.append(r)
        r = request(); r.headers.append(.init(name: "authorization", value: "Bearer {vzm:datadog-pat}")); invalid.append(r)
        for value in [
            "Bearer literal-token", "{vzm:datadog-pat}", "Basic {vzm:datadog-pat}",
            "Bearer {vzm:OTHER}", "Bearer {vzm:datadog-pat} extra", "Bearer {vzm:datadog-pat}\r\n",
        ] {
            r = request()
            r.headers.removeAll { $0.name == "Authorization" }
            r.headers.append(.init(name: "Authorization", value: value))
            invalid.append(r)
        }
        for r in invalid {
            let engine = try isolatedEngine()
            assertEvaluation(engine, r, "notApplicable")
            engine.onEngineApproved(r)
            assertEvaluation(engine, request(), "consent")
            engine.onEngineApproved(request())
            assertEvaluation(engine, r, "notApplicable")
        }
    }

    func testPersistenceFailureDoesNotEstablishConsent() throws {
        let engine = DatadogApprovalEngine(recognizedElementStore: store)
        try FileManager.default.removeItem(at: directory)
        try Data("not a directory".utf8).write(to: directory)
        engine.onEngineApproved(request(secret: "ANY_NAME"))
        assertEvaluation(engine, request(secret: "ANY_NAME"), "consent")
    }

    func testEmptySDKKeyHeadersAllowConsent() {
        let engine = DatadogApprovalEngine(recognizedElementStore: store)
        var r = request()
        r.headers += [
            .init(name: "DD-API-KEY", value: ""),
            .init(name: "dd-api-key", value: ""),
            .init(name: "Dd-Application-Key", value: ""),
        ]
        assertEvaluation(engine, r, "consent")
        engine.onEngineApproved(r)
        assertEvaluation(engine, r, "approved")
    }

    func testNonemptySDKKeysAreDeniedIncludingDuplicates() throws {
        for name in ["DD-API-KEY", "dd-application-key"] {
            for value in ["another-account-key", " ", "\t", "{vzm:OTHER}"] {
                let engine = try isolatedEngine()
                var r = request()
                r.headers += [.init(name: name, value: ""), .init(name: name, value: value)]
                assertEvaluation(engine, r, "denied")
                engine.onEngineApproved(r)
                assertEvaluation(engine, request(), "consent")
                engine.onEngineApproved(request())
                assertEvaluation(engine, r, "denied")
            }
        }
    }

    func testSDKKeyValidationIsScopedToTheFixedHost() {
        let engine = DatadogApprovalEngine(recognizedElementStore: store)
        var r = request(host: "api.datadoghq.eu")
        r.headers.append(.init(name: "DD-API-KEY", value: "other-key"))
        assertEvaluation(engine, r, "notApplicable")
        r.domain = "api.datadoghq.com"
        r.url = "\(r.domain)/api/query"
        assertEvaluation(engine, r, "denied")
        r.domain = "api.datadoghq.com.evil.example"
        r.url = "\(r.domain)/api/query"
        XCTAssertFalse(engine.shouldDeny(r))
        assertEvaluation(engine, r, "notApplicable")
    }

    func testSecretLocationObjectsDecodeAndLegacyOrInvalidLocationsFailClosed() throws {
        let decoded = try JSONDecoder().decode(ProxyApprovalRequest.self, from: JSONEncoder().encode(request()))
        XCTAssertEqual(decoded.secrets, [.init(name: "datadog-pat", location: .authorizationHeader)])
        let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(request())) as? [String: Any])
        let secrets = try XCTUnwrap(wire["secrets"] as? [[String: String]])
        XCTAssertEqual(secrets, [["name": "datadog-pat", "location": "authorizationHeader"]])
        for invalid: Any in [
            ["datadog-pat"],
            [["name": "datadog-pat"]],
            [["name": "datadog-pat", "location": "unknown"]],
        ] {
            var object = wire
            object["secrets"] = invalid
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(try JSONDecoder().decode(ProxyApprovalRequest.self, from: data))
        }
    }

    func testSecretsOutsideAuthorizationAreDeniedBeforeAndAfterConsent() throws {
        for location in ProxySecretLocation.allCases where location != .authorizationHeader {
            for secret in ["datadog-pat", "another-secret"] {
                let engine = try isolatedEngine()
                var invalid = request()
                invalid.secrets.append(.init(name: secret, location: location))
                assertEvaluation(engine, invalid, "denied")
                XCTAssertTrue(engine.shouldDeny(invalid))
                engine.onEngineApproved(invalid)
                assertEvaluation(engine, request(), "consent")
                engine.onEngineApproved(request())
                assertEvaluation(engine, invalid, "denied")

                // Even a missing/malformed auth header must not evade a location denial.
                invalid.headers = []
                invalid.secrets = [.init(name: secret, location: location)]
                assertEvaluation(engine, invalid, "denied")
                invalid.domain = "other.example"
                invalid.url = "other.example/path"
                assertEvaluation(engine, invalid, "notApplicable")
            }
        }
    }

    func testHardDenialsCannotBeOverriddenByModesOrOtherApprovals() async throws {
        let mode = ApprovalModeState()
        let prompts = DatadogPromptRecorder()
        await prompts.setAction(.approveOnce)
        let saved = SecretRequestApprovalEngine(recognizedElementStore: store)
        var invalid = request()
        invalid.secrets.append(.init(name: "datadog-pat", location: .body))
        saved.onEngineApproved(invalid)
        let service = try ApprovalService(
            engines: [DatadogUnconditionalApprovalEngine(), saved, DatadogApprovalEngine(recognizedElementStore: store)],
            recognizedElementStore: store, modeState: mode,
            promptUser: { await prompts.ask($0) }
        )
        var sdkKey = request()
        sdkKey.headers.append(.init(name: "DD-API-KEY", value: "literal-key"))
        for selectedMode in [ApprovalMode.auto, .strict, .approveEverything(until: Date().addingTimeInterval(60))] {
            mode.select(selectedMode)
            await assertDecision(service, invalid, false)
            await assertDecision(service, sdkKey, false)
        }
        let presentations = await prompts.presentations
        XCTAssertTrue(presentations.isEmpty)
    }

    func testExistingSecretConsentRemainsNameBasedAcrossLocations() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = try RecognizedElementStore(directoryURL: directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        let engine = SecretRequestApprovalEngine(recognizedElementStore: store)
        var r = request(host: "other.example")
        engine.onEngineApproved(r)
        r.secrets.append(.init(name: "datadog-pat", location: .body))
        if case .approved = engine.evaluate(r) {} else { XCTFail("Existing name-based consent changed") }
    }

    func testDefaultServiceConsentPersistenceAndStrictMode() async throws {
        let mode = ApprovalModeState()
        let prompts = DatadogPromptRecorder()
        let service = try ApprovalService(recognizedElementStore: store, modeState: mode,
                                          promptUser: { await prompts.ask($0) })
        var r = request()
        // Exercise the normal header-masking path, not just the engine in isolation.
        r.headers.append(.init(name: "Cookie", value: "__cf_bm=safe-bot-cookie"))
        await assertDecision(service, r, false)
        await prompts.setAction(.approveOnce)
        await assertDecision(service, r, true)
        await prompts.setAction(.deny)
        await assertDecision(service, r, false)
        await prompts.setAction(.approveEngine)
        await assertDecision(service, r, true)
        XCTAssertEqual(try store.elements(type: .approvedDatadogSecret), ["datadog-pat"])
        XCTAssertTrue(try store.elements(type: .autoApprovedSecretRequest).isEmpty)

        await prompts.setAction(.deny)
        let restarted = try ApprovalService(recognizedElementStore: store, modeState: mode,
                                            promptUser: { await prompts.ask($0) })
        await assertDecision(restarted, r, true)
        mode.select(.strict)
        await assertDecision(restarted, r, false)
    }

}
