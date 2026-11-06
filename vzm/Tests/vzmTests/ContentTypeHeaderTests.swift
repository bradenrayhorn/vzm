import XCTest
@testable import vzm

final class ContentTypeHeaderTests: XCTestCase {
    private func request(_ value: String) -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            id: UUID().uuidString, type: "REQUEST", domain: "example.com", method: "POST",
            url: "example.com/api", headers: [.init(name: " cOnTeNt-TyPe ", value: value)],
            body: .init(text: "payload", warning: ""), secrets: []
        )
    }

    private func assertFiltered(_ value: String, _ expected: Bool,
                                file: StaticString = #filePath, line: UInt = #line) {
        let r = request(value)
        XCTAssertEqual(ApprovalHeaderMasker.isSafe(r.headers[0], in: r), expected, value, file: file, line: line)
        let remaining = ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: [])
        XCTAssertEqual(remaining, expected ? [] : r.headers, value, file: file, line: line)
    }

    func testCommonMediaTypesAreFiltered() {
        for value in [
            "application/json", "application/problem+json", "application/vnd.api+json",
            "application/vnd.github+json", "application/json-patch+json", "application/merge-patch+json",
            "application/ndjson", "application/x-ndjson", "application/graphql", "application/graphql-response+json",
            "application/x-www-form-urlencoded", "application/xml", "application/xhtml+xml",
            "application/octet-stream", "application/pdf", "application/zip", "application/gzip",
            "application/wasm", "application/javascript", "application/cbor", "application/msgpack",
            "application/x-protobuf", "text/plain", "text/html", "text/xml", "text/event-stream",
            "text/css", "text/javascript", "image/png", "image/jpeg", "image/webp", "image/svg+xml",
            "image/bmp", "image/tiff", "audio/mpeg", "audio/wav", "audio/ogg", "video/mp4", "video/webm",
        ] {
            assertFiltered(value, true)
            assertFiltered(" \t" + value.uppercased() + "\t ", true)
        }
    }

    func testCommonCharsetsAndQuotedValuesAreFiltered() {
        for charset in [
            "utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin1", "windows-1252",
            "utf-16", "utf-16le", "utf-16be",
        ] {
            for type in ["application/json", "text/plain", "application/xml", "application/x-www-form-urlencoded"] {
                assertFiltered("\(type); charset=\(charset)", true)
                assertFiltered("\(type.uppercased()) ; CHARSET = \"\(charset.uppercased())\"", true)
            }
        }
    }

    func testMultipartBoundariesStayVisible() {
        for type in ["multipart/form-data", "multipart/mixed", "multipart/related"] {
            for boundary in [
                "----WebKitFormBoundaryAbCdEf123456",
                "--------------------------012345678901234567890123",
                "----formdata-undici-012345678901", "a", String(repeating: "a", count: 70),
            ] {
                assertFiltered("\(type); boundary=\(boundary)", false)
                assertFiltered("\(type); boundary=\"\(boundary)\"", false)
            }
            assertFiltered("\(type); boundary=\"abc:def/ghi=123?()+_,.'-\"", false)
            assertFiltered("\(type); boundary=\"abc def\"", false)
            assertFiltered("\(type); charset=UTF-8; boundary=abc", false)
            assertFiltered("\(type); boundary=abc; charset=\"UTF-8\"", false)
        }
    }

    func testKnownParameterCombinationsAreFiltered() {
        for value in [
            "multipart/form-data", "multipart/form-data; charset=utf-8",
            "application/json; charset=utf-8; CHARSET=utf-8",
            "application/json; charset=\"utf-8\"; charset=ascii; charset=latin1",
        ] {
            assertFiltered(value, true)
        }
        assertFiltered("application/json; charset=utf-8; charset=unknown", false)
    }

    func testBoundaryParametersStayVisibleRegardlessOfValue() {
        for value in [
            "application/json; boundary=abc",
            "multipart/form-data; boundary=a; BOUNDARY=b",
            "multipart/form-data; boundary=" + String(repeating: "a", count: 71),
            "multipart/form-data; boundary=\"a \"", "multipart/form-data; boundary=a b",
            "multipart/form-data; boundary=a/b", "multipart/form-data; boundary=a=b",
            "multipart/form-data; boundary=\"a\\b\"",
            "multipart/form-data; boundary={vzm:TOKEN}", "multipart/form-data; boundary=ümlaut",
            "multipart/form-data; boundary=", "multipart/form-data; boundary=\"\"",
            "multipart/form-data; boundary=\"abc", "multipart/form-data; boundary=abc\"",
            "multipart/form-data; boundary=abc; boundary=def; custom=value",
        ] {
            assertFiltered(value, false)
        }
    }

    func testBodylessDependencyRequestWithBoundaryRequiresConsent() {
        var r = request("application/json; boundary=arbitrary-data")
        r.domain = "cache.nixos.org"
        r.method = "GET"
        r.url = "cache.nixos.org/nix-cache-info"
        r.body = nil
        r.headers = ApprovalHeaderMasker.maskSafeHeaders(for: r, knownUserAgents: [])

        guard case .needsConsent = NixCacheApprovalEngine().evaluate(r) else {
            return XCTFail("Boundary data must require explicit header consent")
        }
    }

    func testUnknownTypesAndParametersStayVisible() {
        for value in [
            "application/x-custom", "application/vnd.secret-data+json", "application/custom+xml",
            "*/*", "application/*", "text/*", "application/json, text/plain",
            "application/json; q=1", "application/json; custom=value",
            "application/json; charset=secret-data", "application/json; charset={vzm:TOKEN}",
            "application/json; charset=utf-8; custom=value",
            "text/plain; filename=example.txt",
            "multipart/form-data; boundary=abc; filename=example.txt",
            "multipart/related; boundary=abc; type=\"application/json\"",
        ] {
            assertFiltered(value, false)
        }
    }

    func testCommonValueMatchingDoesNotValidateHeaderSyntax() {
        for value in [
            "application/json;", "application/json;;", "application/json\n",
            "application/json; charset=\"utf-8", "application/json; charset=utf-8\"",
        ] {
            assertFiltered(value, true)
        }
        for value in ["", "application/json; charset=", "application/json; charset=unfamiliar"] {
            assertFiltered(value, false)
        }
    }
}
