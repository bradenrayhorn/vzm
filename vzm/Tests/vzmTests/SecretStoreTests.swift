import Security
import XCTest
@testable import vzm

final class SecretStoreTests: XCTestCase {
    private var service: String!
    private var store: SecretStore!

    override func setUpWithError() throws {
        service = "dev.bradenrayhorn.vzm.tests.secret.\(UUID().uuidString)"
        store = SecretStore(service: service)
        try store.upsertSecret(named: "TOKEN", secret: "unchanged-secret", hosts: ["b.example.com"])
    }

    override func tearDownWithError() throws {
        if let service {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
            ]
            let status = SecItemDelete(query as CFDictionary)
            XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        }
        store = nil
        service = nil
    }

    func testAddNormalizesDeduplicatesAndSortsHosts() throws {
        try store.addHost("  A.Example.COM\n", toSecretNamed: " TOKEN ")
        try store.addHost("a.example.com", toSecretNamed: "TOKEN")
        try store.addHost("B.EXAMPLE.COM", toSecretNamed: "TOKEN")

        XCTAssertEqual(try hosts(), ["a.example.com", "b.example.com"])
        XCTAssertEqual(try store.readSecret(named: "TOKEN"), "unchanged-secret")
    }

    func testRemoveNormalizesHostAndPreservesSecret() throws {
        try store.addHost("a.example.com", toSecretNamed: "TOKEN")
        try store.removeHost(" B.Example.COM\n", fromSecretNamed: " TOKEN ")

        XCTAssertEqual(try hosts(), ["a.example.com"])
        XCTAssertEqual(try store.readSecret(named: "TOKEN"), "unchanged-secret")
    }

    func testRemovingAbsentHostIsNoOp() throws {
        try store.removeHost("absent.example.com", fromSecretNamed: "TOKEN")
        XCTAssertEqual(try hosts(), ["b.example.com"])
    }

    func testCannotRemoveLastHost() throws {
        XCTAssertThrowsError(try store.removeHost("B.EXAMPLE.COM", fromSecretNamed: "TOKEN")) { error in
            guard case SecretStore.Error.cannotRemoveLastHost("TOKEN") = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(try hosts(), ["b.example.com"])
        XCTAssertEqual(try store.readSecret(named: "TOKEN"), "unchanged-secret")
    }

    func testAddingHostToUnrestrictedSecretMakesItRestricted() throws {
        try store.upsertSecret(named: "TOKEN", secret: "unchanged-secret", hosts: [])
        try store.removeHost("absent.example.com", fromSecretNamed: "TOKEN")
        XCTAssertEqual(try hosts(), [])

        try store.addHost("a.example.com", toSecretNamed: "TOKEN")
        XCTAssertEqual(try hosts(), ["a.example.com"])
    }

    func testMissingSecretIsNotCreated() throws {
        XCTAssertThrowsError(try store.addHost("a.example.com", toSecretNamed: "MISSING")) { error in
            guard case SecretStore.Error.secretNotFound("MISSING") = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertThrowsError(try store.removeHost("a.example.com", fromSecretNamed: "MISSING")) { error in
            guard case SecretStore.Error.secretNotFound("MISSING") = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(try store.listSecrets().map(\.name), ["TOKEN"])
    }

    func testInvalidInputsDoNotChangeMetadata() throws {
        XCTAssertThrowsError(try store.addHost(" \n", toSecretNamed: "TOKEN")) { error in
            guard case SecretStore.Error.invalidHost = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertThrowsError(try store.removeHost("", fromSecretNamed: "TOKEN"))
        XCTAssertThrowsError(try store.addHost("a.example.com", toSecretNamed: " \n")) { error in
            guard case SecretStore.Error.invalidName = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(try hosts(), ["b.example.com"])
    }

    func testInvalidMetadataIsRejected() throws {
        try replaceMetadata(Data("not JSON".utf8))
        XCTAssertThrowsError(try store.addHost("a.example.com", toSecretNamed: "TOKEN")) { error in
            guard case SecretStore.Error.invalidMetadata("TOKEN") = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(try store.readSecret(named: "TOKEN"), "unchanged-secret")
    }

    func testMismatchedMetadataNameIsRejected() throws {
        try replaceMetadata(JSONEncoder().encode(StoredSecret(name: "OTHER", hosts: ["b.example.com"])))
        XCTAssertThrowsError(try store.removeHost("b.example.com", fromSecretNamed: "TOKEN")) { error in
            guard case SecretStore.Error.invalidMetadata("TOKEN") = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    private func hosts() throws -> [String] {
        try XCTUnwrap(store.listSecrets().first { $0.name == "TOKEN" }).hosts
    }

    private func replaceMetadata(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service!,
            kSecAttrAccount as String: "TOKEN",
        ]
        let attributes: [String: Any] = [kSecAttrGeneric as String: data]
        XCTAssertEqual(SecItemUpdate(query as CFDictionary, attributes as CFDictionary), errSecSuccess)
    }
}

final class SecretHostCommandTests: XCTestCase {
    func testParseAddHost() throws {
        let command = try XCTUnwrap(VZM.parseAsRoot(["secret", "host", "add", "TOKEN", "a.example.com"]) as? SecretHostAdd)
        XCTAssertEqual(command.name, "TOKEN")
        XCTAssertEqual(command.domain, "a.example.com")
    }

    func testParseRemoveHost() throws {
        let command = try XCTUnwrap(VZM.parseAsRoot(["secret", "host", "rm", "TOKEN", "a.example.com"]) as? SecretHostRemove)
        XCTAssertEqual(command.name, "TOKEN")
        XCTAssertEqual(command.domain, "a.example.com")
    }

    func testDomainIsRequired() {
        XCTAssertThrowsError(try VZM.parseAsRoot(["secret", "host", "add", "TOKEN"]))
        XCTAssertThrowsError(try VZM.parseAsRoot(["secret", "host", "rm", "TOKEN"]))
    }

    func testExistingSecretCommandsStillParse() throws {
        XCTAssertTrue(try VZM.parseAsRoot(["secret"]) is SecretList)
        XCTAssertTrue(try VZM.parseAsRoot(["secret", "add", "TOKEN", "--host", "a.example.com"]) is SecretAdd)
        XCTAssertTrue(try VZM.parseAsRoot(["secret", "rm", "TOKEN"]) is SecretRemove)
    }
}
