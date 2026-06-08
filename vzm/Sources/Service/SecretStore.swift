import Foundation
import Security

struct StoredSecret: Codable {
    let name: String
    let hosts: [String]
}

final class SecretStore {
    enum Error: LocalizedError {
        case invalidName
        case invalidHost(String)
        case secretNotFound(String)
        case keychainError(OSStatus)
        case invalidMetadata(String)

        var errorDescription: String? {
            switch self {
            case .invalidName:
                return "Secret name must not be empty."
            case .invalidHost(let host):
                return "Invalid host: \(host)"
            case .secretNotFound(let name):
                return "Secret does not exist: \(name)"
            case .keychainError(let status):
                return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error: \(status)"
            case .invalidMetadata(let name):
                return "Stored secret metadata is invalid for secret: \(name)"
            }
        }
    }

    private let service = "dev.bradenrayhorn.vzm.secret"
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    func upsertSecret(named name: String, secret: String, hosts: [String]) throws {
        let normalizedName = try normalizeName(name)
        let normalizedHosts = try normalizeHosts(hosts)
        let metadata = StoredSecret(name: normalizedName, hosts: normalizedHosts)
        let metadataData = try encoder.encode(metadata)
        let secretData = Data(secret.utf8)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: normalizedName,
        ]

        let attributes: [String: Any] = [
            kSecAttrLabel as String: normalizedName,
            kSecAttrGeneric as String: metadataData,
            kSecValueData as String: secretData,
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var createQuery = query
            attributes.forEach { createQuery[$0.key] = $0.value }
            let createStatus = SecItemAdd(createQuery as CFDictionary, nil)
            guard createStatus == errSecSuccess else {
                throw Error.keychainError(createStatus)
            }
        default:
            throw Error.keychainError(updateStatus)
        }
    }

    func readSecret(named name: String) throws -> String {
        let normalizedName = try normalizeName(name)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: normalizedName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let secret = String(data: data, encoding: .utf8) else {
                throw Error.invalidMetadata(normalizedName)
            }
            return secret
        case errSecItemNotFound:
            throw Error.secretNotFound(normalizedName)
        default:
            throw Error.keychainError(status)
        }
    }

    func listSecrets() throws -> [StoredSecret] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw Error.keychainError(status)
        }

        let items = result as? [[String: Any]] ?? []
        return try items.map { attributes in
            guard
                let name = attributes[kSecAttrAccount as String] as? String,
                let metadataData = attributes[kSecAttrGeneric as String] as? Data
            else {
                throw Error.invalidMetadata(attributes[kSecAttrAccount as String] as? String ?? "<unknown>")
            }

            let metadata = try decoder.decode(StoredSecret.self, from: metadataData)
            guard metadata.name == name else {
                throw Error.invalidMetadata(name)
            }
            return metadata
        }
        .sorted { $0.name < $1.name }
    }

    func removeSecret(named name: String) throws {
        let normalizedName = try normalizeName(name)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: normalizedName,
        ]

        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw Error.secretNotFound(normalizedName)
        default:
            throw Error.keychainError(status)
        }
    }

    private func normalizeName(_ name: String) throws -> String {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            throw Error.invalidName
        }
        return normalized
    }

    private func normalizeHosts(_ hosts: [String]) throws -> [String] {
        var normalizedHosts: [String] = []
        var seen = Set<String>()

        for host in hosts {
            let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !normalizedHost.isEmpty else {
                throw Error.invalidHost(host)
            }
            if seen.insert(normalizedHost).inserted {
                normalizedHosts.append(normalizedHost)
            }
        }

        return normalizedHosts.sorted()
    }
}
