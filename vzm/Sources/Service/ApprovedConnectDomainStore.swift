import CryptoKit
import Foundation

final class ApprovedConnectDomainStore {
    private let fileManager: FileManager
    private let directoryURL: URL

    init(fileManager: FileManager = .default) throws {
        self.fileManager = fileManager

        let paths = try StorePaths(fileManager: fileManager)
        self.directoryURL = paths.vzmDirectoryURL
            .appendingPathComponent("approved-connect-domains", isDirectory: true)

        try createDirectory()
    }

    func contains(_ domain: String) -> Bool {
        guard !domain.isEmpty else {
            return false
        }

        return (try? Data(contentsOf: markerURL(for: domain))) == markerData(for: domain)
    }

    func insert(_ domain: String) throws {
        guard !domain.isEmpty else {
            return
        }

        try createDirectory()

        let url = markerURL(for: domain)
        let data = markerData(for: domain)
        do {
            try data.write(to: url, options: .withoutOverwriting)
        } catch let error as CocoaError where error.code == .fileWriteFileExists {
            if (try? Data(contentsOf: url)) != data {
                try data.write(to: url, options: .atomic)
            }
        }
    }

    private func createDirectory() throws {
        try fileManager.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private func markerURL(for domain: String) -> URL {
        directoryURL.appendingPathComponent(Self.markerName(for: domain))
    }

    private func markerData(for domain: String) -> Data {
        Data(domain.utf8)
    }

    private static func markerName(for domain: String) -> String {
        SHA256.hash(data: Data(domain.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
