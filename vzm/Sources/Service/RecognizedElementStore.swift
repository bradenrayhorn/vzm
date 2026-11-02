import CryptoKit
import Foundation

enum RecognizedElementType: String {
    case domain
    case userAgent
    case approvedForeverRequest
    case autoApprovedSecretRequest
    case approvedAzureDevOpsMavenFeed
}

final class RecognizedElementStore {
    private let fileManager: FileManager
    private let directoryURL: URL

    init(fileManager: FileManager = .default, directoryURL: URL? = nil) throws {
        self.fileManager = fileManager

        if let directoryURL {
            self.directoryURL = directoryURL
        } else {
            let paths = try StorePaths(fileManager: fileManager)
            self.directoryURL = paths.vzmDirectoryURL
                .appendingPathComponent("recognized-elements", isDirectory: true)
        }

        try createDirectory()
    }

    func contains(_ element: String, type: RecognizedElementType) -> Bool {
        let element = Self.normalize(element, type: type)
        guard !element.isEmpty else {
            return false
        }

        return (try? Data(contentsOf: markerURL(for: element, type: type))) == markerData(for: element, type: type)
    }

    func insert(_ element: String, type: RecognizedElementType) throws {
        let element = Self.normalize(element, type: type)
        guard !element.isEmpty else {
            return
        }

        try createDirectory()

        let url = markerURL(for: element, type: type)
        let data = markerData(for: element, type: type)
        do {
            try data.write(to: url, options: .withoutOverwriting)
        } catch let error as CocoaError where error.code == .fileWriteFileExists {
            if (try? Data(contentsOf: url)) != data {
                try data.write(to: url, options: .atomic)
            }
        }
    }

    /// Enumerates only markers whose contents match their hashed filename.
    func elements(type: RecognizedElementType) throws -> [String] {
        let urls = try fileManager.contentsOfDirectory(
            at: directoryURL, includingPropertiesForKeys: nil, options: .skipsHiddenFiles
        )
        let prefix = "\(type.rawValue)\n"
        return urls.compactMap { url in
            guard let data = try? Data(contentsOf: url),
                  let marker = String(data: data, encoding: .utf8),
                  marker.hasPrefix(prefix)
            else { return nil }
            let element = String(marker.dropFirst(prefix.count))
            guard !element.isEmpty,
                  url.lastPathComponent == Self.markerName(for: element, type: type)
            else { return nil }
            return element
        }
    }

    private func createDirectory() throws {
        try fileManager.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private func markerURL(for element: String, type: RecognizedElementType) -> URL {
        directoryURL.appendingPathComponent(Self.markerName(for: element, type: type))
    }

    private func markerData(for element: String, type: RecognizedElementType) -> Data {
        Data("\(type.rawValue)\n\(element)".utf8)
    }

    private static func markerName(for element: String, type: RecognizedElementType) -> String {
        SHA256.hash(data: Data("\(type.rawValue)\u{0}\(element)".utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func normalize(_ element: String, type: RecognizedElementType) -> String {
        switch type {
        case .domain:
            var domain = element.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if domain.hasSuffix(".") {
                domain.removeLast()
            }
            return domain
        case .userAgent:
            return element.trimmingCharacters(in: .whitespaces)
        case .approvedForeverRequest, .autoApprovedSecretRequest, .approvedAzureDevOpsMavenFeed:
            return element
        }
    }
}
