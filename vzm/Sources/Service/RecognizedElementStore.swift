import CryptoKit
import Foundation

enum RecognizedElementType: String {
    case domain
    case userAgent
}

final class RecognizedElementStore {
    private let fileManager: FileManager
    private let directoryURL: URL

    init(fileManager: FileManager = .default) throws {
        self.fileManager = fileManager

        let paths = try StorePaths(fileManager: fileManager)
        self.directoryURL = paths.vzmDirectoryURL
            .appendingPathComponent("recognized-elements", isDirectory: true)

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
        }
    }
}
