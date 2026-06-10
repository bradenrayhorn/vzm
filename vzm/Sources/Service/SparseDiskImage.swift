import Foundation

enum SparseDiskImage {
    static func create(at url: URL, sizeBytes: UInt64, fileManager: FileManager = .default) throws {
        guard fileManager.createFile(atPath: url.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }

        do {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.truncate(atOffset: sizeBytes)
        } catch {
            try? fileManager.removeItem(at: url)
            throw error
        }
    }

    static func createIfMissing(at url: URL, sizeBytes: UInt64, fileManager: FileManager = .default) throws {
        guard !fileManager.fileExists(atPath: url.path) else {
            return
        }

        try create(at: url, sizeBytes: sizeBytes, fileManager: fileManager)
    }
}
