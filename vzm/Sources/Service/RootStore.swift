import Foundation

struct RootStore {
    enum Error: LocalizedError {
        case invalidSourceDirectory(String)
        case missingRequiredFiles([String])

        var errorDescription: String? {
            switch self {
            case .invalidSourceDirectory(let path):
                return "Root source directory does not exist or is not a directory: \(path)"
            case .missingRequiredFiles(let files):
                return "Root source directory is missing required files: \(files.joined(separator: ", "))"
            }
        }
    }

    private let fileManager: FileManager
    let rootsDirectoryURL: URL

    init(fileManager: FileManager = .default) throws {
        self.fileManager = fileManager

        let paths = try StorePaths(fileManager: fileManager)
        self.rootsDirectoryURL = paths.rootsDirectoryURL

        try fileManager.createDirectory(at: rootsDirectoryURL, withIntermediateDirectories: true)
    }

    func storeRoot(named name: String, from sourceFolderPath: String) throws -> URL {
        let sourceURL = URL(fileURLWithPath: sourceFolderPath, isDirectory: true)
        return try storeRoot(named: name, from: sourceURL)
    }

    func storeRoot(named name: String, from sourceDirectoryURL: URL) throws -> URL {
        guard (try? sourceDirectoryURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.invalidSourceDirectory(sourceDirectoryURL.path)
        }

        let requiredFiles = ["initrd", "kernel", "rootfs.squashfs"]
        let missingFiles = requiredFiles.filter { requiredFile in
            !fileManager.fileExists(atPath: sourceDirectoryURL.appendingPathComponent(requiredFile).path)
        }

        guard missingFiles.isEmpty else {
            throw Error.missingRequiredFiles(missingFiles)
        }

        let destinationURL = rootsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        try fileManager.createDirectory(at: destinationURL, withIntermediateDirectories: true)

        do {
            for file in requiredFiles {
                let destinationItemURL = destinationURL.appendingPathComponent(file)
                try fileManager.moveItem(at: sourceDirectoryURL.appendingPathComponent(file), to: destinationItemURL)
            }
        } catch {
            try? fileManager.removeItem(at: destinationURL)
            throw error
        }

        return destinationURL
    }
}
