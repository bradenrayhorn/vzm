import Foundation

struct RootManifest: Codable {
    let schemaVersion: Int
    let architecture: String
    let commandLine: String
    let initrd: String
    let kernel: String
    let rootMode: String
    let rootfs: String
}

struct RootBundle {
    let directoryURL: URL
    let manifest: RootManifest

    var kernelURL: URL { directoryURL.appendingPathComponent(manifest.kernel) }
    var initrdURL: URL { directoryURL.appendingPathComponent(manifest.initrd) }
    var rootfsURL: URL { directoryURL.appendingPathComponent(manifest.rootfs) }
}

struct RootStore {
    enum Error: LocalizedError {
        case invalidSourceDirectory(String)
        case missingRequiredFiles([String])
        case rootDoesNotExist(String)
        case unsupportedSchemaVersion(Int)
        case unsupportedArchitecture(String)
        case unsupportedRootMode(String)

        var errorDescription: String? {
            switch self {
            case .invalidSourceDirectory(let path):
                return "Root source directory does not exist or is not a directory: \(path)"
            case .missingRequiredFiles(let files):
                return "Root source directory is missing required files: \(files.joined(separator: ", "))"
            case .rootDoesNotExist(let name):
                return "Root does not exist: \(name)"
            case .unsupportedSchemaVersion(let version):
                return "Unsupported root manifest schema version: \(version)"
            case .unsupportedArchitecture(let architecture):
                return "Unsupported root architecture: \(architecture)"
            case .unsupportedRootMode(let rootMode):
                return "Unsupported root mode: \(rootMode)"
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

        let requiredFiles = ["initrd", "kernel", "manifest.json", "rootfs.squashfs"]
        let missingFiles = requiredFiles.filter { requiredFile in
            !fileManager.fileExists(atPath: sourceDirectoryURL.appendingPathComponent(requiredFile).path)
        }

        guard missingFiles.isEmpty else {
            throw Error.missingRequiredFiles(missingFiles)
        }

        let destinationURL = rootsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        if fileManager.fileExists(atPath: destinationURL.path) {
            try fileManager.removeItem(at: destinationURL)
        }
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

    func loadRoot(named name: String) throws -> RootBundle {
        let rootURL = rootsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        guard (try? rootURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.rootDoesNotExist(name)
        }

        let manifestURL = rootURL.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONDecoder().decode(RootManifest.self, from: data)

        guard manifest.schemaVersion == 1 else {
            throw Error.unsupportedSchemaVersion(manifest.schemaVersion)
        }
        guard manifest.architecture == "aarch64" else {
            throw Error.unsupportedArchitecture(manifest.architecture)
        }
        guard manifest.rootMode == "immutable" else {
            throw Error.unsupportedRootMode(manifest.rootMode)
        }

        let bundle = RootBundle(directoryURL: rootURL, manifest: manifest)
        let missingFiles = [bundle.kernelURL, bundle.initrdURL, bundle.rootfsURL].filter { url in
            !fileManager.fileExists(atPath: url.path)
        }.map(\.lastPathComponent)

        guard missingFiles.isEmpty else {
            throw Error.missingRequiredFiles(missingFiles)
        }

        return bundle
    }
}
