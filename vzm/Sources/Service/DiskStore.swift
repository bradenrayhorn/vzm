import Foundation

struct DiskManifest: Codable {
    let schemaVersion: Int
    let name: String
    let image: String
    let imageFormat: String
    let filesystem: String
    let sizeGB: UInt64
}

struct DiskBundle {
    let directoryURL: URL
    let manifest: DiskManifest

    var imageURL: URL { directoryURL.appendingPathComponent(manifest.image) }
}

struct DiskStore {
    enum Error: LocalizedError {
        case diskAlreadyExists(String)
        case diskDoesNotExist(String)
        case invalidDiskName(String)
        case invalidDiskSize(UInt64)
        case unsupportedSchemaVersion(Int)
        case unsupportedImageFormat(String)
        case unsupportedFilesystem(String)
        case missingRequiredFiles([String])
        case ioError(operation: String, path: String)
        case diskInUse(String)

        var errorDescription: String? {
            switch self {
            case .diskAlreadyExists(let name):
                return "Disk already exists: \(name)"
            case .diskDoesNotExist(let name):
                return "Disk does not exist: \(name)"
            case .invalidDiskName(let name):
                return "Invalid disk name: \(name). Disk names must be ASCII, at most 20 bytes, and contain only letters, numbers, '.', '_' or '-'."
            case .invalidDiskSize(let size):
                return "Invalid disk size: \(size) GiB. Sizes must be positive."
            case .unsupportedSchemaVersion(let version):
                return "Unsupported disk manifest schema version: \(version)"
            case .unsupportedImageFormat(let format):
                return "Unsupported disk image format: \(format)"
            case .unsupportedFilesystem(let filesystem):
                return "Unsupported disk filesystem: \(filesystem)"
            case .missingRequiredFiles(let files):
                return "Disk bundle is missing required files: \(files.joined(separator: ", "))"
            case .ioError(let operation, let path):
                return "I/O error during \(operation): \(path)"
            case .diskInUse(let name):
                return "Disk is already in use: \(name)"
            }
        }
    }

    private let fileManager: FileManager
    let disksDirectoryURL: URL

    init(fileManager: FileManager = .default) throws {
        self.fileManager = fileManager

        let paths = try StorePaths(fileManager: fileManager)
        self.disksDirectoryURL = paths.disksDirectoryURL

        try fileManager.createDirectory(at: disksDirectoryURL, withIntermediateDirectories: true)
    }

    func createDisk(named name: String, sizeGB: UInt64) throws -> URL {
        guard isValidDiskName(name) else {
            throw Error.invalidDiskName(name)
        }
        guard sizeGB > 0 else {
            throw Error.invalidDiskSize(sizeGB)
        }

        let sizeBytes = sizeGB * 1024 * 1024 * 1024

        let diskDirectoryURL = disksDirectoryURL.appendingPathComponent(name, isDirectory: true)
        guard !fileManager.fileExists(atPath: diskDirectoryURL.path) else {
            throw Error.diskAlreadyExists(name)
        }

        try fileManager.createDirectory(at: diskDirectoryURL, withIntermediateDirectories: true)

        do {
            let imageURL = diskDirectoryURL.appendingPathComponent("disk.raw")
            try SparseDiskImage.create(at: imageURL, sizeBytes: sizeBytes, fileManager: fileManager)

            let manifest = DiskManifest(
                schemaVersion: 1,
                name: name,
                image: "disk.raw",
                imageFormat: "raw",
                filesystem: "ext4",
                sizeGB: sizeGB
            )

            let manifestURL = diskDirectoryURL.appendingPathComponent("manifest.json")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(manifest)
            try data.write(to: manifestURL, options: .atomic)
        } catch {
            try? fileManager.removeItem(at: diskDirectoryURL)
            throw error
        }

        return diskDirectoryURL
    }

    func loadDisk(named name: String) throws -> DiskBundle {
        let diskDirectoryURL = disksDirectoryURL.appendingPathComponent(name, isDirectory: true)
        guard (try? diskDirectoryURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.diskDoesNotExist(name)
        }

        let manifestURL = diskDirectoryURL.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONDecoder().decode(DiskManifest.self, from: data)

        guard manifest.schemaVersion == 1 else {
            throw Error.unsupportedSchemaVersion(manifest.schemaVersion)
        }
        guard manifest.imageFormat == "raw" else {
            throw Error.unsupportedImageFormat(manifest.imageFormat)
        }
        guard manifest.filesystem == "ext4" else {
            throw Error.unsupportedFilesystem(manifest.filesystem)
        }
        guard isValidDiskName(manifest.name), manifest.name == name else {
            throw Error.invalidDiskName(manifest.name)
        }
        guard manifest.sizeGB > 0 else {
            throw Error.invalidDiskSize(manifest.sizeGB)
        }

        let bundle = DiskBundle(directoryURL: diskDirectoryURL, manifest: manifest)
        let missingFiles = [bundle.imageURL, manifestURL].filter { !fileManager.fileExists(atPath: $0.path) }.map(\.lastPathComponent)
        guard missingFiles.isEmpty else {
            throw Error.missingRequiredFiles(missingFiles)
        }

        return bundle
    }

    func acquireLease(for diskBundles: [DiskBundle]) throws -> FileLockLease {
        let lease = FileLockLease()
        for diskBundle in diskBundles {
            let lockURL = diskBundle.directoryURL.appendingPathComponent("in-use.lock")
            try lease.addExclusiveLock(
                at: lockURL,
                fileManager: fileManager,
                createFailedError: Error.ioError(operation: "create lock file", path: lockURL.path),
                alreadyLockedError: Error.diskInUse(diskBundle.manifest.name)
            )
        }
        return lease
    }

    private func isValidDiskName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        guard name.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else { return false }
        guard name.canBeConverted(to: .ascii) else { return false }
        guard name.lengthOfBytes(using: .ascii) <= 20 else { return false }
        return true
    }
}
