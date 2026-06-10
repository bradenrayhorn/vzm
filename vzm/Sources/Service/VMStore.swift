import Foundation

enum VMStateDisk {
    static let imageFileName = "state.raw"
    static let blockDeviceIdentifier = "vzm-state"
    static let mountPath = "/persist"
    static let sizeBytes: UInt64 = 256 * 1024 * 1024
}

struct StoredVM {
    let directoryURL: URL
    let manifest: VMManifest

    var stateImageURL: URL { directoryURL.appendingPathComponent(VMStateDisk.imageFileName) }
    var lockURL: URL { directoryURL.appendingPathComponent("in-use.lock") }
}

struct VMShare: Codable {
    let tag: String
    let hostPath: String
    let mountPath: String
}

struct VMDiskMount: Codable {
    let name: String
    let mountPath: String
}

struct VMManifest: Codable {
    let name: String
    let root: String
    let sshPort: UInt16
    let shares: [VMShare]
    let disks: [VMDiskMount]

    init(name: String, root: String, sshPort: UInt16, shares: [VMShare] = [], disks: [VMDiskMount] = []) {
        self.name = name
        self.root = root
        self.sshPort = sshPort
        self.shares = shares
        self.disks = disks
    }

    enum CodingKeys: String, CodingKey {
        case name
        case root
        case sshPort
        case shares
        case disks
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        root = try container.decode(String.self, forKey: .root)
        sshPort = try container.decode(UInt16.self, forKey: .sshPort)
        shares = try container.decodeIfPresent([VMShare].self, forKey: .shares) ?? []
        disks = try container.decodeIfPresent([VMDiskMount].self, forKey: .disks) ?? []
    }
}

struct VMStore {
    enum Error: LocalizedError {
        case rootDoesNotExist(String)
        case vmDoesNotExist(String)
        case invalidShareHostPath(String)
        case invalidShareMountPath(String)
        case duplicateShareMountPath(String)
        case duplicateShareTag(String)
        case invalidDiskMountPath(String)
        case duplicateDiskMountPath(String)
        case duplicateDiskName(String)
        case reservedDiskName(String)
        case ioError(operation: String, path: String)
        case vmInUse(String)

        var errorDescription: String? {
            switch self {
            case .rootDoesNotExist(let root):
                return "Root does not exist: \(root)"
            case .vmDoesNotExist(let name):
                return "VM does not exist: \(name)"
            case .invalidShareHostPath(let path):
                return "Shared host path does not exist or is not a directory: \(path)"
            case .invalidShareMountPath(let path):
                return "Invalid shared guest mount path: \(path)"
            case .duplicateShareMountPath(let path):
                return "Duplicate shared guest mount path: \(path)"
            case .duplicateShareTag(let tag):
                return "Duplicate shared directory tag: \(tag)"
            case .invalidDiskMountPath(let path):
                return "Invalid disk guest mount path: \(path)"
            case .duplicateDiskMountPath(let path):
                return "Duplicate disk guest mount path: \(path)"
            case .duplicateDiskName(let name):
                return "Duplicate disk name: \(name)"
            case .reservedDiskName(let name):
                return "Reserved disk name: \(name)"
            case .ioError(let operation, let path):
                return "I/O error during \(operation): \(path)"
            case .vmInUse(let name):
                return "VM is already in use: \(name)"
            }
        }
    }

    private let fileManager: FileManager
    private let rootStore: RootStore
    private let diskStore: DiskStore
    let vmsDirectoryURL: URL

    init(fileManager: FileManager = .default) throws {
        try self.init(
            fileManager: fileManager,
            rootStore: RootStore(fileManager: fileManager),
            diskStore: DiskStore(fileManager: fileManager)
        )
    }

    init(fileManager: FileManager = .default, rootStore: RootStore, diskStore: DiskStore) throws {
        self.fileManager = fileManager
        self.rootStore = rootStore
        self.diskStore = diskStore

        let paths = try StorePaths(fileManager: fileManager)
        self.vmsDirectoryURL = paths.vmsDirectoryURL

        try fileManager.createDirectory(at: vmsDirectoryURL, withIntermediateDirectories: true)
    }

    func createVM(named name: String, root: String, sshPort: UInt16, shares: [VMShare] = [], disks: [VMDiskMount] = []) throws -> URL {
        do {
            _ = try rootStore.loadRoot(named: root)
        } catch RootStore.Error.rootDoesNotExist {
            throw Error.rootDoesNotExist(root)
        }

        try validateShares(shares)
        try validateDisks(disks)

        let vmDirectoryURL = vmsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        try fileManager.createDirectory(at: vmDirectoryURL, withIntermediateDirectories: true)
        try ensureStateDisk(in: vmDirectoryURL)

        let manifest = VMManifest(name: name, root: root, sshPort: sshPort, shares: shares, disks: disks)
        let manifestURL = vmDirectoryURL.appendingPathComponent("manifest.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(manifest)
        try data.write(to: manifestURL)

        return vmDirectoryURL
    }

    func loadVM(named name: String) throws -> StoredVM {
        let vmDirectoryURL = vmsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        guard (try? vmDirectoryURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.vmDoesNotExist(name)
        }

        let manifestURL = vmDirectoryURL.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONDecoder().decode(VMManifest.self, from: data)
        return StoredVM(directoryURL: vmDirectoryURL, manifest: manifest)
    }

    func acquireLease(for vm: StoredVM) throws -> FileLockLease {
        let lease = FileLockLease()
        try lease.addExclusiveLock(
            at: vm.lockURL,
            fileManager: fileManager,
            createFailedError: Error.ioError(operation: "create lock file", path: vm.lockURL.path),
            alreadyLockedError: Error.vmInUse(vm.manifest.name)
        )
        return lease
    }

    func ensureStateDisk(for vm: StoredVM) throws {
        try ensureStateDisk(in: vm.directoryURL)
    }

    private func ensureStateDisk(in vmDirectoryURL: URL) throws {
        let stateImageURL = vmDirectoryURL.appendingPathComponent(VMStateDisk.imageFileName)
        try SparseDiskImage.createIfMissing(
            at: stateImageURL,
            sizeBytes: VMStateDisk.sizeBytes,
            fileManager: fileManager
        )
    }

    private func validateShares(_ shares: [VMShare]) throws {
        var seenMountPaths = Set<String>()
        var seenTags = Set<String>()

        for share in shares {
            guard (try? URL(fileURLWithPath: share.hostPath).resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
                throw Error.invalidShareHostPath(share.hostPath)
            }

            guard isValidGuestMountPath(share.mountPath), !isReservedGuestMountPath(share.mountPath) else {
                throw Error.invalidShareMountPath(share.mountPath)
            }

            if !seenMountPaths.insert(share.mountPath).inserted {
                throw Error.duplicateShareMountPath(share.mountPath)
            }

            if !seenTags.insert(share.tag).inserted {
                throw Error.duplicateShareTag(share.tag)
            }
        }
    }

    private func validateDisks(_ disks: [VMDiskMount]) throws {
        var seenNames = Set<String>()
        var seenMountPaths = Set<String>()

        for disk in disks {
            guard disk.name != VMStateDisk.blockDeviceIdentifier else {
                throw Error.reservedDiskName(disk.name)
            }

            _ = try diskStore.loadDisk(named: disk.name)

            guard isValidGuestMountPath(disk.mountPath), !isReservedGuestMountPath(disk.mountPath) else {
                throw Error.invalidDiskMountPath(disk.mountPath)
            }

            if !seenNames.insert(disk.name).inserted {
                throw Error.duplicateDiskName(disk.name)
            }

            if !seenMountPaths.insert(disk.mountPath).inserted {
                throw Error.duplicateDiskMountPath(disk.mountPath)
            }
        }
    }

    private func isValidGuestMountPath(_ path: String) -> Bool {
        guard path.hasPrefix("/") else {
            return false
        }

        guard !path.contains(":") else {
            return false
        }

        guard path.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            return false
        }

        return true
    }

    private func isReservedGuestMountPath(_ path: String) -> Bool {
        path == VMStateDisk.mountPath || path.hasPrefix(VMStateDisk.mountPath + "/")
    }
}

