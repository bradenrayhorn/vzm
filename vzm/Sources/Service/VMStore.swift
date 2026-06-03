import Foundation

struct StoredVM {
    let directoryURL: URL
    let manifest: VMManifest
}

struct VMShare: Codable {
    let tag: String
    let hostPath: String
    let mountPath: String
}

struct VMManifest: Codable {
    let name: String
    let root: String
    let sshPort: UInt16
    let shares: [VMShare]

    init(name: String, root: String, sshPort: UInt16, shares: [VMShare] = []) {
        self.name = name
        self.root = root
        self.sshPort = sshPort
        self.shares = shares
    }

    enum CodingKeys: String, CodingKey {
        case name
        case root
        case sshPort
        case shares
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        root = try container.decode(String.self, forKey: .root)
        sshPort = try container.decode(UInt16.self, forKey: .sshPort)
        shares = try container.decodeIfPresent([VMShare].self, forKey: .shares) ?? []
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
            }
        }
    }

    private let fileManager: FileManager
    private let rootStore: RootStore
    let vmsDirectoryURL: URL

    init(fileManager: FileManager = .default) throws {
        try self.init(fileManager: fileManager, rootStore: RootStore(fileManager: fileManager))
    }

    init(fileManager: FileManager = .default, rootStore: RootStore) throws {
        self.fileManager = fileManager
        self.rootStore = rootStore

        let paths = try StorePaths(fileManager: fileManager)
        self.vmsDirectoryURL = paths.vmsDirectoryURL

        try fileManager.createDirectory(at: vmsDirectoryURL, withIntermediateDirectories: true)
    }

    func createVM(named name: String, root: String, sshPort: UInt16, shares: [VMShare] = []) throws -> URL {
        let rootURL = rootStore.rootsDirectoryURL.appendingPathComponent(root, isDirectory: true)
        guard (try? rootURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.rootDoesNotExist(root)
        }

        try validateShares(shares)

        let vmDirectoryURL = vmsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        try fileManager.createDirectory(at: vmDirectoryURL, withIntermediateDirectories: true)

        let manifest = VMManifest(name: name, root: root, sshPort: sshPort, shares: shares)
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

    private func validateShares(_ shares: [VMShare]) throws {
        var seenMountPaths = Set<String>()
        var seenTags = Set<String>()

        for share in shares {
            guard (try? URL(fileURLWithPath: share.hostPath).resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
                throw Error.invalidShareHostPath(share.hostPath)
            }

            guard isValidGuestMountPath(share.mountPath) else {
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
}

