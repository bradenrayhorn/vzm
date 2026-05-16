import Foundation

struct StoredVM {
    let directoryURL: URL
    let manifest: VMManifest
}

struct VMManifest: Codable {
    let name: String
    let root: String
    let sshPort: UInt16
}

struct VMStore {
    enum Error: LocalizedError {
        case rootDoesNotExist(String)
        case vmDoesNotExist(String)

        var errorDescription: String? {
            switch self {
            case .rootDoesNotExist(let root):
                return "Root does not exist: \(root)"
            case .vmDoesNotExist(let name):
                return "VM does not exist: \(name)"
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

    func createVM(named name: String, root: String, sshPort: UInt16) throws -> URL {
        let rootURL = rootStore.rootsDirectoryURL.appendingPathComponent(root, isDirectory: true)
        guard (try? rootURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
            throw Error.rootDoesNotExist(root)
        }

        let vmDirectoryURL = vmsDirectoryURL.appendingPathComponent(name, isDirectory: true)
        try fileManager.createDirectory(at: vmDirectoryURL, withIntermediateDirectories: true)

        let manifest = VMManifest(name: name, root: root, sshPort: sshPort)
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
}

