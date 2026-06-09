import Foundation
import Virtualization

enum GuestBuilderLog {
    static func info(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}

struct GuestBuilderOptions {
    let builderRootURL: URL
    let sourceURL: URL

    let attribute: String = "guest-bundle"
    let workDiskSizeBytes: UInt64 = 64 * 1024 * 1024 * 1024
    let cpuCount: Int = 4
    let memorySizeBytes: UInt64 = 8 * 1024 * 1024 * 1024
}

struct GuestBuilderStatus: Codable {
    let schemaVersion: Int
    let status: String
    let exitCode: Int
    let endedAt: String?
    let log: String?
}

struct GuestBuilderRequestFile: Codable {
    let schemaVersion: Int
    let sourceDir: String
    let attribute: String
    let outputDir: String
}

struct BuilderRootBundle {
    let directoryURL: URL
    let manifest: RootManifest

    var kernelURL: URL { directoryURL.appendingPathComponent(manifest.kernel) }
    var initrdURL: URL { directoryURL.appendingPathComponent(manifest.initrd) }
    var rootfsURL: URL { directoryURL.appendingPathComponent(manifest.rootfs) }
}

enum GuestBuilderError: LocalizedError {
    case invalidDirectory(String)
    case invalidFile(String)
    case missingRequiredFiles(URL, [String])
    case invalidBuilderManifest(String)
    case unsupportedBuilderRoot(String)
    case invalidWorkDiskSize(UInt64)
    case invalidCPUCount(Int)
    case invalidMemorySize(UInt64)
    case missingStatus(URL)
    case buildFailed(GuestBuilderStatus, URL)

    var errorDescription: String? {
        switch self {
        case .invalidDirectory(let path):
            return "Directory does not exist or is not a directory: \(path)"
        case .invalidFile(let path):
            return "File does not exist or is not a regular file: \(path)"
        case .missingRequiredFiles(let directory, let files):
            return "Directory \(directory.path) is missing required files: \(files.joined(separator: ", "))"
        case .invalidBuilderManifest(let message):
            return "Invalid builder root manifest: \(message)"
        case .unsupportedBuilderRoot(let message):
            return "Unsupported builder root: \(message)"
        case .invalidWorkDiskSize(let size):
            return "Invalid work disk size: \(size) bytes"
        case .invalidCPUCount(let count):
            return "Invalid CPU count: \(count)"
        case .invalidMemorySize(let size):
            return "Invalid memory size: \(size) bytes"
        case .missingStatus(let workspaceURL):
            return "Builder VM stopped without writing status.json. Workspace kept at \(workspaceURL.path)"
        case .buildFailed(let status, let workspaceURL):
            return "Builder failed with exit code \(status.exitCode). Workspace kept at \(workspaceURL.path)"
        }
    }
}

@MainActor
final class GuestBuilder {
    private static let bundleFiles = ["kernel", "initrd", "manifest.json", "rootfs.squashfs"]

    private let options: GuestBuilderOptions
    private let fileManager: FileManager

    init(options: GuestBuilderOptions, fileManager: FileManager = .default) {
        self.options = options
        self.fileManager = fileManager
    }

    func build() async throws -> URL {
        try validateOptions()

        let builderRoot = try loadBuilderRoot(from: options.builderRootURL)
        let workspace = try prepareWorkspace()

        try copySource(from: options.sourceURL, to: workspace.sourceURL)
        try createWorkDisk(at: workspace.workDiskURL, sizeBytes: options.workDiskSizeBytes)
        try writeRequest(to: workspace.requestURL)

        GuestBuilderLog.info("Builder workspace: \(workspace.directoryURL.path)")
        GuestBuilderLog.info("Launching builder VM...")

        try await runBuilderVM(builderRoot: builderRoot, workspaceURL: workspace.directoryURL, workDiskURL: workspace.workDiskURL)
        let status = try readStatus(from: workspace.statusURL, workspaceURL: workspace.directoryURL)

        guard status.status == "success", status.exitCode == 0 else {
            throw GuestBuilderError.buildFailed(status, workspace.directoryURL)
        }

        try validateBundle(at: workspace.outputURL)
        return workspace.outputURL
    }

    private func validateOptions() throws {
        guard options.workDiskSizeBytes > 0 else {
            throw GuestBuilderError.invalidWorkDiskSize(options.workDiskSizeBytes)
        }
        guard options.cpuCount > 0 else {
            throw GuestBuilderError.invalidCPUCount(options.cpuCount)
        }
        guard options.memorySizeBytes >= 512 * 1024 * 1024 else {
            throw GuestBuilderError.invalidMemorySize(options.memorySizeBytes)
        }
        try requireDirectory(options.sourceURL)
    }

    private func loadBuilderRoot(from url: URL) throws -> BuilderRootBundle {
        let rootURL = url.resolvingSymlinksInPath().standardizedFileURL
        try requireDirectory(rootURL)

        let manifestURL = rootURL.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONDecoder().decode(RootManifest.self, from: data)

        guard manifest.schemaVersion == 1 else {
            throw GuestBuilderError.invalidBuilderManifest("unsupported schemaVersion \(manifest.schemaVersion)")
        }
        guard manifest.architecture == "aarch64" else {
            throw GuestBuilderError.unsupportedBuilderRoot("expected aarch64, got \(manifest.architecture)")
        }
        guard manifest.rootMode == "immutable" else {
            throw GuestBuilderError.unsupportedBuilderRoot("expected immutable rootMode, got \(manifest.rootMode)")
        }

        let bundle = BuilderRootBundle(directoryURL: rootURL, manifest: manifest)
        let missingFiles = [bundle.kernelURL, bundle.initrdURL, bundle.rootfsURL].filter { url in
            !fileManager.fileExists(atPath: url.path)
        }.map(\.lastPathComponent)

        guard missingFiles.isEmpty else {
            throw GuestBuilderError.missingRequiredFiles(rootURL, missingFiles)
        }

        return bundle
    }

    private func prepareWorkspace() throws -> GuestBuilderWorkspace {
        let workspaceURL = fileManager.temporaryDirectory
            .appendingPathComponent("vzm-build-root-\(UUID().uuidString)", isDirectory: true)
            .standardizedFileURL
        try fileManager.createDirectory(at: workspaceURL, withIntermediateDirectories: true)

        let workspace = GuestBuilderWorkspace(directoryURL: workspaceURL)
        try cleanWorkspace(workspace)
        try fileManager.createDirectory(at: workspace.outputURL, withIntermediateDirectories: true)
        return workspace
    }

    private func cleanWorkspace(_ workspace: GuestBuilderWorkspace) throws {
        for url in [
            workspace.sourceURL,
            workspace.outputURL,
            workspace.workDiskURL,
            workspace.requestURL,
            workspace.statusURL,
            workspace.statusTemporaryURL,
            workspace.buildLogURL,
            workspace.resultURL,
        ] {
            if fileManager.fileExists(atPath: url.path) {
                try fileManager.removeItem(at: url)
            }
        }
    }

    private func copySource(from sourceURL: URL, to destinationURL: URL) throws {
        let resolvedSourceURL = sourceURL.resolvingSymlinksInPath()
        GuestBuilderLog.info("Copying source \(resolvedSourceURL.path) -> \(destinationURL.path)")
        try fileManager.copyItem(at: resolvedSourceURL, to: destinationURL)
    }

    private func createWorkDisk(at url: URL, sizeBytes: UInt64) throws {
        GuestBuilderLog.info("Creating sparse work disk: \(url.path) (\(sizeBytes / 1024 / 1024 / 1024) GiB)")
        guard fileManager.createFile(atPath: url.path, contents: nil) else {
            throw GuestBuilderError.invalidFile(url.path)
        }

        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: sizeBytes)
        try handle.close()
    }

    private func writeRequest(to url: URL) throws {
        let request = GuestBuilderRequestFile(
            schemaVersion: 1,
            sourceDir: "/run/vzm-builder/source",
            attribute: options.attribute,
            outputDir: "/run/vzm-builder/output"
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(request)
        try data.write(to: url, options: .atomic)
    }

    private func runBuilderVM(builderRoot: BuilderRootBundle, workspaceURL: URL, workDiskURL: URL) async throws {
        let configuration = try buildVirtualMachineConfiguration(
            builderRoot: builderRoot,
            workspaceURL: workspaceURL,
            workDiskURL: workDiskURL
        )

        let machine = VZVirtualMachine(configuration: configuration)
        let stopDelegate = GuestBuilderStopDelegate()
        machine.delegate = stopDelegate

        try await machine.start()

        let statusURL = workspaceURL.appendingPathComponent("status.json")
        do {
            try await waitForBuilderCompletion(statusURL: statusURL, stopDelegate: stopDelegate)
        } catch {
            try? await forceStop(machine)
            throw error
        }

        if fileManager.fileExists(atPath: statusURL.path) {
            try? await forceStop(machine)
        }
    }

    private func waitForBuilderCompletion(statusURL: URL, stopDelegate: GuestBuilderStopDelegate) async throws {
        while !fileManager.fileExists(atPath: statusURL.path) {
            if let stopResult = stopDelegate.stopResult {
                try stopResult.get()
                return
            }

            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }

    private func forceStop(_ machine: VZVirtualMachine) async throws {
        guard machine.canStop else {
            return
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            machine.stop { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func buildVirtualMachineConfiguration(builderRoot: BuilderRootBundle, workspaceURL: URL, workDiskURL: URL) throws -> VZVirtualMachineConfiguration {
        let configuration = VZVirtualMachineConfiguration()

        configuration.platform = VZGenericPlatformConfiguration()

        let bootLoader = VZLinuxBootLoader(kernelURL: builderRoot.kernelURL)
        bootLoader.initialRamdiskURL = builderRoot.initrdURL
        bootLoader.commandLine = builderRoot.manifest.commandLine + " console=hvc0"
        configuration.bootLoader = bootLoader

        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil,
            fileHandleForWriting: FileHandle.standardError
        )
        configuration.serialPorts = [console]

        let rootAttachment = try VZDiskImageStorageDeviceAttachment(url: builderRoot.rootfsURL, readOnly: true)
        let workAttachment = try VZDiskImageStorageDeviceAttachment(url: workDiskURL, readOnly: false)
        configuration.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: rootAttachment),
            VZVirtioBlockDeviceConfiguration(attachment: workAttachment),
        ]

        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = VZNATNetworkDeviceAttachment()
        configuration.networkDevices = [network]

        let sharedDirectory = VZSharedDirectory(url: workspaceURL, readOnly: false)
        let directoryShare = VZSingleDirectoryShare(directory: sharedDirectory)
        let directorySharingDevice = VZVirtioFileSystemDeviceConfiguration(tag: "vzm-builder")
        directorySharingDevice.share = directoryShare
        configuration.directorySharingDevices = [directorySharingDevice]

        configuration.cpuCount = options.cpuCount
        configuration.memorySize = options.memorySizeBytes

        try configuration.validate()
        return configuration
    }

    private func readStatus(from statusURL: URL, workspaceURL: URL) throws -> GuestBuilderStatus {
        guard fileManager.fileExists(atPath: statusURL.path) else {
            throw GuestBuilderError.missingStatus(workspaceURL)
        }

        let data = try Data(contentsOf: statusURL)
        return try JSONDecoder().decode(GuestBuilderStatus.self, from: data)
    }

    private func validateBundle(at directoryURL: URL) throws {
        try requireDirectory(directoryURL)

        let missingFiles = Self.bundleFiles.filter { file in
            !fileManager.fileExists(atPath: directoryURL.appendingPathComponent(file).path)
        }
        guard missingFiles.isEmpty else {
            throw GuestBuilderError.missingRequiredFiles(directoryURL, missingFiles)
        }

        let manifestURL = directoryURL.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONDecoder().decode(RootManifest.self, from: data)

        guard manifest.schemaVersion == 1 else {
            throw GuestBuilderError.invalidBuilderManifest("built bundle has unsupported schemaVersion \(manifest.schemaVersion)")
        }
        guard manifest.architecture == "aarch64" else {
            throw GuestBuilderError.unsupportedBuilderRoot("built bundle expected aarch64, got \(manifest.architecture)")
        }
        guard manifest.rootMode == "immutable" else {
            throw GuestBuilderError.unsupportedBuilderRoot("built bundle expected immutable rootMode, got \(manifest.rootMode)")
        }
    }

    private func requireDirectory(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw GuestBuilderError.invalidDirectory(url.path)
        }
    }
}

struct GuestBuilderWorkspace {
    let directoryURL: URL

    var sourceURL: URL { directoryURL.appendingPathComponent("source", isDirectory: true) }
    var outputURL: URL { directoryURL.appendingPathComponent("output", isDirectory: true) }
    var workDiskURL: URL { directoryURL.appendingPathComponent("work.raw") }
    var requestURL: URL { directoryURL.appendingPathComponent("request.json") }
    var statusURL: URL { directoryURL.appendingPathComponent("status.json") }
    var statusTemporaryURL: URL { directoryURL.appendingPathComponent("status.json.tmp") }
    var buildLogURL: URL { directoryURL.appendingPathComponent("build.log") }
    var resultURL: URL { directoryURL.appendingPathComponent("result") }
}

final class GuestBuilderStopDelegate: NSObject, VZVirtualMachineDelegate {
    private var stopContinuation: CheckedContinuation<Void, Error>?
    private(set) var stopResult: Result<Void, Error>?

    func waitForStop() async throws {
        if let stopResult {
            try stopResult.get()
            return
        }

        try await withCheckedThrowingContinuation { continuation in
            self.stopContinuation = continuation
        }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        finish(.success(()))
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<Void, Error>) {
        if let continuation = stopContinuation {
            stopContinuation = nil
            continuation.resume(with: result)
        } else {
            stopResult = result
        }
    }
}

enum GuestBuilderPaths {
    static func url(from path: String, fileManager: FileManager = .default) -> URL {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let url: URL
        if expandedPath.hasPrefix("/") {
            url = URL(fileURLWithPath: expandedPath)
        } else {
            url = URL(fileURLWithPath: fileManager.currentDirectoryPath).appendingPathComponent(expandedPath)
        }
        return url.standardizedFileURL
    }

    static func builderRootURL(fileManager: FileManager = .default) -> URL {
        if let path = ProcessInfo.processInfo.environment["VZM_BUILDER_ROOT"], !path.isEmpty {
            return url(from: path, fileManager: fileManager)
        }

        let executableURL = URL(fileURLWithPath: CommandLine.arguments.first ?? "vzm")
            .standardizedFileURL
        return executableURL
            .deletingLastPathComponent()
            .appendingPathComponent("builder-guest", isDirectory: true)
            .appendingPathComponent("result", isDirectory: true)
            .standardizedFileURL
    }
}
