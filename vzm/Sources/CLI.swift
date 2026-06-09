import ArgumentParser
import Foundation

struct VZM: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage VMs",
        subcommands: [Create.self, CreateDisk.self, Run.self, BuildRoot.self, Secret.self]
    )
}

struct Create: ParsableCommand {
    @Argument var name: String
    @Option var root: String
    @Option var sshPort: String
    @Option(name: .long, help: "Repeatable share mapping in the form HOST_PATH:GUEST_MOUNT_PATH")
    var share: [String] = []
    @Option(name: .long, help: "Repeatable disk mapping in the form DISK_NAME:GUEST_MOUNT_PATH")
    var disk: [String] = []

    mutating func run() throws {
        guard let parsedSSHPort = UInt16(sshPort) else {
            throw ValidationError("Invalid --ssh-port: \(sshPort)")
        }

        let shares = try share.enumerated().map { index, value in
            try parseShare(value, index: index)
        }
        let disks = try disk.map(parseDisk)

        let vmStore = try VMStore()
        let createdURL = try vmStore.createVM(named: name, root: root, sshPort: parsedSSHPort, shares: shares, disks: disks)
        print("Created VM '\(name)' at \(createdURL.path)")
    }

    private func parseShare(_ value: String, index: Int) throws -> VMShare {
        guard let separatorIndex = value.firstIndex(of: ":") else {
            throw ValidationError("Invalid --share '\(value)'. Expected HOST_PATH:GUEST_MOUNT_PATH")
        }

        let hostPath = String(value[..<separatorIndex])
        let mountPath = String(value[value.index(after: separatorIndex)...])

        guard !hostPath.isEmpty, !mountPath.isEmpty else {
            throw ValidationError("Invalid --share '\(value)'. Expected HOST_PATH:GUEST_MOUNT_PATH")
        }

        let resolvedHostPath = resolveHostPath(hostPath)
        return VMShare(tag: "vzmshare\(index)", hostPath: resolvedHostPath, mountPath: mountPath)
    }

    private func parseDisk(_ value: String) throws -> VMDiskMount {
        guard let separatorIndex = value.firstIndex(of: ":") else {
            throw ValidationError("Invalid --disk '\(value)'. Expected DISK_NAME:GUEST_MOUNT_PATH")
        }

        let diskName = String(value[..<separatorIndex])
        let mountPath = String(value[value.index(after: separatorIndex)...])

        guard !diskName.isEmpty, !mountPath.isEmpty else {
            throw ValidationError("Invalid --disk '\(value)'. Expected DISK_NAME:GUEST_MOUNT_PATH")
        }

        return VMDiskMount(name: diskName, mountPath: mountPath)
    }

    private func resolveHostPath(_ path: String, fileManager: FileManager = .default) -> String {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let url: URL
        if expandedPath.hasPrefix("/") {
            url = URL(fileURLWithPath: expandedPath)
        } else {
            url = URL(fileURLWithPath: fileManager.currentDirectoryPath).appendingPathComponent(expandedPath)
        }
        return url.standardizedFileURL.path
    }
}

struct CreateDisk: ParsableCommand {
    @Argument var name: String
    @Option(name: .long, help: "Disk size in GiB")
    var sizeGB: UInt64

    mutating func run() throws {
        let diskStore = try DiskStore()
        let createdURL = try diskStore.createDisk(named: name, sizeGB: sizeGB)
        print("Created disk '\(name)' at \(createdURL.path)")
    }
}

struct Run: AsyncParsableCommand {
    @Argument var name: String
    @Option(name: .long, help: "Number of virtual CPUs. Defaults to the current value (\(VZConfiguration.defaultCPUCount)).")
    var cpuCount: Int = VZConfiguration.defaultCPUCount
    @Option(name: .long, help: "Memory size in GiB. Defaults to the current value (\(VZConfiguration.defaultMemorySizeBytes / VMResources.gibibyte)).")
    var memoryGB: UInt64 = VZConfiguration.defaultMemorySizeBytes / VMResources.gibibyte

    mutating func run() async throws {
        guard cpuCount > 0 else {
            throw ValidationError("Invalid --cpu-count: must be greater than 0")
        }

        guard memoryGB > 0 else {
            throw ValidationError("Invalid --memory-gb: must be greater than 0")
        }

        let vmStore = try VMStore()
        let vm = try vmStore.loadVM(named: name)

        let rootStore = try RootStore()
        let root = try rootStore.loadRoot(named: vm.manifest.root)

        let resources = VMResources(
            cpuCount: cpuCount,
            memorySizeBytes: memoryGB * VMResources.gibibyte
        )
        let runner = try await Runner(vmBundle: vm, rootBundle: root, resources: resources)
        try await runner.run()
    }
}

struct Secret: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage secrets stored in the macOS Keychain.",
        subcommands: [SecretAdd.self, SecretList.self, SecretRemove.self],
        defaultSubcommand: SecretList.self
    )
}

struct SecretAdd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "add")

    @Argument var name: String
    @Option(name: .long, help: "Repeatable host/domain restriction.")
    var host: [String] = []

    mutating func run() throws {
        let secretData = FileHandle.standardInput.readDataToEndOfFile()
        guard !secretData.isEmpty else {
            throw ValidationError("Secret value must be provided on stdin.")
        }

        let secret = try normalizeSecret(secretData)

        let secretStore = SecretStore()
        try secretStore.upsertSecret(named: name, secret: secret, hosts: host)
        print("Stored secret '\(name)'")
    }

    private func normalizeSecret(_ data: Data) throws -> String {
        guard let secret = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        else {
            throw ValidationError("Secret value on stdin must be valid UTF-8.")
        }

        guard !secret.isEmpty else {
            throw ValidationError("Secret value must not be empty.")
        }

        return secret
    }
}

struct SecretList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list")

    mutating func run() throws {
        let secretStore = SecretStore()
        let secrets = try secretStore.listSecrets()

        print("NAME\tDOMAINS")
        for secret in secrets {
            print("\(secret.name)\t\(secret.hosts.joined(separator: ","))")
        }
    }
}

struct SecretRemove: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "rm")

    @Argument var name: String

    mutating func run() throws {
        let secretStore = SecretStore()
        try secretStore.removeSecret(named: name)
        print("Removed secret '\(name)'")
    }
}

struct BuildRoot: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Build and import a Linux guest root bundle using the separate builder guest VM."
    )

    @Argument(help: "Guest flake/source directory to build.")
    var source: String

    @Argument(help: "Name to import the built root as.")
    var name: String

    @Option(name: .long, help: "Path to the already-built builder guest bundle. Defaults to the nearest builder-guest/result found above the current directory.")
    var builderRoot: String?

    mutating func run() async throws {
        let sourceURL = GuestBuilderPaths.url(from: source)
        let builderRootURL = builderRoot.map { GuestBuilderPaths.url(from: $0) }
            ?? GuestBuilderPaths.defaultBuilderRootURL()

        GuestBuilderLog.info("Builder root: \(builderRootURL.path)")
        GuestBuilderLog.info("Guest source: \(sourceURL.path)")

        let builder = await GuestBuilder(options: GuestBuilderOptions(
            builderRootURL: builderRootURL,
            sourceURL: sourceURL
        ))
        let builtURL = try await builder.build()
        let workspaceURL = builtURL.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: workspaceURL) }

        let rootStore = try RootStore()
        let storedURL = try rootStore.storeRoot(named: name, from: builtURL)
        print("Built and imported root '\(name)' to \(storedURL.path)")
    }
}
