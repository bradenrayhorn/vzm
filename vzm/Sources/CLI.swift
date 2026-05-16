import ArgumentParser
import Foundation

@main
struct VZM: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage VMs",
        subcommands: [Create.self, Run.self, ImportRoot.self, BuildRoot.self]
    )
}

struct Create: ParsableCommand {
    @Argument var name: String
    @Option var root: String
    @Option var sshPort: String

    mutating func run() throws {
        guard let parsedSSHPort = UInt16(sshPort) else {
            throw ValidationError("Invalid --ssh-port: \(sshPort)")
        }

        let vmStore = try VMStore()
        let createdURL = try vmStore.createVM(named: name, root: root, sshPort: parsedSSHPort)
        print("Created VM '\(name)' at \(createdURL.path)")
    }
}

struct Run: AsyncParsableCommand {
    @Argument var name: String

    mutating func run() async throws {
        let vmStore = try VMStore()
        let vm = try vmStore.loadVM(named: name)

        let rootStore = try RootStore()
        let root = try rootStore.loadRoot(named: vm.manifest.root)

        let runner = try await Runner(vmBundle: vm, rootBundle: root)
        try await runner.run()
    }
}

struct ImportRoot: ParsableCommand {
    @Argument var name: String
    @Option var path: String

    mutating func run() throws {
        let rootStore = try RootStore()
        let storedURL = try rootStore.storeRoot(named: name, from: path)
        print("Imported root '\(name)' to \(storedURL.path)")
    }
}

struct BuildRoot: ParsableCommand {
}
