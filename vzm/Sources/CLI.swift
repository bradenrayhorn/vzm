import ArgumentParser

@main
struct VZM: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage VMs",
        subcommands: [Create.self, Run.self]
    )
}

struct Create: ParsableCommand {
    @Argument var name: String
    @Option var bundle: String
    @Option var sshPort: String
    @Option var diskSize: String
}

struct Run: ParsableCommand {
}
