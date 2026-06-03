import Foundation

struct StorePaths {
    let appSupportDirectoryURL: URL
    let vzmDirectoryURL: URL
    let rootsDirectoryURL: URL
    let vmsDirectoryURL: URL
    let disksDirectoryURL: URL

    init(fileManager: FileManager = .default) throws {
        self.appSupportDirectoryURL = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )

        self.vzmDirectoryURL = appSupportDirectoryURL
            .appendingPathComponent("vzm", isDirectory: true)

        self.rootsDirectoryURL = vzmDirectoryURL
            .appendingPathComponent("roots", isDirectory: true)

        self.vmsDirectoryURL = vzmDirectoryURL
            .appendingPathComponent("vms", isDirectory: true)

        self.disksDirectoryURL = vzmDirectoryURL
            .appendingPathComponent("disks", isDirectory: true)
    }
}
