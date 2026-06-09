import Darwin
import Foundation

enum ExecutableLocator {
    static func currentExecutableURL() -> URL? {
        var bufferSize = UInt32(0)
        _NSGetExecutablePath(nil, &bufferSize)
        var buffer = [CChar](repeating: 0, count: Int(bufferSize))

        guard _NSGetExecutablePath(&buffer, &bufferSize) == 0 else {
            return nil
        }

        return URL(fileURLWithPath: String(cString: buffer)).standardizedFileURL
    }

    static func currentExecutableDirectoryURL() -> URL? {
        currentExecutableURL()?
            .resolvingSymlinksInPath()
            .deletingLastPathComponent()
    }

    static func findExecutableNextToCurrentExecutable(
        named names: [String],
        fileManager: FileManager = .default
    ) -> URL? {
        guard let executableDirectoryURL = currentExecutableDirectoryURL() else {
            return nil
        }

        for name in names {
            let url = executableDirectoryURL
                .appendingPathComponent(name)
                .standardizedFileURL
            if fileManager.isExecutableFile(atPath: url.path) {
                return url
            }
        }

        return nil
    }
}
