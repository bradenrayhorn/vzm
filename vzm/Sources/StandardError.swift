import Foundation

/// Writes user-facing diagnostics to the invoking terminal.
enum StandardError {
    private static let lock = NSLock()

    static func write(_ message: String) {
        lock.lock()
        defer { lock.unlock() }

        do {
            try FileHandle.standardError.write(contentsOf: Data(message.utf8))
        } catch {
            // A diagnostic write failure must not terminate the VM process.
        }
    }

    static func writeLine(_ message: String) {
        write(message + "\n")
    }
}
