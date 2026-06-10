import Darwin
import Foundation

final class FileLockLease {
    private var handles: [FileHandle] = []

    func addExclusiveLock(
        at lockURL: URL,
        fileManager: FileManager = .default,
        createFailedError: Error,
        alreadyLockedError: Error
    ) throws {
        if !fileManager.fileExists(atPath: lockURL.path) {
            guard fileManager.createFile(atPath: lockURL.path, contents: nil) else {
                throw createFailedError
            }
        }

        let handle = try FileHandle(forWritingTo: lockURL)
        let result = flock(handle.fileDescriptor, LOCK_EX | LOCK_NB)
        guard result == 0 else {
            try? handle.close()
            throw alreadyLockedError
        }

        handles.append(handle)
    }

    deinit {
        for handle in handles {
            flock(handle.fileDescriptor, LOCK_UN)
            try? handle.close()
        }
    }
}
