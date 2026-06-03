import Foundation
import Virtualization

enum RunnerError : Error {
    case vsockError(message: String)
}

protocol VZMService: Sendable {
    func start() async throws
    func stop() async
}

@MainActor
class Runner {

    let vmBundle: StoredVM
    let rootBundle: RootBundle
    let machine: VZVirtualMachine
    let stopDelegate: VMStopDelegate

    init(vmBundle: StoredVM, rootBundle: RootBundle) throws {
        self.vmBundle = vmBundle
        self.rootBundle = rootBundle

        let configuration = try VZConfiguration().build(vmBundle: vmBundle, rootBundle: rootBundle)
        machine = VZVirtualMachine(configuration: configuration)

        stopDelegate = VMStopDelegate()
        machine.delegate = stopDelegate
    }

    func run() async throws {
        try await machine.start()

        guard machine.socketDevices.count == 1, let virtioDevice = machine.socketDevices.first as? VZVirtioSocketDevice else {
            throw RunnerError.vsockError(message: "Missing VZVirtioSocketDevice")
        }

        let sshListener = try SSHListener(port: vmBundle.manifest.sshPort, virtioDevice: virtioDevice)
        try await withThrowingTaskGroup(of: Void.self) { group in 
            group.addTask { @MainActor in
                try await self.stopDelegate.waitForStop()
            }

            group.addTask {
                try await sshListener.start()
            }

            // wait for first finished task or failed task
            try await group.next()
            group.cancelAll()
        }

    }
}

struct VZConfiguration {
    func build(vmBundle: StoredVM, rootBundle: RootBundle) throws -> VZVirtualMachineConfiguration {
        let configuration = VZVirtualMachineConfiguration()

        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: FileHandle.standardError)

        let vsock = VZVirtioSocketDeviceConfiguration()

        configuration.platform = VZGenericPlatformConfiguration()

        let bootLoader = VZLinuxBootLoader(kernelURL: rootBundle.kernelURL)
        bootLoader.initialRamdiskURL = rootBundle.initrdURL
        bootLoader.commandLine = buildKernelCommandLine(vmBundle: vmBundle, rootBundle: rootBundle)
        configuration.bootLoader = bootLoader

        let rootFs = try VZDiskImageStorageDeviceAttachment(url: rootBundle.rootfsURL, readOnly: true)

        configuration.serialPorts = [console]
        configuration.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: rootFs)
        ]
        configuration.cpuCount = 4
        configuration.memorySize = 8 * 1024 * 1024 * 1024
        configuration.networkDevices = []
        configuration.directorySharingDevices = vmBundle.manifest.shares.map { share in
            let sharedDirectory = VZSharedDirectory(url: URL(fileURLWithPath: share.hostPath), readOnly: false)
            let directoryShare = VZSingleDirectoryShare(directory: sharedDirectory)
            let directorySharingDevice = VZVirtioFileSystemDeviceConfiguration(tag: share.tag)
            directorySharingDevice.share = directoryShare
            return directorySharingDevice
        }
        configuration.socketDevices = [vsock]

        try configuration.validate()
        return configuration
    }

    private func buildKernelCommandLine(vmBundle: StoredVM, rootBundle: RootBundle) -> String {
        let shareArguments = vmBundle.manifest.shares.map { share in
            "vzm.share=\(share.tag):\(share.mountPath)"
        }

        // eventually make serial console output optional
        return ([rootBundle.manifest.commandLine, "console=hvc0"] + shareArguments)
            .joined(separator: " ")
    }
}

class VMStopDelegate: NSObject, VZVirtualMachineDelegate {
    private var stopContinuation: CheckedContinuation<Void, Error>?

    func waitForStop() async throws {
        try await withCheckedThrowingContinuation { continuation in 
            self.stopContinuation = continuation
        }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        if let continuation = stopContinuation {
            self.stopContinuation = nil
            continuation.resume(returning: ())
        }
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        if let continuation = stopContinuation {
            self.stopContinuation = nil
            continuation.resume(throwing: error)
        }
    }
}
