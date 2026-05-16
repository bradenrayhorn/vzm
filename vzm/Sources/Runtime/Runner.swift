import Foundation
import Virtualization

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
        try await stopDelegate.waitForStop()
    }
}

struct VZConfiguration {
    func build(vmBundle: StoredVM, rootBundle: RootBundle) throws -> VZVirtualMachineConfiguration {
        let configuration = VZVirtualMachineConfiguration()

        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: FileHandle.standardError)

        configuration.platform = VZGenericPlatformConfiguration()

        let bootLoader = VZLinuxBootLoader(kernelURL: rootBundle.kernelURL)
        bootLoader.initialRamdiskURL = rootBundle.initrdURL
        bootLoader.commandLine = rootBundle.manifest.commandLine + " console=hvc0" // serial console should be optional one day
        configuration.bootLoader = bootLoader

        let rootFs = try VZDiskImageStorageDeviceAttachment(url: rootBundle.rootfsURL, readOnly: true)

        configuration.serialPorts = [console]
        configuration.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: rootFs)
        ]
        configuration.cpuCount = 4
        configuration.memorySize = 8 * 1024 * 1024 * 1024
        configuration.networkDevices = []
        configuration.directorySharingDevices = []

        try configuration.validate()
        return configuration
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
