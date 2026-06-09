import Foundation
import Virtualization

enum RunnerError : Error {
    case vsockError(message: String)
}

@MainActor
class Runner {

    let vmBundle: StoredVM
    let rootBundle: RootBundle
    let diskBundles: [DiskBundle]
    let diskLease: DiskLease
    let machine: VZVirtualMachine
    let stopDelegate: VMStopDelegate

    init(vmBundle: StoredVM, rootBundle: RootBundle) throws {
        self.vmBundle = vmBundle
        self.rootBundle = rootBundle

        let diskStore = try DiskStore()
        self.diskBundles = try vmBundle.manifest.disks.map { try diskStore.loadDisk(named: $0.name) }
        self.diskLease = try diskStore.acquireLease(for: diskBundles)

        let configuration = try VZConfiguration().build(vmBundle: vmBundle, rootBundle: rootBundle, diskBundles: diskBundles)
        machine = VZVirtualMachine(configuration: configuration)

        stopDelegate = VMStopDelegate()
        machine.delegate = stopDelegate
    }

    func run() async throws {
        let proxyService = try ProxyService(vmName: vmBundle.manifest.name)
        var portExposureService: PortExposureService?

        do {
            try await proxyService.launch()
            try await machine.start()

            guard machine.socketDevices.count == 1, let virtioDevice = machine.socketDevices.first as? VZVirtioSocketDevice else {
                throw RunnerError.vsockError(message: "Missing VZVirtioSocketDevice")
            }

            try proxyService.attach(to: virtioDevice)

            let exposureService = PortExposureService(virtioDevice: virtioDevice)
            portExposureService = exposureService
            PortExposureCoordinator.shared.attach(service: exposureService)

            let sshListener = TCPVirtioForwardListener(
                hostPort: vmBundle.manifest.sshPort,
                target: .directVsock(port: 22),
                virtioDevice: virtioDevice,
                label: "SSH forwarding"
            )
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { @MainActor in
                    try await withTaskCancellationHandler {
                        try await self.stopDelegate.waitForStop()
                    } onCancel: {
                        Task { @MainActor in
                            self.stopDelegate.cancelWait()
                        }
                    }
                }

                group.addTask {
                    try await sshListener.start()
                }

                defer { group.cancelAll() }

                // wait for first finished task or failed task
                try await group.next()
            }
        } catch {
            await stopRuntimeServices(portExposureService: portExposureService, proxyService: proxyService)
            throw error
        }

        await stopRuntimeServices(portExposureService: portExposureService, proxyService: proxyService)
    }

    private func stopRuntimeServices(portExposureService: PortExposureService?, proxyService: ProxyService) async {
        PortExposureCoordinator.shared.detach()
        await portExposureService?.stop()
        await proxyService.stop()
    }
}

struct VZConfiguration {
    func build(vmBundle: StoredVM, rootBundle: RootBundle, diskBundles: [DiskBundle]) throws -> VZVirtualMachineConfiguration {
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
        var storageDevices = [VZStorageDeviceConfiguration]()
        storageDevices.append(VZVirtioBlockDeviceConfiguration(attachment: rootFs))
        for diskBundle in diskBundles {
            let attachment = try VZDiskImageStorageDeviceAttachment(
                url: diskBundle.imageURL,
                readOnly: false,
                cachingMode: .automatic,
                synchronizationMode: .fsync
            )
            let blockDevice = VZVirtioBlockDeviceConfiguration(attachment: attachment)
            blockDevice.blockDeviceIdentifier = diskBundle.manifest.name
            storageDevices.append(blockDevice)
        }
        configuration.storageDevices = storageDevices
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
        let diskArguments = vmBundle.manifest.disks.map { disk in
            "vzm.disk=\(disk.name):ext4:\(disk.mountPath)"
        }

        // eventually make serial console output optional
        return ([rootBundle.manifest.commandLine, "console=hvc0"] + shareArguments + diskArguments)
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

    func cancelWait() {
        if let continuation = stopContinuation {
            self.stopContinuation = nil
            continuation.resume(throwing: CancellationError())
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
