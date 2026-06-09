import Darwin
import Dispatch
import Foundation
import Virtualization

enum RunnerError : Error {
    case vsockError(message: String)
}

struct VMResources {
    let cpuCount: Int
    let memorySizeBytes: UInt64
}

@MainActor
class Runner {

    let vmBundle: StoredVM
    let rootBundle: RootBundle
    let diskBundles: [DiskBundle]
    let diskLease: DiskLease
    let machine: VZVirtualMachine
    let stopDelegate: VMStopDelegate

    private var interruptCount = 0

    init(vmBundle: StoredVM, rootBundle: RootBundle, resources: VMResources = .default) throws {
        self.vmBundle = vmBundle
        self.rootBundle = rootBundle

        let diskStore = try DiskStore()
        self.diskBundles = try vmBundle.manifest.disks.map { try diskStore.loadDisk(named: $0.name) }
        self.diskLease = try diskStore.acquireLease(for: diskBundles)

        let configuration = try VZConfiguration().build(vmBundle: vmBundle, rootBundle: rootBundle, diskBundles: diskBundles, resources: resources)
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

            Darwin.signal(SIGINT, SIG_IGN)
            let interruptSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            interruptSource.setEventHandler { [weak self] in
                Task { @MainActor in
                    guard let self else { return }
                    self.interruptCount += 1
                    await self.stopFromInterrupt(force: self.interruptCount > 1)
                }
            }
            interruptSource.setCancelHandler {
                Darwin.signal(SIGINT, SIG_DFL)
            }
            interruptSource.resume()
            defer { interruptSource.cancel() }

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

    private func stopFromInterrupt(force: Bool) async {
        if force {
            fputs("Received Ctrl-C again; forcing VM stop.\n", stderr)
            await forceStop()
            return
        }

        fputs("Received Ctrl-C; requesting VM shutdown. Press Ctrl-C again to force stop.\n", stderr)

        if machine.canRequestStop {
            do {
                try machine.requestStop()
                return
            } catch {
                fputs("Graceful VM shutdown failed: \(error). Forcing stop.\n", stderr)
            }
        }

        await forceStop()
    }

    private func forceStop() async {
        guard machine.canStop else {
            fputs("VM cannot be stopped right now.\n", stderr)
            return
        }

        do {
            try await stopImmediately()
            stopDelegate.hostDidStop()
        } catch {
            stopDelegate.hostStopFailed(error)
        }
    }

    private func stopImmediately() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            machine.stop { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

extension VMResources {
    static let gibibyte: UInt64 = 1024 * 1024 * 1024
    static let `default` = VMResources(
        cpuCount: VZConfiguration.defaultCPUCount,
        memorySizeBytes: VZConfiguration.defaultMemorySizeBytes
    )
}

struct VZConfiguration {
    static let defaultCPUCount = 4
    static let defaultMemorySizeBytes: UInt64 = 8 * VMResources.gibibyte

    func build(vmBundle: StoredVM, rootBundle: RootBundle, diskBundles: [DiskBundle], resources: VMResources) throws -> VZVirtualMachineConfiguration {
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
        configuration.cpuCount = resources.cpuCount
        configuration.memorySize = resources.memorySizeBytes
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

    func hostDidStop() {
        finish(.success(()))
    }

    func hostStopFailed(_ error: any Error) {
        finish(.failure(error))
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        finish(.success(()))
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<Void, Error>) {
        guard let continuation = stopContinuation else {
            return
        }

        stopContinuation = nil
        continuation.resume(with: result)
    }
}
