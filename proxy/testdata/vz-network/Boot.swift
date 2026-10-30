import Darwin
import Foundation
import Virtualization

final class SmokeDelegate: NSObject, VZVirtualMachineDelegate {
    var continuation: CheckedContinuation<Void, Error>?
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        continuation?.resume()
        continuation = nil
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

@main
struct Boot {
    @MainActor static func main() async throws {
        let args = CommandLine.arguments
        guard args.count == 8 else { fatalError("Boot KERNEL BASE_INITRD GUEST PROXY DIRECTORY PYTHON PACK_SCRIPT") }
        let directory = URL(fileURLWithPath: args[5])
        let network = try PrivateNetwork()
        let proxy = Process()
        proxy.executableURL = URL(fileURLWithPath: args[4])
        proxy.arguments = [
            "--network-fd", "0", "--listen-unix", directory.appendingPathComponent("p.sock").path,
            "--control-unix", directory.appendingPathComponent("a.sock").path,
            "--ca-cert", directory.appendingPathComponent("ca.pem").path,
            "--parent-pid", String(ProcessInfo.processInfo.processIdentifier),
        ]
        proxy.standardInput = network.proxyHandle
        proxy.standardOutput = FileHandle.standardError
        proxy.standardError = FileHandle.standardError
        try proxy.run()
        defer { if proxy.isRunning { proxy.terminate(); proxy.waitUntilExit() } }
        try network.proxyHandle.close()
        let ca = directory.appendingPathComponent("ca.pem")
        for _ in 0..<100 {
            if FileManager.default.fileExists(atPath: ca.path) { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let initrd = directory.appendingPathComponent("test-initrd")
        let pack = Process()
        pack.executableURL = URL(fileURLWithPath: args[6])
        pack.arguments = [args[7], "--pack", args[2], args[3], ca.path, initrd.path]
        try pack.run(); pack.waitUntilExit()
        guard pack.terminationStatus == 0 else { fatalError("initramfs packing failed") }

        let config = VZVirtualMachineConfiguration()
        config.platform = VZGenericPlatformConfiguration()
        config.cpuCount = 2
        config.memorySize = 512 * 1024 * 1024
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: args[1]))
        boot.initialRamdiskURL = initrd
        boot.commandLine = "console=hvc0 rdinit=/init panic=-1 quiet"
        config.bootLoader = boot
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: .standardOutput)
        config.serialPorts = [console]
        config.networkDevices = [network.deviceConfiguration()]
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        try config.validate()
        let vm = VZVirtualMachine(configuration: config)
        let delegate = SmokeDelegate()
        vm.delegate = delegate
        try await vm.start()
        let timeout = Task { @MainActor in
            try await Task.sleep(nanoseconds: 90_000_000_000)
            if vm.canStop { try await vm.stop() }
            delegate.continuation?.resume(throwing: NSError(domain: "SmokeTimeout", code: 1))
            delegate.continuation = nil
        }
        defer { timeout.cancel() }
        try await withCheckedThrowingContinuation { delegate.continuation = $0 }
    }
}
