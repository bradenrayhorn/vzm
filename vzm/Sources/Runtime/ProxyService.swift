import Darwin
import Foundation
import NIOCore
import NIOPosix
import Virtualization

enum ProxyServiceError: LocalizedError {
    case proxyExecutableNotFound(String)
    case proxyExecutableMissing
    case proxyNotReady(String)
    case missingCertificateAuthority

    var errorDescription: String? {
        switch self {
        case .proxyExecutableNotFound(let path):
            return "Proxy executable does not exist or is not executable: \(path)"
        case .proxyExecutableMissing:
            return "Proxy executable not found. Set VZM_PROXY_PATH or run through vzm/run-signed."
        case .proxyNotReady(let message):
            return "Proxy did not become ready: \(message)"
        case .missingCertificateAuthority:
            return "Proxy certificate authority is missing"
        }
    }
}

@MainActor
final class ProxyService {
    private static let proxyVsockPort: UInt32 = 3128
    private static let caVsockPort: UInt32 = 3129

    private let vmName: String
    private let proxyExecutableURL: URL
    private let runDirectoryURL: URL
    private let proxySocketURL: URL
    private let caCertificateURL: URL
    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    private var process: Process?
    private var caPEM: Data?
    private var stopped = false

    private weak var virtioDevice: VZVirtioSocketDevice?
    private var proxyListener: VZVirtioSocketListener?
    private var proxyListenerDelegate: VsockUnixBridgeDelegate?
    private var caListener: VZVirtioSocketListener?
    private var caListenerDelegate: CAVsockListenerDelegate?

    init(vmName: String) throws {
        self.vmName = vmName
        self.proxyExecutableURL = try Self.locateProxyExecutable()
        self.runDirectoryURL = try Self.createRunDirectory()
        self.proxySocketURL = runDirectoryURL.appendingPathComponent("p.sock")
        self.caCertificateURL = runDirectoryURL.appendingPathComponent("ca.pem")
    }

    func launch() async throws {
        let process = Process()
        process.executableURL = proxyExecutableURL
        process.arguments = [
            "--listen-unix", proxySocketURL.path,
            "--ca-cert", caCertificateURL.path,
        ]
        process.currentDirectoryURL = runDirectoryURL
        process.environment = ProcessInfo.processInfo.environment
        process.standardOutput = FileHandle.standardError
        process.standardError = FileHandle.standardError

        self.process = process
        try process.run()
        try await waitForReady()
    }

    func attach(to virtioDevice: VZVirtioSocketDevice) throws {
        guard let caPEM else {
            throw ProxyServiceError.missingCertificateAuthority
        }

        let proxyListener = VZVirtioSocketListener()
        let proxyListenerDelegate = VsockUnixBridgeDelegate(
            unixSocketPath: proxySocketURL.path,
            eventLoopGroup: eventLoopGroup
        )
        proxyListener.delegate = proxyListenerDelegate
        virtioDevice.setSocketListener(proxyListener, forPort: Self.proxyVsockPort)

        let caListener = VZVirtioSocketListener()
        let caListenerDelegate = CAVsockListenerDelegate(caPEM: caPEM)
        caListener.delegate = caListenerDelegate
        virtioDevice.setSocketListener(caListener, forPort: Self.caVsockPort)

        self.virtioDevice = virtioDevice
        self.proxyListener = proxyListener
        self.proxyListenerDelegate = proxyListenerDelegate
        self.caListener = caListener
        self.caListenerDelegate = caListenerDelegate

        FileHandle.standardError.write(Data("Proxy bridge for \(vmName) listening on vsock ports \(Self.proxyVsockPort) and \(Self.caVsockPort)\n".utf8))
    }

    func stop() async {
        guard !stopped else {
            return
        }
        stopped = true

        detach()

        if let process, process.isRunning {
            process.terminate()
            try? await Task.sleep(nanoseconds: 200_000_000)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
        }

        try? await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            eventLoopGroup.shutdownGracefully { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }

        try? FileManager.default.removeItem(at: runDirectoryURL)
    }

    private func detach() {
        virtioDevice?.removeSocketListener(forPort: Self.proxyVsockPort)
        virtioDevice?.removeSocketListener(forPort: Self.caVsockPort)
        virtioDevice = nil
        proxyListener = nil
        proxyListenerDelegate = nil
        caListener = nil
        caListenerDelegate = nil
    }

    private func waitForReady() async throws {
        for _ in 0..<100 {
            if FileManager.default.fileExists(atPath: proxySocketURL.path),
               let data = try? Data(contentsOf: caCertificateURL),
               !data.isEmpty {
                caPEM = data
                return
            }

            try await Task.sleep(nanoseconds: 50_000_000)
        }

        throw ProxyServiceError.proxyNotReady("missing \(proxySocketURL.path) or \(caCertificateURL.path)")
    }

    private static func locateProxyExecutable() throws -> URL {
        let fileManager = FileManager.default

        if let path = ProcessInfo.processInfo.environment["VZM_PROXY_PATH"], !path.isEmpty {
            let url = URL(fileURLWithPath: path).standardizedFileURL
            guard fileManager.isExecutableFile(atPath: url.path) else {
                throw ProxyServiceError.proxyExecutableNotFound(url.path)
            }
            return url
        }

        let argumentZero = CommandLine.arguments.first ?? "vzm"
        let executableURL = argumentZero.hasPrefix("/")
            ? URL(fileURLWithPath: argumentZero)
            : URL(fileURLWithPath: fileManager.currentDirectoryPath).appendingPathComponent(argumentZero)
        let executableDirectoryURL = executableURL.resolvingSymlinksInPath().deletingLastPathComponent()
        let currentDirectoryURL = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)

        for candidate in [
            executableDirectoryURL.appendingPathComponent("vzm-proxy"),
            executableDirectoryURL.appendingPathComponent("proxy"),
            currentDirectoryURL.appendingPathComponent(".build/proxy/vzm-proxy"),
            currentDirectoryURL.appendingPathComponent("../proxy/proxy"),
        ] {
            let url = candidate.standardizedFileURL
            if fileManager.isExecutableFile(atPath: url.path) {
                return url
            }
        }

        throw ProxyServiceError.proxyExecutableMissing
    }

    private static func createRunDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("vzm-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return url
    }
}

private final class CAVsockListenerDelegate: NSObject, VZVirtioSocketListenerDelegate {
    private let caPEM: Data

    init(caPEM: Data) {
        self.caPEM = caPEM
    }

    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection, from socketDevice: VZVirtioSocketDevice) -> Bool {
        guard connection.fileDescriptor >= 0 else {
            return false
        }

        Task.detached { [caPEM, connection] in
            FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false).write(caPEM)
            connection.close()
        }

        return true
    }
}

private final class VsockUnixBridgeDelegate: NSObject, VZVirtioSocketListenerDelegate {
    private let unixSocketPath: String
    private let eventLoopGroup: EventLoopGroup

    init(unixSocketPath: String, eventLoopGroup: EventLoopGroup) {
        self.unixSocketPath = unixSocketPath
        self.eventLoopGroup = eventLoopGroup
    }

    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection, from socketDevice: VZVirtioSocketDevice) -> Bool {
        let nioOwnedFD = dup(connection.fileDescriptor)
        guard nioOwnedFD >= 0 else {
            return false
        }

        ClientBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.autoRead, value: false)
            .withConnectedSocket(nioOwnedFD)
            .flatMap { [unixSocketPath] vsockChannel in
                ClientBootstrap(group: vsockChannel.eventLoop)
                    .channelOption(ChannelOptions.autoRead, value: false)
                    .connect(unixDomainSocketPath: unixSocketPath)
                    .flatMap { proxyChannel in
                        bridge(vsockChannel, proxyChannel)
                    }
                    .flatMapError { error in
                        vsockChannel.close(promise: nil)
                        return vsockChannel.eventLoop.makeFailedFuture(error)
                    }
            }
            .whenComplete { [connection] _ in
                connection.close()
            }

        return true
    }
}

private func bridge(_ first: Channel, _ second: Channel) -> EventLoopFuture<Void> {
    first.pipeline.addHandler(ForwardingHandler(peer: second)).and(
        second.pipeline.addHandler(ForwardingHandler(peer: first))
    ).flatMap { _ in
        first.setOption(ChannelOptions.autoRead, value: true).and(
            second.setOption(ChannelOptions.autoRead, value: true)
        )
    }.flatMap { _ in
        first.read()
        second.read()
        return first.closeFuture.and(second.closeFuture).map { _ in () }
    }.flatMapError { error in
        first.close(promise: nil)
        second.close(promise: nil)
        return first.eventLoop.makeFailedFuture(error)
    }
}
