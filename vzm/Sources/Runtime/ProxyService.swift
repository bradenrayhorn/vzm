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
            return "Proxy executable not found. Set VZM_PROXY_PATH or keep vzm-proxy next to the vzm binary."
        case .proxyNotReady(let message):
            return "Proxy did not become ready: \(message)"
        case .missingCertificateAuthority:
            return "Proxy certificate authority is missing"
        }
    }
}

final class ProxyService {
    private static let proxyVsockPort: UInt32 = 3128
    private static let caVsockPort: UInt32 = 3129

    private let vmName: String
    private let proxyExecutableURL: URL
    private let runDirectoryURL: URL
    private let proxySocketURL: URL
    private let controlSocketURL: URL
    private let caCertificateURL: URL
    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    private var process: Process?
    private var controlChannel: Channel?
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
        self.controlSocketURL = runDirectoryURL.appendingPathComponent("control.sock")
        self.caCertificateURL = runDirectoryURL.appendingPathComponent("ca.pem")
    }

    func launch() async throws {
        controlChannel = try await startApprovalControlSocket()

        let process = Process()
        process.executableURL = proxyExecutableURL
        process.arguments = [
            "--listen-unix", proxySocketURL.path,
            "--ca-cert", caCertificateURL.path,
            "--control-unix", controlSocketURL.path,
            "--parent-pid", String(ProcessInfo.processInfo.processIdentifier),
        ]
        process.currentDirectoryURL = runDirectoryURL
        process.environment = ProcessInfo.processInfo.environment
        process.standardOutput = FileHandle.standardError
        process.standardError = FileHandle.standardError

        self.process = process
        try process.run()
        try await waitForReady()
    }

    @MainActor
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

        await detach()

        if let process, process.isRunning {
            process.terminate()
            try? await Task.sleep(nanoseconds: 200_000_000)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
        }

        try? await controlChannel?.close().get()
        controlChannel = nil

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

    @MainActor
    private func detach() {
        virtioDevice?.removeSocketListener(forPort: Self.proxyVsockPort)
        virtioDevice?.removeSocketListener(forPort: Self.caVsockPort)
        virtioDevice = nil
        proxyListener = nil
        proxyListenerDelegate = nil
        caListener = nil
        caListenerDelegate = nil
    }

    private func startApprovalControlSocket() async throws -> Channel {
        let channel = try await ServerBootstrap(group: eventLoopGroup)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(ApprovalControlHandler())
            }
            .bind(unixDomainSocketPath: controlSocketURL.path, cleanupExistingSocketFile: true)
            .get()
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: controlSocketURL.path)
        return channel
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

        if let bundledProxyURL = ExecutableLocator.findExecutableNextToCurrentExecutable(
            named: ["vzm-proxy", "proxy"],
            fileManager: fileManager
        ) {
            return bundledProxyURL
        }

        let currentDirectoryURL = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)
        for candidate in [
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

struct ProxyApprovalRequest: Codable, Sendable {
    let id: String
    let type: String
    let domain: String
    let method: String
    let path: String
    let secrets: [String]
}

private struct ProxyApprovalResponse: Codable, Sendable {
    let id: String
    let approved: Bool
    let substitutions: [String: String]
}

private func proxyApprovalResponse(for request: ProxyApprovalRequest) async -> ProxyApprovalResponse {
    guard await ApprovalService.shared.askForApproval(request: request) else {
        return ProxyApprovalResponse(id: request.id, approved: false, substitutions: [:])
    }

    do {
        let substitutions = try resolveSecretSubstitutions(for: request)
        return ProxyApprovalResponse(id: request.id, approved: true, substitutions: substitutions)
    } catch {
        FileHandle.standardError.write(Data("Denied proxy request because secrets could not be resolved: \(error)\n".utf8))
        return ProxyApprovalResponse(id: request.id, approved: false, substitutions: [:])
    }
}

private enum ProxySecretResolutionError: LocalizedError {
    case unauthorized(String, String)

    var errorDescription: String? {
        switch self {
        case .unauthorized(let name, let domain):
            return "Secret '\(name)' is not authorized for host: \(domain)"
        }
    }
}

private func resolveSecretSubstitutions(for request: ProxyApprovalRequest) throws -> [String: String] {
    guard !request.secrets.isEmpty else {
        return [:]
    }

    let secretStore = SecretStore()
    let normalizedDomain = request.domain
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
        .trimmingCharacters(in: CharacterSet(charactersIn: "."))

    let metadataByName = try Dictionary(uniqueKeysWithValues: secretStore.listSecrets().map { ($0.name, $0) })

    var substitutions: [String: String] = [:]
    for name in Set(request.secrets) {
        guard let metadata = metadataByName[name] else {
            throw SecretStore.Error.secretNotFound(name)
        }
        guard metadata.hosts.isEmpty || metadata.hosts.contains(normalizedDomain) else {
            throw ProxySecretResolutionError.unauthorized(name, normalizedDomain)
        }
        substitutions[name] = try secretStore.readSecret(named: name)
    }
    return substitutions
}

private final class ApprovalControlHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var buffer: ByteBuffer?
    private var handled = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !handled else {
            return
        }

        var chunk = unwrapInboundIn(data)
        var buffer = self.buffer ?? context.channel.allocator.buffer(capacity: chunk.readableBytes)
        buffer.writeBuffer(&chunk)

        guard let newlineIndex = buffer.readableBytesView.firstIndex(of: 10) else {
            self.buffer = buffer
            return
        }

        let length = newlineIndex - buffer.readerIndex
        guard let line = buffer.readString(length: length) else {
            context.close(promise: nil)
            return
        }
        _ = buffer.readInteger(as: UInt8.self)
        self.buffer = buffer
        handled = true

        guard let requestData = line.data(using: .utf8),
              let request = try? JSONDecoder().decode(ProxyApprovalRequest.self, from: requestData) else {
            context.close(promise: nil)
            return
        }

        let approvalPromise = context.eventLoop.makePromise(of: ProxyApprovalResponse.self)
        approvalPromise.futureResult.whenComplete { result in
            let response = (try? result.get()) ?? ProxyApprovalResponse(id: request.id, approved: false, substitutions: [:])
            guard let responseData = try? JSONEncoder().encode(response) else {
                context.close(promise: nil)
                return
            }

            var output = context.channel.allocator.buffer(capacity: responseData.count + 1)
            output.writeBytes(responseData)
            output.writeInteger(UInt8(10))
            context.writeAndFlush(self.wrapOutboundOut(output)).whenComplete { _ in
                context.close(promise: nil)
            }
        }

        Task {
            let response = await proxyApprovalResponse(for: request)
            approvalPromise.succeed(response)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
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
