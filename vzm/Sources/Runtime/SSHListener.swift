import Darwin
import NIOCore
import NIOPosix
import Virtualization

enum SSHListenerError: Error {
    case invalidPort(message: String)
    case invalidVirtioSocketDescriptor
}

actor SSHListener: VZMService {
    let port: Int
    private let virtioConnector: VirtioSSHConnector

    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
    private var serverChannel: Channel?

    @MainActor
    init(port rawPort: UInt16, virtioDevice: VZVirtioSocketDevice) throws {
        self.port = Int(rawPort)
        self.virtioConnector = VirtioSSHConnector(device: virtioDevice)
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            let bootstrap = ServerBootstrap(group: eventLoopGroup)
                .serverChannelOption(ChannelOptions.backlog, value: 256)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelOption(ChannelOptions.autoRead, value: false)
                .childChannelInitializer { [virtioConnector] channel in
                    channel.pipeline.addHandler(SSHHostConnectHandler(virtioConnector: virtioConnector))
                }

            let channel = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
            self.serverChannel = channel
            print("SSH forwarding listening on 127.0.0.1:\(port)")

            try await channel.closeFuture.get()
        } onCancel: {
            Task {
                await self.stop()
            }
        }
    }

    func stop() async {
        let channel = serverChannel
        serverChannel = nil

        if let channel {
            try? await channel.close().get()
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
    }
}

private final class SSHHostConnectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    private let virtioConnector: VirtioSSHConnector

    init(virtioConnector: VirtioSSHConnector) {
        self.virtioConnector = virtioConnector
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let fdPromise = context.eventLoop.makePromise(of: CInt.self)

        let virtioConnector = self.virtioConnector
        let eventLoop = context.eventLoop
        Task {
            do {
                let fd = try await virtioConnector.connectFileDescriptor()
                eventLoop.execute {
                    fdPromise.succeed(fd)
                }
            } catch {
                eventLoop.execute {
                    fdPromise.fail(error)
                }
            }
        }

        fdPromise.futureResult.flatMap { nioOwnedFD -> EventLoopFuture<Void> in
            guard context.channel.isActive else {
                close(nioOwnedFD)
                return context.eventLoop.makeSucceededVoidFuture()
            }

            return ClientBootstrap(group: context.eventLoop)
                .channelOption(ChannelOptions.autoRead, value: false)
                .withConnectedSocket(nioOwnedFD)
                .flatMap { vsockChannel in
                    let hostForward = ForwardingHandler(peer: vsockChannel)
                    let vsockForward = ForwardingHandler(peer: context.channel)

                    return context.channel.pipeline.addHandler(hostForward).flatMap {
                        vsockChannel.pipeline.addHandler(vsockForward)
                    }.flatMap {
                        context.channel.pipeline.removeHandler(self)
                    }.flatMap {
                        let hostAutoRead = context.channel.setOption(ChannelOptions.autoRead, value: true)
                        let vsockAutoRead = vsockChannel.setOption(ChannelOptions.autoRead, value: true)

                        context.channel.read()
                        vsockChannel.read()

                        return hostAutoRead.and(vsockAutoRead).map { _ in () }
                    }
                }
        }.whenFailure { _ in
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

@MainActor
private final class VirtioSSHConnector {
    private let device: VZVirtioSocketDevice

    init(device: VZVirtioSocketDevice) {
        self.device = device
    }

    func connectFileDescriptor() async throws -> CInt {
        let connection = try await device.connect(toPort: 22)
        defer { connection.close() }

        let originalFD = connection.fileDescriptor
        guard originalFD >= 0 else {
            throw SSHListenerError.invalidVirtioSocketDescriptor
        }

        let nioOwnedFD = dup(originalFD)
        guard nioOwnedFD >= 0 else {
            throw IOError(errnoCode: errno, reason: "dup")
        }

        return nioOwnedFD
    }
}
