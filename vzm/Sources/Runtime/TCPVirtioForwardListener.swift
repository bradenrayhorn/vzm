import Darwin
import NIOCore
import NIOPosix
import Virtualization

enum TCPVirtioForwardError: Error {
    case invalidVirtioSocketDescriptor
}

struct TCPVirtioForwardTarget {
    let guestVsockPort: UInt32
    let initialBytes: [UInt8]

    init(guestVsockPort: UInt32, initialBytes: [UInt8] = []) {
        self.guestVsockPort = guestVsockPort
        self.initialBytes = initialBytes
    }

    static func directVsock(port: UInt32) -> TCPVirtioForwardTarget {
        TCPVirtioForwardTarget(guestVsockPort: port)
    }
}

enum GuestPortExposureBridge {
    static let vsockPort: UInt32 = 4010

    static func target(forGuestTCPPort port: UInt16) -> TCPVirtioForwardTarget {
        TCPVirtioForwardTarget(
            guestVsockPort: vsockPort,
            initialBytes: Array("\(port)\n".utf8)
        )
    }
}

actor TCPVirtioForwardListener {
    private let hostPort: Int
    private let label: String
    private let target: TCPVirtioForwardTarget
    private let virtioConnector: VirtioSocketConnector

    private let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var serverChannel: Channel?
    private var stopped = false

    @MainActor
    init(hostPort rawHostPort: UInt16, target: TCPVirtioForwardTarget, virtioDevice: VZVirtioSocketDevice, label: String) {
        self.hostPort = Int(rawHostPort)
        self.label = label
        self.target = target
        self.virtioConnector = VirtioSocketConnector(device: virtioDevice)
    }

    func startListening() async throws {
        guard !stopped else {
            throw CancellationError()
        }
        guard serverChannel == nil else {
            return
        }

        let virtioConnector = self.virtioConnector
        let target = self.target

        let bootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(TCPVirtioConnectHandler(
                    virtioConnector: virtioConnector,
                    guestVsockPort: target.guestVsockPort,
                    initialBytes: target.initialBytes
                ))
            }

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: hostPort).get()
        guard !stopped else {
            try? await channel.close().get()
            throw CancellationError()
        }

        self.serverChannel = channel
        print("\(label) listening on 127.0.0.1:\(hostPort)")
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            try await startListening()
            try await serverChannel?.closeFuture.get()
        } onCancel: {
            Task {
                await self.stop()
            }
        }
    }

    func stop() async {
        guard !stopped else {
            return
        }
        stopped = true

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

private final class TCPVirtioConnectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    private let virtioConnector: VirtioSocketConnector
    private let guestVsockPort: UInt32
    private let initialBytes: [UInt8]

    init(virtioConnector: VirtioSocketConnector, guestVsockPort: UInt32, initialBytes: [UInt8]) {
        self.virtioConnector = virtioConnector
        self.guestVsockPort = guestVsockPort
        self.initialBytes = initialBytes
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let fdPromise = context.eventLoop.makePromise(of: CInt.self)

        let virtioConnector = self.virtioConnector
        let guestVsockPort = self.guestVsockPort
        let eventLoop = context.eventLoop
        Task {
            do {
                let fd = try await virtioConnector.connectFileDescriptor(toPort: guestVsockPort)
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
                    context.channel.pipeline.removeHandler(self).flatMap {
                        bridge(context.channel, vsockChannel, initialBytesToSecond: self.initialBytes)
                    }.flatMapError { error in
                        vsockChannel.close(promise: nil)
                        return context.eventLoop.makeFailedFuture(error)
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
private final class VirtioSocketConnector {
    private let device: VZVirtioSocketDevice

    init(device: VZVirtioSocketDevice) {
        self.device = device
    }

    func connectFileDescriptor(toPort port: UInt32) async throws -> CInt {
        let connection = try await device.connect(toPort: port)
        defer { connection.close() }

        let originalFD = connection.fileDescriptor
        guard originalFD >= 0 else {
            throw TCPVirtioForwardError.invalidVirtioSocketDescriptor
        }

        let nioOwnedFD = dup(originalFD)
        guard nioOwnedFD >= 0 else {
            throw IOError(errnoCode: errno, reason: "dup")
        }

        return nioOwnedFD
    }
}
