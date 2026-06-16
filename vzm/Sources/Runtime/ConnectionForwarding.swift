import NIOCore

final class ForwardingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private weak var peer: Channel?

    init(peer: Channel) {
        self.peer = peer
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let peer else {
            context.close(promise: nil)
            return
        }

        let buffer = unwrapInboundIn(data)
        peer.write(buffer, promise: nil)

        if !peer.isWritable {
            context.channel.setOption(ChannelOptions.autoRead, value: false).whenFailure { _ in }
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        peer?.flush()
        context.fireChannelReadComplete()
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable {
            peer?.setOption(ChannelOptions.autoRead, value: true).whenFailure { _ in }
        }
        context.fireChannelWritabilityChanged()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case ChannelEvent.inputClosed = event {
            peer?.flush()
            peer?.close(mode: .output, promise: nil)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        peer?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
        peer?.close(promise: nil)
    }
}

func bridge(_ first: Channel, _ second: Channel, initialBytesToSecond initialBytes: [UInt8] = []) -> EventLoopFuture<Void> {
    first.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).and(
        second.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
    ).flatMap { _ in
        first.pipeline.addHandler(ForwardingHandler(peer: second)).and(
            second.pipeline.addHandler(ForwardingHandler(peer: first))
        )
    }.flatMap { _ in
        writeInitialBytes(initialBytes, to: second)
    }.flatMap { _ in
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

private func writeInitialBytes(_ bytes: [UInt8], to channel: Channel) -> EventLoopFuture<Void> {
    guard !bytes.isEmpty else {
        return channel.eventLoop.makeSucceededVoidFuture()
    }

    var buffer = channel.allocator.buffer(capacity: bytes.count)
    buffer.writeBytes(bytes)
    return channel.writeAndFlush(buffer)
}
