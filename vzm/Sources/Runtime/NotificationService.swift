import Darwin
import Foundation
import Virtualization

private enum NotificationProtocolError: LocalizedError {
    case emptyRequest
    case requestTooLarge
    case malformedRequest
    case unsupportedAction
    case missingField(String)

    var errorDescription: String? {
        switch self {
        case .emptyRequest:
            return "Empty request"
        case .requestTooLarge:
            return "Request is too large"
        case .malformedRequest:
            return "Malformed JSON request"
        case .unsupportedAction:
            return "Unsupported action"
        case .missingField(let field):
            return "Missing or empty field: \(field)"
        }
    }
}

private struct NotificationWireRequest: Decodable {
    let action: String
    let from: String?
    let message: String?
}

private struct NotificationWireResponse: Encodable {
    let ok: Bool
    let pending: Int?
    let error: String?
}

@MainActor
final class NotificationService {
    static let vsockPort: UInt32 = 3132

    private let virtioDevice: VZVirtioSocketDevice
    private let listener: VZVirtioSocketListener
    private let listenerDelegate: NotificationVsockListenerDelegate
    private var stopped = false

    init(virtioDevice: VZVirtioSocketDevice) {
        self.virtioDevice = virtioDevice
        listener = VZVirtioSocketListener()
        listenerDelegate = NotificationVsockListenerDelegate()
        listener.delegate = listenerDelegate
        virtioDevice.setSocketListener(listener, forPort: Self.vsockPort)

        NotificationCoordinator.shared.start()
        StandardError.writeLine("Guest notifications listening on vsock port \(Self.vsockPort)")
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        virtioDevice.removeSocketListener(forPort: Self.vsockPort)
        NotificationCoordinator.shared.stop()
    }
}

private final class NotificationVsockListenerDelegate: NSObject, VZVirtioSocketListenerDelegate {
    private static let maximumRequestBytes = 64 * 1024
    private static let requestTimeoutSeconds = 5

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let fileDescriptor = connection.fileDescriptor
        guard fileDescriptor >= 0 else { return false }

        let flags = fcntl(fileDescriptor, F_GETFL)
        guard flags >= 0, fcntl(fileDescriptor, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
            return false
        }

        var timeout = timeval(tv_sec: Self.requestTimeoutSeconds, tv_usec: 0)
        setsockopt(
            fileDescriptor,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )

        Task.detached { [connection] in
            defer { connection.close() }

            let response: NotificationWireResponse

            do {
                let requestData = try Self.readRequest(from: connection.fileDescriptor)
                let request: NotificationWireRequest
                do {
                    request = try JSONDecoder().decode(NotificationWireRequest.self, from: requestData)
                } catch {
                    throw NotificationProtocolError.malformedRequest
                }

                let pending = try await Self.handle(request)
                response = NotificationWireResponse(ok: true, pending: pending, error: nil)
            } catch {
                response = NotificationWireResponse(
                    ok: false,
                    pending: nil,
                    error: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                )
            }

            if let data = try? JSONEncoder().encode(response) {
                let handle = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
                try? handle.write(contentsOf: data + Data([0x0a]))
            }
        }

        return true
    }

    private static func readRequest(from fileDescriptor: Int32) throws -> Data {
        let handle = FileHandle(fileDescriptor: fileDescriptor, closeOnDealloc: false)
        var request = Data()

        while request.count <= maximumRequestBytes {
            guard let chunk = try handle.read(upToCount: min(4096, maximumRequestBytes + 1 - request.count)),
                  !chunk.isEmpty else {
                break
            }
            request.append(chunk)

            if let newline = request.firstIndex(of: 0x0a) {
                request = request[..<newline]
                break
            }
        }

        guard !request.isEmpty else {
            throw NotificationProtocolError.emptyRequest
        }
        guard request.count <= maximumRequestBytes else {
            throw NotificationProtocolError.requestTooLarge
        }
        return request
    }

    private static func handle(_ request: NotificationWireRequest) async throws -> Int {
        switch request.action {
        case "notify":
            guard let from = request.from?.trimmingCharacters(in: .whitespacesAndNewlines), !from.isEmpty else {
                throw NotificationProtocolError.missingField("from")
            }
            guard let message = request.message?.trimmingCharacters(in: .whitespacesAndNewlines), !message.isEmpty else {
                throw NotificationProtocolError.missingField("message")
            }
            guard from.count <= 256 else {
                throw NotificationProtocolError.missingField("from (maximum 256 characters)")
            }
            guard message.count <= 16_384 else {
                throw NotificationProtocolError.missingField("message (maximum 16384 characters)")
            }
            return try await NotificationCoordinator.shared.enqueue(from: from, message: message)

        case "acknowledge":
            return await NotificationCoordinator.shared.acknowledgeOldest()

        default:
            throw NotificationProtocolError.unsupportedAction
        }
    }
}
