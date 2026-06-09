import Observation
import Virtualization

@Observable
@MainActor
final class PortExposureService {
    private let virtioDevice: VZVirtioSocketDevice
    private var listeners: [UInt16: TCPVirtioForwardListener] = [:]
    private var stopped = false

    init(virtioDevice: VZVirtioSocketDevice) {
        self.virtioDevice = virtioDevice
    }

    func isExposed(port: UInt16) -> Bool {
        listeners[port] != nil
    }

    func expose(port: UInt16) {
        guard !stopped, listeners[port] == nil else {
            return
        }

        let listener = TCPVirtioForwardListener(
            hostPort: port,
            target: GuestPortExposureBridge.target(forGuestTCPPort: port),
            virtioDevice: virtioDevice,
            label: "Port forwarding to guest"
        )
        listeners[port] = listener

        Task { @MainActor in
            do {
                try await listener.startListening()
                guard !stopped, listeners[port] === listener else {
                    await listener.stop()
                    return
                }
            } catch {
                if listeners[port] === listener {
                    listeners.removeValue(forKey: port)
                }
                await listener.stop()
            }
        }
    }

    func unexpose(port: UInt16) {
        let listener = listeners.removeValue(forKey: port)

        Task { @MainActor in
            await listener?.stop()
        }
    }

    func stop() async {
        guard !stopped else {
            return
        }
        stopped = true

        let listeners = Array(self.listeners.values)
        self.listeners.removeAll()

        for listener in listeners {
            await listener.stop()
        }
    }
}
