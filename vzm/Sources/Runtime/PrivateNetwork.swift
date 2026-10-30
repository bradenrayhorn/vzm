import Darwin
import Foundation
import Virtualization

/// A private Ethernet link, not a host interface or NAT. One end belongs to VZ;
/// the other becomes the Go proxy's stdin. Nothing can forward packets unless
/// the Go process explicitly implements it. A failed proxy has no fallback.
final class PrivateNetwork {
    static let guestMAC = "02:00:00:00:00:02"
    let guestHandle: FileHandle
    let proxyHandle: FileHandle

    init() throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guestHandle = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        proxyHandle = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        do {
            for fd in fds {
                // VZ requires receive buffers >= 2x send buffers, recommending
                // 4x. Keep datagrams bounded to an ordinary Ethernet MTU.
                var send: Int32 = 256 * 1024
                var receive: Int32 = 1024 * 1024
                guard setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send, socklen_t(MemoryLayout.size(ofValue: send))) == 0,
                      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive, socklen_t(MemoryLayout.size(ofValue: receive))) == 0,
                      fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
        } catch {
            try? guestHandle.close()
            try? proxyHandle.close()
            throw error
        }
    }

    func deviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let device = VZVirtioNetworkDeviceConfiguration()
        device.macAddress = VZMACAddress(string: Self.guestMAC)!
        let attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: guestHandle)
        attachment.maximumTransmissionUnit = 1500
        device.attachment = attachment
        return device
    }

    deinit {
        try? guestHandle.close()
        try? proxyHandle.close()
    }
}
