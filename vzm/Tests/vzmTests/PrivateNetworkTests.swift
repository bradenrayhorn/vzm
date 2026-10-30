import Darwin
import Foundation
import Virtualization
import XCTest
@testable import vzm

final class PrivateNetworkTests: XCTestCase {
    func testNICIsPrivateAndUsesExpectedMAC() throws {
        let network = try PrivateNetwork()
        let device = network.deviceConfiguration()
        XCTAssertEqual(device.macAddress.string, "02:00:00:00:00:02")
        let attachment = try XCTUnwrap(device.attachment as? VZFileHandleNetworkDeviceAttachment)
        XCTAssertEqual(attachment.fileHandle.fileDescriptor, network.guestHandle.fileDescriptor)
        XCTAssertEqual(attachment.maximumTransmissionUnit, 1500)
    }

    func testDatagramSocketSurvivesProcessStandardInput() throws {
        let network = try PrivateNetwork()
        let process = Process()
        // cat reads the inherited datagram socket on stdin and echoes it over
        // stdout, which Foundation duplicates from the same connected socket.
        process.executableURL = URL(fileURLWithPath: "/bin/cat")
        process.standardInput = network.proxyHandle
        process.standardOutput = network.proxyHandle
        try process.run()
        defer {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }
        try network.proxyHandle.close()

        let payload = Array("private Ethernet transport".utf8)
        let fd = network.guestHandle.fileDescriptor
        XCTAssertEqual(payload.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }, payload.count)
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&descriptor, 1, 3000), 1)
        var received = [UInt8](repeating: 0, count: 1500)
        let count = received.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress, $0.count, 0) }
        XCTAssertEqual(count, payload.count)
        XCTAssertEqual(Array(received.prefix(max(0, count))), payload)
    }

    func testSocketBufferSizing() throws {
        let network = try PrivateNetwork()
        for handle in [network.guestHandle, network.proxyHandle] {
            var send: Int32 = 0
            var receive: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            XCTAssertEqual(getsockopt(handle.fileDescriptor, SOL_SOCKET, SO_SNDBUF, &send, &size), 0)
            XCTAssertEqual(getsockopt(handle.fileDescriptor, SOL_SOCKET, SO_RCVBUF, &receive, &size), 0)
            XCTAssertGreaterThanOrEqual(receive, send * 2)
        }
    }
}
