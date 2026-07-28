import Foundation

/// Allows a bounded number of raw TCP connections to one destination after
/// the user explicitly approves the destination.
final class RawTCPApprovalEngine: BaseApprovalEngine {
    override var name: String { "Raw TCP" }

    private struct Target: Hashable {
        let host: String
        let port: Int
    }

    private struct Session {
        let gates: [any ApprovalGate]
    }

    private var sessions: [Target: Session] = [:]

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "TCP_CONNECT",
              let target = Self.target(for: request)
        else {
            return .unknown
        }

        guard let session = sessions[target] else {
            return .userApprovalRequired(.default)
        }

        // canContinue() records the request for RateLimitApprovalGate.
        guard session.gates.allSatisfy({ $0.canContinue() }) else {
            sessions.removeValue(forKey: target)
            return .userApprovalRequired(.default)
        }

        return .approved
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard let target = Self.target(for: request) else { return }

        let gates: [any ApprovalGate] = [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60)(),
            RateLimitApprovalGate.new(windowSeconds: 10 * 60, maxRequests: 10)(),
        ]

        // Count the connection that caused the approval
        guard gates.allSatisfy({ $0.canContinue() }) else { return }
        sessions[target] = Session(gates: gates)
    }

    private static func target(for request: ProxyApprovalRequest) -> Target? {
        let rawURL = request.url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: "tcp://\(rawURL)"),
              let host = components.host?.lowercased(),
              let port = components.port,
              !host.isEmpty
        else {
            return nil
        }

        return Target(host: host, port: port)
    }
}
