import Foundation

final class DenyTrackingApprovalEngine: BaseApprovalEngine {
    override var name: String { "DenyTracking" }

    private static let blockedDomains = [
        "telemetry.nextjs.org",
        "config.liquibase.com"
    ]

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        if Self.blockedDomains.contains(Self.normalizedDomain(request.domain)) {
            return .denied
        }

        return .unknown
    }

    private static func normalizedDomain(_ domain: String) -> String {
        var normalized = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }

        if let colon = normalized.lastIndex(of: ":") {
            normalized = String(normalized[..<colon])
        }

        return normalized
    }
}
