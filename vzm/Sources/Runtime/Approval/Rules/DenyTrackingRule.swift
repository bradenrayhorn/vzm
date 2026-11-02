import Foundation

final class DenyTrackingRule: DenyRule {
    var name: String { "DenyTracking" }

    private static let blockedDomains = [
        "telemetry.nextjs.org",
        "config.liquibase.com"
    ]

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        Self.blockedDomains.contains(Self.normalizedDomain(request.domain))
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
