import Foundation

final class DenyTrackingRule: DenyRule {
    var name: String { "DenyTracking" }

    private static let blockedDomains = [
        "telemetry.nextjs.org",
        "config.liquibase.com"
    ]

    func matches(_ request: ProxyApprovalRequest) -> Bool {
        Self.blockedDomains.contains(DomainName.normalize(request.domain))
    }
}
