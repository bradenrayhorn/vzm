import Foundation

final class DenyTrackingRule: DenyRule {
    var name: String { "DenyTracking" }

    private static let blockedDomains = [
        "telemetry.nextjs.org",
        "config.liquibase.com",
        "api.keydb.dev",
        "instance-data.ec2.internal",
        "metadata.google.internal",
        "register.cockroachdb.com"
    ]

    func shouldDeny(_ request: ProxyApprovalRequest) -> Bool {
        Self.blockedDomains.contains(DomainName.normalize(request.domain))
    }
}
