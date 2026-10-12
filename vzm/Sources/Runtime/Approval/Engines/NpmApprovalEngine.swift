import Foundation

final class NpmApprovalEngine: PatternApprovalEngine {
    override var name: String { "Npm" }

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 120, maxRequests: 2_000),
        ])
    }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.method == "GET",
              request.body == nil, request.secrets.isEmpty,
              let url = NpmPackageURL.hostAndPath(request.url), url.host == "registry.npmjs.org"
        else { return false }
        return NpmPackageURL.isPackagePath(url.path)
    }
}
