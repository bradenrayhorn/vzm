import Foundation

final class YarnPkgApprovalEngine: PatternApprovalEngine {
    override var name: String { "YarnPkg" }

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 120, maxRequests: 2_000),
        ])
    }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.secrets.isEmpty,
              request.body == nil, request.method == "GET",
              let url = NpmPackageURL.hostAndPath(request.url)
        else { return false }
        switch url.host {
        case "yarnpkg.com", "classic.yarnpkg.com":
            return url.path == "latest-version"
        case "registry.yarnpkg.com":
            return NpmPackageURL.isPackagePath(url.path)
        default:
            return false
        }
    }

    override func headersForApproval(_ request: ProxyApprovalRequest) -> [ProxyApprovalHeader] {
        guard matches(request), let url = NpmPackageURL.hostAndPath(request.url),
              url.host == "classic.yarnpkg.com", url.path == "latest-version"
        else { return request.headers }
        // The version-check redirect carries its original URL as Referer.
        // This is not a general permission to send browsing history.
        return request.headers.filter {
            !($0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "referer"
                && $0.value == "https://yarnpkg.com/latest-version")
        }
    }
}
