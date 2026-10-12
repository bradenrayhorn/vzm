import Foundation

/// Mirrors AzureDevOpsMaven consent: a bounded feed session in Default,
/// and in-memory header/secret consent reusable across matching feeds in Auto.
final class AzureDevOpsNpmApprovalEngine: BaseApprovalEngine {
    override var name: String { "AzureDevOpsNpm" }

    private var approvedRepositoryPrefix: String?
    private var approvedHeaders: Set<ProxyApprovalHeader>?
    private var approvedSecrets: Set<String>?

    init() {
        super.init(gateBuilders: [
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 1800),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 120),
        ])
    }

    override func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        guard repositoryPrefixIfMatchingRequest(request) != nil else { return false }
        return (request.headers.isEmpty || approvedHeaders?.isSuperset(of: Set(request.headers)) == true)
            && (request.secrets.isEmpty || approvedSecrets?.isSuperset(of: Set(request.secrets)) == true)
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return .unknown }
        if prefix == approvedRepositoryPrefix,
           let approvedHeaders, let approvedSecrets,
           approvedHeaders.isSuperset(of: Set(request.headers)),
           approvedSecrets.isSuperset(of: Set(request.secrets)),
           checkGates() {
            return .approved
        }
        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return }
        approvedRepositoryPrefix = prefix
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        approvedSecrets = (approvedSecrets ?? []).union(Set(request.secrets))
        super.onEngineApproved(request)
    }

    private func repositoryPrefixIfMatchingRequest(_ request: ProxyApprovalRequest) -> String? {
        guard request.type == "REQUEST", request.body == nil,
              request.method == "GET" || request.method == "HEAD",
              let url = NpmPackageURL.hostAndPath(request.url), url.host == "pkgs.dev.azure.com"
        else { return nil }

        let parts = url.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        // org[/project]/_packaging/feed/npm/registry/package
        let packagingIndex: Int
        if parts.count > 5, parts[1] == "_packaging" {
            packagingIndex = 1
        } else if parts.count > 6, parts[2] == "_packaging" {
            packagingIndex = 2
        } else {
            return nil
        }
        guard parts.prefix(packagingIndex).allSatisfy(NpmPackageURL.isName),
              NpmPackageURL.isName(parts[packagingIndex + 1]),
              parts[packagingIndex + 2] == "npm", parts[packagingIndex + 3] == "registry"
        else { return nil }

        let prefixLength = packagingIndex + 4
        guard NpmPackageURL.isPackagePath(parts.dropFirst(prefixLength).joined(separator: "/")) else { return nil }
        return "\(url.host)/\(parts.prefix(prefixLength).joined(separator: "/"))/"
    }
}
