import Foundation

/// In-memory header/secret consent reusable across matching feeds in Auto
/// (unlike Maven's persisted per-feed consent).
final class AzureDevOpsNpmApprovalEngine: BaseApprovalEngine {
    override var name: String { "AzureDevOpsNpm" }

    private var approvedHeaders: Set<ProxyApprovalHeader> = []
    private var approvedSecrets: Set<String> = []

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        guard matches(request) else { return .notApplicable }
        if approvedHeaders.isSuperset(of: request.headers)
            && approvedSecrets.isSuperset(of: request.secrets) {
            return .approved
        }
        return .needsConsent(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard matches(request) else { return }
        approvedHeaders.formUnion(request.headers)
        approvedSecrets.formUnion(request.secrets)
    }

    private func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.body == nil,
              request.method == "GET" || request.method == "HEAD",
              let url = NpmPackageURL.hostAndPath(request.url), url.host == "pkgs.dev.azure.com"
        else { return false }

        let parts = url.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        // org[/project]/_packaging/feed/npm/registry/package
        let packagingIndex: Int
        if parts.count > 5, parts[1] == "_packaging" {
            packagingIndex = 1
        } else if parts.count > 6, parts[2] == "_packaging" {
            packagingIndex = 2
        } else {
            return false
        }
        guard parts.prefix(packagingIndex).allSatisfy(NpmPackageURL.isName),
              NpmPackageURL.isName(parts[packagingIndex + 1]),
              parts[packagingIndex + 2] == "npm", parts[packagingIndex + 3] == "registry"
        else { return false }

        let prefixLength = packagingIndex + 4
        return NpmPackageURL.isPackagePath(parts.dropFirst(prefixLength).joined(separator: "/"))
    }
}
