import Foundation

final class NpmApprovalEngine: PatternApprovalEngine {
    override var name: String { "Npm" }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.method == "GET",
              request.body == nil, request.secrets.isEmpty,
              let url = NpmPackageURL.hostAndPath(request.url), url.host == "registry.npmjs.org"
        else { return false }
        return NpmPackageURL.isPackagePath(url.path)
    }
}
