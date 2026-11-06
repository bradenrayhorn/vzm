import Foundation

final class NpmApprovalEngine: PatternApprovalEngine {
    override var name: String { "Npm" }

    private static let npmCommands: Set<String> = [
        "install", "ci", "exec", "update", "view", "outdated", "pack", "cache",
        "dedupe", "prune", "diff", "init", "install-test", "install-ci-test",
    ]
    private static let npmSessionRegex = try! NSRegularExpression(pattern: #"\A[0-9a-f]{16}\z"#)
    private static let pacoteVersionRegex = try! NSRegularExpression(
        pattern: #"\A[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\z"#
    )

    override func headersForApproval(_ request: ProxyApprovalRequest) -> [ProxyApprovalHeader] {
        guard matches(request), let url = NpmPackageURL.hostAndPath(request.url) else { return request.headers }
        let parts = url.path.components(separatedBy: "/-/")
        let isTarball = parts.count == 2
        let package = parts[0].replacingOccurrences(of: "%2f", with: "/", options: .caseInsensitive)
        let packageIDs: Set<String>
        if isTarball {
            let target = "\(package)@https://\(url.host)/\(url.path)"
            packageIDs = ["remote:\(target)", "registry:\(target)"]
        } else {
            packageIDs = ["registry:\(package)"]
        }

        return request.headers.filter { header in
            let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = header.value.trimmingCharacters(in: .whitespacesAndNewlines)
            switch name {
            case "npm-auth-type":
                return !["web", "legacy"].contains(value)
            case "npm-command":
                return !Self.npmCommands.contains(value)
            case "npm-scope":
                // This is the project's scope, which can differ from the requested
                // package's scope. Accept only one bounded, normalized @scope name.
                return !value.hasPrefix("@") || !NpmPackageURL.isName(String(value.dropFirst()))
            case "npm-session":
                // npm's random 8-byte session ID, not an authentication token.
                // Shape validation permits a bounded 8-byte residual data channel.
                return Self.npmSessionRegex.firstMatch(
                    in: value, range: NSRange(value.startIndex..<value.endIndex, in: value)
                ) == nil
            case "pacote-req-type":
                return !["packument", "tarball"].contains(value)
            case "pacote-version":
                return Self.pacoteVersionRegex.firstMatch(
                    in: value, range: NSRange(value.startIndex..<value.endIndex, in: value)
                ) == nil
            case "pacote-pkg-id":
                return !packageIDs.contains(value)
            case "pacote-integrity":
                guard isTarball, value.hasPrefix("sha512-") else { return true }
                let digest = String(value.dropFirst("sha512-".count))
                // Protocol shape only, not proof of authenticity. Canonical base64 bounds
                // the residual data channel to one SHA-512 digest on tarball requests.
                guard digest.count == 88, let bytes = Data(base64Encoded: digest), bytes.count == 64,
                      bytes.base64EncodedString() == digest else { return true }
                return false
            default:
                return true
            }
        }
    }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.method == "GET",
              request.body == nil, request.secrets.isEmpty,
              let url = NpmPackageURL.hostAndPath(request.url), url.host == "registry.npmjs.org"
        else { return false }
        return NpmPackageURL.isPackagePath(url.path)
    }
}
