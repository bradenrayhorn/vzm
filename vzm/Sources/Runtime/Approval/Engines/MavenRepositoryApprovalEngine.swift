import Foundation

final class MavenRepositoryApprovalEngine: BaseApprovalEngine {
    override var name: String { "MavenRepository" }

    private var approvedHeaders: [ProxyApprovalHeader]?

    private static let allowedHosts: Set<String> = [
        "plugins.gradle.org",
        "plugins-artifacts.gradle.org",
        "repo.maven.apache.org",
    ]

    private static let pathRegex = try! NSRegularExpression(
        pattern: #"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$"#
    )

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 5 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 60),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST" else {
            return .unknown
        }
        guard request.secrets.isEmpty else {
            return .unknown
        }
        guard request.body == nil else {
            return .unknown
        }
        guard request.method == "GET" || request.method == "HEAD" else {
            return .unknown
        }
        guard isAllowedRepositoryURL(request.url) else {
            return .unknown
        }

        if let approvedHeaders, request.headers == approvedHeaders, self.checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = request.headers
        super.onEngineApproved(request)
    }

    private func isAllowedRepositoryURL(_ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let slash = trimmed.firstIndex(of: "/") else {
            return false
        }

        let host = String(trimmed[..<slash])
        let remainder = String(trimmed[trimmed.index(after: slash)...])
        guard Self.allowedHosts.contains(host) else {
            return false
        }
        guard !remainder.contains("?") && !remainder.contains("#") else {
            return false
        }

        switch host {
        case "repo.maven.apache.org":
            guard remainder.hasPrefix("maven2/") else {
                return false
            }
            return isMavenArtifactPath(String(remainder.dropFirst("maven2/".count)))
        case "plugins.gradle.org":
            guard remainder.hasPrefix("m2/") else {
                return false
            }
            return isMavenArtifactPath(String(remainder.dropFirst("m2/".count)))
        case "plugins-artifacts.gradle.org":
            return isPluginArtifactPath(remainder)
        default:
            return false
        }
    }

    private func isMavenArtifactPath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4 else {
            return false
        }

        let version = parts[parts.count - 2]
        let filename = parts[parts.count - 1]
        let artifact = parts[parts.count - 3]
        let groupParts = Array(parts.dropLast(3))

        guard !version.isEmpty, !artifact.isEmpty, !filename.isEmpty, !groupParts.contains(where: \.isEmpty) else {
            return false
        }
        guard Self.matchesPathCharacters(path) else {
            return false
        }

        return Self.matchesArtifactFilename(filename, artifact: artifact, version: version)
    }

    private func isPluginArtifactPath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 5 else {
            return false
        }

        let filename = parts[parts.count - 1]
        let hash = parts[parts.count - 2]
        let version = parts[parts.count - 3]
        let artifact = parts[parts.count - 4]
        let groupParts = Array(parts.dropLast(4))

        guard !version.isEmpty, !artifact.isEmpty, !filename.isEmpty, !groupParts.contains(where: \.isEmpty) else {
            return false
        }
        guard Self.matchesPathCharacters(path) else {
            return false
        }
        guard Self.isHex(hash) && hash.count >= 32 else {
            return false
        }

        return Self.matchesArtifactFilename(filename, artifact: artifact, version: version)
    }

    private static func matchesPathCharacters(_ path: String) -> Bool {
        let range = NSRange(path.startIndex..<path.endIndex, in: path)
        return pathRegex.firstMatch(in: path, range: range) != nil
    }

    private static func matchesArtifactFilename(_ filename: String, artifact: String, version: String) -> Bool {
        guard let dot = filename.lastIndex(of: ".") else {
            return false
        }

        let base = String(filename[..<dot])
        let ext = String(filename[filename.index(after: dot)...])
        guard ["pom", "module", "jar"].contains(ext) else {
            return false
        }
        guard base == "\(artifact)-\(version)" || base.hasPrefix("\(artifact)-\(version)-") else {
            return false
        }

        return true
    }

    private static func isHex(_ string: String) -> Bool {
        !string.isEmpty && string.allSatisfy { $0.isHexDigit }
    }
}
