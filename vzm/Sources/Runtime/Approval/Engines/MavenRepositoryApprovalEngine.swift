import Foundation

final class MavenRepositoryApprovalEngine: PatternApprovalEngine {
    override var name: String { "MavenRepository" }

    private static let allowedHosts: Set<String> = [
        "plugins.gradle.org",
        "plugins-artifacts.gradle.org",
        "repo.maven.apache.org",
    ]

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        request.type == "REQUEST"
            && request.secrets.isEmpty
            && request.body == nil
            && (request.method == "GET" || request.method == "HEAD")
            && isAllowedRepositoryURL(request.url)
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
            return MavenArtifactPath.matches(String(remainder.dropFirst("maven2/".count)))
        case "plugins.gradle.org":
            guard remainder.hasPrefix("m2/") else {
                return false
            }
            return MavenArtifactPath.matches(String(remainder.dropFirst("m2/".count)))
        case "plugins-artifacts.gradle.org":
            return isPluginArtifactPath(remainder)
        default:
            return false
        }
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
        guard MavenArtifactPath.isValidPath(path) else {
            return false
        }
        guard Self.isHex(hash) && hash.count >= 32 else {
            return false
        }

        return MavenArtifactPath.matchesArtifactFilename(filename, artifact: artifact, version: version)
    }

    private static func isHex(_ string: String) -> Bool {
        !string.isEmpty && string.allSatisfy { $0.isHexDigit }
    }
}
