import Foundation

final class AzureDevOpsMavenApprovalEngine: BaseApprovalEngine {
    override var name: String { "AzureDevOpsMaven" }

    private var approvedRepositoryPrefix: String?
    private var approvedHeaders: Set<ProxyApprovalHeader>?
    private var approvedSecrets: Set<String>?

    private static let host = "pkgs.dev.azure.com"
    private static let pathRegex = try! NSRegularExpression(
        pattern: #"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$"#
    )

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 5 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 30),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 120),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST" else {
            return .unknown
        }
        guard request.body == nil else {
            return .unknown
        }
        guard request.method == "GET" || request.method == "HEAD" else {
            return .unknown
        }
        guard let repositoryPrefix = repositoryPrefixIfAllowedMavenURL(request.url) else {
            return .unknown
        }

        if let approvedRepositoryPrefix,
           let approvedHeaders,
           let approvedSecrets,
           repositoryPrefix == approvedRepositoryPrefix,
           approvedHeaders.isSuperset(of: Set(request.headers)),
           approvedSecrets.isSuperset(of: Set(request.secrets)),
           checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedRepositoryPrefix = repositoryPrefixIfAllowedMavenURL(request.url)
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        approvedSecrets = (approvedSecrets ?? []).union(Set(request.secrets))
        super.onEngineApproved(request)
    }

    private func repositoryPrefixIfAllowedMavenURL(_ url: String) -> String? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let slash = trimmed.firstIndex(of: "/") else {
            return nil
        }

        let host = String(trimmed[..<slash]).lowercased()
        let path = String(trimmed[trimmed.index(after: slash)...])
        guard host == Self.host else {
            return nil
        }
        guard !path.contains("?") && !path.contains("#") else {
            return nil
        }

        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count > 6 else {
            return nil
        }
        guard parts[1] == "_packaging", parts[3] == "maven", parts[4] == "v1" else {
            return nil
        }
        guard !parts[0].isEmpty, !parts[2].isEmpty else {
            return nil
        }

        let artifactPath = parts.dropFirst(5).joined(separator: "/")
        guard isMavenArtifactPath(artifactPath) else {
            return nil
        }

        return "\(Self.host)/\(parts[0])/_packaging/\(parts[2])/maven/v1/"
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
}
