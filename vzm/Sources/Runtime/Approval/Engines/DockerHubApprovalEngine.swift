import Foundation

/// Approves the read-only Docker Hub image-pull protocol after the user approves it once.
final class DockerHubApprovalEngine: BaseApprovalEngine {
    override var name: String { "DockerHub" }

    private var approvedHeaders: Set<ProxyApprovalHeader>?

    private static let registryPathRegex = try! NSRegularExpression(
        pattern: #"^/v2/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)+(?:manifests/(?:sha256:[0-9a-f]{64}|[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})|(?:blobs|referrers)/sha256:[0-9a-f]{64})$"#
    )
    private static let cloudFrontBlobPathRegex = try! NSRegularExpression(
        pattern: #"^/registry-v2/docker/registry/v2/blobs/sha256/([0-9a-f]{2})/\1[0-9a-f]{62}/data$"#
    )

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 60),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 240),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST",
              request.secrets.isEmpty,
              request.body == nil,
              request.method == "GET" || request.method == "HEAD",
              isDockerHubPullURL(request.url)
        else {
            return .unknown
        }

        if let approvedHeaders,
           approvedHeaders.isSuperset(of: Set(request.headers)),
           checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        super.onEngineApproved(request)
    }

    private func isDockerHubPullURL(_ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: "https://\(trimmed)"),
              components.user == nil,
              components.password == nil,
              components.port == nil,
              components.fragment == nil,
              let host = components.host?.lowercased()
        else {
            return false
        }

        switch host {
        case "registry-1.docker.io":
            return components.query == nil && matches(Self.registryPathRegex, components.path)
        case "auth.docker.io":
            return components.path == "/token" && isPullTokenQuery(components.queryItems)
        case "production.cloudfront.docker.com":
            return matches(Self.cloudFrontBlobPathRegex, components.path) && isCloudFrontSignature(components.queryItems)
        default:
            return false
        }
    }

    private func isPullTokenQuery(_ queryItems: [URLQueryItem]?) -> Bool {
        guard let values = queryValues(queryItems),
              values.count == 2,
              values["service"] == "registry.docker.io",
              let scope = values["scope"],
              scope.hasPrefix("repository:"),
              scope.hasSuffix(":pull")
        else {
            return false
        }

        let repository = String(scope.dropFirst("repository:".count).dropLast(":pull".count))
        return matches(Self.registryPathRegex, "/v2/\(repository)/manifests/latest")
    }

    private func isCloudFrontSignature(_ queryItems: [URLQueryItem]?) -> Bool {
        guard let values = queryValues(queryItems),
              values.count == 3,
              let expires = values["Expires"], !expires.isEmpty, expires.allSatisfy(\.isNumber),
              let signature = values["Signature"], !signature.isEmpty,
              signature.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "~" }),
              let keyPairID = values["Key-Pair-Id"], !keyPairID.isEmpty,
              keyPairID.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" })
        else {
            return false
        }
        return true
    }

    private func queryValues(_ queryItems: [URLQueryItem]?) -> [String: String]? {
        guard let queryItems, !queryItems.isEmpty else { return nil }
        var values: [String: String] = [:]
        for item in queryItems {
            guard let value = item.value, values[item.name] == nil else { return nil }
            values[item.name] = value
        }
        return values
    }

    private func matches(_ regex: NSRegularExpression, _ string: String) -> Bool {
        let range = NSRange(string.startIndex..<string.endIndex, in: string)
        return regex.firstMatch(in: string, range: range) != nil
    }
}
