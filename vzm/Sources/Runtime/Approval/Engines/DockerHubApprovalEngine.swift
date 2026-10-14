import Foundation

/// Approves the read-only Docker Hub image-pull protocol after the user approves it once.
final class DockerHubApprovalEngine: PatternApprovalEngine {
    override var name: String { "DockerHub" }

    private static let registryPathRegex = try! NSRegularExpression(
        pattern: #"^/v2/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)+(?:manifests/(?:sha256:[0-9a-f]{64}|[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})|(?:blobs|referrers)/sha256:[0-9a-f]{64})$"#
    )
    private static let cloudFrontBlobPathRegex = try! NSRegularExpression(
        pattern: #"^/registry-v2/docker/registry/v2/blobs/sha256/([0-9a-f]{2})/\1[0-9a-f]{62}/data$"#
    )

    private static let pullMediaTypes: Set<String> = [
        "application/vnd.docker.distribution.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    ]

    init() {
        super.init(gateBuilders: [
            TimeWindowApprovalGate.new(durationSeconds: 10 * 60),
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 60),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 240),
        ])
    }

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        request.type == "REQUEST"
            && request.secrets.isEmpty
            && request.body == nil
            && (request.method == "GET" || request.method == "HEAD")
            && isDockerHubPullURL(request.url)
    }

    override func headersForApproval(_ request: ProxyApprovalRequest) -> [ProxyApprovalHeader] {
        // Never apply this policy to requests outside the read-only pull protocol.
        guard matches(request) else { return request.headers }
        return request.headers.filter { header in
            let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if name == "authorization" {
                // Credentials referenced through vzm secrets are excluded by matches().
                return false
            }
            if name == "baggage" {
                return header.value.trimmingCharacters(in: .whitespacesAndNewlines) != "trigger=api"
            }
            if name == "referer" {
                let value = header.value.trimmingCharacters(in: .whitespacesAndNewlines)
                guard value.hasPrefix("https://") else { return true }
                let url = String(value.dropFirst("https://".count))
                return !isDockerHubPullURL(url)
            }
            if name == "accept" {
                let types = header.value.split(separator: ",", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                return !types.allSatisfy {
                    Self.pullMediaTypes.contains($0)
                        || ApprovalHeaderMasker.isSafe(ProxyApprovalHeader(name: "Accept", value: $0), in: request)
                }
            }
            return true
        }
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
