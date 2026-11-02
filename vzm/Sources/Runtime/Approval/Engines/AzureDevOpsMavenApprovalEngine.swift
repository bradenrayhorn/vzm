import CryptoKit
import Foundation

final class AzureDevOpsMavenApprovalEngine: BaseApprovalEngine {
    override var name: String { "AzureDevOpsMaven" }

    private struct Consent {
        var headers: Set<String> = []
        var secrets: Set<String> = []

        func allows(_ request: ProxyApprovalRequest) -> Bool {
            headers.isSuperset(of: request.headers.map(AzureDevOpsMavenApprovalEngine.headerFingerprint))
                && secrets.isSuperset(of: request.secrets)
        }
    }

    private struct StoredFeed: Codable {
        let prefix: String
        let headers: [String]
        let secrets: [String]
    }

    private struct Session {
        let consent: Consent
        let gates: [any ApprovalGate]
    }

    private let recognizedElementStore: RecognizedElementStore
    private var approvedFeeds: [String: Consent] = [:]
    private var sessions: [String: Session] = [:]

    private static let host = "pkgs.dev.azure.com"
    private static let pathRegex = try! NSRegularExpression(
        pattern: #"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$"#
    )

    init(recognizedElementStore: RecognizedElementStore) {
        self.recognizedElementStore = recognizedElementStore
        super.init(gateBuilders: [
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 1800),
            RateLimitApprovalGate.new(windowSeconds: 30, maxRequests: 120),
        ])
        do {
            for element in try recognizedElementStore.elements(type: .approvedAzureDevOpsMavenFeed) {
                guard let feed = try? JSONDecoder().decode(StoredFeed.self, from: Data(element.utf8)) else { continue }
                var consent = approvedFeeds[feed.prefix] ?? Consent()
                consent.headers.formUnion(feed.headers)
                consent.secrets.formUnion(feed.secrets)
                approvedFeeds[feed.prefix] = consent
            }
        } catch {
            StandardError.writeLine("Failed to load approved Azure Maven feeds: \(error)")
        }
    }

    override func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return false }
        // Persistent consent is feed-specific; Auto never consumes session gates.
        return approvedFeeds[prefix]?.allows(request) == true
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return .unknown }
        if let session = sessions[prefix],
           session.consent.allows(request),
           session.gates.allSatisfy({ $0.canContinue() }) {
            return .approved
        }

        return .userApprovalRequired(.presentation(ApprovalPromptPresentation(
            title: "Outbound",
            subtitle: "🚂 available: \(name)",
            warnings: [
                "‘Approve engine’ permanently allows this Azure Maven feed in Auto with the approved headers and secret names. "
                    + "Default mode uses a temporary feed session.",
            ],
            sections: [ApprovalPromptSection(title: "Feed", text: prefix)] + ApprovalPromptSection.requestDetails(for: request),
            actions: [
                ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                ApprovalPromptAction(id: .approveEngine, label: "🚂 Approve engine", keyboardShortcut: .optionReturn),
                ApprovalPromptAction(id: .approveOnce, label: "✅ Approve", keyboardShortcut: .defaultAction),
            ]
        )))
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return }
        var consent = approvedFeeds[prefix] ?? Consent()
        consent.headers.formUnion(request.headers.map(Self.headerFingerprint))
        consent.secrets.formUnion(request.secrets)
        approvedFeeds[prefix] = consent
        // Each feed has independent, runtime-only Default-mode gates.
        sessions[prefix] = Session(consent: consent, gates: gateBuilders.map { $0() })

        let feed = StoredFeed(prefix: prefix, headers: consent.headers.sorted(), secrets: consent.secrets.sorted())
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let element = String(decoding: try encoder.encode(feed), as: UTF8.self)
            try recognizedElementStore.insert(element, type: .approvedAzureDevOpsMavenFeed)
        } catch {
            StandardError.writeLine("Failed to persist approved Azure Maven feed: \(error)")
        }
    }

    private static func headerFingerprint(_ header: ProxyApprovalHeader) -> String {
        // Keep exact header consent without writing credentials/header values to disk.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try! encoder.encode(header)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func repositoryPrefixIfMatchingRequest(_ request: ProxyApprovalRequest) -> String? {
        guard request.type == "REQUEST",
              request.body == nil,
              request.method == "GET" || request.method == "HEAD"
        else { return nil }
        return repositoryPrefixIfAllowedMavenURL(request.url)
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
        // org[/project]/_packaging/feed/maven/v1/group/artifact/version/file
        let packagingIndex: Int
        if parts.count > 5, parts[1] == "_packaging" {
            packagingIndex = 1
        } else if parts.count > 6, parts[2] == "_packaging" {
            packagingIndex = 2
        } else {
            return nil
        }
        let names = Array(parts.prefix(packagingIndex)) + [parts[packagingIndex + 1]]
        guard names.allSatisfy(Self.isFeedName),
              parts[packagingIndex + 2] == "maven", parts[packagingIndex + 3] == "v1"
        else { return nil }

        let prefixLength = packagingIndex + 4
        let artifactPath = parts.dropFirst(prefixLength).joined(separator: "/")
        guard isMavenArtifactPath(artifactPath) else {
            return nil
        }

        return "\(Self.host)/\(parts.prefix(prefixLength).joined(separator: "/"))/"
    }

    private static func isFeedName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".."
            && name.utf8.allSatisfy { byte in
                (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
                    || byte == 45 || byte == 46 || byte == 95
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

        guard !version.isEmpty, !artifact.isEmpty, !filename.isEmpty, !groupParts.contains(where: \.isEmpty),
              !parts.contains(where: { $0 == "." || $0 == ".." })
        else {
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
        // Checksum sidecars must still name a supported artifact, not an arbitrary file.
        var filename = filename
        if let checksum = ["sha1", "md5", "sha256", "sha512"].first(where: { filename.hasSuffix(".\($0)") }) {
            filename = String(filename.dropLast(checksum.count + 1))
        }
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
