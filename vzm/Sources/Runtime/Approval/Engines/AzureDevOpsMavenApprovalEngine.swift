import CryptoKit
import Foundation

final class AzureDevOpsMavenApprovalEngine: BaseApprovalEngine {
    override var name: String { "AzureDevOpsMaven" }
    override var activityGroup: EngineActivityGroup? { .packages }

    private struct Consent {
        var headers: Set<String> = []
        var secrets: Set<String> = []

        func allows(_ request: ProxyApprovalRequest) -> Bool {
            headers.isSuperset(of: request.headers.map(AzureDevOpsMavenApprovalEngine.headerFingerprint))
                && secrets.isSuperset(of: request.secretNames)
        }
    }

    private struct StoredFeed: Codable {
        let prefix: String
        let headers: [String]
        let secrets: [String]
    }

    private let recognizedElementStore: RecognizedElementStore
    private var approvedFeeds: [String: Consent] = [:]

    private static let host = "pkgs.dev.azure.com"

    init(recognizedElementStore: RecognizedElementStore) {
        self.recognizedElementStore = recognizedElementStore
        super.init()
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

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        guard let prefix = repositoryPrefixIfMatchingRequest(request) else { return .notApplicable }
        if approvedFeeds[prefix]?.allows(request) == true {
            return .approved
        }
        return .needsConsent(.presentation(ApprovalPromptPresentation(
            title: "Outbound",
            subtitle: "🚂 available: \(name)",
            warnings: [
                "‘Approve engine’ permanently allows this Azure Maven feed in Auto with the approved headers and secret names.",
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
        consent.secrets.formUnion(request.secretNames)
        approvedFeeds[prefix] = consent

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
        guard MavenArtifactPath.matches(artifactPath) else {
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
}
