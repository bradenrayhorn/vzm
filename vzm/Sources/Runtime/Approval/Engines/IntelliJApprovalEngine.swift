import Foundation

/// Approves read-only JetBrains IDE metadata and download requests for a short IDE session.
/// Account, AI, and arbitrary JetBrains web requests intentionally do not match.
final class IntelliJApprovalEngine: BaseApprovalEngine {
    override var name: String { "IntelliJ" }

    private var approvedHeaders: Set<ProxyApprovalHeader>?

    init() {
        super.init(gateBuilders: [
            IdleTimeoutApprovalGate.new(idleTimeoutSeconds: 600),
            RateLimitApprovalGate.new(windowSeconds: 60, maxRequests: 30),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST" else {
            return .unknown
        }
        guard request.method == "GET" || request.method == "HEAD" else {
            return .unknown
        }
        guard request.secrets.isEmpty, request.body == nil else {
            return .unknown
        }
        guard Self.isAllowedURL(request.url) else {
            return .unknown
        }

        if let approvedHeaders, approvedHeaders.isSuperset(of: Set(request.headers)), checkGates() {
            return .approved
        }

        return .userApprovalRequired(.default)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        approvedHeaders = (approvedHeaders ?? []).union(Set(request.headers))
        super.onEngineApproved(request)
    }

    private static func isAllowedURL(_ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count <= 8_192,
              !trimmed.contains("#"),
              let slash = trimmed.firstIndex(of: "/") else {
            return false
        }

        let host = String(trimmed[..<slash]).lowercased()
        let resource = String(trimmed[slash...])
        let path = resource.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? resource

        switch host {
        case "download.jetbrains.com", "download-cdn.jetbrains.com":
            return path.hasPrefix("/jdk/feed/")
                || path.hasPrefix("/resources/intellij/")

        case "plugins.jetbrains.com":
            return path.hasPrefix("/feature/getImplementations")
                || path.hasPrefix("/plugins/")
                || path.hasPrefix("/files/")
                || path.hasPrefix("/api/search/updates/")

        case "downloads.marketplace.jetbrains.com":
            return path.hasPrefix("/files/")

        case "www.jetbrains.com":
            return path == "/config/JetBrainsResourceMapping.json"
                || path == "/config/JetBrainsAccount.xml"

        case "frameworks.jetbrains.com":
            return path == "/remote-config/v2/update.json"

        default:
            return false
        }
    }
}
