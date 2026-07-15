import Foundation

/// Blocks optional JetBrains AI, promotional LLM configuration, and Feature Usage
/// Statistics resources. These are not required for IDE updates, plugins, builds, or licensing.
final class DenyJetBrainsOptionalServicesApprovalEngine: BaseApprovalEngine {
    override var name: String { "DenyJetBrainsOptionalServices" }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        let domain = Self.normalizedDomain(request.domain)

        // Blocking CONNECT here avoids a second prompt for the inner AI request.
        if domain == "api.jetbrains.ai" {
            return .denied
        }

        guard request.type == "REQUEST" else {
            return .unknown
        }

        let url = request.url.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if url.hasPrefix("frameworks.jetbrains.com/llm-config/")
            || url.hasPrefix("resources.jetbrains.com/storage/fus/")
            || url.hasPrefix("resources.jetbrains.com/storage/ap/fus/") {
            return .denied
        }

        return .unknown
    }

    private static func normalizedDomain(_ domain: String) -> String {
        var normalized = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }
        if let colon = normalized.lastIndex(of: ":") {
            normalized = String(normalized[..<colon])
        }
        return normalized
    }
}
