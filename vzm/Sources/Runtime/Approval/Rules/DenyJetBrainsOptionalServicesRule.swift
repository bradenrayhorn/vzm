import Foundation

/// Blocks optional JetBrains AI, promotional LLM configuration, and Feature Usage
/// Statistics resources. These are not required for IDE updates, plugins, builds, or licensing.
final class DenyJetBrainsOptionalServicesRule: DenyRule {
    var name: String { "DenyJetBrainsOptionalServices" }

    func shouldDeny(_ request: ProxyApprovalRequest) -> Bool {
        let domain = DomainName.normalize(request.domain)

        // Blocking CONNECT here avoids a second prompt for the inner AI request.
        if domain == "api.jetbrains.ai" {
            return true
        }

        guard request.type == "REQUEST" else {
            return false
        }

        let url = request.url.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if url.hasPrefix("frameworks.jetbrains.com/llm-config/")
            || url.hasPrefix("resources.jetbrains.com/storage/fus/")
            || url.hasPrefix("resources.jetbrains.com/storage/ap/fus/") {
            return true
        }

        return false
    }
}
