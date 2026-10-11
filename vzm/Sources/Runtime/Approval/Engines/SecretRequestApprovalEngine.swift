import Foundation

/// Permanently allows an exact method, URL, and secret-name set in Auto mode.
/// Headers and bodies are intentionally not part of the approval rule.
final class SecretRequestApprovalEngine: BaseApprovalEngine {
    override var name: String { "SecretRequest" }

    private struct ApprovalRule: Encodable {
        let method: String
        let url: String
        let secrets: [String]
    }

    private let recognizedElementStore: RecognizedElementStore

    init(recognizedElementStore: RecognizedElementStore) {
        self.recognizedElementStore = recognizedElementStore
        super.init()
    }

    override func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        guard let key = approvalKey(for: request) else { return false }
        return recognizedElementStore.contains(key, type: .autoApprovedSecretRequest)
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard approvalKey(for: request) != nil else { return .unknown }

        return .userApprovalRequired(
            .presentation(
                ApprovalPromptPresentation(
                    title: "Secret access approval",
                    subtitle: nil,
                    warnings: [
                        "Choosing ‘Always allow in Auto’ saves permanent approval to disk. Auto mode will allow these secrets for this exact method and URL, even if the request body or other headers change.",
                    ],
                    sections: ApprovalPromptSection.requestDetails(for: request),
                    actions: [
                        ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                        ApprovalPromptAction(id: .approveEngine, label: "♾️ Always allow in Auto", keyboardShortcut: nil),
                        ApprovalPromptAction(id: .approveOnce, label: "✅ Approve once", keyboardShortcut: .defaultAction),
                    ]
                )
            )
        )
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard let key = approvalKey(for: request) else { return }
        do {
            try recognizedElementStore.insert(key, type: .autoApprovedSecretRequest)
        } catch {
            StandardError.writeLine("Failed to persist Auto-approved secret request: \(error)")
        }
    }

    private func approvalKey(for request: ProxyApprovalRequest) -> String? {
        guard request.type == "REQUEST",
              !request.method.isEmpty,
              !request.url.isEmpty,
              !request.secrets.isEmpty,
              request.secrets.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty })
        else { return nil }

        let rule = ApprovalRule(method: request.method, url: request.url, secrets: Set(request.secrets).sorted())
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(rule) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
