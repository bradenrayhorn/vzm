import Foundation

/// Persistent consent for arbitrary API traffic to api.datadoghq.com using PAT
/// secret names. Datadog enforces the PAT's permissions; this does not verify
/// the identity of the guest program (such as Pup).
final class DatadogApprovalEngine: BaseApprovalEngine, DenyRule {
    override var name: String { "Datadog" }

    private static let apiHost = "api.datadoghq.com"
    private static let sdkKeyHeaders: Set<String> = ["dd-api-key", "dd-application-key"]
    private static let allowedHeaderNames: Set<String> = [
        "authorization", "accept", "accept-encoding", "content-type", "content-encoding", "user-agent",
        "host", "content-length", "transfer-encoding", "dd-api-key", "dd-application-key",
    ]

    private let recognizedElementStore: RecognizedElementStore
    private var approvedSecrets: Set<String> = []

    init(recognizedElementStore: RecognizedElementStore) {
        self.recognizedElementStore = recognizedElementStore
        super.init()
        do {
            approvedSecrets = Set(try recognizedElementStore.elements(type: .approvedDatadogSecret))
        } catch {
            StandardError.writeLine("Failed to load approved Datadog secrets: \(error)")
        }
    }

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        if shouldDeny(request) { return .denied }
        guard let secret = autoApprovalSecretName(request) else { return .notApplicable }
        if approvedSecrets.contains(secret) { return .approved }

        return .needsConsent(.presentation(ApprovalPromptPresentation(
            title: "Datadog access",
            subtitle: "\(Self.apiHost) · \(secret)",
            warnings: [
                "Permanently allowes DataDog access with the approved secret.",
            ],
            sections: ApprovalPromptSection.requestDetails(for: request),
            actions: [
                ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                ApprovalPromptAction(id: .approveEngine, label: "🐶 Always allow in Auto", keyboardShortcut: .optionReturn),
                ApprovalPromptAction(id: .approveOnce, label: "✅ Approve once", keyboardShortcut: .defaultAction),
            ]
        )))
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard !shouldDeny(request), let secret = autoApprovalSecretName(request) else { return }
        do {
            try recognizedElementStore.insert(secret, type: .approvedDatadogSecret)
            approvedSecrets.insert(secret)
        } catch {
            StandardError.writeLine("Failed to persist approved Datadog secret: \(error)")
        }
    }

    // Also registered as a hard-deny rule by ApprovalService, so saved approvals,
    // Strict prompts, or Approve Everything cannot bypass credential placement.
    func shouldDeny(_ request: ProxyApprovalRequest) -> Bool {
        guard request.domain == Self.apiHost else { return false }
        return request.secrets.contains { $0.location != .authorizationHeader }
            || request.headers.contains {
                Self.sdkKeyHeaders.contains($0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
                    && !$0.value.isEmpty
            }
    }

    // Called after shouldDeny. Hidden headers are already trusted; remaining
    // headers must be allowlisted and include exactly one Bearer placeholder.
    // Returns the referenced secret name, not the PAT or its approval status.
    private func autoApprovalSecretName(_ request: ProxyApprovalRequest) -> String? {
        guard request.type == "REQUEST", !request.method.isEmpty,
              request.domain == Self.apiHost, request.url.hasPrefix("\(Self.apiHost)/"),
              let secret = request.secrets.first?.name,
              request.secrets.allSatisfy({ $0.name == secret }) else { return nil }

        var authorization: String?
        for header in request.headers {
            let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard Self.allowedHeaderNames.contains(name) else { return nil }
            if name == "authorization" {
                guard authorization == nil else { return nil }
                authorization = header.value.trimmingCharacters(in: .whitespaces)
            }
        }
        return authorization == "Bearer {vzm:\(secret)}" ? secret : nil
    }
}
