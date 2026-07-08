import Foundation

struct ApprovedForeverRequest: Sendable {
    let method: String
    let url: String

    func normalize() -> String {
        let method = method.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let url = url.trimmingCharacters(in: .whitespacesAndNewlines)
        return "\(method) \(url)"
    }
}


final class ApproveForeverApprovalEngine: BaseApprovalEngine {
    override var name: String { "ApproveForever" }

    private let recognizedElementStore: RecognizedElementStore

    init(recognizedElementStore: RecognizedElementStore) {
        self.recognizedElementStore = recognizedElementStore
        super.init(gateBuilders: [
            RateLimitApprovalGate.new(windowSeconds: 60, maxRequests: 5),
        ])
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "REQUEST" else {
            return .unknown
        }
        guard (request.method == "GET" || request.method == "HEAD") else {
            return .unknown
        }
        guard request.secrets.isEmpty else {
            return .unknown
        }
        guard request.body == nil else {
            return .unknown
        }
        guard request.headers.isEmpty else {
            return .unknown
        }

        let approvedRequest = ApprovedForeverRequest(method: request.method, url: request.url)
        if recognizedElementStore.contains(approvedRequest.normalize(), type: .approvedForeverRequest), checkGates() {
            return .approved
        }

        return .userApprovalRequired(
            .presentation(
                ApprovalPromptPresentation(
                    title: "Outbound",
                    subtitle: "🚂 available: \(name)",
                    warnings: [],
                    sections: [
                        ApprovalPromptSection(title: "Type", text: request.type),
                        ApprovalPromptSection(title: "URL", text: "\(request.method) \(request.url)"),
                    ],
                    actions: [
                        ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                        ApprovalPromptAction(id: .approveEngine, label: "♾️ Always Approve", keyboardShortcut: nil),
                        ApprovalPromptAction(id: .approveOnce, label: "✅ Approve", keyboardShortcut: .defaultAction),
                    ]
                )
            )
        )
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        super.onEngineApproved(request)
        do {
            try recognizedElementStore.insert(ApprovedForeverRequest(method: request.method, url: request.url).normalize(), type: .approvedForeverRequest)
        } catch {
            FileHandle.standardError.write(Data("Failed to persist forever-approved request \(request.method) \(request.url): \(error)\n".utf8))
        }
    }
}
