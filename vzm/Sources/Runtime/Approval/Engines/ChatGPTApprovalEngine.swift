import Foundation

final class ChatGPTApprovalEngine: BaseApprovalEngine {
    override var name: String { "ChatGPT" }

    private var isActivated = false

    private static let urlRegex = try! NSRegularExpression(
        pattern: #"^chatgpt\.com/backend-api/codex/responses$"#
    )

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard request.type == "WEBSOCKET" else {
            return .unknown
        }
        guard request.method == "GET" else {
            return .unknown
        }
        guard request.body == nil else {
            return .unknown
        }
        guard request.secrets.isEmpty else {
            return .unknown
        }
        guard urlMatches(regexes: [Self.urlRegex], request.url) else {
            return .unknown
        }

        return .userApprovalRequired(
            .presentation(
                ApprovalPromptPresentation(
                    title: "ChatGPT session",
                    subtitle: nil,
                    warnings: [],
                    sections: [
                        ApprovalPromptSection(
                            title: "Headers",
                            text: maskedHeadersForDisplay(request.headers)
                                .map { "\($0.name): \($0.value)" }
                                .joined(separator: "\n")
                        )
                    ],
                    actions: [
                        ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                        ApprovalPromptAction(id: .approveEngine, label: "↪️ Begin session", keyboardShortcut: .optionReturn),
                    ]
                )
            )
        )
    }

    private func maskedHeadersForDisplay(_ headers: [ProxyApprovalHeader]) -> [ProxyApprovalHeader] {
        headers.map { header in
            let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

            switch name {
            case "authorization":
                let value = header.value.trimmingPrefix("Bearer ")
                let maskedValue = "\(value.prefix(5))...\(value.suffix(5))"
                return ProxyApprovalHeader(name: header.name, value: maskedValue)
            default:
                return header
            }
        }
    }
}
