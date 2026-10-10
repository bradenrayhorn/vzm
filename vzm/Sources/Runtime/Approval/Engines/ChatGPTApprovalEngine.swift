import Foundation

final class ChatGPTApprovalEngine: BaseApprovalEngine {
    override var name: String { "ChatGPT" }

    private var approvedAccountIDs: Set<String> = []

    private static let urlRegex = try! NSRegularExpression(
        pattern: #"^chatgpt\.com/backend-api/codex/responses$"#
    )

    override func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        guard matches(request), let accountID = accountID(for: request) else {
            return false
        }
        return approvedAccountIDs.contains(accountID)
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard matches(request), let accountID = accountID(for: request) else { return }
        approvedAccountIDs.insert(accountID)
    }

    private func matches(_ request: ProxyApprovalRequest) -> Bool {
        request.type == "WEBSOCKET"
            && request.method == "GET"
            && request.body == nil
            && request.secrets.isEmpty
            && urlMatches(regexes: [Self.urlRegex], request.url)
    }

    private func accountID(for request: ProxyApprovalRequest) -> String? {
        let headers = request.headers.filter {
            $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "chatgpt-account-id"
        }
        guard headers.count == 1 else { return nil }
        let value = headers[0].value.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    override func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        guard matches(request) else { return .unknown }

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
