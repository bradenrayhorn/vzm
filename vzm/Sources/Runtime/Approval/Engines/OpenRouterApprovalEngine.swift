import Foundation

/// Session-scoped consent for ordinary OpenRouter chat traffic. Header shape
/// checks recognize the protocol; they do not prove that a request came from pi.
final class OpenRouterApprovalEngine: BaseApprovalEngine {
    override var name: String { "OpenRouter" }

    private var approvedSecrets: Set<String> = []
    private var approvedHeaders: Set<ProxyApprovalHeader> = []

    private static let versionRegex = try! NSRegularExpression(
        pattern: #"\Av?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(?:-[A-Za-z0-9.-]{1,32})?\z"#
    )
    private static let sessionRegex = try! NSRegularExpression(
        pattern: #"\A[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\z"#
    )
    private static let dateRegex = try! NSRegularExpression(pattern: #"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z"#)
    private static let betaRegex = try! NSRegularExpression(pattern: #"\A[a-z][a-z0-9]*(?:-[a-z0-9]+)*\z"#)
    private static let numberRegex = try! NSRegularExpression(pattern: #"\A[0-9]{1,10}\z"#)

    override func evaluate(_ request: ProxyApprovalRequest) -> EngineEvaluation {
        guard matches(request) else { return .notApplicable }
        if approvedSecrets.isSuperset(of: request.secretNames)
            && approvedHeaders.isSuperset(of: headersForApproval(request)) {
            return .approved
        }
        return .needsConsent(.presentation(ApprovalPromptPresentation(
            title: "OpenRouter session",
            subtitle: nil,
            warnings: [
                "Begin session allows changing conversation content to be sent to OpenRouter in Auto using these secret names until vzm exits. Unfamiliar headers or new secrets require approval.",
            ],
            sections: ApprovalPromptSection.requestDetails(for: request),
            actions: [
                ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction),
                ApprovalPromptAction(id: .approveEngine, label: "↪️ Begin session", keyboardShortcut: .optionReturn),
                ApprovalPromptAction(id: .approveOnce, label: "✅ Approve once", keyboardShortcut: .defaultAction),
            ]
        )))
    }

    override func onEngineApproved(_ request: ProxyApprovalRequest) {
        guard matches(request) else { return }
        approvedSecrets.formUnion(request.secretNames)
        approvedHeaders.formUnion(headersForApproval(request))
    }

    private func matches(_ request: ProxyApprovalRequest) -> Bool {
        guard request.type == "REQUEST", request.method == "POST", request.body != nil else { return false }
        let authName: String
        switch request.url.trimmingCharacters(in: .whitespacesAndNewlines) {
        case "openrouter.ai/api/v1/chat/completions":
            authName = "authorization"
        case "openrouter.ai/api/v1/messages", "openrouter.ai/api/v1/messages?beta=true":
            authName = "x-api-key"
        default:
            return false
        }
        let headers = request.headers.map(normalized)
        let auth = headers.filter { $0.name == "authorization" || $0.name == "x-api-key" }
        guard auth.count == 1, auth[0].name == authName else { return false }
        let credential = authName == "authorization" ? String(auth[0].value.trimmingPrefix("Bearer ")) : auth[0].value
        // Bearer is required for the OpenAI-compatible endpoint, not just a bare placeholder.
        guard authName != "authorization" || auth[0].value.hasPrefix("Bearer "),
              credential.hasPrefix("{vzm:"), credential.hasSuffix("}") else { return false }
        let secret = String(credential.dropFirst(5).dropLast())
        guard !secret.isEmpty, secret == secret.trimmingCharacters(in: .whitespacesAndNewlines),
              !secret.contains(where: { "{}\r\n".contains($0) }),
              request.secretNames.contains(secret),
              request.secretNames.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty })
        else { return false }
        return true
    }

    private func normalized(_ header: ProxyApprovalHeader) -> ProxyApprovalHeader {
        ProxyApprovalHeader(
            name: header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            value: header.value.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    private func headersForApproval(_ request: ProxyApprovalRequest) -> [ProxyApprovalHeader] {
        request.headers.map(normalized).filter { header in
            // User-Agent is deliberately left to the service's existing explicit approval.
            if ApprovalHeaderMasker.isSafe(header, in: request) { return false }
            let value = header.value
            switch header.name {
            case "authorization", "x-api-key":
                return false // Already validated by matches(); secret consent is checked separately.
            case "x-stainless-lang":
                return value != "js"
            case "x-stainless-runtime":
                return !["node", "bun", "deno"].contains(value)
            case "x-stainless-os":
                return !["Linux", "MacOS", "Windows", "FreeBSD", "OpenBSD", "Android", "iOS", "Unknown"].contains(value)
            case "x-stainless-arch":
                return !["arm64", "x64", "arm", "x32", "unknown"].contains(value)
            case "x-stainless-package-version", "x-stainless-runtime-version":
                return !test(Self.versionRegex, value)
            case "x-stainless-retry-count":
                return !number(value, atMost: 100)
            case "x-stainless-timeout":
                return !number(value, atMost: 86_400)
            case "content-length":
                return !number(value, atMost: 1_073_741_824)
            case "x-session-id":
                // A bounded metadata channel, not an authentication token.
                return !test(Self.sessionRegex, value)
            case "anthropic-version":
                return !test(Self.dateRegex, value)
            case "anthropic-dangerous-direct-browser-access":
                return value != "true"
            case "anthropic-beta":
                let features = value.split(separator: ",", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                return features.count > 16 || !features.allSatisfy {
                    $0.count <= 128 && test(Self.betaRegex, $0)
                }
            default:
                return true
            }
        }
    }

    // Defensive sanity caps, not OpenRouter API limits.
    private func number(_ value: String, atMost maximum: UInt64) -> Bool {
        test(Self.numberRegex, value) && UInt64(value).map { $0 <= maximum } == true
    }

    private func test(_ regex: NSRegularExpression, _ value: String) -> Bool {
        regex.firstMatch(in: value, range: NSRange(value.startIndex..<value.endIndex, in: value)) != nil
    }
}
