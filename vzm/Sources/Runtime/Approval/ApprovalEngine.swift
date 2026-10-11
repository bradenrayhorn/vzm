import Foundation

protocol ApprovalEngine {
    var name: String { get }

    /// Side-effect-free eligibility; excludes session gates and never grants consent.
    func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool
    func handle(_ request: ProxyApprovalRequest) -> EngineResult
    func onEngineApproved(_ request: ProxyApprovalRequest)
}

extension ApprovalEngine {
    func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool { false }
}

struct ApprovalPromptSection: Codable, Sendable {
    let title: String
    let text: String

    static func requestDetails(for request: ProxyApprovalRequest) -> [ApprovalPromptSection] {
        var sections: [ApprovalPromptSection] = [
            ApprovalPromptSection(title: "Type", text: request.type),
            ApprovalPromptSection(title: "URL", text: "\(request.method) \(request.url)"),
        ]

        if !request.domain.isEmpty {
            sections.append(ApprovalPromptSection(title: "Domain", text: request.domain))
        }

        if !request.headers.isEmpty {
            sections.append(
                ApprovalPromptSection(
                    title: "Headers",
                    text: request.headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n")
                )
            )
        }

        if let body = request.body {
            sections.append(ApprovalPromptSection(title: "Body", text: body.text))
        }

        if !request.secrets.isEmpty {
            sections.append(ApprovalPromptSection(title: "Secrets", text: request.secrets.joined(separator: ", ")))
        }

        return sections
    }
}

enum ApprovalPromptActionType: String, Codable, Sendable {
    case deny
    case approveOnce
    case approveEngine
}

extension ApprovalPromptActionType {
    var isApproved: Bool {
        switch self {
        case .deny:
            return false
        case .approveOnce, .approveEngine:
            return true
        }
    }
}

enum ApprovalPromptKeyboardShortcut: String, Codable, Sendable {
    case cancelAction
    case defaultAction
    case optionReturn
}

struct ApprovalPromptAction: Codable, Sendable {
    let id: ApprovalPromptActionType
    let label: String
    let keyboardShortcut: ApprovalPromptKeyboardShortcut?
}

struct ApprovalPromptPresentation: Codable, Sendable {
    let title: String
    let subtitle: String?
    let warnings: [String]
    let sections: [ApprovalPromptSection]
    let actions: [ApprovalPromptAction]
}

enum EnginePrompt {
    case `default`
    case presentation(ApprovalPromptPresentation)
}

open class BaseApprovalEngine: ApprovalEngine {
    open var name: String { String(describing: Self.self) }

    let gateBuilders: [ApprovalGateBuilder]
    private(set) var gates: [any ApprovalGate] = []

    init(gateBuilders: [ApprovalGateBuilder] = []) {
        self.gateBuilders = gateBuilders
    }

    private func initGates() {
        gates = gateBuilders.map { $0() }
    }

    open func checkGates() -> Bool {
        gates.allSatisfy { $0.canContinue() }
    }

    func isEligibleForAuto(_ request: ProxyApprovalRequest) -> Bool {
        false
    }

    func handle(_ request: ProxyApprovalRequest) -> EngineResult {
        .unknown
    }

    func onEngineApproved(_ request: ProxyApprovalRequest) {
        initGates()
    }

    func urlMatches(regexes: [NSRegularExpression], _ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let range = NSRange(trimmed.startIndex..<trimmed.endIndex, in: trimmed)

        return regexes.contains { regex in
            regex.firstMatch(in: trimmed, range: range) != nil
        }
    }
}

enum EngineResult {
    case approved
    case denied
    case userApprovalRequired(EnginePrompt)
    case unknown
}

protocol ApprovalGate {
    func canContinue() -> Bool
}

typealias ApprovalGateBuilder = () -> ApprovalGate

