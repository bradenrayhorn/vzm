import Foundation

protocol ApprovalEngine {
    var name: String { get }

    func handle(_ request: ProxyApprovalRequest) -> EngineResult
    func onEngineApproved(_ request: ProxyApprovalRequest)
}

struct ApprovalPromptSection: Codable, Sendable {
    let title: String
    let text: String
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

