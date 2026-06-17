import Foundation

protocol ApprovalEngine {
    var name: String { get }

    func handle(_ request: ProxyApprovalRequest) -> EngineResult
    func onEngineApproved(_ request: ProxyApprovalRequest)
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
}

enum EngineResult {
    case approved
    case canBeEngineApproved
    case unknown
}

protocol ApprovalGate {
    func canContinue() -> Bool
}

typealias ApprovalGateBuilder = () -> ApprovalGate

