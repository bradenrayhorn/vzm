import Foundation

actor ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private struct PendingApproval {
        let request: ProxyApprovalRequest
        let selectedEngine: (any ApprovalEngine)?
        let warnings: [String]
        let knownDomain: Bool
        let userAgents: [String]
        let knownUserAgents: [String]
    }

    private enum EvaluationResult {
        case approved(request: ProxyApprovalRequest, reason: String)
        case needsUserApproval(PendingApproval)
    }

    private static let neverSeenDomainWarning = "Warning: new domain."

    private static func logDecision(_ approved: Bool, request: ProxyApprovalRequest, reason: String) {
        let decision = approved ? "approved" : "denied"
        let timestamp = Date().ISO8601Format()
        FileHandle.standardError.write(Data("[\(timestamp)] approval \(decision) (\(reason)): \(request.method) \(request.url)\n".utf8))
    }

    private let recognizedElementStore: RecognizedElementStore
    private let engines: [any ApprovalEngine]
    private var approvalInProgress = false
    private var approvalWaiters: [CheckedContinuation<Void, Never>] = []

    init(
        fileManager: FileManager = .default,
        engines: [any ApprovalEngine] = [
            ManualTemporaryApprovalEngine.shared,
            GradleDistributionApprovalEngine(),
            MavenRepositoryApprovalEngine(),
            NixCacheApprovalEngine(),
            NixGitHubApprovalEngine(),
        ]
    ) throws {
        self.recognizedElementStore = try RecognizedElementStore(fileManager: fileManager)
        self.engines = engines
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        switch evaluate(request: request) {
        case let .approved(request, reason):
            Self.logDecision(true, request: request, reason: reason)
            return true
        case .needsUserApproval:
            break
        }

        await waitForApprovalTurn()
        defer { finishApprovalTurn() }

        switch evaluate(request: request) {
        case let .approved(request, reason):
            Self.logDecision(true, request: request, reason: reason)
            return true
        case let .needsUserApproval(pendingApproval):
            let isApproved = await askUserForApproval(pendingApproval)
            Self.logDecision(isApproved, request: request, reason: "user")
            return isApproved
        }
    }

    private func evaluate(request: ProxyApprovalRequest) -> EvaluationResult {
        var request = request
        let knownDomain = !request.domain.isEmpty && recognizedElementStore.contains(request.domain, type: .domain)
        let userAgents = ApprovalHeaderMasker.getUserAgents(for: request)
        let knownUserAgents = userAgents.filter { recognizedElementStore.contains($0, type: .userAgent) }

        var warnings: [String] = []

        if let bodyWarning = request.body?.warning, !bodyWarning.isEmpty {
            warnings.append(bodyWarning)
        }

        if !request.domain.isEmpty && !knownDomain {
            warnings.append(Self.neverSeenDomainWarning)
        }

        if knownDomain && request.type == "CONNECT" {
            return .approved(request: request, reason: "known CONNECT domain")
        }

        request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: knownUserAgents)

        var selectedEngine: (any ApprovalEngine)?
        for engine in engines {
            switch engine.handle(request) {
            case .approved:
                return .approved(request: request, reason: "engine \(engine.name)")
            case .canBeEngineApproved:
                if selectedEngine == nil {
                    selectedEngine = engine
                }
            case .unknown:
                break
            }
        }

        return .needsUserApproval(
            PendingApproval(
                request: request,
                selectedEngine: selectedEngine,
                warnings: warnings,
                knownDomain: knownDomain,
                userAgents: userAgents,
                knownUserAgents: knownUserAgents
            )
        )
    }

    private func askUserForApproval(_ pendingApproval: PendingApproval) async -> Bool {
        var request = pendingApproval.request
        let approved = await ApprovalCoordinator.shared.askForApproval(
            request: ApprovalCoordinatorRequest(
                proxy: request,
                engineRequest: pendingApproval.selectedEngine.map { ApprovalEngineRequest(name: $0.name) },
                warnings: pendingApproval.warnings,
            )
        )

        let isApproved = approved == .approveEngine || approved == .approvedOnce

        if isApproved && pendingApproval.userAgents.count > pendingApproval.knownUserAgents.count {
            for userAgent in Set(pendingApproval.userAgents).subtracting(Set(pendingApproval.knownUserAgents)) {
                do {
                    try recognizedElementStore.insert(userAgent, type: .userAgent)
                } catch {
                    FileHandle.standardError.write(Data("Failed to persist approved User-Agent \(userAgent): \(error)\n".utf8))
                }
            }

            request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: pendingApproval.userAgents)
        }

        if approved == .approveEngine {
            pendingApproval.selectedEngine?.onEngineApproved(request)
        }

        if isApproved && !pendingApproval.knownDomain {
            do {
                try recognizedElementStore.insert(request.domain, type: .domain)
            } catch {
                FileHandle.standardError.write(Data("Failed to persist approved CONNECT domain \(request.domain): \(error)\n".utf8))
            }
        }

        return isApproved
    }

    private func waitForApprovalTurn() async {
        if !approvalInProgress {
            approvalInProgress = true
            return
        }

        await withCheckedContinuation { continuation in
            approvalWaiters.append(continuation)
        }
    }

    private func finishApprovalTurn() {
        if approvalWaiters.isEmpty {
            approvalInProgress = false
            return
        }

        approvalWaiters.removeFirst().resume()
    }
}

