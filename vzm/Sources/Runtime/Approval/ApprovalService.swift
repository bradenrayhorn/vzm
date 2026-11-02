import Foundation

actor ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private struct SelectedEngine {
        let engine: any ApprovalEngine
        let prompt: EnginePrompt
    }

    private struct PendingApproval {
        let request: ProxyApprovalRequest
        let selectedEngine: SelectedEngine?
        let warnings: [String]
        let knownDomain: Bool
        let userAgents: [String]
        let knownUserAgents: [String]
    }

    private enum EvaluationResult {
        case approved(request: ProxyApprovalRequest, reason: String)
        case denied(request: ProxyApprovalRequest, reason: String)
        case needsUserApproval(PendingApproval)
    }

    private static let neverSeenDomainWarning = "Warning: new domain."
    private static let rawTCPWarning = "Warning: raw TCP payload."

    private static func logDecision(_ approved: Bool, request: ProxyApprovalRequest, reason: String) {
        let decision = approved ? "approved" : "denied"
        let timestamp = Date().ISO8601Format()
        StandardError.writeLine("[\(timestamp)] approval \(decision) (\(reason)): \(request.method) \(request.url)")
    }

    private let recognizedElementStore: RecognizedElementStore
    private let denyRules: [any DenyRule]
    private let engines: [any ApprovalEngine]
    private let modeState: ApprovalModeState
    private let promptUser: (ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult
    private struct ApprovalWaiter {
        let id: UUID
        let continuation: CheckedContinuation<Bool, Never>
    }

    // Includes the displayed approval, not just requests waiting behind it.
    private let maxPendingApprovals: Int
    private var approvalInProgress = false
    private var approvalWaiters: [ApprovalWaiter] = []

    init(
        fileManager: FileManager = .default,
        denyRules: [any DenyRule]? = nil,
        engines: [any ApprovalEngine]? = nil,
        recognizedElementStore: RecognizedElementStore? = nil,
        modeState: ApprovalModeState = .shared,
        maxPendingApprovals: Int = 64,
        promptUser: @escaping (ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult = {
            await ApprovalCoordinator.shared.askForApproval(request: $0)
        }
    ) throws {
        let recognizedElementStore = try recognizedElementStore ?? RecognizedElementStore(fileManager: fileManager)
        self.recognizedElementStore = recognizedElementStore
        self.modeState = modeState
        self.maxPendingApprovals = max(0, maxPendingApprovals)
        self.promptUser = promptUser
        self.denyRules = denyRules ?? [
            DenyTrackingRule(),
            DenyJetBrainsOptionalServicesRule(),
        ]
        self.engines = engines ?? [
            AzureDevOpsMavenApprovalEngine(recognizedElementStore: recognizedElementStore),
            AzureDevOpsNpmApprovalEngine(),
            SecretRequestApprovalEngine(recognizedElementStore: recognizedElementStore),
            ChatGPTApprovalEngine(),
            IntelliJApprovalEngine(),
            GradleDistributionApprovalEngine(),
            MavenRepositoryApprovalEngine(),
            DockerHubApprovalEngine(),
            NixCacheApprovalEngine(),
            NixGitHubApprovalEngine(),
            YarnPkgApprovalEngine(),
            NpmApprovalEngine(),
            ApproveForeverApprovalEngine(recognizedElementStore: recognizedElementStore),
        ]
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        guard !Task.isCancelled else { return false }
        switch evaluate(request: request) {
        case let .approved(request, reason):
            Self.logDecision(true, request: request, reason: reason)
            return true
        case let .denied(request, reason):
            Self.logDecision(false, request: request, reason: reason)
            return false
        case .needsUserApproval:
            break
        }

        guard await waitForApprovalTurn() else {
            Self.logDecision(false, request: request, reason: "approval queue full or cancelled")
            return false
        }
        defer { finishApprovalTurn() }
        guard !Task.isCancelled else { return false }

        switch evaluate(request: request) {
        case let .approved(request, reason):
            Self.logDecision(true, request: request, reason: reason)
            return true
        case let .denied(request, reason):
            Self.logDecision(false, request: request, reason: reason)
            return false
        case let .needsUserApproval(pendingApproval):
            let isApproved = await askUserForApproval(pendingApproval)
            Self.logDecision(isApproved, request: request, reason: "user")
            return isApproved
        }
    }

    private func evaluate(request: ProxyApprovalRequest) -> EvaluationResult {
        var request = request
        let isRawTCP = request.type == "TCP_CONNECT"
        let isGit = request.type.uppercased() == "GIT"
        let knownDomain = !isRawTCP && !request.domain.isEmpty && recognizedElementStore.contains(request.domain, type: .domain)
        let userAgents = ApprovalHeaderMasker.getUserAgents(for: request)
        let knownUserAgents = userAgents.filter { recognizedElementStore.contains($0, type: .userAgent) }

        var warnings: [String] = []

        if let bodyWarning = request.body?.warning, !bodyWarning.isEmpty {
            warnings.append(bodyWarning)
        }

        if !isRawTCP && !request.domain.isEmpty && !knownDomain {
            warnings.append(Self.neverSeenDomainWarning)
        }
        if isRawTCP {
            warnings.append(Self.rawTCPWarning)
        }

        for rule in denyRules {
            if rule.matches(request) {
                return .denied(request: request, reason: "deny rule \(rule.name)")
            }
        }

        if knownDomain && request.type == "CONNECT" {
            return .approved(request: request, reason: "known CONNECT domain")
        }

        request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: knownUserAgents)

        let mode = modeState.current()

        // Strict never reuses engine consent. New CONNECT domains and raw TCP
        // connections also require one-shot approval in every mode.
        // Already-open connections are unaffected by approval-mode changes.
        if mode == .strict || isRawTCP || request.type == "CONNECT" {
            return .needsUserApproval(
                PendingApproval(
                    request: request,
                    selectedEngine: nil,
                    warnings: warnings,
                    knownDomain: knownDomain,
                    userAgents: userAgents,
                    knownUserAgents: knownUserAgents
                )
            )
        }

        if case .approveEverything = mode,
           !isGit, request.type != "WEBSOCKET", request.secrets.isEmpty {
            return .approved(request: request, reason: "mode Approve Everything")
        }

        var selectedEngine: SelectedEngine?
        for engine in engines {
            switch engine.evaluate(request) {
            case .approved:
                return .approved(request: request, reason: "Auto rule, engine \(engine.name)")
            case let .needsConsent(prompt):
                if selectedEngine == nil {
                    selectedEngine = SelectedEngine(engine: engine, prompt: prompt)
                }
            case .notApplicable:
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
        let presentation = buildPromptPresentation(for: pendingApproval)
        let action = await promptUser(ApprovalCoordinatorRequest(presentation: presentation))
        // A cancelled prompt must never establish consent, even if a UI action
        // raced with cancellation or a presenter returned approval on cancellation.
        guard !Task.isCancelled else { return false }
        guard action != .approveEngine || pendingApproval.selectedEngine != nil else { return false }

        if action.isApproved && pendingApproval.userAgents.count > pendingApproval.knownUserAgents.count {
            for userAgent in Set(pendingApproval.userAgents).subtracting(Set(pendingApproval.knownUserAgents)) {
                do {
                    try recognizedElementStore.insert(userAgent, type: .userAgent)
                } catch {
                    StandardError.writeLine("Failed to persist approved User-Agent \(userAgent): \(error)")
                }
            }

            request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: pendingApproval.userAgents)
        }

        if action == .approveEngine {
            pendingApproval.selectedEngine?.engine.onEngineApproved(request)
        }

        if action.isApproved && !pendingApproval.knownDomain && !request.domain.isEmpty
            && request.type != "TCP_CONNECT" {
            do {
                try recognizedElementStore.insert(request.domain, type: .domain)
            } catch {
                StandardError.writeLine("Failed to persist approved CONNECT domain \(request.domain): \(error)")
            }
        }

        return action.isApproved
    }

    private func buildPromptPresentation(for pendingApproval: PendingApproval) -> ApprovalPromptPresentation {
        if let selectedEngine = pendingApproval.selectedEngine,
           case let .presentation(presentation) = selectedEngine.prompt {
            return ApprovalPromptPresentation(
                title: presentation.title,
                subtitle: presentation.subtitle,
                warnings: pendingApproval.warnings + presentation.warnings,
                sections: presentation.sections,
                actions: presentation.actions
            )
        }

        let request = pendingApproval.request

        return ApprovalPromptPresentation(
            title: "Outbound",
            subtitle: pendingApproval.selectedEngine.map { "🚂 available: \($0.engine.name)" },
            warnings: pendingApproval.warnings,
            sections: ApprovalPromptSection.requestDetails(for: request),
            actions: buildDefaultActions(hasEngine: pendingApproval.selectedEngine != nil)
        )
    }

    private func buildDefaultActions(hasEngine: Bool) -> [ApprovalPromptAction] {
        var actions: [ApprovalPromptAction] = [
            ApprovalPromptAction(id: .deny, label: "❌ Deny", keyboardShortcut: .cancelAction)
        ]

        if hasEngine {
            actions.append(
                ApprovalPromptAction(id: .approveEngine, label: "🚂 Approve engine", keyboardShortcut: .optionReturn)
            )
        }

        actions.append(
            ApprovalPromptAction(id: .approveOnce, label: "✅ Approve once", keyboardShortcut: .defaultAction)
        )

        return actions
    }

    private func waitForApprovalTurn() async -> Bool {
        let id = UUID()
        return await withTaskCancellationHandler {
            guard !Task.isCancelled,
                  approvalWaiters.count + (approvalInProgress ? 1 : 0) < maxPendingApprovals else {
                return false
            }
            if !approvalInProgress {
                approvalInProgress = true
                return true
            }

            return await withCheckedContinuation { continuation in
                approvalWaiters.append(ApprovalWaiter(id: id, continuation: continuation))
            }
        } onCancel: {
            Task { await self.cancelWaiter(id: id) }
        }
    }

    private func cancelWaiter(id: UUID) {
        // A promoted waiter owns the turn until its defer releases it. Its
        // caller checks cancellation before reevaluation/presentation instead.
        guard let index = approvalWaiters.firstIndex(where: { $0.id == id }) else { return }
        approvalWaiters.remove(at: index).continuation.resume(returning: false)
    }

    private func finishApprovalTurn() {
        if approvalWaiters.isEmpty {
            approvalInProgress = false
            return
        }

        approvalWaiters.removeFirst().continuation.resume(returning: true)
    }
}

