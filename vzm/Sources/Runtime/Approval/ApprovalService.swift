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
    private let denyEngines: [any ApprovalEngine]
    private let engines: [any ApprovalEngine]
    private let rawTCPApprovalEngine: RawTCPApprovalEngine
    private let modeState: ApprovalModeState
    private let promptUser: (ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult
    private var approvalInProgress = false
    private var approvalWaiters: [CheckedContinuation<Void, Never>] = []

    init(
        fileManager: FileManager = .default,
        denyEngines: [any ApprovalEngine]? = nil,
        engines: [any ApprovalEngine]? = nil,
        recognizedElementStore: RecognizedElementStore? = nil,
        modeState: ApprovalModeState = .shared,
        promptUser: @escaping (ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult = {
            await ApprovalCoordinator.shared.askForApproval(request: $0)
        }
    ) throws {
        let recognizedElementStore = try recognizedElementStore ?? RecognizedElementStore(fileManager: fileManager)
        self.recognizedElementStore = recognizedElementStore
        self.modeState = modeState
        self.promptUser = promptUser
        self.denyEngines = denyEngines ?? [
            DenyTrackingApprovalEngine(),
            DenyJetBrainsOptionalServicesApprovalEngine(),
        ]
        self.rawTCPApprovalEngine = RawTCPApprovalEngine()
        self.engines = engines ?? [
            AzureDevOpsMavenApprovalEngine(),
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

        await waitForApprovalTurn()
        defer { finishApprovalTurn() }

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

        for engine in denyEngines {
            switch engine.handle(request) {
            case .denied:
                return .denied(request: request, reason: "deny engine \(engine.name)")
            case .approved, .userApprovalRequired, .unknown:
                break
            }
        }

        if knownDomain && request.type == "CONNECT" {
            return .approved(request: request, reason: "known CONNECT domain")
        }

        request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: knownUserAgents)

        // Raw TCP payloads cannot be inspected, so only the dedicated bounded
        // raw TCP engine may auto-approve an already-approved destination.
        // Normal approval engines must never approve raw TCP traffic.
        if isRawTCP {
            switch rawTCPApprovalEngine.handle(request) {
            case .approved:
                return .approved(request: request, reason: "engine \(rawTCPApprovalEngine.name)")
            case let .userApprovalRequired(prompt):
                return .needsUserApproval(
                    PendingApproval(
                        request: request,
                        selectedEngine: SelectedEngine(engine: rawTCPApprovalEngine, prompt: prompt),
                        warnings: warnings,
                        knownDomain: false,
                        userAgents: userAgents,
                        knownUserAgents: knownUserAgents
                    )
                )
            case .denied, .unknown:
                return .needsUserApproval(
                    PendingApproval(
                        request: request,
                        selectedEngine: nil,
                        warnings: warnings,
                        knownDomain: false,
                        userAgents: userAgents,
                        knownUserAgents: knownUserAgents
                    )
                )
            }
        }

        // A new CONNECT domain always requires explicit consent, in every mode.
        // Neither general approval modes nor pattern engines may establish it.
        if request.type == "CONNECT" {
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

        let mode = modeState.current()
        if case .approveEverything = mode,
           !isGit, request.type != "WEBSOCKET", request.secrets.isEmpty {
            return .approved(request: request, reason: "mode Approve Everything")
        }

        var selectedEngine: SelectedEngine?
        for engine in engines {
            if mode == .auto && engine.isEligibleForAuto(request) {
                return .approved(request: request, reason: "mode Auto, engine \(engine.name)")
            }

            switch engine.handle(request) {
            case .approved:
                return .approved(request: request, reason: "engine \(engine.name)")
            case .denied:
                return .denied(request: request, reason: "engine \(engine.name)")
            case let .userApprovalRequired(prompt):
                if selectedEngine == nil {
                    selectedEngine = SelectedEngine(engine: engine, prompt: prompt)
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
        let action = await promptUser(
            ApprovalCoordinatorRequest(presentation: buildPromptPresentation(for: pendingApproval))
        )

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

        if action.isApproved && !pendingApproval.knownDomain && request.type != "TCP_CONNECT" {
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
            ApprovalPromptAction(id: .approveOnce, label: "✅ Approve", keyboardShortcut: .defaultAction)
        )

        return actions
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

