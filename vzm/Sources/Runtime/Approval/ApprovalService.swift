import Foundation

actor ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private static let neverSeenDomainWarning = "Warning: new domain."

    private static func logDecision(_ approved: Bool, request: ProxyApprovalRequest, reason: String) {
        let decision = approved ? "approved" : "denied"
        let timestamp = Date().ISO8601Format()
        FileHandle.standardError.write(Data("[\(timestamp)] approval \(decision) (\(reason)): \(request.method) \(request.url)\n".utf8))
    }

    private let recognizedElementStore: RecognizedElementStore
    private let engines: [any ApprovalEngine]

    init(
        fileManager: FileManager = .default,
        engines: [any ApprovalEngine] = [
            ManualTemporaryApprovalEngine.shared,
            NixCacheApprovalEngine(),
            NixGitHubApprovalEngine(),
        ]
    ) throws {
        self.recognizedElementStore = try RecognizedElementStore(fileManager: fileManager)
        self.engines = engines
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
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

        // short-circuit if domain is known and it is a CONNECT
        if knownDomain && request.type == "CONNECT" {
            Self.logDecision(true, request: request, reason: "known CONNECT domain")
            return true
        }

        request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: knownUserAgents)

        var selectedEngine: (any ApprovalEngine)?
        for engine in engines {
            switch engine.handle(request) {
            case .approved:
                Self.logDecision(true, request: request, reason: "engine \(engine.name)")
                return true
            case .canBeEngineApproved:
                if selectedEngine == nil {
                    selectedEngine = engine
                }
            case .unknown:
                break
            }
        }

        let approved = await ApprovalCoordinator.shared.askForApproval(
            request: ApprovalCoordinatorRequest(
                proxy: request,
                engineRequest: selectedEngine.map { ApprovalEngineRequest(name: $0.name) },
                warnings: warnings,
            )
        )

        let isApproved = approved == .approveEngine || approved == .approvedOnce

        // permanently recognize new user agents if approved
        if isApproved && userAgents.count > knownUserAgents.count {
            for userAgent in Set(userAgents).subtracting(Set(knownUserAgents)) {
                do {
                    try recognizedElementStore.insert(userAgent, type: .userAgent)
                } catch {
                    FileHandle.standardError.write(Data("Failed to persist approved User-Agent \(userAgent): \(error)\n".utf8))
                }
            }

            request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, knownUserAgents: userAgents)
        }

        if approved == .approveEngine {
            selectedEngine?.onEngineApproved(request)
        }

        Self.logDecision(isApproved, request: request, reason: "user")

        // permanently recognize the domain if it was approved
        if isApproved && !knownDomain {
            do {
                try recognizedElementStore.insert(request.domain, type: .domain)
            } catch {
                FileHandle.standardError.write(Data("Failed to persist approved CONNECT domain \(request.domain): \(error)\n".utf8))
            }
        }

        return isApproved
    }
}

