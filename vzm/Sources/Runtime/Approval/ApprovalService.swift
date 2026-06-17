import Foundation

final class ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private static let neverSeenDomainWarning = "Warning: new domain."

    private let recognizedElementStore: RecognizedElementStore
    private let engines: [any ApprovalEngine]

    init(
        fileManager: FileManager = .default,
        engines: [any ApprovalEngine] = [
            NixCacheApprovalEngine(),
        ]
    ) throws {
        self.recognizedElementStore = try RecognizedElementStore(fileManager: fileManager)
        self.engines = engines
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        var request = request
        let knownDomain = !request.domain.isEmpty && recognizedElementStore.contains(request.domain, type: .domain)
        let userAgent = ApprovalHeaderMasker.getUserAgent(for: request)
        let isKnownUserAgent = !userAgent.isEmpty && recognizedElementStore.contains(userAgent, type: .userAgent)

        if !request.domain.isEmpty && !knownDomain && !request.warnings.contains(Self.neverSeenDomainWarning) {
            request.warnings.append(Self.neverSeenDomainWarning)
        }

        // short-circuit if domain is known and it is a CONNECT
        if knownDomain && request.type == "CONNECT" {
            return true
        }

        request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, isKnownUserAgent: isKnownUserAgent)

        var selectedEngine: (any ApprovalEngine)?
        for engine in engines {
            switch engine.handle(request) {
            case .approved:
                FileHandle.standardError.write(Data("engine approved: \(request.method) \(request.url)\n".utf8))
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
                engineRequest: selectedEngine.map { ApprovalEngineRequest(name: $0.name) }
            )
        )
        let isApproved = approved == .approveEngine || approved == .approvedOnce

        // permanently recognize user agent if it was approved
        if isApproved && !isKnownUserAgent {
            do {
                try recognizedElementStore.insert(userAgent, type: .userAgent)
            } catch {
                FileHandle.standardError.write(Data("Failed to persist approved User-Agent \(userAgent): \(error)\n".utf8))
            }

            request.headers = ApprovalHeaderMasker.maskSafeHeaders(for: request, isKnownUserAgent: true)
        }

        if approved == .approveEngine {
            selectedEngine?.onEngineApproved(request)
        }

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

