import Foundation

final class ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private static let neverSeenDomainWarning = "Warning: this VM is connecting to a domain that has not been approved before."
    private static let credentialHeaderWarning = "Warning: this request includes credential-bearing headers."
    private static let credentialHeaderNames: Set<String> = ["authorization", "cookie", "proxy-authorization"]

    private let approvedConnectDomainStore: ApprovedConnectDomainStore

    init(fileManager: FileManager = .default) throws {
        self.approvedConnectDomainStore = try ApprovedConnectDomainStore(fileManager: fileManager)
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        var request = request
        let knownDomain = !request.domain.isEmpty && approvedConnectDomainStore.contains(request.domain)
        if !request.domain.isEmpty && !knownDomain && !request.warnings.contains(Self.neverSeenDomainWarning) {
            request.warnings.append(Self.neverSeenDomainWarning)
        }
        if request.type == "REQUEST" && hasCredentialHeaders(request) && !request.warnings.contains(Self.credentialHeaderWarning) {
            request.warnings.append(Self.credentialHeaderWarning)
        }

        guard request.type == "CONNECT", !request.domain.isEmpty else {
            return await ApprovalCoordinator.shared.askForApproval(request: request)
        }
        if knownDomain {
            return true
        }

        let approved = await ApprovalCoordinator.shared.askForApproval(request: request)
        if approved {
            do {
                try approvedConnectDomainStore.insert(request.domain)
            } catch {
                FileHandle.standardError.write(Data("Failed to persist approved CONNECT domain \(request.domain): \(error)\n".utf8))
            }
        }
        return approved
    }

    private func hasCredentialHeaders(_ request: ProxyApprovalRequest) -> Bool {
        request.headers.contains { header in
            let normalizedName = header.name
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            return Self.credentialHeaderNames.contains(normalizedName)
        }
    }
}

