import Foundation

final class ApprovalService {
    static let shared: ApprovalService = {
        do {
            return try ApprovalService()
        } catch {
            fatalError("Failed to initialize ApprovalService: \(error)")
        }
    }()

    private let approvedConnectDomainStore: ApprovedConnectDomainStore

    init(fileManager: FileManager = .default) throws {
        self.approvedConnectDomainStore = try ApprovedConnectDomainStore(fileManager: fileManager)
    }

    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        guard request.type == "CONNECT", !request.domain.isEmpty else {
            return await ApprovalCoordinator.shared.askForApproval(request: request)
        }

        if approvedConnectDomainStore.contains(request.domain) {
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
}

