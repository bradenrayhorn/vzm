import SwiftUI
import ArgumentParser
import AppKit

class MenuBarAppEnvironment {
    static let shared = MenuBarAppEnvironment()
    
    var command: AsyncParsableCommand? 
}

struct VZMMenuBarApp: App {
    init() {
        if var command = MenuBarAppEnvironment.shared.command {
            Task { @MainActor in
                do {
                    try await command.run()
                    exit(EXIT_SUCCESS)
                } catch {
                    print("Background task failed: \(error)")
                    exit(1)
                }
            }
        }
    }

    @State private var portExposureCoordinator = PortExposureCoordinator.shared

    var body: some Scene {
        MenuBarExtra("vm") {
            VStack {
                Text("VM Running...")
                Divider()
                ApprovalModeMenuView()
                Divider()
                PortExposureMenuView(coordinator: portExposureCoordinator)
            }
            .padding(.vertical, 4)
        }
    }
}

@Observable
@MainActor
class PortExposureCoordinator {
    static let shared = PortExposureCoordinator()

    private(set) var service: PortExposureService?

    func attach(service: PortExposureService) {
        self.service = service
    }

    func detach() {
        service = nil
    }
}

struct PortExposureMenuView: View {
    @Bindable var coordinator: PortExposureCoordinator

    let availablePorts: [UInt16] = [3000, 5173, 7835, 8000, 8080]

    var body: some View {
        Section("Port forwarding") {
            if let service = coordinator.service {
                PortExposureControls(service: service, availablePorts: availablePorts)
            } else {
                Text("VM is not ready")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(minWidth: 280, alignment: .leading)
    }
}

struct PortExposureControls: View {
    @Bindable var service: PortExposureService
    let availablePorts: [UInt16]

    var body: some View {
        ForEach(availablePorts, id: \.self) { port in
            Toggle(isOn: Binding(
                get: { service.isExposed(port: port) },
                set: { isStarting in
                    if isStarting {
                        service.expose(port: port)
                    } else {
                        service.unexpose(port: port)
                    }
                }
            )) {
                Text(":\(port, format: .number.grouping(.never))")
            }
        }
    }
}

struct ApprovalEngineRequest: Codable, Sendable {
    let name: String
}

struct ApprovalCoordinatorRequest: Codable, Sendable {
    let proxy: ProxyApprovalRequest
    let engineRequest: ApprovalEngineRequest?
    var warnings: [String]
}

enum ApprovalCoordinatorResult {
    case approvedOnce
    case approveEngine
    case denied
}

struct ApprovalModeMenuView: View {
    var body: some View {
        Section("Approvals") {
            Button("Approve everything for 5 min") {
                ManualTemporaryApprovalEngine.shared.activateForFiveMinutes()
            }
        }
        .frame(minWidth: 280, alignment: .leading)
    }
}

@Observable
@MainActor
class ApprovalCoordinator: NSObject, NSWindowDelegate {
    static let shared = ApprovalCoordinator()

    private struct QueuedApproval {
        let request: ApprovalCoordinatorRequest
        let continuation: CheckedContinuation<ApprovalCoordinatorResult, Never>
    }

    private let maxPendingApprovals = 64
    private var activeApproval: QueuedApproval?
    private var queuedApprovals: [QueuedApproval] = []
    private var popupWindow: NSWindow?

    func askForApproval(request: ApprovalCoordinatorRequest) async -> ApprovalCoordinatorResult {
        await withCheckedContinuation { continuation in
            let pendingCount = queuedApprovals.count + (activeApproval == nil ? 0 : 1)
            guard pendingCount < maxPendingApprovals else {
                continuation.resume(returning: .denied)
                return
            }

            queuedApprovals.append(QueuedApproval(request: request, continuation: continuation))
            showNextApprovalIfIdle()
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if sender === popupWindow, activeApproval != nil {
            finishActiveApproval(result: .denied, closeWindow: false)
        }
        return true
    }

    private func finishActiveApproval(result: ApprovalCoordinatorResult, closeWindow: Bool) {
        guard let activeApproval else {
            return
        }

        let continuation = activeApproval.continuation
        let windowToClose = popupWindow
        self.activeApproval = nil
        popupWindow = nil

        if closeWindow {
            windowToClose?.delegate = nil
            windowToClose?.close()
        }

        continuation.resume(returning: result)
        showNextApprovalIfIdle()
    }

    private func showNextApprovalIfIdle() {
        guard activeApproval == nil, !queuedApprovals.isEmpty else {
            return
        }

        activeApproval = queuedApprovals.removeFirst()
        showPopupWindow()
    }

    private func showPopupWindow() {
        guard let request = self.activeApproval?.request else { return }
        let promptView = ApprovalPromptView(request: request) { [weak self] result in
            self?.finishActiveApproval(result: result, closeWindow: true)
        }
        
        let hostingController = NSHostingController(rootView: promptView)
        let fittingSize = hostingController.view.fittingSize
        let panelSize = NSSize(
            width: min(max(fittingSize.width, 360), 900),
            height: max(fittingSize.height, 220)
        )

        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: panelSize),
            styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        
        panel.delegate = self
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        panel.isMovableByWindowBackground = true
        panel.level = .floating 
        panel.isFloatingPanel = true
        panel.center()
        panel.contentViewController = hostingController
        
        self.popupWindow = panel
        
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct ApprovalPromptView: View {
    let request: ApprovalCoordinatorRequest
    let onResolve: (ApprovalCoordinatorResult) -> Void

    private var headerText: String {
        request.proxy.headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n")
    }
    
    var body: some View {
        VStack(spacing: 16) {
            Text("Outbound")
                .font(.headline)
            
            VStack(spacing: 8) {
                Text(request.proxy.type)
                Text(request.proxy.domain)
                    .font(.body.bold())

                if !request.warnings.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(request.warnings, id: \.self) { warning in
                            Text("⚠️ \(warning)")
                                .foregroundStyle(.orange)
                                .textSelection(.enabled)
                        }
                    }
                }

                if let engine = request.engineRequest {
                    Text("🚂 available engine: \(engine.name)")
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(request.proxy.method)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(request.proxy.url)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                if !request.proxy.headers.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Headers")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ScrollView {
                            Text(headerText)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 140)
                    }
                }

                if let body = request.proxy.body {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Body")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ScrollView {
                            Text(body.text)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 180)
                    }
                }

                if !request.proxy.secrets.isEmpty {
                    VStack(spacing: 4) {
                        Text("Secrets")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(request.proxy.secrets.joined(separator: ", "))
                            .font(.body)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 8)
                }
            }
            
            HStack(spacing: 20) {
                Button("❌ Deny") {
                    onResolve(.denied)
                }
                .keyboardShortcut(.cancelAction)

                if request.engineRequest != nil {
                    Button("🚂 Approve engine") {
                        onResolve(.approveEngine)
                    }
                    .keyboardShortcut(.return, modifiers: [.option])
                }
                
                Button("✅ Approve") {
                    onResolve(.approvedOnce)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(minWidth: 460, idealWidth: 520, maxWidth: 900)
        .fixedSize(horizontal: false, vertical: true)
    }
}
