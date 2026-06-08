import SwiftUI
import ArgumentParser

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
                } catch {
                    print("Background task failed: \(error)")
                    exit(1)
                }
            }
        }
    }

    @State private var coordinator = ApprovalCoordinator.shared

    var body: some Scene {
        MenuBarExtra("vm") {
            VStack {
                Text("VM Running...")
                Divider()
            }
        }
    }
}

@Observable
@MainActor
class ApprovalCoordinator {
    static let shared = ApprovalCoordinator()
    
    var pendingRequest: ProxyApprovalRequest? = nil
    
    private var activeContinuation: CheckedContinuation<Bool, Never>?
    private var popupWindow: NSWindow?
    
    func askForApproval(request: ProxyApprovalRequest) async -> Bool {
        return await withCheckedContinuation { continuation in
            self.activeContinuation = continuation
            self.pendingRequest = request
            self.showPopupWindow()
        }
    }
    
    func resolve(approved: Bool) {
        activeContinuation?.resume(returning: approved)
        
        activeContinuation = nil
        pendingRequest = nil
        
        popupWindow?.close()
        popupWindow = nil
    }
    
    private func showPopupWindow() {
        guard let request = self.pendingRequest else { return }
        let promptView = ApprovalPromptView(request: request) { [weak self] approved in
            self?.resolve(approved: approved)
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
    let request: ProxyApprovalRequest
    let onResolve: (Bool) -> Void
    
    var body: some View {
        VStack(spacing: 16) {
            Text("Outbound")
                .font(.headline)
            
            VStack(spacing: 4) {
                Text(request.type)
                    .font(.body)

                Text(request.domain)
                    .font(.body.bold())

                Text("\(request.method) \(request.path)")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .lineLimit(3)
                    .textSelection(.enabled)

                if !request.secrets.isEmpty {
                    VStack(spacing: 4) {
                        Text("Secrets")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(request.secrets.joined(separator: ", "))
                            .font(.body)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 8)
                }
            }
            
            HStack(spacing: 20) {
                Button("❌ Deny") {
                    onResolve(false)
                }
                .keyboardShortcut(.cancelAction)
                
                Button("✅ Approve") {
                    onResolve(true)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(minWidth: 360, idealWidth: 480, maxWidth: 900)
        .fixedSize(horizontal: false, vertical: true)
    }
}
