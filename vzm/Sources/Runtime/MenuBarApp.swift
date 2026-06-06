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
        
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 150),
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
        .frame(minWidth: 300)
    }
}
