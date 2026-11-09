import AppKit
import Observation
import SwiftUI

@Observable
@MainActor
final class EngineActivityOverlayCoordinator {
    static let shared = EngineActivityOverlayCoordinator()

    private(set) var snapshot = EngineActivitySnapshot()
    private(set) var isEnabled: Bool
    private var runtimeActive = false
    private let defaults: UserDefaults
    private static let enabledKey = "autoOverlayEnabled"
    private var refreshTask: Task<Void, Never>?
    private var panel: NSPanel?
    private var screenObserver: NSObjectProtocol?
    private let store: EngineActivityStore

    init(defaults: UserDefaults = .standard, store: EngineActivityStore = .shared) {
        self.defaults = defaults
        self.store = store
        self.isEnabled = defaults.object(forKey: Self.enabledKey) == nil
            ? true : defaults.bool(forKey: Self.enabledKey)
    }

    func setEnabled(_ enabled: Bool) {
        guard enabled != isEnabled else { return }
        isEnabled = enabled
        defaults.set(enabled, forKey: Self.enabledKey)
        if enabled && runtimeActive {
            showOverlay()
        } else {
            hideOverlay()
        }
    }

    private static let emojiSize: CGFloat = 18
    private static let panelSize = NSSize(
        width: CGFloat(EngineActivityGroup.allCases.count) * (emojiSize + 10) + 16,
        height: emojiSize + 24
    )

    func attach() {
        detach()
        runtimeActive = true
        if isEnabled { showOverlay() }
    }

    func detach() {
        runtimeActive = false
        hideOverlay()
    }

    private func showOverlay() {
        guard panel == nil else { return }
        store.start()
        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: Self.panelSize),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = false
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.ignoresMouseEvents = true
        panel.contentView = NSHostingView(rootView: EngineActivityStrip(coordinator: self))
        self.panel = panel
        positionPanel()
        panel.orderFrontRegardless()

        screenObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.positionPanel() }
        }
        refreshTask = Task { [weak self, store] in
            while !Task.isCancelled {
                let latest = store.snapshot()
                if self?.snapshot != latest {
                    self?.snapshot = latest
                }
                do {
                    try await Task.sleep(for: .milliseconds(100))
                } catch {
                    return
                }
            }
        }
    }

    private func hideOverlay() {
        refreshTask?.cancel()
        refreshTask = nil
        if let screenObserver {
            NotificationCenter.default.removeObserver(screenObserver)
        }
        screenObserver = nil
        panel?.close()
        panel = nil
        store.stop()
        snapshot = EngineActivitySnapshot()
    }

    private func positionPanel() {
        // Use the primary display consistently, not whichever window happens to be key.
        guard let screen = NSScreen.screens.first else { return }
        let visible = screen.visibleFrame
        panel?.setFrameOrigin(NSPoint(
            x: visible.maxX - Self.panelSize.width - 12,
            y: visible.maxY - Self.panelSize.height * 1.5 - 12
        ))
    }
}

private struct EngineActivityStrip: View {
    let coordinator: EngineActivityOverlayCoordinator

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30)) { _ in
            let time = ProcessInfo.processInfo.systemUptime
            HStack(spacing: 0) {
                ForEach(EngineActivityGroup.allCases) { group in
                    let intensity = coordinator.snapshot.intensity(for: group, at: time)
                    Text(group.emoji)
                        .font(.system(size: 18))
                        .opacity(coordinator.snapshot.opacity(for: group, at: time))
                        .shadow(color: .white.opacity(intensity * 0.8), radius: 4 * intensity)
                        .frame(width: 28, height: 42)
                        .accessibilityLabel("\(group.title) automatic approvals")
                }
            }
            .padding(.horizontal, 8)
        }
    }
}
