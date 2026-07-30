import AppKit
import SwiftUI

struct GuestNotification: Identifiable {
    let id = UUID()
    let from: String
    let message: String
}

enum NotificationQueueError: LocalizedError {
    case full

    var errorDescription: String? {
        "Notification queue is full"
    }
}

@Observable
@MainActor
final class NotificationCoordinator {
    static let shared = NotificationCoordinator()

    private(set) var notifications: [GuestNotification] = []

    private let maximumPendingNotifications = 64
    private let notificationSound = NSSound(named: NSSound.Name("Submerge"))
    private var panel: NSPanel?
    private var screenParametersObserver: NSObjectProtocol?

    func start() {
        guard screenParametersObserver == nil else { return }

        screenParametersObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.positionPanel() }
        }
    }

    func stop() {
        guard let screenParametersObserver else { return }
        NotificationCenter.default.removeObserver(screenParametersObserver)
        self.screenParametersObserver = nil

        panel?.orderOut(nil)
        panel?.close()
        panel = nil
        notifications.removeAll()
    }

    @discardableResult
    func enqueue(from: String, message: String) throws -> Int {
        guard notifications.count < maximumPendingNotifications else {
            throw NotificationQueueError.full
        }

        notifications.append(GuestNotification(from: from, message: message))
        notificationSound?.play()
        showPanel()
        return notifications.count
    }

    /// Removes the oldest pending notification, regardless of how acknowledgement was requested.
    @discardableResult
    func acknowledgeOldest() -> Int {
        guard !notifications.isEmpty else { return 0 }
        notifications.removeFirst()

        if notifications.isEmpty {
            panel?.orderOut(nil)
        } else {
            positionPanel()
        }
        return notifications.count
    }

    private func showPanel() {
        if panel == nil {
            let content = NotificationStackView(coordinator: self)
            let hostingController = NSHostingController(rootView: content)
            let panel = NonActivatingNotificationPanel(
                contentRect: NSRect(x: 0, y: 0, width: 390, height: 230),
                styleMask: [.borderless, .nonactivatingPanel],
                backing: .buffered,
                defer: false
            )
            panel.contentViewController = hostingController
            panel.level = .floating
            panel.isFloatingPanel = true
            panel.hidesOnDeactivate = false
            panel.isOpaque = false
            panel.backgroundColor = .clear
            panel.hasShadow = false
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            panel.isReleasedWhenClosed = false
            self.panel = panel
        }

        positionPanel()
        panel?.orderFrontRegardless()
    }

    private func positionPanel() {
        guard let panel else { return }
        let mouseLocation = NSEvent.mouseLocation
        let screen = NSScreen.screens.first(where: { NSMouseInRect(mouseLocation, $0.frame, false) })
            ?? NSScreen.main
            ?? NSScreen.screens.first
        guard let screen else { return }

        let margin: CGFloat = 20
        let frame = screen.visibleFrame
        panel.setFrameOrigin(NSPoint(
            x: frame.maxX - panel.frame.width - margin,
            y: frame.minY + margin
        ))
    }
}

private final class NonActivatingNotificationPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

private struct NotificationStackView: View {
    @Bindable var coordinator: NotificationCoordinator

    private var visibleNotifications: ArraySlice<GuestNotification> {
        coordinator.notifications.prefix(4)
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            ForEach(Array(visibleNotifications.enumerated()).reversed(), id: \.element.id) { index, notification in
                NotificationCard(
                    notification: notification,
                    pendingCount: index == 0 ? coordinator.notifications.count : nil,
                    onAcknowledge: {
                        _ = coordinator.acknowledgeOldest()
                    }
                )
                .offset(x: -CGFloat(index) * 7, y: -CGFloat(index) * 11)
                .zIndex(Double(10 - index))
                .allowsHitTesting(index == 0)
            }
        }
        .padding(.top, 40)
        .padding(.leading, 28)
        .padding(8)
        .frame(width: 390, height: 230, alignment: .bottomTrailing)
    }
}

private struct NotificationCard: View {
    let notification: GuestNotification
    let pendingCount: Int?
    let onAcknowledge: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(notification.from)
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                if let pendingCount, pendingCount > 1 {
                    Text("\(pendingCount) pending")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Text(notification.message)
                .font(.body)
                .lineLimit(5)
                .frame(maxWidth: .infinity, alignment: .leading)

            Button("Acknowledge", action: onAcknowledge)
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(16)
        .frame(width: 350)
        .frame(minHeight: 150, maxHeight: 190, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(.white.opacity(0.16), lineWidth: 1)
        }
        .shadow(color: .black.opacity(0.25), radius: 12, y: 5)
    }
}
