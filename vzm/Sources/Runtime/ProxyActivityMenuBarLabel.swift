import AppKit
import SwiftUI

enum ProxyActivityLevel: String {
    case idle
    case active
    case medium
    case hyperactive

    init(rate: Double, mediumThreshold: Double, hyperactiveThreshold: Double) {
        if rate >= hyperactiveThreshold {
            self = .hyperactive
        } else if rate >= mediumThreshold {
            self = .medium
        } else if rate > 0 {
            self = .active
        } else {
            self = .idle
        }
    }

    var litSegments: Int {
        switch self {
        case .idle: return 0
        case .active: return 1
        case .medium: return 2
        case .hyperactive: return 3
        }
    }
}

/// Use an image because MenuBarExtra's native status button does not reliably
/// preserve arbitrary SwiftUI stacks. Non-template rendering preserves colors.
struct ProxyActivityMenuBarLabel: View {
    let vmName: String
    let snapshot: ProxyActivitySnapshot?
    @Environment(\.colorScheme) private var colorScheme

    // Thresholds apply to the same 10-second average as the numeric menu rates.
    static let mediumAttemptsPerSecond: Double = 1
    static let mediumMbps: Double = 10
    static let hyperactiveAttemptsPerSecond: Double = 10
    static let hyperactiveMbps: Double = 100

    private struct ImageKey: Hashable {
        let level: ProxyActivityLevel
        let darkAppearance: Bool
    }

    // Cache only the current VM's four levels in two appearances (at most
    // eight images). Main-actor confinement avoids adding cache locks.
    @MainActor private static var cachedVMName: String?
    @MainActor private static var cachedImages: [ImageKey: NSImage] = [:]

    var body: some View {
        Image(nsImage: Self.image(for: snapshot, vmName: vmName, darkAppearance: colorScheme == .dark))
            .renderingMode(.original)
            .accessibilityLabel(description)
            .help(description)
    }

    private var description: String {
        guard let snapshot else { return "\(vmName): proxy activity is not ready" }
        return "\(vmName): \(Self.level(for: snapshot).rawValue) proxy activity. "
            + "\(Self.number(snapshot.attemptsPerSecond)) approval attempts/sec, "
            + "download \(Self.number(snapshot.downloadMbps)) Mbps, "
            + "upload \(Self.number(snapshot.uploadMbps)) Mbps."
    }

    static func number(_ value: Double) -> String {
        value.formatted(.number.precision(.fractionLength(1)).grouping(.never))
    }

    /// OR across metrics: any metric reaching a threshold lights that level.
    static func level(for snapshot: ProxyActivitySnapshot?) -> ProxyActivityLevel {
        let snapshot = snapshot ?? ProxyActivitySnapshot()
        let levels = [
            ProxyActivityLevel(rate: snapshot.attemptsPerSecond,
                               mediumThreshold: mediumAttemptsPerSecond,
                               hyperactiveThreshold: hyperactiveAttemptsPerSecond),
            ProxyActivityLevel(rate: snapshot.downloadMbps,
                               mediumThreshold: mediumMbps,
                               hyperactiveThreshold: hyperactiveMbps),
            ProxyActivityLevel(rate: snapshot.uploadMbps,
                               mediumThreshold: mediumMbps,
                               hyperactiveThreshold: hyperactiveMbps),
        ]
        return levels.max(by: { $0.litSegments < $1.litSegments }) ?? .idle
    }

    @MainActor
    static func image(for snapshot: ProxyActivitySnapshot?, vmName: String, darkAppearance: Bool = false) -> NSImage {
        if cachedVMName != vmName {
            cachedImages.removeAll(keepingCapacity: true)
            cachedVMName = vmName
        }
        let key = ImageKey(level: level(for: snapshot), darkAppearance: darkAppearance)
        if let image = cachedImages[key] {
            return image
        }
        let image = renderImage(level: key.level, vmName: vmName, darkAppearance: darkAppearance)
        cachedImages[key] = image
        return image
    }

    private static func renderImage(level: ProxyActivityLevel, vmName: String, darkAppearance: Bool) -> NSImage {
        let foreground = NSColor(calibratedWhite: darkAppearance ? 1 : 0, alpha: 1)
        let muted = foreground.withAlphaComponent(0.25)
        let name = NSAttributedString(string: vmName, attributes: [
            .font: NSFont.systemFont(ofSize: 13),
            .foregroundColor: foreground,
        ])
        let nameSize = name.size()
        let barX = ceil(nameSize.width) + 6
        let image = NSImage(size: NSSize(width: barX + 8, height: 22), flipped: false) { _ in
            name.draw(at: NSPoint(x: 0, y: floor((22 - nameSize.height) / 2)))
            for segment in 0..<3 {
                let color: NSColor
                if segment < level.litSegments {
                    switch level {
                    case .idle: color = muted
                    case .active: color = .systemGray
                    case .medium: color = .systemGreen
                    case .hyperactive: color = .systemRed
                    }
                } else {
                    color = muted
                }
                color.setFill()
                let rect = NSRect(x: barX, y: CGFloat(2 + segment * 6), width: 6, height: 5)
                NSBezierPath(roundedRect: rect, xRadius: 1, yRadius: 1).fill()
            }
            return true
        }
        image.isTemplate = false
        return image
    }
}

struct ProxyActivityMenuView: View {
    let snapshot: ProxyActivitySnapshot?

    var body: some View {
        Section("Proxy activity") {
            if let snapshot {
                Text("Requests: \(ProxyActivityMenuBarLabel.number(snapshot.attemptsPerSecond)) activities/s")
                Text("Download: \(ProxyActivityMenuBarLabel.number(snapshot.downloadMbps)) Mbps")
                Text("Upload: \(ProxyActivityMenuBarLabel.number(snapshot.uploadMbps)) Mbps")
            } else {
                Text("VM proxy activity is not ready")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(minWidth: 280, alignment: .leading)
    }
}
