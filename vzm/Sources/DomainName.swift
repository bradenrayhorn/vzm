import Foundation

/// Textual domain normalization; does not parse URLs or canonicalize IP addresses.
enum DomainName {
    static func normalize(_ domain: String) -> String {
        var normalized = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // Preserve the order: a dot before a port is not stripped.
        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }
        if let colon = normalized.lastIndex(of: ":") {
            normalized = String(normalized[..<colon])
        }
        return normalized
    }
}
