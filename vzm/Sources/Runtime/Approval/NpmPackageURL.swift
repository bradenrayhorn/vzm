import Foundation

/// Validates only npm package metadata and tarball paths, not registry API endpoints.
enum NpmPackageURL {
    private static let nameRegex = try! NSRegularExpression(pattern: #"\A[A-Za-z0-9._-]{1,128}\z"#)
    private static let versionRegex = try! NSRegularExpression(pattern: #"\A[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\z"#)

    static func hostAndPath(_ url: String) -> (host: String, path: String)? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let slash = trimmed.firstIndex(of: "/") else { return nil }
        return (String(trimmed[..<slash]).lowercased(), String(trimmed[trimmed.index(after: slash)...]))
    }

    static func isPackagePath(_ path: String) -> Bool {
        let parts = path.components(separatedBy: "/-/")
        if parts.count == 1 {
            return packageName(path, allowEncodedScope: true) != nil
        }
        guard parts.count == 2,
              let name = packageName(parts[0], allowEncodedScope: false),
              parts[1].hasPrefix("\(name)-"), parts[1].hasSuffix(".tgz")
        else { return false }

        let version = String(parts[1].dropFirst(name.count + 1).dropLast(4))
        return matches(versionRegex, version)
    }

    private static func packageName(_ path: String, allowEncodedScope: Bool) -> String? {
        if path.hasPrefix("@") {
            let scopedPath = allowEncodedScope
                ? path.replacingOccurrences(of: "%2f", with: "/", options: .caseInsensitive)
                : path
            let parts = scopedPath.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2, isName(parts[0]), isName(parts[1]) else { return nil }
            return parts[1]
        }
        return isName(path) ? path : nil
    }

    static func isName(_ name: String) -> Bool {
        name != "." && name != ".." && matches(nameRegex, name)
    }

    private static func matches(_ regex: NSRegularExpression, _ value: String) -> Bool {
        regex.firstMatch(in: value, range: NSRange(value.startIndex..<value.endIndex, in: value)) != nil
    }
}
