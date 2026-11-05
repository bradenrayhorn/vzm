import Foundation

/// Validates artifact paths only; repository URLs and consent scopes stay engine-specific.
enum MavenArtifactPath {
    private static let pathRegex = try! NSRegularExpression(
        pattern: #"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$"#
    )

    static func matches(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4 else {
            return false
        }

        let version = parts[parts.count - 2]
        let filename = parts[parts.count - 1]
        let artifact = parts[parts.count - 3]
        let groupParts = Array(parts.dropLast(3))

        guard !version.isEmpty, !artifact.isEmpty, !filename.isEmpty, !groupParts.contains(where: \.isEmpty),
              isValidPath(path)
        else {
            return false
        }

        return matchesArtifactFilename(filename, artifact: artifact, version: version)
    }

    static func isValidPath(_ path: String) -> Bool {
        guard !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            return false
        }
        let range = NSRange(path.startIndex..<path.endIndex, in: path)
        return pathRegex.firstMatch(in: path, range: range) != nil
    }

    static func matchesArtifactFilename(_ filename: String, artifact: String, version: String) -> Bool {
        // Strip at most one checksum suffix, and still require a supported artifact.
        var filename = filename
        if let checksum = ["sha1", "md5", "sha256", "sha512"].first(where: { filename.hasSuffix(".\($0)") }) {
            filename = String(filename.dropLast(checksum.count + 1))
        }
        guard let dot = filename.lastIndex(of: ".") else {
            return false
        }

        let base = String(filename[..<dot])
        let ext = String(filename[filename.index(after: dot)...])
        guard ["pom", "module", "jar"].contains(ext) else {
            return false
        }
        return base == "\(artifact)-\(version)" || base.hasPrefix("\(artifact)-\(version)-")
    }
}
