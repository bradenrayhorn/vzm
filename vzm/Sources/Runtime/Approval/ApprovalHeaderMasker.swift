import Foundation

enum ApprovalHeaderMasker {
    private static let safeExact: [String: Set<String>] = [
        "accept-language": ["*"],
        "cache-control": ["no-cache", "max-age=0"],
        "pragma": ["no-cache"],
        "connection": ["keep-alive", "close"],
        "originator": ["pi"],
        "proxy-connection": ["keep-alive"],
        "transfer-encoding": ["chunked"],
        "content-encoding": ["identity"],
        "te": ["trailers"],
        "upgrade-insecure-requests": ["1"],
        "sec-fetch-mode": ["cors"],
        "sec-fetch-dest": ["empty"],
        "sec-fetch-site": ["same-origin", "cross-site"],
    ]

    private static let safeAccept: Set<String> = [
        "*/*",
        "text/html", "text/plain", "text/xml", "text/css", "text/javascript", "text/event-stream",
        "image/gif", "image/jpeg", "image/png", "image/webp", "image/avif", "image/svg+xml", "image/x-icon",
        "application/octet-stream", "application/xhtml+xml", "application/xml",
        "application/javascript", "application/wasm", "application/pdf", "application/zip", "application/gzip",
        "application/json", "application/problem+json", "application/vnd.api+json",
        "application/vnd.github+json", "application/vnd.npm.install-v1+json",
        "application/rss+xml", "application/atom+xml",
    ]
    private static let qualityRegex = try! NSRegularExpression(pattern: #"\A[0-9]{0,3}(?:\.[0-9]{0,3})?\z"#)
    private static let safeEncodings: Set<String> = ["zstd", "br", "gzip", "deflate", "bzip2", "xz"]

    static func maskSafeHeaders(for request: ProxyApprovalRequest, knownUserAgents: [String]) -> [ProxyApprovalHeader] {
        request.headers.filter { 
            let name = $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if name == "user-agent" {
                return !knownUserAgents.contains($0.value)
            }
            
            return !isSafe($0, in: request)
        }
    }

    static func getUserAgents(for request: ProxyApprovalRequest) -> [String] {
        request.headers.filter {
            $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "user-agent"
        }.map { $0.value }
    }

    private static func isSafeAcceptItem(_ item: String) -> Bool {
        isSafeWeightedItem(item, allowed: safeAccept)
    }

    private static func isSafeWeightedItem(_ item: String, allowed: Set<String>) -> Bool {
        let parts = item.split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        guard let token = parts.first, allowed.contains(token), parts.count <= 2 else { return false }
        if parts.count == 1 { return true }

        let parameter = parts[1].split(separator: "=", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard parameter.count == 2, parameter[0] == "q" else { return false }

        let quality = parameter[1]
        return qualityRegex.firstMatch(in: quality, range: NSRange(quality.startIndex..<quality.endIndex, in: quality)) != nil
    }

    static func isSafe(_ header: ProxyApprovalHeader, in request: ProxyApprovalRequest) -> Bool {
        let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let value = header.value.trimmingCharacters(in: .whitespacesAndNewlines)
        let lowerValue = value.lowercased()

        switch name {
        case "host", ":authority":
            return !request.domain.isEmpty && value == request.domain.trimmingCharacters(in: .whitespacesAndNewlines)
        case "accept-encoding":
            let encodings = value.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            return !encodings.isEmpty && encodings.allSatisfy { isSafeWeightedItem($0, allowed: safeEncodings) }
        case "accept":
            let accepts = value.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            return !accepts.isEmpty && accepts.allSatisfy(isSafeAcceptItem)
        case "content-length":
            return value == "0"
        case ":method":
            return value == request.method.trimmingCharacters(in: .whitespacesAndNewlines)
        case ":scheme":
            return URLComponents(string: request.url.trimmingCharacters(in: .whitespacesAndNewlines))?.scheme?.lowercased() == lowerValue
        case ":path":
            let url = request.url.trimmingCharacters(in: .whitespacesAndNewlines)
            if let components = URLComponents(string: url), components.scheme != nil {
                var path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
                if let query = components.percentEncodedQuery { path += "?\(query)" }
                return value == path
            }
            return url.firstIndex(of: "/").map { value == String(url[$0...]) } ?? false
        default:
            return safeExact[name]?.contains(lowerValue) ?? false
        }
    }
}
