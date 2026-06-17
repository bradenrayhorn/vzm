import Foundation

enum ApprovalHeaderMasker {
    private static let safeExact: [String: Set<String>] = [
        "accept": ["*/*"],
        "connection": ["keep-alive", "close"],
        "proxy-connection": ["keep-alive"],
        "transfer-encoding": ["chunked"],
        "content-encoding": ["identity"],
        "te": ["trailers"],
        "upgrade-insecure-requests": ["1"],
        "sec-fetch-mode": ["cors"],
        "sec-fetch-dest": ["empty"],
        "sec-fetch-site": ["same-origin", "cross-site"],
    ]

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
            return !encodings.isEmpty && encodings.allSatisfy { safeEncodings.contains($0) }
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
