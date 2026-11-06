import Foundation

/// Locations use the proxy's substitution inspection, not the UI's body display.
enum ProxySecretLocation: String, Codable, Sendable, CaseIterable {
    case authorizationHeader
    case header
    case urlPath
    case urlQuery
    case body
}

/// A secret can have multiple references with different locations in one request.
struct ProxyApprovalSecret: Codable, Sendable, Hashable {
    var name: String
    var location: ProxySecretLocation
}
