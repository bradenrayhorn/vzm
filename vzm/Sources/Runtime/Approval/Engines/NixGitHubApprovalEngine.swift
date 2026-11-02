import Foundation

final class NixGitHubApprovalEngine: PatternApprovalEngine {
    override var name: String { "NixGitHub" }

    private static let urlRegexes: [NSRegularExpression] = [
        try! NSRegularExpression(pattern: #"^github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/archive/[0-9a-f]{40}\.tar\.gz$"#),
        try! NSRegularExpression(pattern: #"^codeload\.github\.com/[A-Za-z0-9-]{1,40}/[A-Za-z0-9-]{1,40}/tar\.gz/[0-9a-f]{40}$"#),
        try! NSRegularExpression(pattern: #"^api\.github\.com/repos/NixOS/nixpkgs/commits/nixos-(?:[0-9]{1,2}\.[0-9]{1,2}|unstable)$"#),
    ]

    override func matches(_ request: ProxyApprovalRequest) -> Bool {
        request.type == "REQUEST"
            && request.secrets.isEmpty
            && request.body == nil
            && request.method == "GET"
            && urlMatches(regexes: Self.urlRegexes, request.url)
    }
}
