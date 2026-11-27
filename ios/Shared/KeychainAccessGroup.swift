import Foundation

enum KeychainAccessGroup {
    private static let prefixPlaceholder = "$(AppIdentifierPrefix)"

    static func isApplicationGroup(_ group: String?, bundleID: String?) -> Bool {
        guard let group, let bundleID, !bundleID.isEmpty, !bundleID.contains("*"),
              let separator = group.firstIndex(of: "."), separator != group.startIndex else { return false }
        return group[group.index(after: separator)...] == bundleID
    }

    static func resolve(_ configured: String, defaultGroup: String? = nil) -> String? {
        let configuredPrefix = prefix(in: configured)
        let suffix: Substring
        if let configuredPrefix {
            suffix = configured.dropFirst(configuredPrefix.count + 1)
        } else if configured.hasPrefix(prefixPlaceholder) {
            suffix = configured.dropFirst(prefixPlaceholder.count)
        } else {
            suffix = configured[...]
        }
        guard !suffix.isEmpty, !suffix.contains("$(") else { return nil }
        let signingPrefix = if let defaultGroup { prefix(in: defaultGroup) } else { configuredPrefix }
        guard let signingPrefix else { return nil }
        return "\(signingPrefix).\(suffix)"
    }

    private static func prefix(in group: String) -> Substring? {
        guard let separator = group.firstIndex(of: ".") else { return nil }
        let prefix = group[..<separator]
        guard prefix.utf8.count == 10, prefix.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0)
        }) else { return nil }
        return prefix
    }
}
