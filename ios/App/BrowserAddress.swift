import Foundation

struct BrowserProxy {
    let host: String
    let port: UInt16
    let username: String
    let password: String

    init?(address: String, username: String, password: String) {
        guard let url = BrowserAddress.httpsURL(address),
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let host = parts.host, parts.path.isEmpty || parts.path == "/",
              parts.query == nil, parts.fragment == nil,
              username.isEmpty == password.isEmpty else { return nil }
        self.host = VPNProfile.unbracket(host)
        self.port = UInt16(parts.port ?? 443)
        self.username = username
        self.password = password
    }
}

enum BrowserAddress {
    static func ip(_ input: String) -> String? {
        let value = VPNProfile.unbracket(input.trimmingCharacters(in: .whitespacesAndNewlines))
        return VPNProfile.isIP(value) ? value : nil
    }

    static func httpsURL(_ input: String) -> URL? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains("\\"), !value.hasPrefix("/"),
              !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return nil }
        let text: String
        if value.contains("://") {
            text = value
        } else if let ip = ip(value), ip.contains(":") {
            text = "https://[\(ip)]"
        } else {
            text = "https://" + value
        }
        guard let parts = URLComponents(string: text), parts.scheme?.lowercased() == "https",
              parts.user == nil, parts.password == nil, let host = parts.host,
              VPNProfile.isHost(VPNProfile.unbracket(host)), (1...65535).contains(parts.port ?? 443),
              let url = parts.url else { return nil }
        return url
    }
}
