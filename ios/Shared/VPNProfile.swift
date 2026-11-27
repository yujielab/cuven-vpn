import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum TunnelConfiguration {
    static let profileKey = "Profile"
    static let credentialKey = "Credential"
    static let automaticFallbackKey = "AutomaticFallback"
    static let alternateProfileKey = "AlternateProfile"
    static let alternateCredentialKey = "AlternateCredential"
    static let legacyMTU = 1280
    static let maximumMTU = 1500
    static let rttRequest = Data("cuven.rtt-ms".utf8)

    static var keychainAccessGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "CuvenKeychainAccessGroup") as? String ?? ""
    }
}

struct VPNProfile: Codable, Sendable, Equatable {
    let transport: VPNTransport
    let cuvenIPv6: Bool
    let wireGuard: WireGuardProfile?
    let wireGuardDirect: Bool
    let host: String
    let port: Int
    let serverName: String?
    let customDNSServers: [String]
    let useCustomDNS: Bool
    let autoConnect: AutoConnect
    let requirePostQuantum: Bool
    let blockLAN: Bool
    let preventBypass: Bool
    let highSecurity: Bool
    let https3Camouflage: Bool
    let encryptedDNS: EncryptedDNSProfile?
    let hy2Insecure: Bool
    let hy2Salamander: Bool

    var dnsServers: [String] { useCustomDNS ? customDNSServers : Self.defaultDNSServers }
    var requiresEncryptedDNS: Bool { transport == .cuven || highSecurity || encryptedDNS != nil }
    var usesFullRouting: Bool { requiresEncryptedDNS || preventBypass }

    func permitsAutomaticFallback(to alternate: Self) -> Bool {
        transport != alternate.transport && !highSecurity && !requirePostQuantum &&
            !alternate.highSecurity && !alternate.hy2Insecure &&
            encryptedDNS == alternate.encryptedDNS
    }

    static let defaultDNSServers = ["1.1.1.1", "2606:4700:4700::1111"]

    init(
        host: String,
        transport: VPNTransport = .hy2,
        cuvenIPv6: Bool = false,
        wireGuard: WireGuardProfile? = nil,
        wireGuardDirect: Bool = false,
        port: Int = 443,
        serverName: String? = nil,
        customDNSServers: [String] = Self.defaultDNSServers,
        useCustomDNS: Bool = false,
        autoConnect: AutoConnect = .off,
        requirePostQuantum: Bool = false,
        blockLAN: Bool = false,
        preventBypass: Bool = false,
        highSecurity: Bool = false,
        https3Camouflage: Bool = false,
        encryptedDNS: EncryptedDNSProfile? = nil,
        hy2Insecure: Bool = false,
        hy2Salamander: Bool = false
    ) throws {
        let host = Self.unbracket(host.trimmingCharacters(in: .whitespacesAndNewlines))
        let serverName = serverName?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isHost(host), (1...65535).contains(port) else {
            throw ProfileError.endpoint
        }
        if highSecurity && !Self.isIP(host) { throw ProfileError.numericSecurityEndpoint }
        if transport == .hy2 && hy2Insecure && (highSecurity || requirePostQuantum) {
            throw ProfileError.insecureSecurityMode
        }
        if let serverName, !serverName.isEmpty, !Self.isHost(serverName) {
            throw ProfileError.serverName
        }
        guard !useCustomDNS || (
            !customDNSServers.isEmpty && customDNSServers.count <= 4 && customDNSServers.allSatisfy(Self.isIP)
        ) else {
            throw ProfileError.dns
        }
        if transport == .cuvenWG && wireGuard == nil { throw ProfileError.wireGuard }
        self.transport = transport
        self.cuvenIPv6 = transport == .cuven && cuvenIPv6
        self.wireGuard = transport == .cuvenWG ? wireGuard : nil
        self.wireGuardDirect = transport == .cuvenWG && wireGuardDirect
        self.host = host
        self.port = port
        self.serverName = serverName.flatMap { $0.isEmpty ? nil : $0 }
        self.customDNSServers = useCustomDNS ? customDNSServers : Self.defaultDNSServers
        self.useCustomDNS = useCustomDNS
        self.autoConnect = autoConnect
        self.requirePostQuantum = transport == .hy2 && requirePostQuantum
        self.blockLAN = blockLAN
        self.preventBypass = preventBypass
        self.highSecurity = highSecurity
        self.https3Camouflage = highSecurity && transport == .cuvenWG && !wireGuardDirect && https3Camouflage
        self.encryptedDNS = try encryptedDNS?.validated()
        self.hy2Insecure = transport == .hy2 && hy2Insecure
        self.hy2Salamander = transport == .hy2 && hy2Salamander
    }

    var endpoint: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    private enum CodingKeys: String, CodingKey {
        case transport, cuvenIPv6, wireGuard, wireGuardDirect, host, port, serverName, customDNSServers, useCustomDNS, autoConnect
        case requirePostQuantum, blockLAN, preventBypass, highSecurity, https3Camouflage, encryptedDNS
        case hy2Insecure, hy2Salamander
    }

    init(from decoder: any Decoder) throws {
        let saved = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            host: saved.decode(String.self, forKey: .host),
            transport: saved.decode(VPNTransport.self, forKey: .transport),
            cuvenIPv6: saved.decodeIfPresent(Bool.self, forKey: .cuvenIPv6) ?? false,
            wireGuard: saved.decodeIfPresent(WireGuardProfile.self, forKey: .wireGuard)?.validated(),
            wireGuardDirect: saved.decodeIfPresent(Bool.self, forKey: .wireGuardDirect) ?? false,
            port: saved.decode(Int.self, forKey: .port),
            serverName: saved.decodeIfPresent(String.self, forKey: .serverName),
            customDNSServers: saved.decode([String].self, forKey: .customDNSServers),
            useCustomDNS: saved.decode(Bool.self, forKey: .useCustomDNS),
            autoConnect: saved.decode(AutoConnect.self, forKey: .autoConnect),
            requirePostQuantum: saved.decode(Bool.self, forKey: .requirePostQuantum),
            blockLAN: saved.decode(Bool.self, forKey: .blockLAN),
            preventBypass: saved.decode(Bool.self, forKey: .preventBypass),
            highSecurity: saved.decodeIfPresent(Bool.self, forKey: .highSecurity) ?? false,
            https3Camouflage: saved.decodeIfPresent(Bool.self, forKey: .https3Camouflage) ?? false,
            encryptedDNS: saved.decodeIfPresent(EncryptedDNSProfile.self, forKey: .encryptedDNS),
            hy2Insecure: saved.decodeIfPresent(Bool.self, forKey: .hy2Insecure) ?? false,
            hy2Salamander: saved.decodeIfPresent(Bool.self, forKey: .hy2Salamander) ?? false
        )
    }

    static func decode(_ data: Data) throws -> Self {
        try JSONDecoder().decode(Self.self, from: data)
    }

    static func importURI(_ text: String) throws -> (profile: Self, credential: HY2Credential) {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(),
              scheme == "hysteria2" || scheme == "hy2",
              let host = components.host,
              components.path.isEmpty || components.path == "/" else {
            throw ProfileError.uri
        }
        var serverName: String?
        var peer: String?
        var insecure = false
        var salamander = false
        var obfuscationPassword: String?
        var visited = Set<String>()
        for item in components.queryItems ?? [] {
            guard visited.insert(item.name).inserted else { throw ProfileError.uri }
            switch item.name {
            case "sni", "peer":
                guard let value = item.value, !value.isEmpty else { throw ProfileError.serverName }
                if item.name == "sni" { serverName = value } else { peer = value }
            case "insecure" where item.value == "0" || item.value == "1":
                insecure = item.value == "1"
            case "obfs" where item.value == "salamander":
                salamander = true
            case "obfs-password":
                guard let value = item.value, !value.isEmpty else { throw ProfileError.obfuscationPassword }
                obfuscationPassword = value
            default:
                throw ProfileError.unsupportedURI
            }
        }
        guard let user = components.user else { throw ProfileError.credential }
        let credential = HY2Credential(
            auth: components.password.map { user + ":" + $0 } ?? user,
            obfuscationPassword: obfuscationPassword
        )
        _ = try credential.validated(salamander: salamander)
        return (try Self(
            host: host, port: components.port ?? 443, serverName: serverName ?? peer,
            hy2Insecure: insecure, hy2Salamander: salamander
        ), credential)
    }

    static func validateCredential(_ credential: String, maximumBytes: Int = 1024) throws {
        let bytes = credential.utf8
        guard !bytes.isEmpty, bytes.count <= maximumBytes,
              bytes.allSatisfy({ $0 >= 0x20 && $0 != 0x7f }),
              credential.first != " ", credential.last != " " else {
            throw ProfileError.credential
        }
    }

    static func validateAccessToken(_ credential: String) throws {
        guard credential.utf8.count == 43 else { throw ProfileError.credential }
        let base64 = credential.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "="
        guard let bytes = Data(base64Encoded: base64), bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            throw ProfileError.credential
        }
        let canonical = String(bytes.base64EncodedString().dropLast())
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        guard canonical == credential else { throw ProfileError.credential }
    }

    static func unbracket(_ host: String) -> String {
        guard host.hasPrefix("["), host.hasSuffix("]") else { return host }
        return String(host.dropFirst().dropLast())
    }

    static func isIP(_ host: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return host.withCString {
            inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1
        } && !host.utf8.contains(0)
    }

    static func isHost(_ host: String) -> Bool {
        if isIP(host) { return true }
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard (1...253).contains(name.utf8.count) else { return false }
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
                label.utf8.allSatisfy {
                    (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
                }
        }
    }
}

struct HY2Credential: Codable, Sendable {
    let auth: String
    let obfuscationPassword: String?

    func validated(salamander: Bool) throws -> Self {
        try VPNProfile.validateCredential(auth)
        if salamander {
            guard let obfuscationPassword, (4...1024).contains(obfuscationPassword.utf8.count),
                  obfuscationPassword.utf8.allSatisfy({ $0 >= 0x20 && $0 != 0x7f }) else {
                throw ProfileError.obfuscationPassword
            }
        } else if obfuscationPassword != nil {
            throw ProfileError.obfuscationPassword
        }
        return self
    }

    func encoded(salamander: Bool) throws -> String {
        _ = try validated(salamander: salamander)
        if !salamander { return auth }
        return String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }

    static func decode(_ value: String, salamander: Bool) throws -> Self {
        if !salamander {
            return try Self(auth: value, obfuscationPassword: nil).validated(salamander: false)
        }
        return try JSONDecoder().decode(Self.self, from: Data(value.utf8)).validated(salamander: true)
    }
}

enum VPNTransport: String, Codable, Sendable, CaseIterable, Identifiable {
    case cuven
    case hy2
    case cuvenWG

    var id: Self { self }

    var title: String {
        switch self {
        case .cuven: "Cuven IP"
        case .hy2: "Hysteria 2"
        case .cuvenWG: "WireGuard"
        }
    }

    var defaultPort: Int {
        switch self {
        case .cuven: 4433
        case .hy2: 443
        case .cuvenWG: 51820
        }
    }
}

struct WireGuardProfile: Codable, Sendable, Equatable {
    let tunnelAddresses: [String]
    let peerPublicKey: String

    func validated() throws -> Self {
        guard (1...2).contains(tunnelAddresses.count), Self.isKey(peerPublicKey) else {
            throw ProfileError.wireGuard
        }
        var families = Set<Bool>()
        for address in tunnelAddresses {
            let parts = address.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, let prefix = Int(parts[1]), VPNProfile.isIP(String(parts[0])) else {
                throw ProfileError.wireGuard
            }
            let ipv6 = parts[0].contains(":")
            guard (1...(ipv6 ? 128 : 32)).contains(prefix), families.insert(ipv6).inserted else {
                throw ProfileError.wireGuard
            }
        }
        return self
    }

    static func isKey(_ key: String) -> Bool {
        guard let bytes = Data(base64Encoded: key), bytes.count == 32 else { return false }
        return bytes.contains { $0 != 0 }
    }
}

struct EncryptedDNSProfile: Codable, Sendable, Equatable {
    let url: URL?
    let tlsServerName: String?
    let bootstrapServers: [String]

    init(url: URL? = nil, tlsServerName: String? = nil, bootstrapServers: [String]) {
        self.url = url
        self.tlsServerName = tlsServerName
        self.bootstrapServers = bootstrapServers
    }

    func validated() throws -> Self {
        guard (1...4).contains(bootstrapServers.count),
              bootstrapServers.allSatisfy(VPNProfile.isIP) else {
            throw ProfileError.encryptedDNS
        }
        switch (url, tlsServerName) {
        case (let url?, nil):
            guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  parts.scheme?.lowercased() == "https", let host = parts.host,
                  VPNProfile.isHost(VPNProfile.unbracket(host)),
                  parts.port.map({ (1...65535).contains($0) }) ?? true,
                  parts.user == nil, parts.password == nil, parts.fragment == nil else {
                throw ProfileError.encryptedDNS
            }
        case (nil, let name?):
            guard VPNProfile.isHost(name), !VPNProfile.isIP(name) else { throw ProfileError.encryptedDNS }
        default:
            throw ProfileError.encryptedDNS
        }
        return self
    }
}

struct WireGuardCredential: Codable, Sendable {
    let privateKey: String
    let relayKey: String?
    let presharedKey: String?

    func encoded(requiresRelay: Bool = true) throws -> String {
        _ = try validated(requiresRelay: requiresRelay)
        return String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }

    private func validated(requiresRelay: Bool) throws -> Self {
        guard WireGuardProfile.isKey(privateKey), relayKey.map(WireGuardProfile.isKey) ?? !requiresRelay,
              presharedKey.map(WireGuardProfile.isKey) ?? true else {
            throw ProfileError.wireGuard
        }
        return self
    }

    static func decode(_ string: String, requiresRelay: Bool = true) throws -> Self {
        try JSONDecoder().decode(Self.self, from: Data(string.utf8)).validated(requiresRelay: requiresRelay)
    }
}

enum AutoConnect: String, Codable, Sendable, CaseIterable, Identifiable {
    case off
    case all
    case wifi
    case cellular

    var id: Self { self }

    var title: String {
        switch self {
        case .off: "关闭"
        case .all: "所有网络"
        case .wifi: "仅 Wi-Fi"
        case .cellular: "仅蜂窝网络"
        }
    }
}

enum ProfileError: LocalizedError {
    case endpoint
    case serverName
    case dns
    case uri
    case unsupportedURI
    case credential
    case wireGuard
    case numericSecurityEndpoint
    case encryptedDNS
    case insecureSecurityMode
    case obfuscationPassword

    var errorDescription: String? {
        switch self {
        case .endpoint: "请输入有效的服务器地址和端口。"
        case .serverName: "请输入有效的 TLS 服务器名称。"
        case .dns: "请输入一到四个 DNS 服务器的 IPv4 或 IPv6 地址。"
        case .uri: "请输入有效的 hysteria2:// 或 hy2:// 链接。"
        case .unsupportedURI: "此 HY2 链接包含不支持的参数或参数值。"
        case .credential: "请输入有效的连接凭据。"
        case .numericSecurityEndpoint: "请在「服务器地址」填写网关的 IPv4 或 IPv6 地址。高安全模式下，网关证书的域名可填在「TLS 证书域名」。"
        case .encryptedDNS: "请填写 DoH 的完整 HTTPS URL 或 DoT 的证书域名，以及一到四个解析器 IP。"
        case .wireGuard: "请检查 WireGuard 密钥和隧道地址。密钥应为 Base64 编码的 32 字节，隧道地址需包含前缀长度。"
        case .insecureSecurityMode: "高安全模式和严格后量子模式需要验证服务器证书。"
        case .obfuscationPassword: "Salamander 需要 4 至 1024 字节的混淆密码。"
        }
    }
}
