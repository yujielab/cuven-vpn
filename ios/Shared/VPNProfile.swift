import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum TunnelConfiguration {
    static let providerBundleIdentifier = "dev.cuven.vpn.tunnel"
    static let profileKey = "Profile"
    static let credentialKey = "Credential"
    static let automaticFallbackKey = "AutomaticFallback"
    static let alternateProfileKey = "AlternateProfile"
    static let alternateCredentialKey = "AlternateCredential"
    static let mtu = 1280

    static var keychainAccessGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "CuvenKeychainAccessGroup") as? String ?? ""
    }
}

struct VPNProfile: Codable, Sendable, Equatable {
    let transport: VPNTransport
    let wireGuard: WireGuardProfile?
    let host: String
    let port: Int
    let serverName: String?
    let customDNSServers: [String]
    let useCustomDNS: Bool
    let autoConnect: AutoConnect
    let requirePostQuantum: Bool
    let blockLAN: Bool
    let preventBypass: Bool

    var dnsServers: [String] { useCustomDNS ? customDNSServers : Self.defaultDNSServers }

    static let defaultDNSServers = ["1.1.1.1", "2606:4700:4700::1111"]

    init(
        host: String,
        transport: VPNTransport = .hy2,
        wireGuard: WireGuardProfile? = nil,
        port: Int = 443,
        serverName: String? = nil,
        customDNSServers: [String] = Self.defaultDNSServers,
        useCustomDNS: Bool = false,
        autoConnect: AutoConnect = .off,
        requirePostQuantum: Bool = false,
        blockLAN: Bool = false,
        preventBypass: Bool = false
    ) throws {
        let host = Self.unbracket(host.trimmingCharacters(in: .whitespacesAndNewlines))
        let serverName = serverName?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isHost(host), (1...65535).contains(port) else {
            throw ProfileError.endpoint
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
        self.wireGuard = transport == .cuvenWG ? wireGuard : nil
        self.host = host
        self.port = port
        self.serverName = serverName.flatMap { $0.isEmpty ? nil : $0 }
        self.customDNSServers = useCustomDNS ? customDNSServers : Self.defaultDNSServers
        self.useCustomDNS = useCustomDNS
        self.autoConnect = autoConnect
        self.requirePostQuantum = transport == .hy2 && requirePostQuantum
        self.blockLAN = blockLAN
        self.preventBypass = preventBypass
    }

    var endpoint: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    static func decode(_ data: Data) throws -> Self {
        let profile = try JSONDecoder().decode(Self.self, from: data)
        return try Self(
            host: profile.host,
            transport: profile.transport,
            wireGuard: try profile.wireGuard?.validated(),
            port: profile.port,
            serverName: profile.serverName,
            customDNSServers: profile.customDNSServers,
            useCustomDNS: profile.useCustomDNS,
            autoConnect: profile.autoConnect,
            requirePostQuantum: profile.requirePostQuantum,
            blockLAN: profile.blockLAN,
            preventBypass: profile.preventBypass
        )
    }

    static func importURI(_ text: String) throws -> (profile: Self, credential: String) {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(),
              scheme == "hysteria2" || scheme == "hy2",
              let host = components.host,
              components.path.isEmpty || components.path == "/" else {
            throw ProfileError.uri
        }
        var serverName: String?
        var visited = Set<String>()
        for item in components.queryItems ?? [] {
            guard visited.insert(item.name).inserted else { throw ProfileError.uri }
            switch item.name {
            case "sni":
                guard let value = item.value, !value.isEmpty else { throw ProfileError.serverName }
                serverName = value
            case "insecure" where item.value == "0":
                break
            default:
                throw ProfileError.unsupportedURI
            }
        }
        guard let user = components.user else { throw ProfileError.credential }
        let credential = components.password.map { user + ":" + $0 } ?? user
        try validateCredential(credential)
        return (try Self(host: host, port: components.port ?? 443, serverName: serverName), credential)
    }

    static func validateCredential(_ credential: String) throws {
        let bytes = credential.utf8
        guard !bytes.isEmpty, bytes.count <= 1024,
              bytes.allSatisfy({ $0 >= 0x20 && $0 != 0x7f }),
              credential.first != " ", credential.last != " " else {
            throw ProfileError.credential
        }
    }

    private static func unbracket(_ host: String) -> String {
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

    private static func isHost(_ host: String) -> Bool {
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

enum VPNTransport: String, Codable, Sendable, CaseIterable, Identifiable {
    case hy2
    case cuvenWG

    var id: Self { self }

    var title: String {
        switch self {
        case .hy2: "Hysteria 2"
        case .cuvenWG: "Cuven WG"
        }
    }

    var defaultPort: Int {
        switch self {
        case .hy2: 443
        case .cuvenWG: 51821
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

struct WireGuardCredential: Codable, Sendable {
    let privateKey: String
    let relayKey: String
    let presharedKey: String?

    func encoded() throws -> String {
        guard WireGuardProfile.isKey(privateKey), WireGuardProfile.isKey(relayKey),
              presharedKey.map(WireGuardProfile.isKey) ?? true else {
            throw ProfileError.wireGuard
        }
        return String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }

    static func decode(_ string: String) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: Data(string.utf8))
        _ = try value.encoded()
        return value
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

    var errorDescription: String? {
        switch self {
        case .endpoint: "请输入有效的服务器地址和端口。"
        case .serverName: "请输入有效的 TLS 服务器名称。"
        case .dns: "请输入一到四个 DNS 服务器的 IPv4 或 IPv6 地址。"
        case .uri: "请输入有效的 hysteria2:// 或 hy2:// 链接。"
        case .unsupportedURI: "此链接含有首版未支持的参数。请使用标准 HY2 和受信任的 TLS 证书。"
        case .credential: "请输入有效的连接凭据。"
        case .wireGuard: "请检查 Cuven WG 密钥和隧道地址。密钥应为 Base64 编码的 32 字节，隧道地址需包含前缀长度。"
        }
    }
}
