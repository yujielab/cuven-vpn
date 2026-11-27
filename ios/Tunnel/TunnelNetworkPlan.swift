import Foundation

struct TunnelNetworkPlan {
    struct Address {
        let host: String
        let prefix: Int

        var ipv4Mask: String {
            let mask = UInt32.max << (32 - prefix)
            return [24, 16, 8, 0].map { String(UInt8(truncatingIfNeeded: mask >> $0)) }.joined(separator: ".")
        }
    }

    static let placeholderIPv4 = Address(host: "198.18.0.1", prefix: 32)
    static let placeholderIPv6 = Address(host: "fd31:6375:7665::1", prefix: 128)

    let ipv4: Address?
    let ipv6: Address?
    let dnsServers: [String]
    let dnsOverHTTPSURL: URL?

    init(profile: VPNProfile) throws {
        if let wireGuard = profile.wireGuard {
            var ipv4: Address?
            var ipv6: Address?
            for cidr in wireGuard.tunnelAddresses {
                let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count == 2, let prefix = Int(parts[1]) else { throw ProfileError.wireGuard }
                let address = Address(host: String(parts[0]), prefix: prefix)
                if address.host.contains(":") {
                    ipv6 = address
                } else {
                    ipv4 = address
                }
            }
            self.ipv4 = ipv4
            self.ipv6 = ipv6
        } else {
            ipv4 = Self.placeholderIPv4
            ipv6 = Self.placeholderIPv6
        }
        let hasIPv4 = ipv4 != nil
        let hasIPv6 = ipv6 != nil
        let servers: [String]
        if profile.highSecurity {
            if let resolver = profile.encryptedDNS {
                dnsOverHTTPSURL = resolver.url
                servers = resolver.bootstrapServers
            } else {
                guard let url = URL(string: "https://cloudflare-dns.com/dns-query") else { throw ProfileError.dns }
                dnsOverHTTPSURL = url
                servers = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
            }
        } else {
            dnsOverHTTPSURL = nil
            servers = profile.dnsServers
        }
        dnsServers = servers.filter { server in
            server.contains(":") ? hasIPv6 : hasIPv4
        }
        guard !dnsServers.isEmpty else { throw ProfileError.dns }
    }
}
