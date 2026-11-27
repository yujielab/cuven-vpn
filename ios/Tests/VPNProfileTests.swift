import Foundation
import XCTest
@testable import Cuven

final class VPNProfileTests: XCTestCase {
    func testKeychainGroupUsesCurrentSigningPrefixForRepackagedIPA() {
        let group = "dev.cuven.vpn.shared"
        let defaultGroup = "ABCDE12345.dev.cuven.vpn"
        XCTAssertNil(KeychainAccessGroup.resolve(group))
        XCTAssertEqual(KeychainAccessGroup.resolve(group, defaultGroup: defaultGroup), "ABCDE12345." + group)
        XCTAssertEqual(
            KeychainAccessGroup.resolve("$(AppIdentifierPrefix)" + group, defaultGroup: defaultGroup),
            "ABCDE12345." + group
        )
        XCTAssertEqual(KeychainAccessGroup.resolve("ABCDE12345." + group), "ABCDE12345." + group)
        XCTAssertEqual(
            KeychainAccessGroup.resolve("ZYXWV98765." + group, defaultGroup: defaultGroup), "ABCDE12345." + group
        )
        XCTAssertNil(KeychainAccessGroup.resolve(group, defaultGroup: "dev.cuven.vpn"))
    }

    func testCuvenProfileAndToken() throws {
        let token = String(Data(repeating: 255, count: 32).base64EncodedString().dropLast())
            .replacingOccurrences(of: "/", with: "_")
        XCTAssertNoThrow(try VPNProfile.validateAccessToken(token))
        XCTAssertThrowsError(try VPNProfile.validateAccessToken(token.replacingOccurrences(of: "_", with: "/")))
        XCTAssertThrowsError(try VPNProfile.validateAccessToken(String(repeating: "A", count: 43)))
        let profile = try VPNProfile(
            host: "203.0.113.7", transport: .cuven, cuvenIPv6: true,
            port: 4433, serverName: "vpn.example", preventBypass: true
        )
        let plan = try TunnelNetworkPlan(profile: VPNProfile.decode(JSONEncoder().encode(profile)))
        XCTAssertEqual(plan.ipv4?.host, "10.66.0.2")
        XCTAssertEqual(plan.ipv6?.host, "fd66::2")
    }

    func testIPv4OnlyCuvenDropsCapturedIPv6BeforeForwarding() throws {
        let ipv4 = Data([0x45] + Array(repeating: 0, count: 19))
        let ipv6 = Data([0x60] + Array(repeating: 0, count: 39))
        let packets = [ipv4, ipv6]
        let plan = try TunnelNetworkPlan(profile: VPNProfile(host: "vpn.example", transport: .cuven))
        let batch = PacketBatch.encode(
            packets[...], mtu: TunnelConfiguration.mtu,
            allowIPv4: plan.ipv4 != nil, allowIPv6: plan.ipv6 != nil
        )
        XCTAssertEqual(PacketBatch.decode(batch, mtu: TunnelConfiguration.mtu)?.packets, [ipv4])
        guard case .https = plan.dnsMode else { return XCTFail("Cuven must use encrypted DNS by default") }
    }

    func testHY2ImportPreservesPercentEncodedCredentialsAndIPv6() throws {
        let result = try VPNProfile.importURI("hy2://alice:pa%40ss%3Aword@[2001:db8::1]:8443/?sni=edge.example.com")
        XCTAssertEqual(result.profile.transport, .hy2)
        XCTAssertEqual(result.profile.endpoint, "[2001:db8::1]:8443")
        XCTAssertEqual(result.profile.serverName, "edge.example.com")
        XCTAssertEqual(result.credential.auth, "alice:pa@ss:word")
    }

    func testHY2ImportRejectsUnsupportedSecuritySettings() {
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?insecure=true"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs=unknown"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs=salamander"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs-password=example"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs=salamander&obfs-password=abc"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?insecure=0&insecure=1"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://a%0Ab@edge.example.com"))
    }

    func testHY2ImportWithPeerInsecureAndSalamander() throws {
        let link = "hysteria2://fixture-auth@203.0.113.7:443?peer=edge.example.com&insecure=1&obfs=salamander&obfs-password=fake%20password#Hysteria2-Server"
        let imported = try VPNProfile.importURI(link)
        XCTAssertEqual(imported.profile.endpoint, "203.0.113.7:443")
        XCTAssertEqual(imported.profile.serverName, "edge.example.com")
        XCTAssertTrue(imported.profile.hy2Insecure)
        XCTAssertTrue(imported.profile.hy2Salamander)
        let profileData = try JSONEncoder().encode(imported.profile)
        XCTAssertEqual(try VPNProfile.decode(profileData), imported.profile)
        XCTAssertFalse(String(decoding: profileData, as: UTF8.self).contains("fake password"))
        XCTAssertFalse(String(decoding: profileData, as: UTF8.self).contains("fixture-auth"))
        let stored = try imported.credential.encoded(salamander: true)
        let credential = try HY2Credential.decode(stored, salamander: true)
        XCTAssertEqual(credential.auth, "fixture-auth")
        XCTAssertEqual(credential.obfuscationPassword, "fake password")
        XCTAssertEqual(try HY2Credential.decode("legacy-auth", salamander: false).auth, "legacy-auth")
    }

    func testHY2PrefersExplicitSNIAliasAndRejectsUnverifiedStrictModes() throws {
        let url = "hy2://fixture@203.0.113.7?sni=real.example&peer=alias.example&insecure=0"
        let imported = try VPNProfile.importURI(url)
        XCTAssertEqual(imported.profile.serverName, "real.example")
        XCTAssertFalse(imported.profile.hy2Insecure)
        XCTAssertThrowsError(try VPNProfile(host: "203.0.113.7", highSecurity: true, hy2Insecure: true))
        XCTAssertThrowsError(try VPNProfile(host: "203.0.113.7", requirePostQuantum: true, hy2Insecure: true))
    }

    func testHighSecurityRequiresAnIPButAllowsASeparateTLSName() throws {
        XCTAssertThrowsError(try VPNProfile(host: "edge.example.com", highSecurity: true))
        let profile = try VPNProfile(
            host: "2001:db8::1", serverName: "edge.example.com", highSecurity: true
        )
        let decoded = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertTrue(decoded.highSecurity)
        XCTAssertEqual(decoded.serverName, "edge.example.com")
    }

    func testLegacyProfileLoadsWithHighSecurityOff() throws {
        let profile = try VPNProfile(host: "edge.example.com")
        let data = try JSONEncoder().encode(profile)
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        fields.removeValue(forKey: "highSecurity")
        fields.removeValue(forKey: "https3Camouflage")
        fields.removeValue(forKey: "encryptedDNS")
        fields.removeValue(forKey: "hy2Insecure")
        fields.removeValue(forKey: "hy2Salamander")
        fields.removeValue(forKey: "wireGuardDirect")
        let previous = try JSONSerialization.data(withJSONObject: fields)
        XCTAssertEqual(try VPNProfile.decode(previous), profile)
    }

    func testEncryptedDNSRequiresHTTPSAndLiteralBootstrap() throws {
        let url = try XCTUnwrap(URL(string: "https://resolver.example.com/dns-query"))
        let dns = try EncryptedDNSProfile(url: url, bootstrapServers: ["203.0.113.1"]).validated()
        let profile = try VPNProfile(host: "203.0.113.2", highSecurity: true, encryptedDNS: dns)
        XCTAssertEqual(try VPNProfile.decode(JSONEncoder().encode(profile)).encryptedDNS, dns)
        XCTAssertThrowsError(try EncryptedDNSProfile(url: url, bootstrapServers: ["resolver.example.com"]).validated())
        let http = try XCTUnwrap(URL(string: "http://resolver.example.com/dns-query"))
        XCTAssertThrowsError(try EncryptedDNSProfile(url: http, bootstrapServers: ["203.0.113.1"]).validated())
    }

    func testDNSOverTLSWorksWithOrdinaryProfilesAndFiltersAddressFamilies() throws {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let peer = try WireGuardProfile(tunnelAddresses: ["2001:db8::2/128"], peerPublicKey: key).validated()
        let dns = EncryptedDNSProfile(
            tlsServerName: "resolver.example.com", bootstrapServers: ["203.0.113.1", "2001:db8::53"]
        )
        let profile = try VPNProfile(
            host: "edge.example.com", transport: .cuvenWG, wireGuard: peer,
            wireGuardDirect: true, encryptedDNS: dns
        )
        let decoded = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertEqual(decoded.encryptedDNS, dns)
        XCTAssertTrue(decoded.requiresEncryptedDNS)
        XCTAssertTrue(decoded.usesFullRouting)
        let plan = try TunnelNetworkPlan(profile: decoded)
        XCTAssertEqual(plan.dnsMode, .tls("resolver.example.com"))
        XCTAssertEqual(plan.dnsServers, ["2001:db8::53"])
    }

    func testLegacyHTTPSResolverAndStrictDefaultRemainHTTPS() throws {
        let legacy = Data(#"{"url":"https://resolver.example/dns-query","bootstrapServers":["203.0.113.1"]}"#.utf8)
        let resolver = try JSONDecoder().decode(EncryptedDNSProfile.self, from: legacy).validated()
        let profile = try VPNProfile(host: "203.0.113.7", encryptedDNS: resolver)
        let url = try XCTUnwrap(resolver.url)
        XCTAssertEqual(try TunnelNetworkPlan(profile: profile).dnsMode, .https(url))

        let strict = try VPNProfile(host: "203.0.113.7", highSecurity: true)
        let defaultURL = try XCTUnwrap(URL(string: "https://cloudflare-dns.com/dns-query"))
        XCTAssertEqual(try TunnelNetworkPlan(profile: strict).dnsMode, .https(defaultURL))
        let ordinary = try VPNProfile(host: "203.0.113.7")
        XCTAssertEqual(try TunnelNetworkPlan(profile: ordinary).dnsMode, .cleartext)
    }

    func testEncryptedDNSRejectsConflictingSettingsAndFallbackDowngrade() throws {
        let url = try XCTUnwrap(URL(string: "https://resolver.example/dns-query"))
        let addresses = ["203.0.113.1"]
        XCTAssertThrowsError(try EncryptedDNSProfile(
            url: url, tlsServerName: "resolver.example", bootstrapServers: addresses
        ).validated())
        XCTAssertThrowsError(try EncryptedDNSProfile(tlsServerName: "203.0.113.1", bootstrapServers: addresses).validated())

        let resolver = EncryptedDNSProfile(tlsServerName: "resolver.example", bootstrapServers: addresses)
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let peer = WireGuardProfile(tunnelAddresses: ["10.66.0.2/32"], peerPublicKey: key)
        let primary = try VPNProfile(host: "203.0.113.7", encryptedDNS: resolver)
        let compatible = try VPNProfile(
            host: "203.0.113.8", transport: .cuvenWG, wireGuard: peer, encryptedDNS: resolver
        )
        let cleartext = try VPNProfile(host: "203.0.113.8", transport: .cuvenWG, wireGuard: peer)
        let otherResolver = try VPNProfile(
            host: "203.0.113.8", transport: .cuvenWG, wireGuard: peer,
            encryptedDNS: EncryptedDNSProfile(url: url, bootstrapServers: addresses)
        )
        XCTAssertTrue(primary.permitsAutomaticFallback(to: compatible))
        XCTAssertFalse(primary.permitsAutomaticFallback(to: cleartext))
        XCTAssertFalse(primary.permitsAutomaticFallback(to: otherResolver))
    }

    func testHTTPS3CarrierRequiresHighSecurityAndCuvenWG() throws {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let peer = try WireGuardProfile(tunnelAddresses: ["10.66.0.2/32"], peerPublicKey: key).validated()
        let plain = try VPNProfile(host: "203.0.113.2", transport: .cuvenWG, wireGuard: peer, https3Camouflage: true)
        let high = try VPNProfile(
            host: "203.0.113.2", transport: .cuvenWG, wireGuard: peer,
            serverName: "edge.example.com", highSecurity: true, https3Camouflage: true
        )
        let hy2 = try VPNProfile(host: "203.0.113.2", highSecurity: true, https3Camouflage: true)
        XCTAssertFalse(plain.https3Camouflage)
        XCTAssertFalse(hy2.https3Camouflage)
        let decoded = try VPNProfile.decode(JSONEncoder().encode(high))
        XCTAssertTrue(decoded.https3Camouflage)
        XCTAssertEqual(decoded.serverName, "edge.example.com")
    }

    func testWireGuardProfileAndCredentialValidation() throws {
        let publicKey = Data(repeating: 1, count: 32).base64EncodedString()
        let relayKey = Data(repeating: 2, count: 32).base64EncodedString()
        let wireGuard = try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "fd00::2/128"], peerPublicKey: publicKey
        ).validated()
        let profile = try VPNProfile(
            host: "edge.example.com", transport: .cuvenWG, wireGuard: wireGuard,
            port: 51821, customDNSServers: ["9.9.9.9"], useCustomDNS: true,
            autoConnect: .wifi, requirePostQuantum: true, blockLAN: true, preventBypass: true
        )
        let roundTrip = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertEqual(profile, roundTrip)
        XCTAssertFalse(roundTrip.wireGuardDirect)
        XCTAssertFalse(roundTrip.requirePostQuantum)
        XCTAssertEqual(roundTrip.dnsServers, ["9.9.9.9"])

        let credentials = WireGuardCredential(privateKey: publicKey, relayKey: relayKey, presharedKey: nil)
        XCTAssertEqual(try WireGuardCredential.decode(credentials.encoded()).relayKey, relayKey)
        XCTAssertThrowsError(try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "10.66.0.3/32"], peerPublicKey: publicKey
        ).validated())
    }

    func testDirectWireGuardDoesNotRequireRelayCredentials() throws {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let peer = try WireGuardProfile(tunnelAddresses: ["10.66.0.2/32"], peerPublicKey: key).validated()
        let profile = try VPNProfile(
            host: "203.0.113.7", transport: .cuvenWG, wireGuard: peer, wireGuardDirect: true,
            port: 51820, highSecurity: true, https3Camouflage: true
        )
        let stored = try WireGuardCredential(privateKey: key, relayKey: nil, presharedKey: nil)
            .encoded(requiresRelay: false)
        XCTAssertNil(try WireGuardCredential.decode(stored, requiresRelay: false).relayKey)
        XCTAssertThrowsError(try WireGuardCredential.decode(stored))
        let decoded = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertTrue(decoded.wireGuardDirect)
        XCTAssertFalse(decoded.https3Camouflage)
        XCTAssertTrue(decoded.usesFullRouting)
    }
}
