import Foundation
import XCTest
@testable import Cuven

final class VPNProfileTests: XCTestCase {
    func testHY2ImportPreservesPercentEncodedCredentialsAndIPv6() throws {
        let result = try VPNProfile.importURI("hy2://alice:pa%40ss%3Aword@[2001:db8::1]:8443/?sni=edge.example.com")
        XCTAssertEqual(result.profile.transport, .hy2)
        XCTAssertEqual(result.profile.endpoint, "[2001:db8::1]:8443")
        XCTAssertEqual(result.profile.serverName, "edge.example.com")
        XCTAssertEqual(result.credential, "alice:pa@ss:word")
        XCTAssertFalse(result.profile.insecure)
        XCTAssertNil(result.profile.obfs)
        XCTAssertNil(result.obfsPassword)
    }

    func testHY2ImportAcceptsSalamanderPeerInsecureAndFragment() throws {
        let links = [
            "hysteria2://example-auth-token@198.51.100.1:443?peer=example.com&insecure=1&obfs=salamander&obfs-password=example-obfs-pass#Example-Server",
            "hy2://example-auth-token@198.51.100.1:443?obfs-password=example-obfs-pass&obfs=Salamander&insecure=true&peer=example.com#Example-Server",
        ]
        for uri in links {
            let result = try VPNProfile.importURI(uri)
            XCTAssertEqual(result.profile.transport, .hy2)
            XCTAssertEqual(result.profile.host, "198.51.100.1")
            XCTAssertEqual(result.profile.port, 443)
            XCTAssertEqual(result.profile.endpoint, "198.51.100.1:443")
            XCTAssertEqual(result.profile.serverName, "example.com")
            XCTAssertTrue(result.profile.insecure)
            XCTAssertEqual(result.profile.obfs, "salamander")
            XCTAssertEqual(result.credential, "example-auth-token")
            XCTAssertEqual(result.obfsPassword, "example-obfs-pass")
            let encoded = String(decoding: try JSONEncoder().encode(result.profile), as: UTF8.self)
            XCTAssertFalse(encoded.contains("example-obfs-pass"))
            XCTAssertFalse(encoded.contains("example-auth-token"))
            XCTAssertEqual(try VPNProfile.decode(Data(encoded.utf8)), result.profile)
        }
    }

    func testPeerIsAnAliasAndSNIWinsWhenBothArePresent() throws {
        let peerOnly = try VPNProfile.importURI("hy2://example-auth-token@198.51.100.1?peer=peer.example.com")
        XCTAssertEqual(peerOnly.profile.serverName, "peer.example.com")
        XCTAssertFalse(peerOnly.profile.insecure)
        XCTAssertNil(peerOnly.profile.obfs)

        let sniOnly = try VPNProfile.importURI("hysteria2://example-auth-token@198.51.100.1:8443?sni=sni.example.com&insecure=0")
        XCTAssertEqual(sniOnly.profile.serverName, "sni.example.com")
        XCTAssertEqual(sniOnly.profile.port, 8443)
        XCTAssertFalse(sniOnly.profile.insecure)

        let same = try VPNProfile.importURI("hy2://example-auth-token@example.com?sni=edge.example.com&peer=edge.example.com&insecure=false")
        XCTAssertEqual(same.profile.serverName, "edge.example.com")
        XCTAssertFalse(same.profile.insecure)

        let both = try VPNProfile.importURI("hy2://example-auth-token@198.51.100.1?peer=peer.example.com&sni=sni.example.com")
        XCTAssertEqual(both.profile.serverName, "sni.example.com")

        let encodedPassword = try VPNProfile.importURI(
            "hy2://example-auth-token@198.51.100.1?peer=edge.example.com&insecure=1&obfs=salamander&obfs-password=example%2Dobfs%2Dpass"
        )
        XCTAssertEqual(encodedPassword.profile.serverName, "edge.example.com")
        XCTAssertEqual(encodedPassword.obfsPassword, "example-obfs-pass")
        XCTAssertTrue(encodedPassword.profile.insecure)
    }

    func testFragmentIsNotParsedAsParameters() throws {
        let result = try VPNProfile.importURI("hy2://example-auth-token@example.com:443#Example-Server?insecure=1&obfs=salamander")
        XCTAssertEqual(result.profile.host, "example.com")
        XCTAssertEqual(result.credential, "example-auth-token")
        XCTAssertFalse(result.profile.insecure)
        XCTAssertNil(result.profile.obfs)
        XCTAssertNil(result.obfsPassword)
        XCTAssertNil(result.profile.serverName)
    }

    func testHY2ImportRejectsUnsupportedOrIncompleteObfuscation() {
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?obfs=salamander"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?obfs=salamander&obfs-password=no"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?obfs=gecko&obfs-password=example-obfs-pass"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?obfs-password=example-obfs-pass"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?insecure=yes"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?pinSHA256=abcd"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://example-auth-token@example.com?sni=edge.example.com&sni=other.example.com"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://a%0Ab@example.com"))
        XCTAssertThrowsError(try VPNProfile(host: "example.com", obfs: "gecko"))
    }

    func testProfileRoundTripPreservesInsecureAndObfuscationWithoutThePassword() throws {
        let profile = try VPNProfile(
            host: "198.51.100.1", serverName: "example.com", insecure: true, obfs: "salamander"
        )
        XCTAssertTrue(profile.insecure)
        XCTAssertEqual(profile.obfs, "salamander")
        let encoded = try JSONEncoder().encode(profile)
        let decoded = try VPNProfile.decode(encoded)
        XCTAssertEqual(decoded, profile)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("example-obfs-pass"))
    }

    func testLegacyProfileLeavesVerificationOnAndObfuscationOff() throws {
        let profile = try VPNProfile(host: "edge.example.com")
        XCTAssertFalse(profile.insecure)
        XCTAssertNil(profile.obfs)
        let encoded = try JSONEncoder().encode(profile)
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        fields.removeValue(forKey: "insecure")
        fields.removeValue(forKey: "obfs")
        fields.removeValue(forKey: "highSecurity")
        fields.removeValue(forKey: "blockAppUDP")
        let decoded = try VPNProfile.decode(try JSONSerialization.data(withJSONObject: fields))
        XCTAssertEqual(decoded, profile)
    }

    func testHysteriaCredentialKeepsObfsPasswordOutOfTheAuthSecret() throws {
        let stored = try HysteriaCredential(
            version: HysteriaCredential.currentVersion, auth: "example-auth-token", obfsPassword: "example-obfs-pass"
        ).encoded()
        let parsed = try HysteriaCredential.parseStored(stored)
        XCTAssertEqual(parsed.auth, "example-auth-token")
        XCTAssertEqual(parsed.obfsPassword, "example-obfs-pass")
        XCTAssertFalse(parsed.auth.contains("example-obfs-pass"))

        let legacy = try HysteriaCredential.parseStored("example-auth-token")
        XCTAssertEqual(legacy.auth, "example-auth-token")
        XCTAssertNil(legacy.obfsPassword)
        XCTAssertThrowsError(try VPNProfile.validateObfsPassword("no"))
        XCTAssertThrowsError(try HysteriaCredential(
            version: HysteriaCredential.currentVersion, auth: "example-auth-token", obfsPassword: ""
        ).encoded())
    }

    func testHighSecurityRequiresAnIPButAllowsASeparateTLSName() throws {
        XCTAssertThrowsError(try VPNProfile(host: "edge.example.com", highSecurity: true))
        let profile = try VPNProfile(
            host: "2001:db8::1", serverName: "edge.example.com", highSecurity: true, blockAppUDP: true
        )
        let decoded = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertTrue(decoded.highSecurity)
        XCTAssertTrue(decoded.blockAppUDP)
        XCTAssertEqual(decoded.serverName, "edge.example.com")
    }

    func testLegacyProfileLoadsWithHighSecurityOff() throws {
        let profile = try VPNProfile(host: "edge.example.com")
        let data = try JSONEncoder().encode(profile)
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        fields.removeValue(forKey: "highSecurity")
        fields.removeValue(forKey: "blockAppUDP")
        let previous = try JSONSerialization.data(withJSONObject: fields)
        XCTAssertEqual(try VPNProfile.decode(previous), profile)
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
        XCTAssertFalse(roundTrip.requirePostQuantum)
        XCTAssertEqual(roundTrip.dnsServers, ["9.9.9.9"])

        let credentials = WireGuardCredential(privateKey: publicKey, relayKey: relayKey, presharedKey: nil)
        XCTAssertEqual(try WireGuardCredential.decode(credentials.encoded()).relayKey, relayKey)
        XCTAssertThrowsError(try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "10.66.0.3/32"], peerPublicKey: publicKey
        ).validated())
    }
}
