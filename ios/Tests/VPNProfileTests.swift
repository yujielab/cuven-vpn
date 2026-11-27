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
    }

    func testHY2ImportRejectsUnsupportedSecuritySettings() {
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?insecure=1"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs=salamander"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://a%0Ab@edge.example.com"))
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
        XCTAssertFalse(roundTrip.requirePostQuantum)
        XCTAssertEqual(roundTrip.dnsServers, ["9.9.9.9"])

        let credentials = WireGuardCredential(privateKey: publicKey, relayKey: relayKey, presharedKey: nil)
        XCTAssertEqual(try WireGuardCredential.decode(credentials.encoded()).relayKey, relayKey)
        XCTAssertThrowsError(try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "10.66.0.3/32"], peerPublicKey: publicKey
        ).validated())
    }
}
