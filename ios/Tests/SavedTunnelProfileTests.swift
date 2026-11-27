import NetworkExtension
import XCTest
@testable import Cuven

final class SavedTunnelProfileTests: XCTestCase {
    func testOnlyTheSameGatewayAndCredentialBindingKeepAnUnsavedDraft() throws {
        let original = NETunnelProviderProtocol()
        let profile = try VPNProfile(host: "first.example", transport: .cuven, port: 4433)
        let reference = Data([1])
        original.passwordReference = reference
        original.providerConfiguration = [TunnelConfiguration.profileKey: try JSONEncoder().encode(profile)]
        let saved = try XCTUnwrap(SavedTunnelProfile(configuration: original))

        let current = NETunnelProviderProtocol()
        current.providerConfiguration = original.providerConfiguration
        current.passwordReference = reference
        XCTAssertEqual(saved, SavedTunnelProfile(configuration: current))
        current.passwordReference = Data([2])
        XCTAssertNotEqual(saved, SavedTunnelProfile(configuration: current))
        current.passwordReference = reference
        let moved = try VPNProfile(host: "changed.example", transport: .cuven, port: 4433)
        current.providerConfiguration?[TunnelConfiguration.profileKey] = try JSONEncoder().encode(moved)
        XCTAssertNotEqual(saved, SavedTunnelProfile(configuration: current))
        current.providerConfiguration?[TunnelConfiguration.profileKey] = Data([0xff])
        XCTAssertNil(SavedTunnelProfile(configuration: current))
    }

    func testAppKeychainAndOneTimeSessionBindingsStayDistinct() throws {
        let config = NETunnelProviderProtocol()
        let profile = try VPNProfile(host: "gateway.example", transport: .cuven, port: 4433)
        config.providerConfiguration = [
            TunnelConfiguration.profileKey: try JSONEncoder().encode(profile),
            AppCredentialHandoff.modeKey: true, TunnelConfiguration.credentialKey: Data([1])
        ]
        let app = try XCTUnwrap(SavedTunnelProfile(configuration: config))
        XCTAssertTrue(app.requiresAppStart)
        XCTAssertEqual(app.reference, Data([1]))
        config.providerConfiguration?.removeValue(forKey: TunnelConfiguration.credentialKey)
        config.providerConfiguration?[AppCredentialHandoff.sessionIDKey] = Data([2])
        let once = try XCTUnwrap(SavedTunnelProfile(configuration: config))
        XCTAssertNil(once.reference)
        XCTAssertNotEqual(once, app)
        config.providerConfiguration?[AppCredentialHandoff.sessionIDKey] = Data([3])
        XCTAssertNotEqual(once, SavedTunnelProfile(configuration: config))
    }
}
