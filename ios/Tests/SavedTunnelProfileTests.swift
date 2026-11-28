import NetworkExtension
import XCTest
@testable import Cuven

final class SavedTunnelProfileTests: XCTestCase {
    func testActivationMatchesSavedConnectionMode() {
        let manager = NETunnelProviderManager()
        manager.isEnabled = false
        manager.isOnDemandEnabled = false
        XCTAssertFalse(manager.hasRequestedActivation(for: .off))
        manager.isEnabled = true
        XCTAssertTrue(manager.hasRequestedActivation(for: .off))
        XCTAssertFalse(manager.hasRequestedActivation(for: .wifi))
        manager.isOnDemandEnabled = true
        XCTAssertFalse(manager.hasRequestedActivation(for: .off))
        for mode in [AutoConnect.wifi, .cellular, .all] {
            XCTAssertTrue(manager.hasRequestedActivation(for: mode))
        }
    }

    func testSavedFullTunnelAndDNSRoutesCanBeRepaired() throws {
        guard #available(macOS 13.3, *) else { throw XCTSkip("Requires routing controls from macOS 13.3") }
        let profile = try VPNProfile(host: "gateway.example", transport: .cuven, port: 4433)
        let config = NETunnelProviderProtocol()
        config.applyRouting(for: profile)
        config.excludeAPNs = true
        config.excludeCellularServices = true
        XCTAssertTrue(config.hasRequiredRouting(for: profile))
        config.includeAllNetworks = false
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
        config.applyRouting(for: profile)
        config.excludeLocalNetworks = true
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
        config.applyRouting(for: profile)
        XCTAssertTrue(config.includeAllNetworks)
        XCTAssertFalse(config.excludeLocalNetworks)
        XCTAssertTrue(config.hasRequiredRouting(for: profile))
    }

    func testHighSecurityRequiresBothSystemServiceExclusionsToBeOff() throws {
        guard #available(macOS 13.3, *) else { throw XCTSkip("Requires routing controls from macOS 13.3") }
        let profile = try VPNProfile(host: "192.0.2.1", transport: .cuven, port: 4433, highSecurity: true)
        let config = NETunnelProviderProtocol()
        config.applyRouting(for: profile)
        config.excludeAPNs = true
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
        config.applyRouting(for: profile)
        config.excludeCellularServices = true
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
        config.applyRouting(for: profile)
        XCTAssertFalse(config.excludeAPNs)
        XCTAssertFalse(config.excludeCellularServices)
        XCTAssertTrue(config.hasRequiredRouting(for: profile))
    }

    func testLockdownRequiresFullRoutesEvenWhenHighSecurityWasOff() throws {
        guard #available(macOS 13.3, *) else { throw XCTSkip("Requires routing controls from macOS 13.3") }
        let profile = try VPNProfile(host: "192.0.2.1", transport: .cuven, lockdown: true,
                                     gatewayKeyPin: Data(repeating: 8, count: 32).base64EncodedString())
        let config = NETunnelProviderProtocol()
        config.applyRouting(for: profile)
        XCTAssertTrue(config.hasRequiredRouting(for: profile))
        config.includeAllNetworks = false
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
        config.applyRouting(for: profile)
        config.excludeCellularServices = true
        XCTAssertFalse(config.hasRequiredRouting(for: profile))
    }

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
