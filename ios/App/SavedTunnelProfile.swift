import Foundation
import NetworkExtension

/// Persisted profile and credential binding used as the base for edits in the app.
struct SavedTunnelProfile: Equatable {
    let profile: VPNProfile
    let reference: Data?
    let requiresAppStart: Bool
    let sessionID: Data?

    init(profile: VPNProfile, configuration: NETunnelProviderProtocol) {
        self.profile = profile
        let fields = configuration.providerConfiguration
        let isCuven = profile.transport == .cuven
        reference = isCuven ? Self.credentialReference(in: configuration) : nil
        requiresAppStart = isCuven && fields?[AppCredentialHandoff.modeKey] as? Bool == true
        sessionID = isCuven ? fields?[AppCredentialHandoff.sessionIDKey] as? Data : nil
    }

    init?(configuration: NETunnelProviderProtocol) {
        guard let fields = configuration.providerConfiguration,
              let profile = TunnelConfiguration.storedProfile(in: fields) else { return nil }
        self.init(profile: profile, configuration: configuration)
    }

    static func credentialReference(in configuration: NETunnelProviderProtocol) -> Data? {
        configuration.passwordReference
            ?? configuration.providerConfiguration?[TunnelConfiguration.credentialKey] as? Data
    }
}

extension NETunnelProviderManager {
    func hasRequestedActivation(for mode: AutoConnect) -> Bool {
        isEnabled && isOnDemandEnabled == (mode != .off)
    }
}
