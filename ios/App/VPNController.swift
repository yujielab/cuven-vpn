import Foundation
import NetworkExtension
import Security
import SwiftUI

@MainActor
final class VPNController: ObservableObject {
    @Published var host = ""
    @Published var port = String(VPNTransport.cuven.defaultPort)
    @Published var serverName = ""
    @Published var credential = ""
    @Published var enableIPv6 = false
    @Published var autoConnect = AutoConnect.off
    @Published var blockLAN = false
    @Published var highSecurity = false
    @Published var useEncryptedDNS = false
    @Published var useDNSOverTLS = false
    @Published var encryptedDNSURL = ""
    @Published var encryptedDNSTLSName = ""
    @Published var encryptedDNSBootstrap = ""
    @Published private(set) var autoConnectPaused = false
    @Published private(set) var offersOneTimeStart = false
    @Published private var stored: SavedTunnelProfile?
    var requiresAppStart: Bool { stored?.requiresAppStart ?? false }
    private enum SavedCredential { case absent, available, awaitingUnlock }
    @Published private var savedCredential = SavedCredential.absent
    var hasCredential: Bool { savedCredential == .available }
    var credentialAwaitsUnlock: Bool { savedCredential == .awaitingUnlock }
    @Published private(set) var status = NEVPNStatus.invalid
    @Published private var rtt = TunnelRTTMeasurement()
    var tunnelRTT: Int64? { rtt.milliseconds }
    @Published private(set) var busy = false
    @Published private(set) var loaded = false
    @Published private(set) var error: String?

    private var manager: NETunnelProviderManager?
    private var savedProfile: VPNProfile? { stored?.profile }
    private var credentialReference: Data? { stored?.reference }
    private var connectionRequested = false
    private var stoppingByUser = false
    private var pendingDisconnectReport: UUID?
    private var preferencesNeedReload = false

    var canEdit: Bool {
        loaded && !busy && (status == .invalid || status == .disconnected)
    }

    var canStart: Bool {
        canEdit && !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            (hasCredential || hasNewCredential)
    }

    var canStartOnce: Bool {
        offersOneTimeStart && canStart && hasNewCredential && !hasCredential && autoConnect == .off
    }

    var canSave: Bool {
        guard canStart else { return false }
        return hasNewCredential || (try? draftProfile()) != savedProfile || autoConnectPaused || routingNeedsRepair
    }

    private var routingNeedsRepair: Bool {
        guard let profile = savedProfile, profile.transport == .cuven,
              let configuration = manager?.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        return !configuration.hasRequiredRouting(for: profile)
    }

    private var hasNewCredential: Bool {
        !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var canStop: Bool {
        !busy && (status == .connected || status == .connecting || status == .reasserting)
    }

    func load() async {
        guard !loaded, !busy else { return }
        busy = true
        defer { busy = false }
        do {
            _ = try await readSystemConfiguration()
        } catch {
            self.error = "无法读取系统 VPN 配置。\(error.localizedDescription)"
        }
    }

    /// Returns whether the saved configuration still matches the form's base.
    /// Only an unchanged base can keep an unsubmitted token and draft together.
    private func readSystemConfiguration() async throws -> Bool {
        let providerID = try Self.embeddedProviderID()
        let previousHadConfiguration = manager?.protocolConfiguration != nil
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let existing = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
        let configuration = existing?.protocolConfiguration as? NETunnelProviderProtocol
        let current = configuration.flatMap(SavedTunnelProfile.init(configuration:))
        let profile = current?.profile
        let keepDraft = manager != nil && stored == current && previousHadConfiguration == (existing != nil) &&
            (existing == nil || profile?.transport == .cuven)

        if let existing, let profile, profile.transport != .cuven && existing.isOnDemandEnabled {
            existing.isOnDemandEnabled = false
            do {
                try await existing.saveToPreferences()
            } catch {
                existing.isOnDemandEnabled = true
                throw error
            }
            preferencesNeedReload = true
        } else {
            preferencesNeedReload = false
        }
        error = nil
        pendingDisconnectReport = nil
        stoppingByUser = false
        connectionRequested = false
        manager = existing ?? NETunnelProviderManager()
        stored = current
        offersOneTimeStart = current?.sessionID != nil || (keepDraft && offersOneTimeStart)
        autoConnectPaused = false
        if !keepDraft {
            credential = ""
            apply(profile?.transport == .cuven ? profile : nil)
        }
        if let profile {
            if profile.transport == .cuven {
                autoConnectPaused = profile.autoConnect != .off && existing?.isOnDemandEnabled == false
            } else {
                error = "请填写 Cuven IP 网关和新的接入令牌。"
            }
        }
        refreshCredential()
        loaded = true
        refreshStatus()
        return keepDraft
    }

    private func recoverPreferenceConflict(_ cause: Error) async -> Bool {
        let failure = cause as NSError
        guard failure.domain == NEVPNErrorDomain, failure.code == NEVPNError.configurationStale.rawValue else {
            return false
        }
        loaded = false
        do {
            let kept = try await readSystemConfiguration()
            error = kept ? "已重新读取系统 VPN 配置，当前输入已保留。请重试。"
                : "系统 VPN 配置已更改，请核对重新读取的网关和连接设置。"
        } catch {
            self.error = "系统 VPN 配置已更改。重新读取失败。\(error.localizedDescription)"
        }
        return true
    }

    func refreshStatus() {
        let previous = status
        let next = manager?.connection.status ?? .invalid
        status = next
        if next != .connected { rtt = TunnelRTTMeasurement() }
        switch next {
        case .connecting, .reasserting:
            pendingDisconnectReport = nil
            connectionRequested = !stoppingByUser
        case .connected:
            pendingDisconnectReport = nil
            connectionRequested = !stoppingByUser
            error = nil
        case .disconnected, .invalid:
            stoppingByUser = false
            if connectionRequested && previous != next {
                connectionRequested = false
                showDisconnectReason()
            }
        default:
            break
        }
    }

    private func showDisconnectReason() {
        error = "VPN 连接已中断。"
        guard let connection = manager?.connection else { return }
        let report = UUID()
        pendingDisconnectReport = report
        connection.fetchLastDisconnectError { [weak self, weak connection] cause in
            let message = cause.flatMap { DisconnectDiagnostic.message(for: $0 as NSError) }
            Task { @MainActor in
                guard let self, let connection, self.pendingDisconnectReport == report,
                      self.manager?.connection === connection,
                      self.status == .disconnected || self.status == .invalid else { return }
                self.pendingDisconnectReport = nil
                if let message { self.error = message }
            }
        }
    }

    func refreshTunnelRTT() {
        guard status == .connected, let session = manager?.connection as? NETunnelProviderSession else { return }
        let request = rtt.begin()
        do {
            try session.sendProviderMessage(TunnelConfiguration.rttRequest) { [weak self, weak session] data in
                Task { @MainActor in
                    guard let self, let session, self.status == .connected,
                          self.manager?.connection === session else { return }
                    self.rtt.finish(request, reply: data)
                }
            }
        } catch {
            rtt.finish(request, reply: nil)
        }
    }

    func save(connect: Bool, once: Bool = false) async {
        guard canStart, let manager, !once || (connect && canStartOnce) else { return }
        busy = true
        pendingDisconnectReport = nil
        error = nil
        defer { busy = false }
        do {
            try await reloadPreferencesIfNeeded(manager)
            let profile = try draftProfile()
            let sessionToken = once ? credential.trimmingCharacters(in: .whitespacesAndNewlines) : nil
            if let sessionToken { try VPNProfile.validateAccessToken(sessionToken) }
            if profile != savedProfile || hasNewCredential || autoConnectPaused || !manager.isEnabled || routingNeedsRepair {
                try await persist(profile, manager: manager, once: once)
            }
            guard !routingNeedsRepair else { throw TunnelFailure.strictRouting }
            refreshStatus()
            if connect && (status == .invalid || status == .disconnected) {
                if requiresAppStart {
                    guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
                          configuration.providerBundleIdentifier == (try Self.embeddedProviderID()),
                          configuration.providerConfiguration?[AppCredentialHandoff.modeKey] as? Bool == true,
                          profile.autoConnect == .off, !manager.isOnDemandEnabled
                    else { throw CredentialError.missing }
                    let options: [String: NSObject]
                    if let sessionToken,
                       let id = configuration.providerConfiguration?[AppCredentialHandoff.sessionIDKey] as? Data,
                       SavedTunnelProfile.credentialReference(in: configuration) == nil {
                        options = try AppCredentialHandoff.options(token: sessionToken, reference: id)
                    } else if !once, let reference = credentialReference, reference == SavedTunnelProfile.credentialReference(in: configuration) {
                        let token = try KeychainCredential.load(reference: reference)
                        options = try AppCredentialHandoff.options(token: token, reference: reference)
                    } else {
                        throw CredentialError.missing
                    }
                    try manager.connection.startVPNTunnel(options: options)
                    if once { credential = "" }
                } else {
                    try manager.connection.startVPNTunnel()
                }
                connectionRequested = true
                let observed = manager.connection.status
                if observed == .invalid || observed == .disconnected {
                    status = .connecting
                } else {
                    refreshStatus()
                }
            }
        } catch {
            refreshStatus()
            pendingDisconnectReport = nil
            if await recoverPreferenceConflict(error) { return }
            if let failure = error as? CredentialError {
                switch failure {
                case .appKeychain(errSecMissingEntitlement), .unexpectedDefaultGroup: offersOneTimeStart = true
                default: break
                }
            }
            self.error = error.localizedDescription
        }
    }

    func disconnect() async {
        guard canStop, let manager else { return }
        busy = true
        defer { busy = false }
        error = nil
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            do {
                try await manager.saveToPreferences()
                preferencesNeedReload = true
                autoConnectPaused = true
            } catch {
                manager.isOnDemandEnabled = true
                if await recoverPreferenceConflict(error) { return }
                self.error = "无法暂停自动连接。\(error.localizedDescription)"
                return
            }
        }
        stoppingByUser = true
        connectionRequested = false
        manager.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func persist(_ profile: VPNProfile, manager: NETunnelProviderManager, once: Bool) async throws {
        let providerID = try Self.embeddedProviderID()
        let profileData = try JSONEncoder().encode(profile)
        let previous = manager.protocolConfiguration as? NETunnelProviderProtocol
        let previousReference = credentialReference
        let reference: Data?
        var appStart = requiresAppStart
        if once {
            reference = nil
            appStart = true
        } else if hasNewCredential || (appStart && profile.autoConnect != .off) {
            let token: String
            if hasNewCredential {
                token = credential.trimmingCharacters(in: .whitespacesAndNewlines)
            } else if let previousReference {
                token = try KeychainCredential.load(reference: previousReference)
            } else {
                throw CredentialError.missing
            }
            try VPNProfile.validateAccessToken(token)
            do {
                reference = try KeychainCredential.store(token)
                appStart = false
            } catch let failure as CredentialError where failure.sharedGroupUnavailable {
                guard profile.autoConnect == .off else {
                    if case .unresolvedSharedGroup = failure { throw failure }
                    throw CredentialError.sharedRequired
                }
                reference = try KeychainCredential.storeForApp(token)
                appStart = true
            }
        } else if hasCredential, let previousReference {
            let token = try KeychainCredential.load(reference: previousReference)
            try VPNProfile.validateAccessToken(token)
            reference = previousReference
        } else {
            throw CredentialError.missing
        }

        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerID
        configuration.serverAddress = profile.endpoint
        configuration.passwordReference = appStart ? nil : reference
        var values: [String: Any] = [
            TunnelConfiguration.profileKey: profileData,
            AppCredentialHandoff.modeKey: appStart
        ]
        if let reference {
            values[TunnelConfiguration.credentialKey] = reference
        } else {
            values[AppCredentialHandoff.sessionIDKey] = Data(UUID().uuidString.utf8)
        }
        configuration.providerConfiguration = values
        configuration.applyRouting(for: profile)

        let wasEnabled = manager.isEnabled
        let previousDescription = manager.localizedDescription
        let previousRules = manager.onDemandRules
        let wasOnDemandEnabled = manager.isOnDemandEnabled
        manager.protocolConfiguration = configuration
        manager.isEnabled = true
        manager.localizedDescription = "Cuven"
        manager.onDemandRules = Self.onDemandRules(profile.autoConnect)
        manager.isOnDemandEnabled = profile.autoConnect != .off
        do {
            try await manager.saveToPreferences()
        } catch {
            manager.protocolConfiguration = previous
            manager.isEnabled = wasEnabled
            manager.localizedDescription = previousDescription
            manager.onDemandRules = previousRules
            manager.isOnDemandEnabled = wasOnDemandEnabled
            if let reference, reference != previousReference { KeychainCredential.remove(reference: reference) }
            throw error
        }
        if let previousReference, previousReference != reference {
            KeychainCredential.remove(reference: previousReference)
        }
        if !once { credential = "" }
        offersOneTimeStart = once
        stored = SavedTunnelProfile(profile: profile, configuration: configuration)
        autoConnectPaused = false
        apply(profile)
        refreshCredential()
        // The write is committed even if the following read fails. Retry the
        // read before the next save or start without rotating the token again.
        preferencesNeedReload = true
        try await reloadPreferencesIfNeeded(manager)
    }

    private func reloadPreferencesIfNeeded(_ manager: NETunnelProviderManager) async throws {
        guard preferencesNeedReload else { return }
        try await manager.loadFromPreferences()
        let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol
        guard let configuration, configuration.providerBundleIdentifier == (try Self.embeddedProviderID()),
              SavedTunnelProfile(configuration: configuration) == stored else {
            throw NSError(domain: NEVPNErrorDomain, code: NEVPNError.configurationStale.rawValue)
        }
        preferencesNeedReload = false
    }

    private static func onDemandRules(_ mode: AutoConnect) -> [NEOnDemandRule] {
        guard mode != .off else { return [] }
        let connect = NEOnDemandRuleConnect()
        switch mode {
        case .off, .all: connect.interfaceTypeMatch = .any
        case .wifi: connect.interfaceTypeMatch = .wiFi
        case .cellular: connect.interfaceTypeMatch = .cellular
        }
        if mode == .all { return [connect] }
        let disconnect = NEOnDemandRuleDisconnect()
        disconnect.interfaceTypeMatch = .any
        return [connect, disconnect]
    }

    private static func embeddedProviderID() throws -> String {
        guard let plugins = Bundle.main.builtInPlugInsURL, let appID = Bundle.main.bundleIdentifier,
              let provider = Bundle(url: plugins.appendingPathComponent("CuvenTunnel.appex")),
              let identifier = provider.bundleIdentifier, identifier.hasPrefix(appID + "."),
              let settings = provider.object(forInfoDictionaryKey: "NSExtension") as? [String: Any],
              settings["NSExtensionPointIdentifier"] as? String == "com.apple.networkextension.packet-tunnel"
        else { throw CredentialError.providerMissing }
        return identifier
    }

    private func draftProfile() throws -> VPNProfile {
        let encryptedDNS: EncryptedDNSProfile?
        if useEncryptedDNS {
            let servers = Self.splitList(encryptedDNSBootstrap)
            if useDNSOverTLS {
                let name = encryptedDNSTLSName.trimmingCharacters(in: .whitespacesAndNewlines)
                encryptedDNS = EncryptedDNSProfile(tlsServerName: name, bootstrapServers: servers)
            } else {
                let text = encryptedDNSURL.trimmingCharacters(in: .whitespacesAndNewlines)
                guard let url = URL(string: text) else { throw ProfileError.encryptedDNS }
                encryptedDNS = EncryptedDNSProfile(url: url, bootstrapServers: servers)
            }
        } else {
            encryptedDNS = nil
        }
        let profile = try VPNProfile(
            host: host, transport: .cuven, cuvenIPv6: enableIPv6,
            port: Int(port.trimmingCharacters(in: .whitespaces)) ?? 0,
            serverName: serverName, autoConnect: autoConnect, blockLAN: blockLAN,
            highSecurity: highSecurity, encryptedDNS: encryptedDNS
        )
        _ = try TunnelNetworkPlan(profile: profile)
        return profile
    }

    func retryCredentialAfterUnlock() {
        if credentialAwaitsUnlock { refreshCredential() }
    }

    private func refreshCredential() {
        guard let credentialReference else {
            savedCredential = .absent
            return
        }
        do {
            let token = try KeychainCredential.load(reference: credentialReference)
            try VPNProfile.validateAccessToken(token)
            savedCredential = .available
        } catch CredentialError.keychain(errSecInteractionNotAllowed) {
            savedCredential = .awaitingUnlock
        } catch {
            savedCredential = .absent
        }
    }

    private static func splitList(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init)
    }

    private func apply(_ profile: VPNProfile?) {
        enableIPv6 = profile?.cuvenIPv6 ?? false
        host = profile?.host ?? ""
        port = String(profile?.port ?? VPNTransport.cuven.defaultPort)
        serverName = profile?.serverName ?? ""
        autoConnect = profile?.autoConnect ?? .off
        blockLAN = profile?.blockLAN ?? false
        highSecurity = profile?.highSecurity ?? false
        let dns = profile?.encryptedDNS
        useEncryptedDNS = dns != nil
        useDNSOverTLS = dns?.tlsServerName != nil
        encryptedDNSURL = dns?.url?.absoluteString ?? ""
        encryptedDNSTLSName = dns?.tlsServerName ?? ""
        encryptedDNSBootstrap = dns?.bootstrapServers.joined(separator: ", ") ?? ""
    }
}
