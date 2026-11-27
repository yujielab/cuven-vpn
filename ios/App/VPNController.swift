import Foundation
import NetworkExtension
import SwiftUI

@MainActor
final class VPNController: ObservableObject {
    @Published private(set) var transport = VPNTransport.hy2
    @Published private(set) var activeTransport: VPNTransport?
    @Published var host = ""
    @Published var port = "443"
    @Published var serverName = ""
    @Published var dns = VPNProfile.defaultDNSServers.joined(separator: ", ")
    @Published var credential = ""
    @Published var tunnelAddresses = ""
    @Published var peerPublicKey = ""
    @Published var privateKey = ""
    @Published var relayKey = ""
    @Published var presharedKey = ""
    @Published var useCustomDNS = false
    @Published var automaticFallback = false
    @Published var autoConnect = AutoConnect.off
    @Published var requirePostQuantum = false
    @Published var blockLAN = false
    @Published var preventBypass = false
    @Published var highSecurity = false
    @Published var blockAppUDP = false
    @Published private(set) var autoConnectPaused = false
    @Published private(set) var hasCredential = false
    @Published private(set) var status = NEVPNStatus.invalid
    @Published private(set) var busy = false
    @Published private(set) var loaded = false
    @Published private(set) var error: String?

    private var manager: NETunnelProviderManager?
    private struct Enrollment {
        let profile: VPNProfile
        let reference: Data
    }

    private var savedProfile: VPNProfile?
    private var savedAutomaticFallback = false
    private var enrollments: [VPNTransport: Enrollment] = [:]
    private var connectionRequested = false

    var displayedHost: String {
        guard let activeTransport, let enrollment = enrollments[activeTransport] else { return host }
        return enrollment.profile.host
    }

    var canEdit: Bool {
        loaded && !busy && (status == .invalid || status == .disconnected)
    }

    var canStart: Bool {
        canEdit && !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            (hasCredential || hasNewCredential)
    }

    var hasAlternateTransport: Bool {
        enrollments.values.contains { $0.profile.transport != transport && !$0.profile.highSecurity }
    }

    private var wantsFallback: Bool {
        automaticFallback && !highSecurity && !requirePostQuantum && hasAlternateTransport
    }

    var canSave: Bool {
        guard canStart else { return false }
        return hasNewCredential || (try? draftProfile()) != savedProfile ||
            wantsFallback != savedAutomaticFallback || autoConnectPaused
    }

    private var hasNewCredential: Bool {
        switch transport {
        case .hy2: !credential.isEmpty
        case .cuvenWG: !privateKey.isEmpty || !relayKey.isEmpty || !presharedKey.isEmpty
        }
    }

    var canStop: Bool {
        !busy && (status == .connected || status == .connecting || status == .reasserting)
    }

    func load() async {
        guard !loaded, !busy else { return }
        busy = true
        defer { busy = false }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let existing = managers.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == TunnelConfiguration.providerBundleIdentifier
            }
            manager = existing ?? NETunnelProviderManager()
            if let configuration = existing?.protocolConfiguration as? NETunnelProviderProtocol,
               let data = configuration.providerConfiguration?[TunnelConfiguration.profileKey] as? Data,
               let profile = try? VPNProfile.decode(data) {
                if let reference = Self.credentialReference(in: configuration) {
                    enrollments[profile.transport] = Enrollment(profile: profile, reference: reference)
                }
                if let alternate = configuration.providerConfiguration?[TunnelConfiguration.alternateProfileKey] as? Data,
                   let reference = configuration.providerConfiguration?[TunnelConfiguration.alternateCredentialKey] as? Data,
                   let alternateProfile = try? VPNProfile.decode(alternate),
                   alternateProfile.transport != profile.transport {
                    enrollments[alternateProfile.transport] = Enrollment(profile: alternateProfile, reference: reference)
                }
                savedProfile = profile
                savedAutomaticFallback = configuration.providerConfiguration?[TunnelConfiguration.automaticFallbackKey]
                    as? Bool ?? false
                automaticFallback = savedAutomaticFallback
                apply(profile)
                refreshCredential()
                autoConnectPaused = profile.autoConnect != .off && existing?.isOnDemandEnabled == false
            }
            loaded = true
            refreshStatus()
        } catch {
            self.error = "无法读取系统 VPN 配置。\(error.localizedDescription)"
        }
    }

    func refreshStatus() {
        let previous = status
        let next = manager?.connection.status ?? .invalid
        status = next
        if next != .connected { activeTransport = nil }
        switch next {
        case .connected:
            connectionRequested = true
            error = nil
            queryActiveTransport()
        case .disconnected, .invalid:
            if connectionRequested && previous != next {
                connectionRequested = false
                error = "VPN 连接已中断。请检查服务器、凭据和 TLS 设置。"
            }
        default:
            break
        }
    }

    private func queryActiveTransport() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(Data("cuven.active-transport".utf8)) { [weak self] response in
            guard let response, let selected = VPNTransport(rawValue: String(decoding: response, as: UTF8.self)) else {
                return
            }
            Task { @MainActor in
                guard let self, self.status == .connected, self.manager?.connection === session else { return }
                self.activeTransport = selected
            }
        }
    }

    func selectTransport(_ selected: VPNTransport) {
        guard canEdit, selected != transport else { return }
        transport = selected
        clearCredentials()
        if let enrollment = enrollments[selected] {
            apply(enrollment.profile)
        } else {
            host = ""
            port = String(selected.defaultPort)
            serverName = ""
            dns = VPNProfile.defaultDNSServers.joined(separator: ", ")
            tunnelAddresses = ""
            peerPublicKey = ""
            useCustomDNS = false
            autoConnect = .off
            requirePostQuantum = false
            blockLAN = false
            preventBypass = false
            highSecurity = false
            blockAppUDP = false
        }
        refreshCredential()
        error = nil
    }

    @discardableResult
    func importURI(_ uri: String) -> Bool {
        guard canEdit else { return false }
        do {
            let result = try VPNProfile.importURI(uri)
            selectTransport(.hy2)
            host = result.profile.host
            port = String(result.profile.port)
            serverName = result.profile.serverName ?? ""
            credential = result.credential
            error = nil
            return true
        } catch {
            self.error = error.localizedDescription
            return false
        }
    }

    func save(connect: Bool) async {
        guard canStart, let manager else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let profile = try draftProfile()
            if profile != savedProfile || hasNewCredential || wantsFallback != savedAutomaticFallback ||
                autoConnectPaused || !manager.isEnabled {
                try await persist(profile, manager: manager)
            }
            refreshStatus()
            if connect && (status == .invalid || status == .disconnected) {
                try manager.connection.startVPNTunnel()
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
                autoConnectPaused = true
            } catch {
                manager.isOnDemandEnabled = true
                self.error = "无法暂停自动连接。\(error.localizedDescription)"
                return
            }
        }
        connectionRequested = false
        manager.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func persist(_ profile: VPNProfile, manager: NETunnelProviderManager) async throws {
        let profileData = try JSONEncoder().encode(profile)
        let previous = manager.protocolConfiguration as? NETunnelProviderProtocol
        let previousReference = enrollments[profile.transport]?.reference
        let fallback = wantsFallback
        var providerConfiguration: [String: Any] = [
            TunnelConfiguration.profileKey: profileData,
            TunnelConfiguration.automaticFallbackKey: fallback
        ]
        if let alternate = enrollments.values.first(where: { $0.profile.transport != profile.transport }) {
            providerConfiguration[TunnelConfiguration.alternateProfileKey] = try JSONEncoder().encode(alternate.profile)
            providerConfiguration[TunnelConfiguration.alternateCredentialKey] = alternate.reference
        }
        let reference: Data
        if hasNewCredential {
            reference = try KeychainCredential.store(newCredential())
        } else if let previousReference {
            _ = try KeychainCredential.load(reference: previousReference)
            reference = previousReference
        } else {
            throw CredentialError.missing
        }

        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = TunnelConfiguration.providerBundleIdentifier
        configuration.serverAddress = profile.endpoint
        configuration.passwordReference = reference
        providerConfiguration[TunnelConfiguration.credentialKey] = reference
        configuration.providerConfiguration = providerConfiguration
        configuration.includeAllNetworks = profile.highSecurity || profile.preventBypass
        configuration.enforceRoutes = profile.blockLAN && !configuration.includeAllNetworks
        configuration.excludeLocalNetworks = !profile.highSecurity && !profile.blockLAN
        if profile.highSecurity {
            configuration.excludeAPNs = false
            configuration.excludeCellularServices = false
        }

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
            if reference != previousReference { KeychainCredential.remove(reference: reference) }
            throw error
        }
        if let previousReference, previousReference != reference {
            KeychainCredential.remove(reference: previousReference)
        }
        hasCredential = true
        clearCredentials()
        enrollments[profile.transport] = Enrollment(profile: profile, reference: reference)
        savedProfile = profile
        savedAutomaticFallback = fallback
        automaticFallback = fallback
        autoConnectPaused = false
        apply(profile)
        try await manager.loadFromPreferences()
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

    private static func credentialReference(in configuration: NETunnelProviderProtocol) -> Data? {
        configuration.passwordReference
            ?? configuration.providerConfiguration?[TunnelConfiguration.credentialKey] as? Data
    }

    private func draftProfile() throws -> VPNProfile {
        let wireGuard: WireGuardProfile?
        if transport == .cuvenWG {
            wireGuard = try WireGuardProfile(
                tunnelAddresses: Self.splitList(tunnelAddresses),
                peerPublicKey: peerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
            ).validated()
        } else {
            wireGuard = nil
        }
        return try VPNProfile(
            host: host, transport: transport, wireGuard: wireGuard, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? 0,
            serverName: serverName, customDNSServers: Self.splitList(dns), useCustomDNS: useCustomDNS,
            autoConnect: autoConnect, requirePostQuantum: requirePostQuantum,
            blockLAN: blockLAN, preventBypass: preventBypass, highSecurity: highSecurity, blockAppUDP: blockAppUDP
        )
    }

    private func newCredential() throws -> String {
        switch transport {
        case .hy2:
            return credential
        case .cuvenWG:
            let preshared = presharedKey.trimmingCharacters(in: .whitespacesAndNewlines)
            return try WireGuardCredential(
                privateKey: privateKey.trimmingCharacters(in: .whitespacesAndNewlines),
                relayKey: relayKey.trimmingCharacters(in: .whitespacesAndNewlines),
                presharedKey: preshared.isEmpty ? nil : preshared
            ).encoded()
        }
    }

    private func clearCredentials() {
        credential = ""
        privateKey = ""
        relayKey = ""
        presharedKey = ""
    }

    private func refreshCredential() {
        guard let reference = enrollments[transport]?.reference else {
            hasCredential = false
            return
        }
        hasCredential = (try? KeychainCredential.load(reference: reference)) != nil
    }

    private static func splitList(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init)
    }

    private func apply(_ profile: VPNProfile) {
        transport = profile.transport
        tunnelAddresses = profile.wireGuard?.tunnelAddresses.joined(separator: ", ") ?? ""
        peerPublicKey = profile.wireGuard?.peerPublicKey ?? ""
        host = profile.host
        port = String(profile.port)
        serverName = profile.serverName ?? ""
        dns = profile.customDNSServers.joined(separator: ", ")
        useCustomDNS = profile.useCustomDNS
        autoConnect = profile.autoConnect
        requirePostQuantum = profile.requirePostQuantum
        blockLAN = profile.blockLAN
        preventBypass = profile.preventBypass
        highSecurity = profile.highSecurity
        blockAppUDP = profile.blockAppUDP
    }
}
