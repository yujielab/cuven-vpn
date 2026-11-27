import Foundation
import NetworkExtension
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
    @Published private(set) var hasCredential = false
    @Published private(set) var status = NEVPNStatus.invalid
    @Published private(set) var tunnelRTT: Int64?
    @Published private(set) var busy = false
    @Published private(set) var loaded = false
    @Published private(set) var error: String?

    private var manager: NETunnelProviderManager?
    private var savedProfile: VPNProfile?
    private var credentialReference: Data?
    private var connectionRequested = false

    var canEdit: Bool {
        loaded && !busy && (status == .invalid || status == .disconnected)
    }

    var canStart: Bool {
        canEdit && !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            (hasCredential || hasNewCredential)
    }

    var canSave: Bool {
        guard canStart else { return false }
        return hasNewCredential || (try? draftProfile()) != savedProfile || autoConnectPaused
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
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let existing = managers.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == TunnelConfiguration.providerBundleIdentifier
            }
            manager = existing ?? NETunnelProviderManager()
            if let configuration = existing?.protocolConfiguration as? NETunnelProviderProtocol,
               let data = configuration.providerConfiguration?[TunnelConfiguration.profileKey] as? Data,
               let profile = try? VPNProfile.decode(data) {
                savedProfile = profile
                if profile.transport == .cuven {
                    credentialReference = Self.credentialReference(in: configuration)
                    apply(profile)
                    refreshCredential()
                    autoConnectPaused = profile.autoConnect != .off && existing?.isOnDemandEnabled == false
                } else {
                    if let existing, existing.isOnDemandEnabled {
                        existing.isOnDemandEnabled = false
                        try await existing.saveToPreferences()
                    }
                    error = "请填写 Cuven IP 网关和新的接入令牌。"
                }
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
        if next != .connected { tunnelRTT = nil }
        switch next {
        case .connected:
            connectionRequested = true
            error = nil
        case .disconnected, .invalid:
            if connectionRequested && previous != next {
                connectionRequested = false
                error = "VPN 连接已中断。请检查服务器、凭据和 TLS 设置。"
            }
        default:
            break
        }
    }

    func refreshTunnelRTT() {
        guard status == .connected, let session = manager?.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(TunnelConfiguration.rttRequest) { [weak self] data in
            let sample = data.flatMap { Int64(String(decoding: $0, as: UTF8.self)) }
            Task { @MainActor in
                guard let self, self.status == .connected, self.manager?.connection === session else { return }
                self.tunnelRTT = sample
            }
        }
    }

    func save(connect: Bool) async {
        guard canStart, let manager else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let profile = try draftProfile()
            if profile != savedProfile || hasNewCredential || autoConnectPaused || !manager.isEnabled {
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
        let previousReference = credentialReference
        let reference: Data
        if hasNewCredential {
            let token = credential.trimmingCharacters(in: .whitespacesAndNewlines)
            try VPNProfile.validateAccessToken(token)
            reference = try KeychainCredential.store(token)
        } else if hasCredential, let previousReference {
            let token = try KeychainCredential.load(reference: previousReference)
            try VPNProfile.validateAccessToken(token)
            reference = previousReference
        } else {
            throw CredentialError.missing
        }

        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = TunnelConfiguration.providerBundleIdentifier
        configuration.serverAddress = profile.endpoint
        configuration.passwordReference = reference
        configuration.providerConfiguration = [
            TunnelConfiguration.profileKey: profileData,
            TunnelConfiguration.credentialKey: reference
        ]
        configuration.includeAllNetworks = profile.usesFullRouting
        configuration.enforceRoutes = profile.blockLAN && !configuration.includeAllNetworks
        configuration.excludeLocalNetworks = !profile.requiresEncryptedDNS && !profile.blockLAN
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
        credential = ""
        credentialReference = reference
        savedProfile = profile
        autoConnectPaused = false
        apply(profile)
        refreshCredential()
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

    private func refreshCredential() {
        guard let credentialReference,
              let token = try? KeychainCredential.load(reference: credentialReference) else {
            hasCredential = false
            return
        }
        hasCredential = (try? VPNProfile.validateAccessToken(token)) != nil
    }

    private static func splitList(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init)
    }

    private func apply(_ profile: VPNProfile) {
        enableIPv6 = profile.cuvenIPv6
        host = profile.host
        port = String(profile.port)
        serverName = profile.serverName ?? ""
        autoConnect = profile.autoConnect
        blockLAN = profile.blockLAN
        highSecurity = profile.highSecurity
        useEncryptedDNS = profile.encryptedDNS != nil
        useDNSOverTLS = profile.encryptedDNS?.tlsServerName != nil
        encryptedDNSURL = profile.encryptedDNS?.url?.absoluteString ?? ""
        encryptedDNSTLSName = profile.encryptedDNS?.tlsServerName ?? ""
        encryptedDNSBootstrap = profile.encryptedDNS?.bootstrapServers.joined(separator: ", ") ?? ""
    }
}
