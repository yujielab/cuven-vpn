import Foundation
import Network
import NetworkExtension
import CuvenCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let state = DispatchQueue(label: "dev.cuven.vpn.state", qos: .userInitiated)
    private let worker = DispatchQueue(label: "dev.cuven.vpn.core", qos: .userInitiated, attributes: .concurrent)
    private var session: Session?
    private var packetReadPending = false

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        state.async {
            do {
                try self.begin(completionHandler: completionHandler)
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        state.async {
            guard let session = self.session else {
                completionHandler()
                return
            }
            self.session = nil
            self.reasserting = false
            session.cancelMonitoring()
            session.finishStart(TunnelFailure.cancelled)
            let engine = session.takeEngine()
            self.worker.async {
                engine?.stop()
                completionHandler()
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard messageData == Data("cuven.active-transport".utf8) else {
            completionHandler?(nil)
            return
        }
        state.async {
            guard let session = self.session, session.ready else {
                completionHandler?(nil)
                return
            }
            completionHandler?(Data(session.current.profile.transport.rawValue.utf8))
        }
    }

    private func begin(completionHandler: @escaping (Error?) -> Void) throws {
        guard session == nil, let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              let values = configuration.providerConfiguration,
              let profileData = values[TunnelConfiguration.profileKey] as? Data,
              let credential = configuration.passwordReference ?? values[TunnelConfiguration.credentialKey] as? Data else {
            throw TunnelFailure.configuration
        }
        let profile = try VPNProfile.decode(profileData)
        if profile.highSecurity {
            guard configuration.includeAllNetworks, !configuration.excludeLocalNetworks,
                  !configuration.excludeAPNs, !configuration.excludeCellularServices else {
                throw TunnelFailure.strictRouting
            }
        }
        let primary = try ConnectionProfile(profile: profile, reference: credential)
        var alternate: ConnectionProfile?
        if values[TunnelConfiguration.automaticFallbackKey] as? Bool == true,
           !profile.highSecurity, !profile.requirePostQuantum,
           let alternateData = values[TunnelConfiguration.alternateProfileKey] as? Data,
           let reference = values[TunnelConfiguration.alternateCredentialKey] as? Data,
           let alternateProfile = try? VPNProfile.decode(alternateData),
           !alternateProfile.highSecurity, alternateProfile.transport != profile.transport {
            alternate = try? ConnectionProfile(profile: alternateProfile, reference: reference)
        }
        let session = Session(primary: primary, alternate: alternate, completion: completionHandler)
        self.session = session
        resolve(session)
    }

    private func resolve(_ session: Session) {
        let profile = session.current.profile
        if profile.highSecurity {
            session.endpoints = [profile.endpoint]
            connect(session)
            return
        }
        let endpointLimit = session.endpointLimit
        worker.async {
            let resolved = TunnelEndpoint.resolve(host: profile.host, port: profile.port)
            self.state.async {
                guard self.session === session else { return }
                guard !resolved.isEmpty else {
                    self.tryFallback(session, failure: .resolution)
                    return
                }
                session.endpoints = Array(resolved.prefix(endpointLimit))
                self.connect(session)
            }
        }
    }

    private func tryFallback(_ session: Session, failure: TunnelFailure) {
        guard let alternate = session.alternate else {
            terminate(session, failure: failure)
            return
        }
        session.alternate = nil
        session.current = alternate
        session.endpoints = []
        session.nextEndpoint = 0
        resolve(session)
    }

    private func connect(_ session: Session) {
        let instance: MobileEngine? = MobileNewEngine()
        guard let engine = instance else {
            terminate(session, failure: .connection)
            return
        }
        let endpoint = session.endpoints[session.nextEndpoint % session.endpoints.count]
        session.nextEndpoint += 1
        session.engine = engine
        if !session.routesInstalled && (session.nextEndpoint < session.endpoints.count || session.alternate != nil) {
            let deadline = DispatchWorkItem { [weak self, weak session, weak engine] in
                guard let self, let session, let engine, self.session === session, session.engine === engine else {
                    return
                }
                self.connectionFailed(session)
            }
            session.attemptDeadline = deadline
            state.asyncAfter(deadline: .now() + .seconds(8), execute: deadline)
        }
        let connection = session.current
        let blockLAN = session.blockLAN
        worker.async {
            let connected: Bool
            do {
                switch connection.auth {
                case .hy2(let password):
                    try engine.start(
                        endpoint,
                        auth: password,
                        serverName: connection.profile.serverName ?? connection.profile.host,
                        receiveBytesPerSecond: 0,
                        mtu: Int64(TunnelConfiguration.mtu),
                        requirePostQuantum: connection.profile.requirePostQuantum,
                        blockLAN: blockLAN,
                        highSecurity: connection.profile.highSecurity
                    )
                case .wireGuard(let keys, let peerPublicKey):
                    try engine.startWireGuard(
                        endpoint,
                        privateKey: keys.privateKey,
                        peerPublicKey: peerPublicKey,
                        presharedKey: keys.presharedKey ?? "",
                        transportKey: keys.relayKey,
                        mtu: Int64(TunnelConfiguration.mtu),
                        blockLAN: blockLAN,
                        camouflage: connection.profile.highSecurity
                    )
                }
                connected = true
            } catch {
                connected = false
            }
            self.state.async {
                guard self.session === session, session.engine === engine else { return }
                session.clearAttemptDeadline()
                guard connected else {
                    self.connectionFailed(session)
                    return
                }
                // Reuse the address that worked, and alternate addresses if reconnect fails.
                session.nextEndpoint -= 1
                if session.routesInstalled {
                    self.activate(session, engine: engine)
                } else {
                    self.installRoutes(session, engine: engine)
                }
            }
        }
    }

    private func installRoutes(_ session: Session, engine: MobileEngine) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Route both families so unsupported traffic cannot escape a single-stack tunnel.
        let plan = session.current.plan
        let v4 = plan.ipv4 ?? TunnelNetworkPlan.placeholderIPv4
        let v6 = plan.ipv6 ?? TunnelNetworkPlan.placeholderIPv6
        let ipv4 = NEIPv4Settings(addresses: [v4.host], subnetMasks: [v4.ipv4Mask])
        ipv4.includedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: [v6.host], networkPrefixLengths: [NSNumber(value: v6.prefix)])
        ipv6.includedRoutes = [.default()]
        settings.ipv6Settings = ipv6
        let dns: NEDNSSettings
        if let url = plan.dnsOverHTTPSURL {
            let encrypted = NEDNSOverHTTPSSettings(servers: plan.dnsServers)
            encrypted.serverURL = url
            if #available(iOS 26.0, *) {
                encrypted.allowFailover = false
            }
            dns = encrypted
        } else {
            dns = NEDNSSettings(servers: plan.dnsServers)
        }
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: TunnelConfiguration.mtu)
        setTunnelNetworkSettings(settings) { error in
            self.state.async {
                guard self.session === session, session.engine === engine else { return }
                guard error == nil else {
                    self.terminate(session, failure: .settings)
                    return
                }
                session.routesInstalled = true
                self.startPathMonitor(session)
                self.activate(session, engine: engine)
            }
        }
    }

    private func activate(_ session: Session, engine: MobileEngine) {
        session.alternate = nil
        session.ready = true
        session.connectedAt = .now()
        reasserting = false
        schedulePacketRead()
        readFromCore(session, engine: engine)
        session.finishStart(nil)
    }

    private func schedulePacketRead() {
        guard !packetReadPending, let session, session.routesInstalled else { return }
        packetReadPending = true
        let sessionID = session.id
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.state.async {
                self.packetReadPending = false
                if let session = self.session, session.id == sessionID, session.ready, let engine = session.engine {
                    self.writeToCore(packets, session: session, engine: engine)
                }
                self.schedulePacketRead()
            }
        }
    }

    private func writeToCore(_ packets: [Data], session: Session, engine: MobileEngine) {
        for start in stride(from: 0, to: packets.count, by: PacketBatch.maxPackets) {
            let end = min(start + PacketBatch.maxPackets, packets.count)
            let batch = PacketBatch.encode(
                packets[start..<end],
                mtu: TunnelConfiguration.mtu,
                allowIPv4: session.current.plan.ipv4 != nil,
                allowIPv6: session.current.plan.ipv6 != nil
            )
            guard !batch.isEmpty else { continue }
            do {
                try engine.writeBatch(batch)
            } catch {
                connectionFailed(session)
                return
            }
        }
    }

    private func readFromCore(_ session: Session, engine: MobileEngine) {
        worker.async {
            let batch: Data? = try? engine.readBatch()
            self.state.async {
                guard self.session === session, session.engine === engine else { return }
                guard let batch else {
                    self.connectionFailed(session)
                    return
                }
                if let decoded = PacketBatch.decode(batch, mtu: TunnelConfiguration.mtu) {
                    _ = self.packetFlow.writePackets(decoded.packets, withProtocols: decoded.protocols)
                } else {
                    if session.current.profile.highSecurity {
                        self.connectionFailed(session)
                    } else {
                        self.terminate(session, failure: .packetFormat)
                    }
                    return
                }
                self.readFromCore(session, engine: engine)
            }
        }
    }

    private func connectionFailed(_ session: Session) {
        let engine = session.takeEngine()
        worker.async { engine?.stop() }
        if !session.routesInstalled {
            if session.nextEndpoint < session.endpoints.count {
                connect(session)
            } else {
                tryFallback(session, failure: .connection)
            }
            return
        }

        reasserting = true
        if let connectedAt = session.connectedAt, .now() >= connectedAt + .seconds(30) {
            session.reconnectAttempts = 0
        }
        session.connectedAt = nil
        scheduleReconnect(session)
    }

    private func startPathMonitor(_ session: Session) {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self, weak session] path in
            guard let self, let session, self.session === session else { return }
            self.pathChanged(path, session: session)
        }
        session.monitor = monitor
        monitor.start(queue: state)
    }

    private func pathChanged(_ path: Network.NWPath, session: Session) {
        let available = path.status != .unsatisfied
        let interface = path.availableInterfaces.first { interface in
            switch interface.type {
            case .wifi, .cellular, .wiredEthernet:
                path.usesInterfaceType(interface.type)
            default:
                false
            }
        }?.name
        let previous = session.path
        let newPath = Session.PhysicalPath(available: available, interface: interface ?? previous?.interface)
        session.path = newPath
        guard let previous else { return }
        if available {
            let switchedInterface = previous.interface != nil && interface != nil && previous.interface != interface
            guard !previous.available || switchedInterface else { return }
            session.reconnectAttempts = 0
        }

        session.pendingRetry?.cancel()
        session.pendingRetry = nil
        if session.engine != nil {
            connectionFailed(session)
        } else {
            scheduleReconnect(session)
        }
    }

    private func scheduleReconnect(_ session: Session) {
        guard session.path?.available != false, session.pendingRetry == nil else { return }
        guard session.current.profile.highSecurity || session.reconnectAttempts < 3 else {
            terminate(session, failure: .disconnected)
            return
        }
        let delay = min(1 << session.reconnectAttempts, 30)
        let retry = DispatchWorkItem { [weak self, weak session] in
            guard let self, let session, self.session === session else { return }
            session.pendingRetry = nil
            session.reconnectAttempts = min(session.reconnectAttempts + 1, 5)
            self.connect(session)
        }
        session.pendingRetry = retry
        state.asyncAfter(deadline: .now() + .seconds(delay), execute: retry)
    }

    private func terminate(_ session: Session, failure: TunnelFailure) {
        self.session = nil
        reasserting = false
        session.cancelMonitoring()
        let engine = session.takeEngine()
        worker.async { engine?.stop() }
        if session.routesInstalled {
            cancelTunnelWithError(failure)
        } else {
            session.finishStart(failure)
        }
    }
}

private struct ConnectionProfile {
    enum Authentication {
        case hy2(String)
        case wireGuard(WireGuardCredential, peerPublicKey: String)
    }

    let profile: VPNProfile
    let auth: Authentication
    let plan: TunnelNetworkPlan

    init(profile: VPNProfile, reference: Data) throws {
        let secret = try KeychainCredential.load(reference: reference)
        self.profile = profile
        switch profile.transport {
        case .hy2:
            auth = .hy2(secret)
        case .cuvenWG:
            guard let wireGuard = profile.wireGuard, let keys = try? WireGuardCredential.decode(secret) else {
                throw TunnelFailure.configuration
            }
            auth = .wireGuard(keys, peerPublicKey: wireGuard.peerPublicKey)
        }
        plan = try TunnelNetworkPlan(profile: profile)
    }
}

private final class Session {
    struct PhysicalPath {
        let available: Bool
        let interface: String?
    }

    let id = UUID()
    let blockLAN: Bool
    let endpointLimit: Int
    var current: ConnectionProfile
    var alternate: ConnectionProfile?
    private var completion: ((Error?) -> Void)?
    var engine: MobileEngine?
    var endpoints: [String] = []
    var nextEndpoint = 0
    var routesInstalled = false
    var ready = false
    var connectedAt: DispatchTime?
    var reconnectAttempts = 0
    var monitor: NWPathMonitor?
    var path: PhysicalPath?
    var pendingRetry: DispatchWorkItem?
    var attemptDeadline: DispatchWorkItem?

    init(primary: ConnectionProfile, alternate: ConnectionProfile?, completion: @escaping (Error?) -> Void) {
        current = primary
        self.alternate = alternate
        blockLAN = primary.profile.blockLAN || primary.profile.highSecurity
        endpointLimit = alternate == nil ? 3 : 2
        self.completion = completion
    }

    func finishStart(_ error: Error?) {
        let callback = completion
        completion = nil
        callback?(error)
    }

    func clearAttemptDeadline() {
        attemptDeadline?.cancel()
        attemptDeadline = nil
    }

    func takeEngine() -> MobileEngine? {
        clearAttemptDeadline()
        let current = engine
        engine = nil
        ready = false
        return current
    }

    func cancelMonitoring() {
        monitor?.cancel()
        pendingRetry?.cancel()
        monitor = nil
        pendingRetry = nil
    }
}

private enum TunnelFailure: Int, LocalizedError, CustomNSError {
    case configuration = 1, resolution, connection, settings, disconnected, packetFormat, cancelled
    case strictRouting

    static let errorDomain = "dev.cuven.vpn.tunnel"
    var errorCode: Int { rawValue }
    var errorUserInfo: [String: Any] { [NSLocalizedDescriptionKey: errorDescription ?? "隧道错误。"] }

    var errorDescription: String? {
        switch self {
        case .configuration: "VPN 配置无效，请在 Cuven 中重新保存。"
        case .resolution: "无法解析 VPN 服务器地址。"
        case .connection: "无法连接 VPN 服务器，请检查地址、凭据和服务端配置。"
        case .settings: "无法应用系统 VPN 路由或 DNS 设置。"
        case .disconnected: "VPN 连接已断开，且无法恢复。"
        case .packetFormat: "隧道核心返回了无效的数据包。"
        case .cancelled: "VPN 连接已取消。"
        case .strictRouting: "高安全模式的系统 VPN 路由配置不完整，请在 Cuven 中重新保存。"
        }
    }
}
