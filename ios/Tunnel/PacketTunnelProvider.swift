import Foundation
import Network
import NetworkExtension
import Security
import CuvenCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let state = DispatchQueue(label: "dev.cuven.vpn.state", qos: .userInitiated)
    private let worker = DispatchQueue(label: "dev.cuven.vpn.core", qos: .userInitiated, attributes: .concurrent)
    private lazy var startupResolver = GatewayStartupResolver(state: state, lookup: TunnelEndpoint.resolve)
    private var session: Session?
    private var packetReadPending = false

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        state.async {
            do {
                try self.begin(options: options, completionHandler: completionHandler)
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
            self.startupResolver.cancel()
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

    override func sleep(completionHandler: @escaping () -> Void) {
        state.async {
            if let session = self.session, session.ready { session.sleepInterval.begin() }
            completionHandler()
        }
    }

    override func wake() {
        state.async {
            guard let session = self.session, session.sleepInterval.needsReconnectOnWake(),
                  session.ready else { return }
            session.reconnectAttempts = 0
            self.connectionFailed(session)
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        state.async {
            guard messageData == TunnelConfiguration.rttRequest,
                  let session = self.session, session.ready, let engine = session.engine else {
                completionHandler?(nil)
                return
            }
            let rtt = engine.rttMilliseconds()
            completionHandler?(rtt < 0 ? nil : Data(String(rtt).utf8))
        }
    }

    private func begin(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) throws {
        guard session == nil, let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              let values = configuration.providerConfiguration,
              let profile = TunnelConfiguration.storedProfile(in: values) else {
            throw TunnelFailure.configuration
        }
        guard profile.transport == .cuven else { throw TunnelFailure.configuration }
        guard configuration.hasRequiredRouting(for: profile) else { throw TunnelFailure.strictRouting }
        let token: String
        let reference = configuration.passwordReference ?? values[TunnelConfiguration.credentialKey] as? Data
        let sessionID = values[AppCredentialHandoff.sessionIDKey] as? Data
        if values[AppCredentialHandoff.modeKey] as? Bool == true {
            do {
                token = try AppCredentialHandoff.token(options: options, storedReference: reference, sessionID: sessionID, autoConnect: profile.autoConnect)
            } catch {
                throw TunnelFailure.manualCredential
            }
        } else {
            guard let reference, sessionID == nil else { throw TunnelFailure.configuration }
            do {
                token = try KeychainCredential.load(reference: reference)
            } catch CredentialError.keychain(errSecMissingEntitlement) {
                throw TunnelFailure.credentialEntitlement
            } catch CredentialError.keychain(errSecInteractionNotAllowed) {
                throw TunnelFailure.credentialLocked
            } catch CredentialError.keychain(errSecItemNotFound), CredentialError.missing {
                throw TunnelFailure.credentialUnavailable
            }
        }
        let connection = try ConnectionProfile(profile: profile, token: token)
        let session = Session(connection: connection, completion: completionHandler)
        self.session = session
        resolve(session)
    }

    private func resolve(_ session: Session) {
        let profile = session.current.profile
        if profile.requiresStrictRouting {
            session.endpoints.replace(with: [profile.endpoint])
            connect(session)
            return
        }
        if session.monitor == nil && !VPNProfile.isIP(profile.host) { startPathMonitor(session) }
        startupResolver.start(host: profile.host, port: profile.port, available: session.path?.available != false) { [weak self, weak session] result in
            guard let self, let session, self.session === session else { return }
            switch result {
            case .success(let resolved):
                if let failure = session.endpoints.installStartupAnswers(resolved) {
                    self.terminate(session, failure: failure)
                } else {
                    self.connect(session)
                }
            case .failure(let reason):
                self.terminate(session, failure: session.endpoints.exhaustedStartupFailure ?? reason)
            }
        }
    }

    private func refreshReconnectEndpoints(_ session: Session) {
        let profile = session.current.profile
        guard session.routesInstalled, session.path?.available != false,
              !profile.requiresStrictRouting, !VPNProfile.isIP(profile.host),
              let lookup = session.endpoints.beginRefresh() else { return }
        worker.async {
            let fresh = TunnelEndpoint.resolve(host: profile.host, port: profile.port)
            self.state.async {
                guard self.session === session else { return }
                let added = session.endpoints.finishRefresh(lookup, with: session.ready ? [] : fresh)
                guard added, session.path?.available != false, session.engine == nil,
                      let pending = session.pendingRetry else { return }
                pending.cancel()
                session.pendingRetry = nil
                self.scheduleReconnect(session, after: 0)
            }
        }
    }

    private func connect(_ session: Session, to retryEndpoint: String? = nil) {
        let instance: MobileEngine? = MobileNewEngine()
        guard let engine = instance else {
            terminate(session, failure: .connection)
            return
        }
        guard let endpoint = retryEndpoint ?? session.endpoints.next() else {
            connectionFailed(session, failure: .resolution)
            return
        }
        session.engine = engine
        if !session.routesInstalled && session.endpoints.hasUntriedAddress {
            let deadline = DispatchWorkItem { [weak self, weak session, weak engine] in
                guard let self, let session, let engine, self.session === session, session.engine === engine else {
                    return
                }
                self.connectionFailed(session, endpoint: endpoint)
            }
            session.attemptDeadline = deadline
            state.asyncAfter(deadline: .now() + .seconds(8), execute: deadline)
        }
        let connection = session.current
        let blockLAN = session.blockLAN
        worker.async {
            let failure: TunnelFailure?
            do {
                if connection.profile.requiresEncryptedDNS {
                    try engine.requireEncryptedDNS()
                }
                if connection.profile.lockdown {
                    guard let pin = connection.profile.gatewayKeyPin else { throw ProfileError.gatewayKeyPin }
                    try engine.pinGatewayPublicKey(pin)
                }
                let code = engine.startCuvenDiagnosed(
                    endpoint, accessToken: connection.token,
                    serverName: connection.profile.serverName ?? connection.profile.host,
                    requireIPv6: connection.profile.cuvenIPv6,
                    blockLAN: blockLAN
                )
                failure = TunnelFailure.fromStartupCode(code)
            } catch {
                failure = .connection
            }
            self.state.async {
                guard self.session === session, session.engine === engine else { return }
                session.clearAttemptDeadline()
                if let failure {
                    if failure == .gatewayTimeout || failure == .connection {
                        self.refreshReconnectEndpoints(session)
                    }
                    self.connectionFailed(session, failure: failure, endpoint: endpoint)
                    return
                }
                // Reuse the address that worked, and alternate addresses if reconnect fails.
                session.endpoints.prefer(endpoint)
                let mtu = Int(engine.packetMTU())
                guard mtu == TunnelConfiguration.legacyMTU || mtu == TunnelConfiguration.maximumMTU else {
                    self.connectionFailed(session, failure: .settings)
                    return
                }
                if session.packetFlowState.needsSettings(mtu: mtu) {
                    self.installRoutes(session, engine: engine, mtu: mtu)
                } else {
                    self.activate(session, engine: engine)
                }
            }
        }
    }

    private func installRoutes(_ session: Session, engine: MobileEngine, mtu: Int) {
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
        switch plan.dnsMode {
        case .https(let url):
            let encrypted = NEDNSOverHTTPSSettings(servers: plan.dnsServers)
            encrypted.serverURL = url
            dns = encrypted
        case .tls(let name):
            let encrypted = NEDNSOverTLSSettings(servers: plan.dnsServers)
            encrypted.serverName = name
            dns = encrypted
        case .cleartext:
            dns = NEDNSSettings(servers: plan.dnsServers)
        }
        if #available(iOS 26.0, *), session.current.profile.requiresEncryptedDNS {
            dns.allowFailover = false
        }
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: mtu)
        setTunnelNetworkSettings(settings) { error in
            self.state.async {
                guard self.session === session, session.engine === engine else { return }
                guard error == nil else {
                    if session.routesInstalled && session.retainsRoutesOnFailure {
                        self.connectionFailed(session, failure: .settings)
                    } else {
                        self.terminate(session, failure: .settings)
                    }
                    return
                }
                session.packetFlowState.didApplySettings(mtu: mtu)
                if session.monitor == nil { self.startPathMonitor(session) }
                self.activate(session, engine: engine)
            }
        }
    }

    private func activate(_ session: Session, engine: MobileEngine) {
        session.ready = true
        session.busyRetry = GatewayBusyRetry()
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
                guard let session = self.session, session.id == sessionID, session.ready,
                      let engine = session.engine, let mtu = session.packetFlowState.mtu else {
                    self.finishPacketRead()
                    return
                }
                let plan = session.current.plan
                // QUIC can block a writer under congestion. Keep one read in
                // flight while leaving the state queue free to stop the engine.
                self.worker.async {
                    let sent = Result {
                        try PacketBatch.send(packets, mtu: mtu, plan: plan) { try engine.writeBatch($0) }
                    }
                    self.state.async {
                        if case .failure = sent, self.session === session, session.engine === engine {
                            self.connectionFailed(session)
                        }
                        self.finishPacketRead()
                    }
                }
            }
        }
    }

    private func finishPacketRead() {
        packetReadPending = false
        schedulePacketRead()
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
                if let mtu = session.packetFlowState.mtu, let decoded = PacketBatch.decode(batch, mtu: mtu) {
                    let written = self.packetFlow.writePackets(decoded.packets, withProtocols: decoded.protocols)
                    // A batch may have been partly delivered. Do not replay it.
                    if session.packetFlowState.shouldRecoverAfterWrite(succeeded: written) {
                        self.connectionFailed(session, failure: .settings)
                        return
                    }
                } else {
                    if session.retainsRoutesOnFailure {
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

    private func connectionFailed(_ session: Session, failure: TunnelFailure = .connection, endpoint: String? = nil) {
        let engine = session.takeEngine()
        worker.async { engine?.stop() }
        if !session.routesInstalled {
            let report = session.endpoints.recordStartupFailure(failure, at: endpoint)
            let profile = session.current.profile
            if !profile.requiresStrictRouting, !VPNProfile.isIP(profile.host),
               session.endpoints.retryStartupResolution(after: failure) {
                resolve(session)
            } else if session.endpoints.hasUntriedAddress {
                connect(session)
            } else if report == .gatewayBusy, let busyEndpoint = session.endpoints.startupBusyEndpoint,
                      failure == .gatewayBusy || busyEndpoint != endpoint, session.path?.available != false,
                      let delay = session.busyRetry.delay(for: report, routesInstalled: false) {
                scheduleRetry(session, after: delay, to: busyEndpoint)
            } else {
                terminate(session, failure: report)
            }
            return
        }

        reasserting = true
        if let connectedAt = session.connectedAt, .now() >= connectedAt + .seconds(30) {
            session.reconnectAttempts = 0
        }
        session.connectedAt = nil
        guard session.path?.available != false else { return }
        scheduleReconnect(session, after: session.busyRetry.delay(for: failure, routesInstalled: true))
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
        if let previous {
            if available {
                let switchedInterface = previous.interface != nil && interface != nil && previous.interface != interface
                guard !previous.available || switchedInterface else { return }
                session.reconnectAttempts = 0
            }
        } else if available || session.routesInstalled {
            return
        }

        session.endpoints.pathChanged(whileResolving: startupResolver.isPending)
        if startupResolver.isPending {
            startupResolver.pathChanged(available: available)
            return
        }
        guard session.routesInstalled else {
            // A delayed busy retry still belongs to the previous physical path.
            let profile = session.current.profile
            if let pending = session.pendingRetry, !profile.requiresStrictRouting, !VPNProfile.isIP(profile.host),
               session.endpoints.retryStartupResolution(after: .connection) {
                pending.cancel()
                session.pendingRetry = nil
                resolve(session)
            }
            return
        }
        session.pendingRetry?.cancel()
        session.pendingRetry = nil
        if session.engine != nil {
            connectionFailed(session)
        } else {
            scheduleReconnect(session)
        }
    }

    private func scheduleReconnect(_ session: Session, after delay: Int? = nil) {
        guard session.path?.available != false, session.pendingRetry == nil else { return }
        guard session.retainsRoutesOnFailure || session.reconnectAttempts < 3 else {
            terminate(session, failure: .disconnected)
            return
        }
        scheduleRetry(session, after: delay ?? min(1 << session.reconnectAttempts, 30))
    }

    private func scheduleRetry(_ session: Session, after delay: Int, to endpoint: String? = nil) {
        let retry = DispatchWorkItem { [weak self, weak session] in
            guard let self, let session, self.session === session else { return }
            session.pendingRetry = nil
            if session.path?.available == false {
                if !session.routesInstalled { self.terminate(session, failure: .connection) }
                return
            }
            if session.routesInstalled {
                session.reconnectAttempts = min(session.reconnectAttempts + 1, 5)
            }
            self.connect(session, to: endpoint)
        }
        session.pendingRetry = retry
        state.asyncAfter(deadline: .now() + .seconds(delay), execute: retry)
    }

    private func terminate(_ session: Session, failure: TunnelFailure) {
        startupResolver.cancel()
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
    let profile: VPNProfile
    let token: String
    let plan: TunnelNetworkPlan

    init(profile: VPNProfile, token: String) throws {
        try VPNProfile.validateAccessToken(token)
        self.profile = profile
        self.token = token
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
    let retainsRoutesOnFailure: Bool
    let current: ConnectionProfile
    private var completion: ((Error?) -> Void)?
    var engine: MobileEngine?
    var endpoints = GatewayEndpoints()
    var packetFlowState = PacketFlowState()
    var routesInstalled: Bool { packetFlowState.mtu != nil }
    var ready = false
    var sleepInterval = TunnelSleepInterval()
    var connectedAt: DispatchTime?
    var reconnectAttempts = 0
    var busyRetry = GatewayBusyRetry()
    var monitor: NWPathMonitor?
    var path: PhysicalPath?
    var pendingRetry: DispatchWorkItem?
    var attemptDeadline: DispatchWorkItem?

    init(connection: ConnectionProfile, completion: @escaping (Error?) -> Void) {
        current = connection
        blockLAN = connection.profile.blockLAN || connection.profile.requiresStrictRouting
        retainsRoutesOnFailure = connection.profile.usesFullRouting
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
        sleepInterval = TunnelSleepInterval()
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
