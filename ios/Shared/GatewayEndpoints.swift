import Foundation

/// The provider owns this state on its serial queue. A lookup may finish after
/// the active path changed or after an attempt using the old list succeeded.
struct GatewayEndpoints {
    private enum StartupResolution { case current, stale, retried }
    private var startupResolution = StartupResolution.current
    private var startupGatewayFailure: TunnelFailure?
    private(set) var exhaustedStartupFailure: TunnelFailure?
    private var addresses: [String] = []
    private var nextIndex = 0
    private var pathID = UUID()
    private var lookupPaths: [UUID: UUID] = [:]
    private var nextLookup: DispatchTime?

    var hasUntriedAddress: Bool { nextIndex < addresses.count }

    mutating func replace(with resolved: [String]) {
        let fresh = Array(resolved.prefix(3))
        guard !fresh.isEmpty, fresh != addresses else { return }
        addresses = fresh
        nextIndex = 0
    }

    mutating func next() -> String? {
        guard !addresses.isEmpty else { return nil }
        let address = addresses[nextIndex % addresses.count]
        nextIndex += 1
        return address
    }

    mutating func prefer(_ address: String) {
        if let index = addresses.firstIndex(of: address) { nextIndex = index }
    }

    /// A later unreachable address must not hide a response from a reachable gateway.
    mutating func recordStartupFailure(_ failure: TunnelFailure) -> TunnelFailure {
        switch failure {
        case .certificateName, .certificateTime, .certificateTrust, .certificatePin, .gatewayRejected, .gatewayBusy, .gatewayIPv6:
            startupGatewayFailure = failure
        case .connection, .gatewayTimeout:
            return startupGatewayFailure ?? failure
        default:
            break
        }
        return failure
    }

    mutating func pathChanged(whileResolving: Bool = false) {
        startupGatewayFailure = nil
        if exhaustedStartupFailure != nil {
            // An address already tried on the old link can work on the new one.
            exhaustedStartupFailure = nil
            addresses.removeAll()
            nextIndex = 0
        }
        if startupResolution == .current && !whileResolving { startupResolution = .stale }
        pathID = UUID()
        nextLookup = nil
    }

    /// A changed path can retry all answers. On the same path, do one last
    /// lookup after exhausting the list, and dial only newly returned addresses.
    mutating func retryStartupResolution(after failure: TunnelFailure) -> Bool {
        guard startupResolution != .retried, failure == .connection || failure == .gatewayTimeout else {
            return false
        }
        if startupResolution == .current {
            guard !addresses.isEmpty, !hasUntriedAddress, startupGatewayFailure == nil else { return false }
            exhaustedStartupFailure = failure
        } else {
            startupGatewayFailure = nil
            addresses.removeAll()
            nextIndex = 0
        }
        startupResolution = .retried
        return true
    }

    mutating func installStartupAnswers(_ resolved: [String]) -> TunnelFailure? {
        guard let failure = exhaustedStartupFailure else {
            replace(with: resolved)
            return nil
        }
        exhaustedStartupFailure = nil
        let tried = Set(addresses)
        let answer = resolved.prefix(3)
        let newAddresses = answer.filter { !tried.contains($0) }
        guard !newAddresses.isEmpty else { return failure }
        // Keep known addresses available for rotation once the tunnel is up.
        let previous = answer.filter(tried.contains)
        addresses = previous + newAddresses
        nextIndex = previous.count
        return nil
    }

    mutating func beginRefresh(now: DispatchTime = .now()) -> UUID? {
        // Allow a new path to resolve while getaddrinfo on its predecessor is
        // still blocked. Bound the work even if interfaces keep changing.
        guard lookupPaths.count < 2, !lookupPaths.values.contains(pathID) else { return nil }
        if let nextLookup, now < nextLookup { return nil }
        let id = UUID()
        lookupPaths[id] = pathID
        nextLookup = now + .seconds(60)
        return id
    }

    mutating func finishRefresh(_ id: UUID, with resolved: [String]) {
        guard lookupPaths.removeValue(forKey: id) == pathID else { return }
        replace(with: resolved)
    }
}
