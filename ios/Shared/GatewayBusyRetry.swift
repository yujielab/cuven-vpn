/// The gateway can still be releasing a previous session after a handover.
/// Bound quicker retries by both count and elapsed time, including device sleep.
struct GatewayBusyRetry {
    private var firstBusy: ContinuousClock.Instant?
    private var retries = 0

    mutating func delay(for failure: TunnelFailure, routesInstalled: Bool,
                        now: ContinuousClock.Instant = .now) -> Int? {
        guard failure == .gatewayBusy else { return nil }
        let start = firstBusy ?? now
        firstBusy = start
        let limit = routesInstalled ? 8 : 3
        let window = Duration.seconds(routesInstalled ? 20 : 8)
        guard retries < limit, now.advanced(by: .seconds(2)) <= start.advanced(by: window) else {
            return nil
        }
        retries += 1
        return 2
    }
}
