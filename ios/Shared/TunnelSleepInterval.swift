/// The continuous clock includes time spent asleep. Keep short naps on the
/// established path and renew a session after two 45-second QUIC idle periods.
struct TunnelSleepInterval {
    private var start: ContinuousClock.Instant?

    mutating func begin(at now: ContinuousClock.Instant = .now) {
        if start == nil { start = now }
    }

    mutating func needsReconnectOnWake(at now: ContinuousClock.Instant = .now) -> Bool {
        guard let start else { return false }
        self.start = nil
        return start.duration(to: now) >= .seconds(90)
    }
}
