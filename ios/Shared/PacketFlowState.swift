/// State of the system tunnel interface, retained across gateway reconnects.
struct PacketFlowState {
    private(set) var mtu: Int?
    private var lastWriteFailed = false

    func needsSettings(mtu: Int) -> Bool {
        self.mtu != mtu || lastWriteFailed
    }

    mutating func didApplySettings(mtu: Int) {
        self.mtu = mtu
        lastWriteFailed = false
    }

    mutating func shouldRecoverAfterWrite(succeeded: Bool) -> Bool {
        let repeatedFailure = lastWriteFailed && !succeeded
        lastWriteFailed = !succeeded
        return repeatedFailure
    }
}
