import Foundation

struct TunnelRTTMeasurement {
    private var pending: UUID?
    private(set) var milliseconds: Int64?

    mutating func begin() -> UUID {
        // A full polling interval passed without a reply to the previous request.
        if pending != nil { milliseconds = nil }
        let request = UUID()
        pending = request
        return request
    }

    mutating func finish(_ request: UUID, reply: Data?) {
        guard pending == request else { return }
        pending = nil
        if let reply, let value = Int64(String(decoding: reply, as: UTF8.self)), value >= 0 {
            milliseconds = value
        } else {
            milliseconds = nil
        }
    }
}
