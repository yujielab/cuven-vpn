import Darwin
import Foundation

enum TunnelEndpoint {
    static func resolve(host: String, port: Int) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = AI_NUMERICSERV
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0 else { return [] }
        defer { freeaddrinfo(result) }

        var endpoints: [String] = []
        var alternateFamily: String?
        var firstFamily: Int32?
        var cursor = result
        while let current = cursor {
            let address = current.pointee
            cursor = address.ai_next
            guard address.ai_family == AF_INET || address.ai_family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address.ai_addr, address.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
                continue
            }
            let value = String(cString: host)
            let endpoint = address.ai_family == AF_INET6 ? "[\(value)]:\(port)" : "\(value):\(port)"
            if firstFamily == nil { firstFamily = address.ai_family }
            if firstFamily != address.ai_family && alternateFamily == nil { alternateFamily = endpoint }
            if endpoints.count < 3 && !endpoints.contains(endpoint) { endpoints.append(endpoint) }
            if endpoints.count == 3 && alternateFamily != nil { break }
        }
        if let alternateFamily {
            endpoints.removeAll { $0 == alternateFamily }
            endpoints.insert(alternateFamily, at: 1)
        }
        return Array(endpoints.prefix(3))
    }
}
