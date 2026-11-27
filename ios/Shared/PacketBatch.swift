import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum PacketBatch {
    static let maxPackets = 64

    static func encode(
        _ packets: ArraySlice<Data>,
        mtu: Int,
        allowIPv4: Bool = true,
        allowIPv6: Bool = true
    ) -> Data {
        var batch = Data()
        batch.reserveCapacity(packets.count * (mtu + 2))
        for packet in packets where packet.count <= mtu {
            guard let leadingByte = packet.first,
                  let length = UInt16(exactly: packet.count) else { continue }
            let version = leadingByte >> 4
            guard (version == 4 && allowIPv4) || (version == 6 && allowIPv6) else { continue }
            batch.append(UInt8(length >> 8))
            batch.append(UInt8(truncatingIfNeeded: length))
            batch.append(packet)
        }
        return batch
    }

    static func decode(_ batch: Data, mtu: Int) -> (packets: [Data], protocols: [NSNumber])? {
        guard !batch.isEmpty, batch.count <= maxPackets * (mtu + 2) else { return nil }
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        var offset = batch.startIndex
        while offset < batch.endIndex {
            guard batch.endIndex - offset >= 2, packets.count < maxPackets else { return nil }
            let length = Int(batch[offset]) << 8 | Int(batch[offset + 1])
            offset += 2
            guard length > 0, length <= mtu, length <= batch.endIndex - offset else { return nil }
            switch batch[offset] >> 4 {
            case 4:
                protocols.append(NSNumber(value: AF_INET))
            case 6:
                protocols.append(NSNumber(value: AF_INET6))
            default:
                return nil
            }
            let end = offset + length
            packets.append(batch[offset..<end])
            offset = end
        }
        return (packets, protocols)
    }
}
