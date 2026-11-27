package tunnel

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// RejectPrivateTraffic reports whether the strict privacy policy rejects a raw
// outbound IP packet. It blocks conventional plaintext DNS and STUN/TURN ports,
// recognizable STUN messages, and packets that cannot be classified safely.
func RejectPrivateTraffic(packet []byte) bool {
	if len(packet) == 0 {
		return true
	}

	var protocol byte
	var payload []byte
	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < header.IPv4MinimumSize {
			return true
		}
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		offset := int(packet[0]&0x0f) * 4
		// Only Don't Fragment may be set. The other flag bits and any
		// fragment offset make the transport header unreliable.
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if length != len(packet) || offset < header.IPv4MinimumSize || offset > length || fragment&^0x4000 != 0 {
			return true
		}
		protocol, payload = packet[9], packet[offset:]
	case 6:
		if len(packet) < header.IPv6MinimumSize ||
			int(binary.BigEndian.Uint16(packet[4:6])) != len(packet)-header.IPv6MinimumSize {
			return true
		}
		var ok bool
		protocol, payload, ok = ipv6Transport(packet[6], packet[header.IPv6MinimumSize:])
		if !ok {
			return true
		}
	default:
		return true
	}

	var data []byte
	switch protocol {
	case byte(header.TCPProtocolNumber):
		if len(payload) < header.TCPMinimumSize {
			return true
		}
		offset := int(payload[12]>>4) * 4
		if offset < header.TCPMinimumSize || offset > len(payload) {
			return true
		}
		data = payload[offset:]
	case byte(header.UDPProtocolNumber):
		if len(payload) < header.UDPMinimumSize || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return true
		}
		data = payload[header.UDPMinimumSize:]
	case byte(header.ICMPv4ProtocolNumber):
		return version != 4 || len(payload) < header.ICMPv4MinimumSize
	case byte(header.ICMPv6ProtocolNumber):
		return version != 6 || len(payload) < header.ICMPv6MinimumSize
	case 59: // IPv6 No Next Header.
		return version != 6 || len(payload) != 0
	default:
		return true
	}
	return restrictedPort(binary.BigEndian.Uint16(payload[:2])) ||
		restrictedPort(binary.BigEndian.Uint16(payload[2:4])) ||
		visibleSTUN(data, protocol == byte(header.UDPProtocolNumber))
}

func ipv6Transport(protocol byte, payload []byte) (byte, []byte, bool) {
	const maxExtensions = 8
	for count := 0; ; count++ {
		var size int
		switch protocol {
		case 0, 43, 60: // Hop-by-Hop Options, Routing, Destination Options.
			if count == maxExtensions || len(payload) < 8 || (protocol == 0 && count != 0) {
				return 0, nil, false
			}
			size = (int(payload[1]) + 1) * 8
		case 51: // Authentication Header (RFC 4302).
			if count == maxExtensions || len(payload) < 12 {
				return 0, nil, false
			}
			size = (int(payload[1]) + 2) * 4
			if size < 12 || size%8 != 0 {
				return 0, nil, false
			}
		case 44, 50: // Fragment and Encapsulating Security Payload.
			return 0, nil, false
		default:
			return protocol, payload, true
		}
		if size > len(payload) {
			return 0, nil, false
		}
		protocol, payload = payload[0], payload[size:]
	}
}

func restrictedPort(port uint16) bool {
	switch port {
	case 53, 5353, 5355, 3478, 5349: // DNS, mDNS, LLMNR, STUN/TURN and secure STUN/TURN.
		return true
	default:
		return false
	}
}

func visibleSTUN(data []byte, datagram bool) bool {
	const (
		stunHeaderSize  = 20
		stunMagicCookie = 0x2112a442
	)
	if len(data) < stunHeaderSize || data[0]&0xc0 != 0 || binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	// UDP carries one complete message. On TCP the same header may precede a
	// partial body or another message within the segment.
	return length%4 == 0 && (!datagram || len(data) == stunHeaderSize+length)
}
