package tunnel

import (
	"encoding/binary"
	"testing"
)

func TestRejectPrivateTraffic(t *testing.T) {
	udpWithPayload := func(source, destination uint16, data []byte) []byte {
		packet := make([]byte, 8)
		binary.BigEndian.PutUint16(packet, source)
		binary.BigEndian.PutUint16(packet[2:], destination)
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)+len(data)))
		return append(packet, data...)
	}
	udp := func(source, destination uint16) []byte { return udpWithPayload(source, destination, nil) }
	tcp := func(source, destination uint16) []byte {
		packet := make([]byte, 20)
		binary.BigEndian.PutUint16(packet, source)
		binary.BigEndian.PutUint16(packet[2:], destination)
		packet[12] = 5 << 4
		return packet
	}
	v4 := func(proto byte, options, fragment uint16, payload []byte) []byte {
		packet := make([]byte, 20+int(options))
		packet[0] = 0x40 | byte(len(packet)/4)
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)+len(payload)))
		binary.BigEndian.PutUint16(packet[6:], fragment)
		packet[9] = proto
		return append(packet, payload...)
	}
	v6 := func(proto byte, payload []byte) []byte {
		packet := make([]byte, 40)
		packet[0], packet[6] = 0x60, proto
		binary.BigEndian.PutUint16(packet[4:], uint16(len(payload)))
		return append(packet, payload...)
	}
	extension := func(next byte, payload []byte) []byte {
		return append([]byte{next, 0, 0, 0, 0, 0, 0, 0}, payload...)
	}
	chain := extension(17, udp(65000, 443))
	for range 7 {
		chain = extension(60, chain)
	}
	stun := make([]byte, 20)
	stun[1] = 1 // Binding request.
	binary.BigEndian.PutUint32(stun[4:], 0x2112a442)
	badSTUNLength := append([]byte(nil), stun...)
	badSTUNLength[3] = 4
	quic := append([]byte(nil), stun...)
	quic[0] = 0xc0
	for _, test := range []struct {
		name   string
		packet []byte
		reject bool
	}{
		{"IPv4 UDP DNS", v4(17, 0, 0, udp(30000, 53)), true},
		{"IPv4 DNS with options", v4(17, 4, 0, udp(30000, 53)), true},
		{"IPv4 TCP DNS", v4(6, 0, 0, tcp(30000, 53)), true},
		{"IPv4 response from DNS", v4(17, 0, 0, udp(53, 30000)), true},
		{"IPv4 LLMNR", v4(17, 0, 0, udp(30000, 5355)), true},
		{"IPv4 HTTPS", v4(6, 0, 0x4000, tcp(30000, 443)), false},
		{"IPv4 QUIC", v4(17, 0, 0, udp(30000, 443)), false},
		{"IPv4 STUN port", v4(17, 0, 0, udp(30000, 3478)), true},
		{"IPv4 STUN in UDP on another port", v4(17, 0, 0, udpWithPayload(30000, 443, stun)), true},
		{"IPv4 STUN in TCP on another port", v4(6, 0, 0, append(tcp(30000, 443), stun...)), true},
		{"IPv4 STUN header with split TCP body", v4(6, 0, 0, append(tcp(30000, 443), badSTUNLength...)), true},
		{"IPv4 UDP lookalike with invalid length", v4(17, 0, 0, udpWithPayload(30000, 443, badSTUNLength)), false},
		{"IPv4 UDP lookalike with QUIC fixed bits", v4(17, 0, 0, udpWithPayload(30000, 443, quic)), false},
		{"IPv4 PMTU", v4(1, 0, 0, make([]byte, 8)), false},
		{"IPv4 first fragment", v4(17, 0, 0x2000, udp(30000, 443)), true},
		{"IPv4 later fragment", v4(17, 0, 0x0010, udp(30000, 443)), true},
		{"IPv4 invalid length", append(v4(17, 0, 0, udp(30000, 443)), 0), true},
		{"IPv4 TCP truncated", v4(6, 0, 0, tcp(30000, 443)[:13]), true},
		{"IPv4 UDP truncated", v4(17, 0, 0, udp(30000, 443)[:6]), true},
		{"IPv6 UDP DNS", v6(17, udp(30000, 53)), true},
		{"IPv6 TCP DNS", v6(6, tcp(30000, 53)), true},
		{"IPv6 mDNS", v6(17, udp(30000, 5353)), true},
		{"IPv6 HTTPS with options", v6(0, extension(43, extension(60, extension(6, tcp(30000, 443))))), false},
		{"IPv6 DNS with options", v6(60, extension(17, udp(30000, 53))), true},
		{"IPv6 QUIC", v6(17, udp(30000, 443)), false},
		{"IPv6 TURN over TLS", v6(6, tcp(30000, 5349)), true},
		{"IPv6 STUN after extension", v6(60, extension(17, udpWithPayload(30000, 443, stun))), true},
		{"IPv6 adjacent unreserved port", v6(17, udp(30000, 3479)), false},
		{"IPv6 PMTU", v6(58, make([]byte, 8)), false},
		{"IPv6 fragment", v6(44, extension(17, udp(30000, 443))), true},
		{"IPv6 extension bound", v6(60, chain), false},
		{"IPv6 too many extensions", v6(60, extension(60, chain)), true},
		{"IPv6 invalid options length", v6(60, []byte{17, 1, 0, 0, 0, 0, 0, 0}), true},
		{"IPv6 invalid payload length", append(v6(17, udp(30000, 443)), 0), true},
		{"IPv6 unknown unparsed protocol", v6(41, make([]byte, 40)), true},
		{"empty", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RejectPrivateTraffic(test.packet); got != test.reject {
				t.Fatalf("RejectPrivateTraffic() = %t, want %t", got, test.reject)
			}
		})
	}
}
