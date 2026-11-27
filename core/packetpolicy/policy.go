package packetpolicy

import "net/netip"

var (
	sharedIPv4     = netip.MustParsePrefix("100.64.0.0/10")
	localIPv4      = netip.MustParsePrefix("0.0.0.0/8")
	broadcastIPv4  = netip.MustParseAddr("255.255.255.255")
	wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")
	localNAT64     = netip.MustParsePrefix("64:ff9b:1::/48")
)

// IsLocalDestination reports whether address belongs to a local IP range.
func IsLocalDestination(address netip.Addr) bool {
	address = address.Unmap()
	if wellKnownNAT64.Contains(address) {
		bytes := address.As16()
		address = netip.AddrFrom4([4]byte(bytes[12:]))
	}
	return address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address == broadcastIPv4 ||
		sharedIPv4.Contains(address) || localIPv4.Contains(address) || localNAT64.Contains(address)
}

// IsLANPacket reports whether an IPv4 or IPv6 packet has a local destination.
func IsLANPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch {
	case packet[0]>>4 == 4 && len(packet) >= 20:
		return IsLocalDestination(netip.AddrFrom4([4]byte(packet[16:20])))
	case packet[0]>>4 == 6 && len(packet) >= 40:
		return IsLocalDestination(netip.AddrFrom16([16]byte(packet[24:40])))
	default:
		return false
	}
}
