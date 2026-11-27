package tunnel

import (
	"net/netip"
	"testing"
)

func TestLANTarget(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.32.0.1", false},
		{"192.168.1.255", true},
		{"127.0.0.1", true},
		{"0.0.0.1", true},
		{"169.254.1.10", true},
		{"100.64.1.10", true},
		{"224.0.0.251", true},
		{"255.255.255.255", true},
		{"1.1.1.1", false},
		{"198.18.0.1", false},
		{"::", true},
		{"::1", true},
		{"fc00::2", true},
		{"fd31:6375:7665::1", true},
		{"fe80::1", true},
		{"ff02::fb", true},
		{"2606:4700:4700::1111", false},
		{"::ffff:192.168.1.1", true},
		{"64:ff9b::c0a8:101", true},
		{"64:ff9b::101:101", false},
		{"64:ff9b:1::1", true},
	} {
		if got := IsLocalDestination(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("IsLocalDestination(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}
