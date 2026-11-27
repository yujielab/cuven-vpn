package cuventransport

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRelayAuthenticatedTrafficAndPeerLimit(t *testing.T) {
	t.Run("v1", func(t *testing.T) { testRelayTraffic(t, Version1) })
	t.Run("v2", func(t *testing.T) { testRelayTraffic(t, Version2) })
}

func testRelayTraffic(t *testing.T, version Version) {
	t.Helper()
	upstream := localSocket(t)
	listener := localSocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- ServeRelay(ctx, listener, RelayConfig{
			Key: bytes.Repeat([]byte{7}, KeySize), Upstream: upstream.LocalAddr().(*net.UDPAddr).AddrPort(), MaxPeers: 2,
			Version: version,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("relay did not stop after cancel")
		}
	})
	remote := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	a, b, c := localSocket(t), localSocket(t), localSocket(t)
	codec, other := testVersionCodec(t, 7, version), testVersionCodec(t, 8, version)
	token := bytes.Repeat([]byte{3}, TokenSize)
	probe := encode(t, codec, Probe, token)
	write(t, c, remote, probe)
	ack, _ := read(t, c)
	kind, payload, err := codec.Open(ServerToClient, ack)
	if err != nil || kind != ProbeAck || !bytes.Equal(payload, token) || len(probe) != len(ack) {
		t.Fatalf("relay sent invalid ProbeAck; kind %v, error %v", kind, err)
	}
	freshToken := bytes.Repeat([]byte{4}, TokenSize)
	write(t, b, remote, probe)
	write(t, b, remote, encode(t, other, Probe, bytes.Repeat([]byte{5}, TokenSize)))
	freshProbe := encode(t, codec, Probe, freshToken)
	write(t, b, remote, freshProbe)
	ack, _ = read(t, b)
	kind, payload, err = codec.Open(ServerToClient, ack)
	if err != nil || kind != ProbeAck || !bytes.Equal(payload, freshToken) || len(freshProbe) != len(ack) {
		t.Fatalf("relay did not acknowledge only the fresh authenticated probe; kind %v, error %v", kind, err)
	}

	packetA := wireGuardData(0xaa)
	packetB := wireGuardData(0xbb)
	write(t, a, remote, encode(t, other, Data, packetB))
	sealedA := encode(t, codec, Data, packetA)
	write(t, a, remote, sealedA)
	request, peerA := read(t, upstream)
	if !bytes.Equal(request, packetA) {
		t.Fatal("relay forwarded a packet with a different key")
	}
	write(t, upstream, peerA, packetB)
	response, _ := read(t, a)
	kind, payload, err = codec.Open(ServerToClient, response)
	if err != nil || kind != Data || !bytes.Equal(payload, packetB) {
		t.Fatalf("relay sent invalid wrapped upstream data; kind %v, error %v", kind, err)
	}

	write(t, b, remote, sealedA)
	write(t, b, remote, encode(t, codec, Data, packetB))
	request, peerB := read(t, upstream)
	if !bytes.Equal(request, packetB) || peerB == peerA {
		t.Fatal("relay accepted a replay on another address or merged unrelated addresses")
	}
	write(t, c, remote, encode(t, codec, Data, wireGuardData(0xcc)))
	if err := upstream.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [MaxDatagramSize]byte
	if _, _, err := upstream.ReadFromUDPAddrPort(buf[:]); err == nil {
		t.Fatal("relay admitted an address above its peer limit")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
}

func TestRelayReplayCacheBound(t *testing.T) {
	cache := newReplayCache(2)
	makeNonce := func(value byte) []byte { return bytes.Repeat([]byte{value}, len(packetNonce{})) }
	a, b, c := makeNonce(1), makeNonce(2), makeNonce(3)
	if !cache.add(a) || !cache.add(b) || cache.add(a) || !cache.add(c) || cache.add(b) || !cache.add(a) {
		t.Fatal("replay cache did not keep only the two most recent distinct nonces")
	}
	if len(cache.seen) != 2 || len(cache.ring) != 2 {
		t.Fatal("replay cache grew over its capacity")
	}
}

func localSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	return socket
}

func wireGuardData(value byte) []byte {
	data := bytes.Repeat([]byte{value}, 32)
	copy(data, []byte{4, 0, 0, 0})
	return data
}

func encode(t *testing.T, codec *Codec, kind Kind, plain []byte) []byte {
	t.Helper()
	data, err := codec.Seal(ClientToServer, kind, plain)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func write(t *testing.T, socket *net.UDPConn, remote netip.AddrPort, data []byte) {
	t.Helper()
	if _, err := socket.WriteToUDPAddrPort(data, remote); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, socket *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	if err := socket.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [MaxDatagramSize]byte
	n, remote, err := socket.ReadFromUDPAddrPort(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n], remote
}
