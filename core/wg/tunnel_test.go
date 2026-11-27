package wg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yujielab/cuven-vpn/core/cuventransport"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func TestTunnelThroughCuvenRelay(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		testTunnelThroughCuvenRelay(t, cuventransport.Version1)
	})
	t.Run("v2", func(t *testing.T) {
		testTunnelThroughCuvenRelay(t, cuventransport.Version2)
	})
}

func testTunnelThroughCuvenRelay(t *testing.T, version cuventransport.Version) {
	t.Helper()
	const mtu = 1280
	clientKey := newWireGuardKey(t)
	serverKey := newWireGuardKey(t)
	relayKey := randomSharedKey(t)
	psk := randomSharedKey(t)

	serverTUN := newMemoryTUN(mtu)
	server := device.NewDevice(serverTUN, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	serverCfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=192.0.2.2/32\nallowed_ip=2001:db8::2/128\n",
		hex.EncodeToString(serverKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()), hex.EncodeToString(psk))
	if err := server.IpcSet(serverCfg); err != nil {
		t.Fatal(err)
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	serverAddr := localEndpoint(t, server)

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayCtx, stopRelay := context.WithCancel(t.Context())
	relayErr := make(chan error, 1)
	go func() {
		relayErr <- cuventransport.ServeRelay(relayCtx, listener, cuventransport.RelayConfig{
			Key: relayKey, Upstream: serverAddr, Version: version,
		})
	}()
	defer func() {
		stopRelay()
		if err := <-relayErr; err != nil {
			t.Errorf("relay stopped with error: %v", err)
		}
	}()

	cfg := Config{
		Endpoint:      listener.LocalAddr().String(),
		PrivateKey:    base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		PeerPublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		TransportKey:  base64.RawStdEncoding.EncodeToString(relayKey),
		Camouflage:    version == cuventransport.Version2,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Open(ctx, cfg, mtu)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	t.Run("IPv4", func(t *testing.T) {
		assertPacketRoundTrip(t, ctx, client, serverTUN, "192.0.2.2", "198.51.100.8", 1280)
	})
	t.Run("IPv6", func(t *testing.T) {
		assertPacketRoundTrip(t, ctx, client, serverTUN, "2001:db8::2", "2001:db8:1::8", 1280)
	})
	t.Run("wrong relay key", func(t *testing.T) {
		bad := cfg
		bad.TransportKey = base64.StdEncoding.EncodeToString(randomSharedKey(t))
		short, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		invalid, err := Open(short, bad, mtu)
		if err == nil {
			invalid.Close()
			t.Fatal("relay accepted an incorrect transport key")
		}
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Cuven relay probe") {
			t.Fatalf("wanted missing authenticated probe, got %v", err)
		}
	})
	t.Run("wrong relay version", func(t *testing.T) {
		bad := cfg
		bad.Camouflage = !cfg.Camouflage
		short, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		invalid, err := Open(short, bad, mtu)
		if err == nil {
			invalid.Close()
			t.Fatal("relay accepted an incompatible transport version")
		}
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Cuven relay probe") {
			t.Fatalf("wanted missing authenticated probe, got %v", err)
		}
	})
	t.Run("wrong WireGuard PSK", func(t *testing.T) {
		bad := cfg
		bad.PresharedKey = base64.StdEncoding.EncodeToString(randomSharedKey(t))
		short, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		invalid, err := Open(short, bad, mtu)
		if err == nil {
			invalid.Close()
			t.Fatal("WireGuard accepted an incorrect peer PSK")
		}
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "WireGuard peer handshake") {
			t.Fatalf("wanted incomplete WireGuard handshake, got %v", err)
		}
	})
}

func assertPacketRoundTrip(t *testing.T, ctx context.Context, client *Tunnel, server *memoryTUN, source, destination string, size int) {
	t.Helper()
	up := makeTestPacket(source, destination, size)
	if err := client.WritePacket(up); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-server.egress:
		if !bytes.Equal(got, up) {
			t.Fatal("WireGuard server received different packet bytes")
		}
	case <-ctx.Done():
		t.Fatalf("server did not receive packet: %v", ctx.Err())
	}
	down := makeTestPacket(destination, source, size)
	if err := server.inject(down); err != nil {
		t.Fatal(err)
	}
	got, err := client.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, down) {
		t.Fatal("Cuven client received different packet bytes")
	}
}

func makeTestPacket(source, destination string, size int) []byte {
	src := netip.MustParseAddr(source)
	dst := netip.MustParseAddr(destination)
	packet := bytes.Repeat([]byte{0x42}, size)
	if src.Is4() {
		clear(packet[:20])
		packet[0] = 0x45
		packet[8], packet[9] = 64, 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(size))
		copy(packet[12:16], src.AsSlice())
		copy(packet[16:20], dst.AsSlice())
	} else {
		clear(packet[:40])
		packet[0] = 0x60
		packet[6], packet[7] = 17, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(size-40))
		copy(packet[8:24], src.AsSlice())
		copy(packet[24:40], dst.AsSlice())
	}
	return packet
}

func localEndpoint(t *testing.T, server *device.Device) netip.AddrPort {
	t.Helper()
	state, err := server.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(state, "\n") {
		if port, ok := strings.CutPrefix(line, "listen_port="); ok {
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(value))
		}
	}
	t.Fatal("WireGuard server did not bind a port")
	return netip.AddrPort{}
}

func newWireGuardKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func randomSharedKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}
