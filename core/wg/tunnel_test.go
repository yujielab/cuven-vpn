package wg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
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
		testTunnelThroughCuvenRelay(t, cuventransport.Version1, false)
	})
	t.Run("v2", func(t *testing.T) {
		testTunnelThroughCuvenRelay(t, cuventransport.Version2, false)
	})
	t.Run("HTTPS3", func(t *testing.T) {
		testTunnelThroughCuvenRelay(t, cuventransport.Version2, true)
	})
}

func TestDirectWireGuardTunnel(t *testing.T) {
	const mtu = 1280
	clientKey := newWireGuardKey(t)
	serverKey := newWireGuardKey(t)
	psk := randomSharedKey(t)
	server, serverTUN := startWireGuardTestPeer(t, mtu, clientKey, serverKey, psk)

	cfg := Config{
		Direct:        true,
		Endpoint:      localEndpoint(t, server).String(),
		PrivateKey:    base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		PeerPublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Open(ctx, cfg, mtu)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertPacketRoundTrip(t, ctx, client, serverTUN, "192.0.2.2", "198.51.100.8", mtu)
	assertPacketRoundTrip(t, ctx, client, serverTUN, "2001:db8::2", "2001:db8:1::8", mtu)

	t.Run("wrong peer PSK", func(t *testing.T) {
		bad := cfg
		bad.PresharedKey = base64.StdEncoding.EncodeToString(randomSharedKey(t))
		short, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		unexpected, err := Open(short, bad, mtu)
		if unexpected != nil {
			unexpected.Close()
			t.Fatal("direct peer accepted an incorrect PSK")
		}
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "WireGuard peer handshake") {
			t.Fatalf("wanted incomplete WireGuard handshake, got %v", err)
		}
	})
}

func startWireGuardTestPeer(t *testing.T, mtu int, clientKey, serverKey *ecdh.PrivateKey, psk []byte) (*device.Device, *memoryTUN) {
	t.Helper()
	tun := newMemoryTUN(mtu)
	server := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(server.Close)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=192.0.2.2/32\nallowed_ip=2001:db8::2/128\n",
		hex.EncodeToString(serverKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()), hex.EncodeToString(psk))
	if err := server.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	return server, tun
}

func testTunnelThroughCuvenRelay(t *testing.T, version cuventransport.Version, https3 bool) {
	t.Helper()
	const mtu = 1280
	clientKey := newWireGuardKey(t)
	serverKey := newWireGuardKey(t)
	relayKey := randomSharedKey(t)
	psk := randomSharedKey(t)

	server, serverTUN := startWireGuardTestPeer(t, mtu, clientKey, serverKey, psk)
	serverAddr := localEndpoint(t, server)

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayCtx, stopRelay := context.WithCancel(t.Context())
	relayErr := make(chan error, 1)
	var tlsConfig *tls.Config
	var roots *x509.CertPool
	const serverName = "cuven-relay.test"
	if https3 {
		tlsConfig, roots = newTLSConfig(t, serverName)
	}
	go func() {
		cfg := cuventransport.RelayConfig{Key: relayKey, Upstream: serverAddr, Version: version}
		if https3 {
			relayErr <- cuventransport.ServeHTTPS3Relay(relayCtx, listener, tlsConfig, cfg)
		} else {
			relayErr <- cuventransport.ServeRelay(relayCtx, listener, cfg)
		}
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
		HTTPS3:        https3,
		ServerName:    serverName,
		RootCAs:       roots,
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
		if https3 {
			if !strings.Contains(err.Error(), "rejected CONNECT-UDP") {
				t.Fatalf("wanted HTTP/3 authorization rejection, got %v", err)
			}
		} else if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Cuven relay probe") {
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
		if https3 {
			if !strings.Contains(err.Error(), "requires the v2 envelope") {
				t.Fatalf("wanted an HTTPS/3 profile validation error, got %v", err)
			}
		} else if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Cuven relay probe") {
			t.Fatalf("wanted missing authenticated probe, got %v", err)
		}
	})
	if https3 {
		t.Run("untrusted certificate", func(t *testing.T) {
			bad := cfg
			bad.RootCAs = x509.NewCertPool()
			invalid, err := Open(ctx, bad, mtu)
			if err == nil {
				invalid.Close()
				t.Fatal("accepted an untrusted HTTPS/3 certificate")
			}
			if !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("wanted a certificate rejection, got %v", err)
			}
		})
	}
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

func newTLSConfig(t *testing.T, serverName string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &tls.Config{Certificates: []tls.Certificate{
		{Certificate: [][]byte{der}, PrivateKey: privateKey},
	}}, roots
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
