package iptunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestAuthenticatedIPRoundTrip(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	listener, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	token := Token{1, 2, 3}
	peers := make(chan *Session, 1)
	serverErrors := make(chan error, 2)
	var verified atomic.Int32
	go func() {
		for attempt := range 3 {
			connection, err := listener.Accept(ctx)
			if err != nil {
				serverErrors <- err
				return
			}
			peer, err := AuthenticateWithAdmission(ctx, connection, token, true, func() bool {
				verified.Add(1)
				return attempt != 2
			})
			if err != nil {
				serverErrors <- err
			} else {
				peers <- peer
			}
		}
	}()
	address := listener.Addr().String()
	conf := &tls.Config{RootCAs: roots}
	classical, err := quic.DialAddr(ctx, address, &tls.Config{
		RootCAs: roots, NextProtos: []string{ALPN},
		CurvePreferences: []tls.CurveID{tls.X25519},
	}, quicConfig())
	if err == nil {
		_ = classical.CloseWithError(0, "")
		t.Fatal("accepted a TLS client offering only classical key exchange")
	}
	if peer, err := Dial(ctx, address, Token{4}, conf); !errors.Is(err, ErrGatewayRejected) || !errors.Is(err, ErrAuthentication) || peer != nil {
		t.Fatalf("wrong token: peer %v, error %v", peer, err)
	}
	if err := <-serverErrors; !errors.Is(err, ErrAuthentication) {
		t.Fatalf("gateway rejected the wrong token with %v", err)
	}
	client, err := Dial(ctx, address, token, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.connection.ConnectionState().TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatal("Cuven did not negotiate hybrid X25519 + ML-KEM-768")
	}
	if !client.IPv6Enabled() {
		t.Fatal("authenticated gateway IPv6 capability was not negotiated")
	}
	var server *Session
	select {
	case server = <-peers:
		defer server.Close()
	case err := <-serverErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if other, err := Dial(ctx, address, token, conf); other != nil || !errors.Is(err, ErrGatewayBusy) {
		t.Fatalf("occupied gateway: peer %v, error %v", other, err)
	}
	if err := <-serverErrors; !errors.Is(err, ErrGatewayBusy) {
		t.Fatalf("server admission decision: %v", err)
	}
	if verified.Load() != 2 {
		t.Fatalf("admission ran %d times for two valid proofs and one invalid proof", verified.Load())
	}
	if client.PacketMTU() != 1500 || server.PacketMTU() != 1500 {
		t.Fatalf("current client and gateway negotiated MTUs %d and %d", client.PacketMTU(), server.PacketMTU())
	}
	for _, test := range []struct {
		from, to *Session
		packet   []byte
	}{
		{client, server, testPacket4(60)},
		{server, client, testPacket4(MTU)},
		{client, server, testPacket6(MTU)},
	} {
		if err := test.from.WritePacket(test.packet); err != nil {
			t.Fatal(err)
		}
		if packet, err := test.to.ReadPacket(ctx); err != nil || !bytes.Equal(packet, test.packet) {
			t.Fatalf("packet round trip: got %d of %d bytes, error %v", len(packet), len(test.packet), err)
		}
	}
}

// Older installed clients offer only the original ALPN. They must keep the
// 1280-byte IP limit even when the gateway also supports larger packets.
func TestLegacyClientKeepsOriginalMTU(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	listener, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	token := Token{1}
	type result struct {
		peer *Session
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			accepted <- result{err: err}
			return
		}
		peer, err := Authenticate(ctx, conn, token, false)
		accepted <- result{peer, err}
	}()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		RootCAs: roots, NextProtos: []string{"cuven-ip/1"}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}, quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if _, err := authenticateClient(ctx, conn, token); err != nil {
		t.Fatal(err)
	}
	res := <-accepted
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.peer.Close()
	if res.peer.PacketMTU() != 1280 {
		t.Fatalf("legacy gateway session MTU = %d", res.peer.PacketMTU())
	}
	if err := res.peer.WritePacket(testPacket4(1281)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("oversize legacy packet: %v", err)
	}
	client := newSession(conn, false)
	if err := res.peer.WritePacket(testPacket6(1280)); err != nil {
		t.Fatal(err)
	}
	packet, err := client.ReadPacket(ctx)
	if err != nil || !bytes.Equal(packet, testPacket6(1280)) {
		t.Fatalf("legacy packet, length=%d error=%v", len(packet), err)
	}
}

// A 1280-byte IPv6 path leaves 1232 bytes for the outer UDP payload.
// A NAT64 gateway may see a larger local MTU and receive no usable PMTU hint.
func TestSessionOverMinimumIPv6Path(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	gateway, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	hop, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer hop.Close()
	remote := gateway.Addr().(*net.UDPAddr).AddrPort()
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	var pathMTU atomic.Int32
	pathMTU.Store(1280)
	go func() {
		var packet [4096]byte
		var client netip.AddrPort
		for {
			n, source, err := hop.ReadFromUDPAddrPort(packet[:])
			if err != nil {
				return
			}
			if n > int(pathMTU.Load())-40-8 {
				continue
			}
			destination := remote
			if source == remote {
				destination = client
			} else {
				client = source
			}
			if destination.IsValid() {
				if _, err := hop.WriteToUDPAddrPort(packet[:n], destination); err != nil {
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	token := Token{1}
	type result struct {
		peer *Session
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := gateway.Accept(ctx)
		if err != nil {
			accepted <- result{err: err}
			return
		}
		peer, err := Authenticate(ctx, conn, token, true)
		accepted <- result{peer: peer, err: err}
	}()
	client, err := Dial(ctx, hop.LocalAddr().String(), token, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	defer server.peer.Close()
	transfer := func(from, to *Session, packet []byte) {
		t.Helper()
		if err := from.WritePacket(packet); err != nil {
			t.Fatal(err)
		}
		got, err := to.ReadPacket(ctx)
		if err != nil || !bytes.Equal(got, packet) {
			t.Fatalf("inner packet %d bytes, outer path MTU %d: got %d bytes, err %v", len(packet), pathMTU.Load(), len(got), err)
		}
	}
	transfer(client, server.peer, testPacket6(MTU))
	// An unchanged address pair can acquire a smaller path during an
	// authenticated session, without an ICMP Packet Too Big indication.
	for _, mtu := range []int32{1500, 1280} {
		pathMTU.Store(mtu)
		for range 16 {
			transfer(client, server.peer, testPacket4(1350))
			transfer(server.peer, client, testPacket6(1350))
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestRecognizeRemoteGatewayClose(t *testing.T) {
	for _, tc := range []struct {
		remote bool
		code   quic.ApplicationErrorCode
		reason string
		want   error
	}{
		{true, closeRejected, "gateway busy", ErrGatewayBusy},
		{true, closeRejected, "authentication failed", ErrGatewayRejected},
		{false, closeRejected, "gateway busy", nil},
		{true, closeNormal, "gateway busy", nil},
		{true, closeRejected, "unrecognized reason", nil},
	} {
		raw := &quic.ApplicationError{Remote: tc.remote, ErrorCode: tc.code, ErrorMessage: tc.reason}
		want := tc.want
		if want == nil {
			want = raw
		}
		if got := dialError(raw); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestUntrustedCertificateFails(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	listener, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	peer, err := Dial(ctx, listener.Addr().String(), Token{1}, &tls.Config{RootCAs: x509.NewCertPool()})
	var unknown x509.UnknownAuthorityError
	if peer != nil || !errors.As(err, &unknown) {
		t.Fatalf("untrusted certificate: peer %v, error %v", peer, err)
	}
}

func testPacket4(size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	copy(packet[12:20], []byte{10, 66, 0, 2, 192, 0, 2, 9})
	return packet
}

func testPacket6(size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(size-40))
	copy(packet[8:24], []byte{0xfd, 0x66})
	copy(packet[24:40], []byte{0x20, 1, 0x0d, 0xb8})
	return packet
}
