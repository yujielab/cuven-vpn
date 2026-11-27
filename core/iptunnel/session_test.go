package iptunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net/http/httptest"
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
	go func() {
		for range 2 {
			connection, err := listener.Accept(ctx)
			if err != nil {
				serverErrors <- err
				return
			}
			peer, err := Authenticate(ctx, connection, token, true)
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
	if peer, err := Dial(ctx, address, Token{4}, conf); !errors.Is(err, ErrAuthentication) || peer != nil {
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
