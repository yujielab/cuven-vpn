package hy2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestStrictPostQuantumAuthentication(t *testing.T) {
	for _, test := range []struct {
		name    string
		curve   tls.CurveID
		require bool
		ok      bool
	}{
		{name: "hybrid required and available", curve: tls.X25519MLKEM768, require: true, ok: true},
		{name: "hybrid required and unavailable", curve: tls.X25519, require: true},
		{name: "default permits classic fallback", curve: tls.X25519, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, roots := startAuthServer(t, test.curve, "secret")
			client, err := Dial(t.Context(), Config{
				Address: server.String(), Auth: "secret", RootCAs: roots, RequirePostQuantum: test.require,
			})
			if !test.ok {
				if err == nil {
					_ = client.Close()
					t.Fatal("client accepted a classical-only server with hybrid required")
				}
				if !strings.Contains(err.Error(), "connect QUIC") {
					t.Fatalf("expected a QUIC TLS failure, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if got := client.connection.ConnectionState().TLS.CurveID; got != test.curve {
				t.Fatalf("negotiated curve = %v, want %v", got, test.curve)
			}
		})
	}
}

func TestAuthenticationRejectionDoesNotExposeCredential(t *testing.T) {
	server, roots := startAuthServer(t, tls.X25519, "secret")
	const credential = "wrong-test-credential"
	client, err := Dial(t.Context(), Config{Address: server.String(), Auth: credential, RootCAs: roots})
	if client != nil {
		_ = client.Close()
		t.Fatal("client was returned after authentication rejection")
	}
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), credential) {
		t.Fatalf("unexpected authentication error %v", err)
	}
}

func TestDialFallsBackWhenFirstAddressIsUnreachable(t *testing.T) {
	server, roots := startAuthServer(t, tls.X25519, "secret")
	_, port, err := net.SplitHostPort(server.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	connection, err := raceQUIC(ctx, []netip.Addr{
		netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1"),
	}, port, &tls.Config{
		ServerName: "127.0.0.1", RootCAs: roots,
		NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(noError, "")
	if remote := connection.RemoteAddr().String(); remote != server.String() {
		t.Fatalf("remote = %s, want IPv4 fallback %s", remote, server)
	}
}

func startAuthServer(t *testing.T, curve tls.CurveID, credential string) (net.Addr, *x509.CertPool) {
	t.Helper()
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()

	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{curve},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "hysteria" || r.URL.Path != "/auth" || r.Method != http.MethodPost ||
			r.Header.Get("Hysteria-Auth") != credential || r.Header.Get("Hysteria-CC-RX") != "0" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Hysteria-UDP", "false")
		w.Header().Set("Hysteria-CC-RX", "auto")
		w.WriteHeader(233)
	})}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = srv.ServeListener(listener)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = listener.Close()
		<-finished
	})
	return listener.Addr(), roots
}

func TestTCPResponsePreservesPayload(t *testing.T) {
	stream := bytes.NewReader([]byte{0, 2, 'O', 'K', 2, '.', '.', 'd', 'a', 't', 'a'})
	if err := readTCPResponse(stream); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil || string(payload) != "data" {
		t.Fatalf("remaining payload = %q, error = %v", payload, err)
	}
}

func TestUDPFragmentsCompleteOutOfOrder(t *testing.T) {
	fragments := make(fragmentBuffer)
	now := time.Now()
	for _, index := range []uint8{2, 2, 0, 1} {
		original := udpMessage{sessionID: 42, packetID: 14, fragmentIndex: index,
			fragmentCount: 3, address: "[::1]:53", payload: []byte{'a' + index}}
		message, err := decodeUDP(original.encode(nil))
		if err != nil {
			t.Fatal(err)
		}
		complete, ready := fragments.complete(now, message)
		if ready != (index == 1) {
			t.Fatalf("ready = %t after fragment %d", ready, index)
		}
		if ready && string(complete.payload) != "abc" {
			t.Fatalf("assembled payload = %q", complete.payload)
		}
	}
}

func TestUDPSessionCloseUnblocksReceive(t *testing.T) {
	client := &Client{sessions: make(map[uint32]*UDPSession)}
	session := &UDPSession{client: client, id: 1, incoming: make(chan udpMessage, 1), closed: make(chan struct{})}
	client.sessions[session.id] = session
	client.enqueueDatagram(session, udpMessage{payload: []byte("a")})
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := session.Receive(context.Background())
	if err != net.ErrClosed || client.queuedBytes.Load() != 0 {
		t.Fatalf("Receive error = %v, queued payload bytes = %d", err, client.queuedBytes.Load())
	}
}
