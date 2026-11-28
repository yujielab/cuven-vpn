package mobile

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yujielab/cuven-vpn/core/iptunnel"
)

func TestGatewayPinRequiresValidTLSAndMatchingKey(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	hash := sha256.Sum256(fixture.Certificate().RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(hash[:])
	hash[0] ^= 1
	other := base64.StdEncoding.EncodeToString(hash[:])
	identity := fixture.TLS.Certificates[0]
	fixture.Close()

	for _, tc := range []struct {
		name, pin, serverName, want string
		roots                       *x509.CertPool
	}{
		{"trusted and pinned", pin, "127.0.0.1", "", roots},
		{"wrong pin", other, "127.0.0.1", "certificate-pin", roots},
		{"wrong name", pin, "different.example", "certificate-name", roots},
		{"untrusted issuer", pin, "127.0.0.1", "certificate", x509.NewCertPool()},
		{"ordinary mode", "", "127.0.0.1", "", roots},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := iptunnel.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{identity}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			token, err := iptunnel.ParseToken(testAccessToken())
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err == nil {
					_, err = iptunnel.Authenticate(ctx, conn, token, false)
				}
				done <- err
			}()
			engine := NewEngine()
			defer engine.Stop()
			if tc.pin != "" {
				if err := engine.PinGatewayPublicKey(tc.pin); err != nil {
					t.Fatal(err)
				}
			}
			err = engine.startCuven(listener.Addr().String(), testAccessToken(), &tls.Config{ServerName: tc.serverName, RootCAs: tc.roots}, false, true)
			if got := startFailureCode(err); got != tc.want {
				t.Fatalf("got %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if err := engine.PinGatewayPublicKey(other); err != errEngineUsed {
					t.Fatal("active session accepted a pin change")
				}
			} else {
				cancel()
				if err := <-done; err == nil {
					t.Fatal("gateway authenticated a rejected session")
				}
			}
		})
	}

	for _, invalid := range []string{"", "short", pin + "\n"} {
		if err := NewEngine().PinGatewayPublicKey(invalid); err == nil {
			t.Fatal("accepted invalid pin")
		}
	}
}
