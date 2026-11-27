package hy2_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yujielab/cuven-vpn/core/hy2"
)

// TestOfficialHysteriaInterop exercises the custom client against the released
// upstream server. Set CUVEN_HYSTERIA_BIN to the official CLI's absolute path.
func TestOfficialHysteriaInterop(t *testing.T) {
	binary := os.Getenv("CUVEN_HYSTERIA_BIN")
	if binary == "" {
		t.Skip("set CUVEN_HYSTERIA_BIN to run against the upstream Hysteria server")
	}
	const serverName = "cuven-interop.test"
	const auth = "cuven-interop-fixture"

	dir := t.TempDir()
	certFile, keyFile, roots := writeServerCertificate(t, dir, serverName)
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.LocalAddr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	configFile := filepath.Join(dir, "server.yaml")
	config := fmt.Sprintf("listen: %q\ntls:\n  cert: %q\n  key: %q\nauth:\n  type: password\n  password: %q\n",
		address, certFile, keyFile, auth)
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "server", "--config", configFile, "--log-level", "debug", "--disable-update-check")
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(exited)
	}()
	defer func() {
		cancel()
		<-exited
		if t.Failed() {
			log, _ := os.ReadFile(logFile.Name())
			t.Logf("official server output:\n%s", log)
		}
	}()

	clientConfig := hy2.Config{Address: address, Auth: auth, ServerName: serverName, RootCAs: roots}
	var client *hy2.Client
	for {
		attempt, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		client, err = hy2.Dial(attempt, clientConfig)
		stop()
		if err == nil {
			break
		}
		select {
		case <-exited:
			t.Fatalf("upstream server exited before authenticating: %v", err)
		case <-ctx.Done():
			t.Fatalf("upstream server did not authenticate: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer client.Close()
	exerciseOfficialProxy(t, ctx, client)

	t.Run("rejected credential", func(t *testing.T) {
		badAuth := clientConfig
		badAuth.Auth = "incorrect-test-credential"
		checkUpstreamDialRejected(t, ctx, badAuth)
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		untrusted := clientConfig
		untrusted.RootCAs = x509.NewCertPool()
		checkUpstreamDialRejected(t, ctx, untrusted)
	})
	t.Run("required hybrid TLS", func(t *testing.T) {
		hybrid := clientConfig
		hybrid.RequirePostQuantum = true
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		tunnel, err := hy2.Dial(attempt, hybrid)
		if err != nil {
			t.Fatal(err)
		}
		_ = tunnel.Close()
	})
}

func TestOfficialHysteriaSalamanderInsecureInterop(t *testing.T) {
	binary := os.Getenv("CUVEN_HYSTERIA_BIN")
	if binary == "" {
		t.Skip("set CUVEN_HYSTERIA_BIN to run against the upstream Hysteria server")
	}
	// ServerName is the TLS name supplied by a URI's sni or peer parameter.
	// The socket address stays an IP, and the self-signed certificate is not trusted.
	const serverName = "cuven-obfs.example"
	const auth = "example-auth-token"
	const obfsPassword = "example-obfs-pass"

	dir := t.TempDir()
	certFile, keyFile, _ := writeServerCertificate(t, dir, serverName)
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.LocalAddr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	configFile := filepath.Join(dir, "server.yaml")
	config := fmt.Sprintf("listen: %q\ntls:\n  cert: %q\n  key: %q\nauth:\n  type: password\n  password: %q\nobfs:\n  type: salamander\n  salamander:\n    password: %q\n",
		address, certFile, keyFile, auth, obfsPassword)
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "server", "--config", configFile, "--log-level", "debug", "--disable-update-check")
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(exited)
	}()
	defer func() {
		cancel()
		<-exited
		if t.Failed() {
			log, _ := os.ReadFile(logFile.Name())
			t.Logf("official server output:\n%s", log)
		}
	}()

	clientConfig := hy2.Config{
		Address: address, Auth: auth, ServerName: serverName,
		InsecureSkipVerify: true, Obfs: "salamander", ObfsPassword: obfsPassword,
	}
	var client *hy2.Client
	for {
		attempt, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		client, err = hy2.Dial(attempt, clientConfig)
		stop()
		if err == nil {
			break
		}
		select {
		case <-exited:
			t.Fatalf("upstream server exited before authenticating: %v", err)
		case <-ctx.Done():
			t.Fatalf("upstream server did not authenticate: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer client.Close()
	exerciseOfficialProxy(t, ctx, client)

	t.Run("verification stays on without insecure", func(t *testing.T) {
		verified := clientConfig
		verified.InsecureSkipVerify = false
		checkUpstreamDialRejected(t, ctx, verified)
	})
	t.Run("wrong obfuscation password", func(t *testing.T) {
		wrong := clientConfig
		wrong.ObfsPassword = "wrong-obfs-pass"
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		rejected, err := hy2.Dial(attempt, wrong)
		if rejected != nil {
			_ = rejected.Close()
			t.Fatal("wrong salamander password authenticated")
		}
		if err == nil {
			t.Fatal("expected the wrong salamander password to fail")
		}
	})
}

func exerciseOfficialProxy(t *testing.T, ctx context.Context, client *hy2.Client) {
	t.Helper()
	t.Run("TCP", func(t *testing.T) {
		local, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer local.Close()
		go func() {
			socket, err := local.Accept()
			if err != nil {
				return
			}
			defer socket.Close()
			_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.Copy(socket, socket)
		}()
		streamCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		stream, err := client.OpenTCP(streamCtx, local.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		want := bytes.Repeat([]byte("cuven-tcp-"), 1600)
		written, err := stream.Write(want)
		if err != nil || written != len(want) {
			t.Fatalf("TCP write sent %d of %d bytes: %v", written, len(want), err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("TCP echo differs")
		}
	})

	t.Run("UDP", func(t *testing.T) {
		local, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer local.Close()
		go func() {
			buf := make([]byte, 8192)
			for {
				n, addr, err := local.ReadFrom(buf)
				if err != nil {
					return
				}
				if _, err := local.WriteTo(buf[:n], addr); err != nil {
					return
				}
			}
		}()
		session, err := client.OpenUDP()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		// The upstream implementation's 4096-byte send buffer includes
		// framing. 3000 bytes exercises fragmentation in both directions.
		for _, length := range []int{49, 3000} {
			want := bytes.Repeat([]byte{'U'}, length)
			if err := session.Send(want, local.LocalAddr().String()); err != nil {
				t.Fatalf("send %d-byte UDP echo: %v", length, err)
			}
			wait, stop := context.WithTimeout(ctx, 5*time.Second)
			got, source, err := session.Receive(wait)
			stop()
			if err != nil {
				t.Fatalf("receive %d-byte UDP echo: %v", length, err)
			}
			if !bytes.Equal(got, want) || source != local.LocalAddr().String() {
				t.Fatalf("UDP echo differs for %d-byte packet: got %d bytes from %q", length, len(got), source)
			}
		}
	})
}

func checkUpstreamDialRejected(t *testing.T, ctx context.Context, config hy2.Config) {
	t.Helper()
	attempt, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	client, err := hy2.Dial(attempt, config)
	if err == nil {
		_ = client.Close()
		t.Fatal("upstream connection unexpectedly authenticated")
	}
	if attempt.Err() != nil {
		t.Fatalf("expected an explicit rejection, got %v", err)
	}
}

func writeServerCertificate(t *testing.T, directory, name string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(directory, "server.pem")
	keyFile := filepath.Join(directory, "server-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot trust upstream fixture certificate")
	}
	return certFile, keyFile, roots
}
