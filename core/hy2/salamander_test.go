package hy2

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSalamanderMatchesSpecificationVector(t *testing.T) {
	password := []byte("example-obfs-pass")
	salt := []byte{0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	payload := []byte("hysteria2")
	key := salamanderKey(password, salt, nil)
	wantKey, err := hex.DecodeString("21ab13cff0f3fd3b93d334db49fccc14637f165c88679c67a51fec2fc482923d")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], wantKey) {
		t.Fatalf("BLAKE2b-256(password || salt) = %x", key)
	}

	wire := make([]byte, salamanderSaltLen+len(payload))
	if n := obfuscateSalamander(password, salt, payload, wire, nil); n != len(wire) {
		t.Fatalf("obfuscated length = %d", n)
	}
	wantWire, err := hex.DecodeString("102233445566778849d260bb9581945aa1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wire packet = %x", wire)
	}
	plain := make([]byte, len(payload))
	if n := deobfuscateSalamander(password, wire, plain, nil); n != len(payload) || !bytes.Equal(plain, payload) {
		t.Fatalf("recovered %q (%d bytes)", plain, n)
	}
	other := make([]byte, len(payload))
	if n := deobfuscateSalamander([]byte("wrong-obfs-pass"), wire, other, nil); n != len(payload) || bytes.Equal(other, payload) {
		t.Fatal("wrong password recovered the payload")
	}
	if deobfuscateSalamander(password, wire[:salamanderSaltLen], plain, nil) != 0 ||
		deobfuscateSalamander(password, wire[:4], plain, nil) != 0 {
		t.Fatal("short packet was accepted")
	}
}

func TestSalamanderRoundTrip(t *testing.T) {
	password := []byte("example-obfs-pass")
	salt := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	for _, length := range []int{1, 31, 32, 33, 1200} {
		payload := bytes.Repeat([]byte{byte(length)}, length)
		wire := make([]byte, salamanderSaltLen+length)
		if obfuscateSalamander(password, salt, payload, wire, nil) != len(wire) {
			t.Fatalf("length %d did not fit", length)
		}
		plain := make([]byte, length)
		if n := deobfuscateSalamander(password, wire, plain, nil); n != length || !bytes.Equal(plain, payload) {
			t.Fatalf("length %d round trip failed", length)
		}
	}
}

func TestSalamanderConnRoundTripAndInvalidPackets(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	const password = "example-obfs-pass"
	wrapped, err := wrapSalamander(server, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapped.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("cuven"), 80)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	first := make([]byte, salamanderSaltLen+len(payload))
	second := make([]byte, salamanderSaltLen+len(payload))
	if obfuscateSalamander([]byte(password), salt, payload, first, nil) == 0 {
		t.Fatal("failed to build first packet")
	}
	salt[0] = 9
	if obfuscateSalamander([]byte(password), salt, payload, second, nil) == 0 {
		t.Fatal("failed to build second packet")
	}
	if bytes.Equal(first[:salamanderSaltLen], second[:salamanderSaltLen]) {
		t.Fatal("distinct salts produced the same prefix")
	}
	if _, err := client.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(first); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload)+32)
	n, _, err := wrapped.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("recovered %q, error %v", buf[:n], err)
	}

	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	senderSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer senderSocket.Close()
	sender, err := wrapSalamander(senderSocket, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteTo(payload, raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteTo(make([]byte, salamanderBufferSize), raw.LocalAddr()); err == nil {
		t.Fatal("oversized packet was written")
	}
	if err := raw.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, salamanderBufferSize)
	n, _, err = raw.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload)+salamanderSaltLen {
		t.Fatalf("wire length = %d, want %d", n, len(payload)+salamanderSaltLen)
	}
	plain := make([]byte, len(payload))
	if deobfuscateSalamander([]byte(password), wire[:n], plain, nil) != len(payload) || !bytes.Equal(plain, payload) {
		t.Fatalf("raw wire did not recover %q", plain)
	}
}

func TestDialRejectsObfuscationConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := validateObfs("", ""); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		obfs     string
		password string
		want     string
	}{
		{name: "unknown", obfs: "gecko", password: "example-obfs-pass", want: "unsupported"},
		{name: "missing password", obfs: "salamander", want: "at least 4"},
		{name: "short password", obfs: "salamander", password: "no", want: "at least 4"},
		{name: "password without type", password: "example-obfs-pass", want: "requires obfs=salamander"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Dial(ctx, Config{
				Address: "198.51.100.1:443", Auth: "example-auth-token",
				Obfs: test.obfs, ObfsPassword: test.password,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || errors.Is(err, context.Canceled) {
				t.Fatalf("Dial error = %v", err)
			}
		})
	}
}

func TestCertificateVerificationDefaultsOn(t *testing.T) {
	var config Config
	if config.InsecureSkipVerify || config.Obfs != "" || config.ObfsPassword != "" {
		t.Fatal("verification must stay on and obfuscation must stay off")
	}
}
