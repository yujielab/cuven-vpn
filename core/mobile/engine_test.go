package mobile

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

func TestStartFailureCode(t *testing.T) {
	expired := &tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired}}
	hostname := &tls.CertificateVerificationError{Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "private.example"}}
	untrusted := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}}
	for _, tc := range []struct {
		err  error
		code string
	}{
		{nil, ""}, {errIPv6Unavailable, "gateway-ipv6"}, {expired, "certificate-time"},
		{hostname, "certificate-name"}, {untrusted, "certificate"},
		{context.DeadlineExceeded, "timeout"}, {context.Canceled, "cancelled"},
		{errors.New("private details"), "connection"},
	} {
		err := tc.err
		if err != nil {
			err = fmt.Errorf("startup: %w", err)
		}
		if got := startFailureCode(err); got != tc.code {
			t.Errorf("got %q for %T, want %q", got, tc.err, tc.code)
		}
	}
}

func TestDecodeBatch(t *testing.T) {
	batch := []byte{0, 3, 0x45, 1, 2, 0, 2, 0x60, 3}
	var packets [maxBatchPackets][]byte
	count, err := decodeBatch(batch, 1380, &packets)
	if err != nil || count != 2 || !bytes.Equal(packets[0], batch[2:5]) || !bytes.Equal(packets[1], batch[7:]) {
		t.Fatalf("decodeBatch returned %d packets, %v", count, err)
	}

	limit := bytes.Repeat([]byte{0, 1, 0x45}, maxBatchPackets)
	if count, err := decodeBatch(limit, 1380, &packets); err != nil || count != maxBatchPackets {
		t.Fatalf("valid maximum batch returned %d packets, %v", count, err)
	}
}

func TestDecodeRejectsMalformedBatches(t *testing.T) {
	oversize := make([]byte, 1381+packetHeaderLen)
	binary.BigEndian.PutUint16(oversize, 1381)

	for name, batch := range map[string][]byte{
		"truncated header":  {0, 1, 0x45, 0},
		"truncated payload": {0, 2, 0x45},
		"empty record":      {0, 0},
		"above MTU":         oversize,
		"too many packets":  bytes.Repeat([]byte{0, 1, 0x45}, maxBatchPackets+1),
	} {
		t.Run(name, func(t *testing.T) {
			var packets [maxBatchPackets][]byte
			count, err := decodeBatch(batch, 1380, &packets)
			if count != 0 || !errors.Is(err, errInvalidBatch) {
				t.Fatalf("decodeBatch returned %d packets, %v", count, err)
			}
		})
	}
}

func TestWriteBatchPrivacyPolicy(t *testing.T) {
	ipv4 := func(protocol byte, transport []byte) []byte {
		packet := make([]byte, 20, 20+len(transport))
		packet[0], packet[9] = 0x45, protocol
		binary.BigEndian.PutUint16(packet[2:4], uint16(20+len(transport)))
		copy(packet[16:20], []byte{1, 1, 1, 1})
		return append(packet, transport...)
	}
	udp := func(port uint16, payload []byte) []byte {
		header := make([]byte, 8, 8+len(payload))
		binary.BigEndian.PutUint16(header[0:2], 49152)
		binary.BigEndian.PutUint16(header[2:4], port)
		binary.BigEndian.PutUint16(header[4:6], uint16(8+len(payload)))
		return ipv4(17, append(header, payload...))
	}
	stunPayload := make([]byte, 20)
	copy(stunPayload, []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}) // STUN binding request
	stun := udp(45000, stunPayload)
	quic := udp(443, []byte{0xc0, 0, 0, 0, 1})
	dns := udp(53, make([]byte, 12))
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 49152)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50
	https := ipv4(6, tcp)
	binary.BigEndian.PutUint16(tcp[2:4], 853)
	dot := ipv4(6, tcp)
	var batch []byte
	for _, packet := range [][]byte{stun, quic, dns, https, dot} {
		batch = binary.BigEndian.AppendUint16(batch, uint16(len(packet)))
		batch = append(batch, packet...)
	}

	for _, test := range []struct {
		name         string
		policy       packetPolicy
		encryptedDNS bool
		want         [][]byte
	}{
		{"normal", packetPolicy{}, false, [][]byte{stun, quic, dns, https, dot}},
		{"high security", packetPolicy{blockPlainDNS: true}, false, [][]byte{stun, quic, https, dot}},
		{"encrypted DNS", packetPolicy{}, true, [][]byte{stun, quic, https, dot}},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, sink := NewEngine(), &recordingTunnel{}
			defer engine.Stop()
			if test.encryptedDNS {
				if err := engine.RequireEncryptedDNS(); err != nil {
					t.Fatal(err)
				}
			}
			open := func(context.Context) (packetTunnel, error) { return sink, nil }
			if err := engine.start(1280, test.policy, open); err != nil {
				t.Fatal(err)
			}
			if err := engine.WriteBatch(batch); err != nil {
				t.Fatal(err)
			}
			if err := engine.RequireEncryptedDNS(); !errors.Is(err, errEngineUsed) {
				t.Fatalf("changing DNS policy after startup returned %v", err)
			}
			if !slices.EqualFunc(sink.packets, test.want, bytes.Equal) {
				t.Fatalf("forwarded packets: got %x, want %x", sink.packets, test.want)
			}
		})
	}
}

type recordingTunnel struct{ packets [][]byte }

func (r *recordingTunnel) WritePacket(packet []byte) error {
	r.packets = append(r.packets, bytes.Clone(packet))
	return nil
}

func (*recordingTunnel) ReadPacket(context.Context) ([]byte, error) { return nil, io.EOF }
func (*recordingTunnel) TryReadPacket() []byte                      { return nil }
func (*recordingTunnel) Close() error                               { return nil }

func TestStopBeforeStart(t *testing.T) {
	engine := NewEngine()
	engine.Stop()
	engine.Stop()
	if err := engine.StartCuven("127.0.0.1:4433", testAccessToken(), "localhost", false, false); !errors.Is(err, errEngineUsed) {
		t.Fatalf("Start after Stop returned %v", err)
	}
	if _, err := engine.ReadBatch(); !errors.Is(err, errEngineInactive) {
		t.Fatalf("ReadBatch after Stop returned %v", err)
	}
	if err := engine.WriteBatch(nil); !errors.Is(err, errEngineInactive) {
		t.Fatalf("WriteBatch after Stop returned %v", err)
	}
}

func TestStopCancelsStartup(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	defer engine.Stop()
	started := make(chan error, 1)
	go func() {
		started <- engine.StartCuven(socket.LocalAddr().String(), testAccessToken(), "localhost", false, false)
	}()
	var packet [2048]byte
	if _, _, err := socket.ReadFrom(packet[:]); err != nil {
		t.Fatalf("waiting for transport dial: %v", err)
	}

	engine.Stop()
	select {
	case err := <-started:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Start returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not unblock after Stop")
	}
}

func testAccessToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
}
