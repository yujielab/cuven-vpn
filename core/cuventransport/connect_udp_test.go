package cuventransport

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type sizedDatagramWriter struct {
	bytes.Buffer
	datagram []byte
	limit    int
	blocked  bool
}

func (w *sizedDatagramWriter) TryWriteAll(data []byte) error {
	if w.blocked {
		return quic.ErrWouldBlock
	}
	_, err := w.Write(data)
	return err
}

func (w *sizedDatagramWriter) SendDatagram(data []byte) error {
	if len(data) > w.limit {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(w.limit)}
	}
	w.datagram = bytes.Clone(data)
	return nil
}

func TestConnectUDPUsesDatagramsWhenTheyFit(t *testing.T) {
	envelope := bytes.Repeat([]byte{0x39}, 900)
	stream := &sizedDatagramWriter{limit: 1200}
	if err := SendConnectUDP(stream, envelope); err != nil {
		t.Fatal(err)
	}
	if stream.Len() != 0 {
		t.Fatal("packet that fits used a reliable capsule")
	}
	got, ok := ParseConnectUDPDatagram(stream.datagram)
	if !ok || !bytes.Equal(got, envelope) {
		t.Fatal("lost the context-zero datagram payload")
	}
}

func TestConnectUDPUsesCapsuleWhenPathCannotCarryFullDatagram(t *testing.T) {
	envelope := bytes.Repeat([]byte{0x39}, MaxDatagramSize)
	stream := &sizedDatagramWriter{limit: 1200}
	if err := SendConnectUDP(stream, envelope); err != nil {
		t.Fatal(err)
	}
	if len(stream.datagram) != 0 {
		t.Fatal("oversized datagram was emitted")
	}
	parser := http3.NewCapsuleParser(bytes.NewReader(stream.Bytes()))
	got, err := ReadConnectUDPCapsule(parser, make([]byte, MaxDatagramSize))
	if err != nil || !bytes.Equal(got, envelope) {
		t.Fatalf("lost the context-zero capsule payload: %v", err)
	}
}

func TestConnectUDPDoesNotBlockOnCapsuleFlowControl(t *testing.T) {
	envelope := bytes.Repeat([]byte{0x39}, MaxDatagramSize)
	stream := &sizedDatagramWriter{limit: 1200, blocked: true}
	if err := SendConnectUDP(stream, envelope); err != nil {
		t.Fatal(err)
	}
	if stream.Len() != 0 || len(stream.datagram) != 0 {
		t.Fatal("congested stream emitted a partial packet")
	}
}
