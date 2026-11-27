package cuventransport

import (
	"bytes"
	"testing"
)

func TestEnvelopeAuthentication(t *testing.T) {
	codec := testCodec(t, 7)
	payload := bytes.Repeat([]byte{0x5a}, MaxPayloadSize)
	packet, err := codec.Seal(ClientToServer, Data, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != MaxDatagramSize {
		t.Fatalf("envelope size = %d, want %d", len(packet), MaxDatagramSize)
	}
	buf := make([]byte, 1, MaxPayloadSize+1)
	buf[0] = 0x21
	kind, plain, err := codec.OpenTo(ClientToServer, buf, packet)
	if err != nil || kind != Data || plain[0] != 0x21 || !bytes.Equal(plain[1:], payload) || &plain[0] != &buf[0] {
		t.Fatalf("OpenTo did not append exact plaintext to buffer; kind %v, error %v", kind, err)
	}
	if _, _, err := codec.Open(ServerToClient, packet); err == nil {
		t.Fatal("accepted an envelope in the opposite direction")
	}
	if _, _, err := testCodec(t, 8).Open(ClientToServer, packet); err == nil {
		t.Fatal("accepted an envelope encrypted with a different key")
	}
	for _, index := range []int{0, kindOffset - 1, kindOffset, nonceStart, headerSize, len(packet) - 1} {
		changed := bytes.Clone(packet)
		changed[index] ^= 1
		if _, _, err := codec.Open(ClientToServer, changed); err == nil {
			t.Fatalf("accepted an envelope with a changed byte at offset %d", index)
		}
	}
	second, err := codec.Seal(ClientToServer, Data, payload)
	if err != nil || bytes.Equal(second[nonceStart:headerSize], packet[nonceStart:headerSize]) {
		t.Fatalf("encodings reused a nonce; error %v", err)
	}
}

func TestEnvelopeBoundsAndProbeDirections(t *testing.T) {
	codec := testCodec(t, 7)
	for _, length := range []int{0, MaxPayloadSize + 1} {
		if _, err := codec.Seal(ClientToServer, Data, make([]byte, length)); err == nil {
			t.Fatalf("accepted %d bytes of data", length)
		}
	}
	for _, length := range []int{0, Overhead, MaxDatagramSize + 1} {
		if _, _, err := codec.Open(ClientToServer, make([]byte, length)); err == nil {
			t.Fatalf("opened an envelope of length %d", length)
		}
	}
	for _, key := range [][]byte{nil, make([]byte, KeySize), make([]byte, KeySize+1)} {
		if _, err := NewCodec(key); err == nil {
			t.Fatalf("accepted invalid key of length %d", len(key))
		}
	}
	token := bytes.Repeat([]byte{0x4b}, TokenSize)
	if _, err := codec.Seal(ServerToClient, Probe, token); err == nil {
		t.Fatal("encoded a server-to-client Probe")
	}
	if _, err := codec.Seal(ClientToServer, ProbeAck, token); err == nil {
		t.Fatal("encoded a client-to-server ProbeAck")
	}
	if _, err := codec.Seal(ClientToServer, Probe, token[:TokenSize-1]); err == nil {
		t.Fatal("encoded a Probe with a short nonce")
	}
}

func testCodec(t *testing.T, value byte) *Codec {
	t.Helper()
	codec, err := NewCodec(bytes.Repeat([]byte{value}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
