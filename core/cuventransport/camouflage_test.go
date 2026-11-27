package cuventransport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestVersion2Envelope(t *testing.T) {
	codec := testVersionCodec(t, 7, Version2)
	receiver := testVersionCodec(t, 7, Version2)
	otherKey := testVersionCodec(t, 8, Version2)
	legacy := testCodec(t, 7)
	payload := bytes.Repeat([]byte{0x42}, 32)
	lengths := make(map[int]bool)
	for range 20 {
		packet, err := codec.Seal(ClientToServer, Data, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) < len(payload)+v2Overhead || len(packet) > len(payload)+v2Overhead+v2PaddingMax {
			t.Fatalf("padded envelope length outside bounds: %d", len(packet))
		}
		lengths[len(packet)] = true
		buf := make([]byte, 1, MaxDatagramSize)
		buf[0] = 0x21
		kind, cleartext, err := receiver.OpenTo(ClientToServer, buf, packet)
		if err != nil || kind != Data || cleartext[0] != 0x21 || &cleartext[0] != &buf[0] || !bytes.Equal(cleartext[1:], payload) {
			t.Fatalf("OpenTo did not append exact payload to buffer; kind %v, error %v", kind, err)
		}
		if _, _, err := receiver.Open(ServerToClient, packet); err == nil {
			t.Fatal("accepted v2 envelope in wrong direction")
		}
		if _, _, err := otherKey.Open(ClientToServer, packet); err == nil {
			t.Fatal("accepted v2 envelope encrypted with a different key")
		}
		if _, _, err := legacy.Open(ClientToServer, packet); err == nil {
			t.Fatal("accepted a v2 envelope in v1 mode")
		}
		for _, offset := range []int{0, chacha20poly1305.NonceSizeX, len(packet) - 1} {
			changed := bytes.Clone(packet)
			changed[offset] ^= 1
			if _, _, err := receiver.Open(ClientToServer, changed); err == nil {
				t.Fatalf("accepted a changed byte at v2 envelope offset %d", offset)
			}
		}
	}
	if len(lengths) < 2 {
		t.Fatal("fixed plaintext length always produced the same v2 envelope length")
	}
	oldPacket, err := legacy.Seal(ClientToServer, Data, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.Open(ClientToServer, oldPacket); err == nil {
		t.Fatal("accepted a v1 envelope in v2 mode")
	}
	packet := encode(t, codec, Data, make([]byte, MaxPayloadSize))
	if len(packet) > MaxDatagramSize {
		t.Fatalf("maximum payload produced oversized envelope: %d", len(packet))
	}
}

func TestVersion2PaddingGroupsNearbySizes(t *testing.T) {
	for _, size := range []int{32, 63, 84} {
		if first, last := paddedLengthRange(size); first != 128 || last != 191 {
			t.Fatalf("payload %d produces wire range %d–%d, want 128–191", size, first, last)
		}
	}
	for size := 1; size <= MaxPayloadSize; size++ {
		first, last := paddedLengthRange(size)
		base := size + v2Overhead
		if first < base || last < first || last-base > paddingLimit(size) {
			t.Fatalf("wire range %d–%d falls outside the v2 limits for payload %d", first, last, size)
		}
	}

	codec := testVersionCodec(t, 7, Version2)
	payload := bytes.Repeat([]byte{0x42}, 32)
	// Older encoders could choose zero padding at this size.
	packet, err := codec.sealV2(ClientToServer, Data, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	kind, decoded, err := codec.Open(ClientToServer, packet)
	if err != nil || kind != Data || !bytes.Equal(decoded, payload) {
		t.Fatalf("opening a legacy v2 envelope: kind %v, error %v", kind, err)
	}
}

func TestVersion2RejectsInvalidEncryptedMetadata(t *testing.T) {
	codec := testVersionCodec(t, 7, Version2)
	for i, test := range []struct {
		kind     Kind
		declared uint16
		bytes    int
	}{
		{Data, 16, 15},
		{Data, 16, 16 + v2PaddingMax + 1},
		{Probe, TokenSize + 1, TokenSize + 1},
		{ProbeAck, TokenSize, TokenSize},
		{0xff, 16, 16},
	} {
		plain := make([]byte, v2MetadataSize+test.bytes)
		plain[0] = byte(test.kind)
		binary.BigEndian.PutUint16(plain[1:v2MetadataSize], test.declared)
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		nonce[0] = byte(i)
		packet := codec.keys[ClientToServer].Seal(bytes.Clone(nonce), nonce, plain, nil)
		if _, _, err := codec.Open(ClientToServer, packet); err == nil {
			t.Fatalf("accepted invalid encrypted metadata %+v", test)
		}
	}
}

func testVersionCodec(t *testing.T, value byte, version Version) *Codec {
	t.Helper()
	codec, err := NewCodecVersion(bytes.Repeat([]byte{value}, KeySize), version)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
