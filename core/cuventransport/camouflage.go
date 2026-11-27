package cuventransport

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	v2MetadataSize = 3
	v2Overhead     = chacha20poly1305.NonceSizeX + v2MetadataSize + chacha20poly1305.Overhead
	v2PaddingMax   = 128
	v2LengthBlock  = 64
)

func paddingLimit(size int) int {
	return min(v2PaddingMax, MaxDatagramSize-v2Overhead-size)
}

func paddedLengthRange(size int) (int, int) {
	length := size + v2Overhead
	start := min(MaxDatagramSize, (length+v2LengthBlock-1)/v2LengthBlock*v2LengthBlock)
	return start, min(MaxDatagramSize, start+v2LengthBlock-1)
}

func randomPadding(size int) (int, error) {
	// Payload lengths within a block share the same range of wire lengths.
	first, last := paddedLengthRange(size)
	var choice [2]byte
	if _, err := rand.Read(choice[:]); err != nil {
		return 0, err
	}
	offset := int(binary.BigEndian.Uint16(choice[:])) * (last - first + 1) / 65536
	return first + offset - size - v2Overhead, nil
}

func (c *Codec) sealV2(direction Direction, kind Kind, payload []byte, padding int) ([]byte, error) {
	if padding < 0 || padding > paddingLimit(len(payload)) {
		return nil, errFrame
	}
	const nonceSize = chacha20poly1305.NonceSizeX
	var random [nonceSize + v2PaddingMax]byte
	if _, err := rand.Read(random[:nonceSize+padding]); err != nil {
		return nil, err
	}
	size := len(payload) + padding + v2Overhead
	packet := make([]byte, size-chacha20poly1305.Overhead, size)
	copy(packet, random[:nonceSize])
	cleartext := packet[nonceSize:]
	cleartext[0] = byte(kind)
	binary.BigEndian.PutUint16(cleartext[1:v2MetadataSize], uint16(len(payload)))
	copy(cleartext[v2MetadataSize:], payload)
	copy(cleartext[v2MetadataSize+len(payload):], random[nonceSize:nonceSize+padding])
	return c.keys[direction].Seal(packet[:nonceSize], packet[:nonceSize], cleartext, nil), nil
}

func (c *Codec) openV2(direction Direction, dst []byte, packet []byte) (Kind, []byte, error) {
	if len(packet) <= v2Overhead || len(packet) > MaxDatagramSize {
		return 0, nil, errFrame
	}
	const nonceSize = chacha20poly1305.NonceSizeX
	output, err := c.keys[direction].Open(dst, packet[:nonceSize], packet[nonceSize:], nil)
	if err != nil {
		return 0, nil, errFrame
	}
	cleartext := output[len(dst):]
	kind := Kind(cleartext[0])
	size := int(binary.BigEndian.Uint16(cleartext[1:v2MetadataSize]))
	padding := len(cleartext) - v2MetadataSize - size
	if !validPayload(direction, kind, size) || padding < 0 || padding > paddingLimit(size) {
		clear(cleartext)
		return 0, nil, errFrame
	}
	copy(cleartext, cleartext[v2MetadataSize:v2MetadataSize+size])
	return kind, output[:len(dst)+size], nil
}
