// Package cuventransport implements the Cuven UDP envelope for WireGuard packets.
// Version 1 starts with the four bytes 43 56 57 01, a one-byte kind, and a
// 24-byte random nonce. XChaCha20-Poly1305 ciphertext and its 16-byte tag follow.
// The entire header is authenticated as additional data. Version 2 transmits
// only a random nonce followed by the ciphertext and tag. Its encrypted data
// starts with a one-byte kind and a two-byte big-endian payload length, then the
// payload and up to 128 random padding bytes. HKDF-SHA256 derives an independent
// key per version and direction using an empty salt and a versioned info label.
package cuventransport

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize         = chacha20poly1305.KeySize
	TokenSize       = 16
	MaxDatagramSize = 1452
	MaxPayloadSize  = MaxDatagramSize - Overhead
	Overhead        = headerSize + chacha20poly1305.Overhead // Version 1 overhead.

	magic      = "CVW\x01"
	kindOffset = len(magic)
	nonceStart = kindOffset + 1
	headerSize = nonceStart + chacha20poly1305.NonceSizeX
)

type Version uint8

const (
	Version1 Version = 1
	Version2 Version = 2
)

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

type Kind uint8

const (
	Data Kind = iota + 1
	Probe
	ProbeAck
)

var (
	errKeySize   = errors.New("Cuven envelope key must contain 32 bytes")
	errDirection = errors.New("invalid Cuven envelope direction")
	errFrame     = errors.New("invalid Cuven envelope")
	errVersion   = errors.New("unsupported Cuven envelope version")
)

// Codec encrypts and authenticates envelopes of one configured wire version.
// It is safe for concurrent use.
type Codec struct {
	keys    [2]cipher.AEAD
	version Version
}

func NewCodec(key []byte) (*Codec, error) {
	return NewCodecVersion(key, Version1)
}

func NewCodecVersion(key []byte, version Version) (*Codec, error) {
	if len(key) != KeySize {
		return nil, errKeySize
	}
	var zero [KeySize]byte
	if bytes.Equal(key, zero[:]) {
		return nil, errors.New("Cuven envelope key must be nonzero")
	}
	var domain string
	switch version {
	case Version1:
		domain = "cuven/wireguard-envelope/v1/"
	case Version2:
		domain = "cuven/wireguard-envelope/v2/"
	default:
		return nil, errVersion
	}
	c := &Codec{version: version}
	for direction, label := range []string{"client-to-server", "server-to-client"} {
		derived, err := hkdf.Key(sha256.New, key, nil, domain+label, KeySize)
		if err != nil {
			return nil, err
		}
		c.keys[direction], err = chacha20poly1305.NewX(derived)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Codec) Seal(direction Direction, kind Kind, payload []byte) ([]byte, error) {
	if direction > ServerToClient {
		return nil, errDirection
	}
	if !validPayload(direction, kind, len(payload)) {
		return nil, errFrame
	}
	if c.version == Version2 {
		padding, err := randomPadding(len(payload))
		if err != nil {
			return nil, err
		}
		return c.sealV2(direction, kind, payload, padding)
	}
	packet := make([]byte, headerSize, len(payload)+Overhead)
	copy(packet, magic)
	packet[kindOffset] = byte(kind)
	nonce := packet[nonceStart:headerSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.keys[direction].Seal(packet, nonce, payload, packet), nil
}

func (c *Codec) Open(direction Direction, packet []byte) (Kind, []byte, error) {
	return c.OpenTo(direction, nil, packet)
}

// OpenTo appends authenticated plaintext to dst. The dst and packet buffers
// must not overlap.
func (c *Codec) OpenTo(direction Direction, dst []byte, packet []byte) (Kind, []byte, error) {
	if direction > ServerToClient {
		return 0, nil, errDirection
	}
	if c.version == Version2 {
		return c.openV2(direction, dst, packet)
	}
	if len(packet) <= Overhead || len(packet) > MaxDatagramSize || string(packet[:kindOffset]) != magic {
		return 0, nil, errFrame
	}
	kind := Kind(packet[kindOffset])
	if !validPayload(direction, kind, len(packet)-Overhead) {
		return 0, nil, errFrame
	}
	payload, err := c.keys[direction].Open(dst, packet[nonceStart:headerSize], packet[headerSize:], packet[:headerSize])
	if err != nil {
		return 0, nil, errFrame
	}
	return kind, payload, nil
}

func (c *Codec) nonce(packet []byte) []byte {
	if c.version == Version2 {
		return packet[:chacha20poly1305.NonceSizeX]
	}
	return packet[nonceStart:headerSize]
}

func (c *Codec) sealProbeAck(payload []byte, requestSize int) ([]byte, error) {
	if c.version == Version2 {
		// An ACK uses the same wire length as the authenticated probe.
		return c.sealV2(ServerToClient, ProbeAck, payload, requestSize-v2Overhead-len(payload))
	}
	return c.Seal(ServerToClient, ProbeAck, payload)
}

func validPayload(direction Direction, kind Kind, size int) bool {
	switch kind {
	case Data:
		return size > 0 && size <= MaxPayloadSize
	case Probe:
		return direction == ClientToServer && size == TokenSize
	case ProbeAck:
		return direction == ServerToClient && size == TokenSize
	default:
		return false
	}
}
