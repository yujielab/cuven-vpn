package hy2

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
)

const (
	salamanderSaltLen     = 8
	salamanderMinPassword = 4
	salamanderBufferSize  = 2048
)

var errSalamanderPassword = errors.New("Hysteria salamander password must be at least 4 bytes")

// salamanderKey is BLAKE2b-256(password || salt), the unkeyed hash from the
// Hysteria 2 Salamander specification. scratch is optional reusable storage.
func salamanderKey(password, salt, scratch []byte) [blake2b.Size256]byte {
	combined := scratch
	size := len(password) + len(salt)
	if cap(combined) < size {
		combined = make([]byte, size)
	}
	combined = combined[:size]
	copy(combined, password)
	copy(combined[len(password):], salt)
	return blake2b.Sum256(combined)
}

// obfuscateSalamander writes salt || (payload XOR key). salt must be 8 bytes.
// The salt is copied to the front of dst, so callers may pass dst[:8] as salt
// after filling it with random bytes.
func obfuscateSalamander(password, salt, payload, dst, scratch []byte) int {
	outLen := salamanderSaltLen + len(payload)
	if len(salt) != salamanderSaltLen || len(dst) < outLen {
		return 0
	}
	copy(dst[:salamanderSaltLen], salt)
	key := salamanderKey(password, salt, scratch)
	for i, value := range payload {
		dst[salamanderSaltLen+i] = value ^ key[i%len(key)]
	}
	return outLen
}

// deobfuscateSalamander recovers a payload. Packets shorter than the salt are
// invalid and must be discarded, matching the specification. A wrong password
// is not detectable here: Salamander has no authentication tag, and the QUIC
// layer rejects the resulting garbage.
func deobfuscateSalamander(password, packet, dst, scratch []byte) int {
	outLen := len(packet) - salamanderSaltLen
	if outLen <= 0 || len(dst) < outLen {
		return 0
	}
	key := salamanderKey(password, packet[:salamanderSaltLen], scratch)
	for i, value := range packet[salamanderSaltLen:] {
		dst[i] = value ^ key[i%len(key)]
	}
	return outLen
}

// salamanderConn wraps a UDP socket so QUIC only sees deobfuscated datagrams.
// Wire packets are 8 bytes larger than the QUIC payload.
type salamanderConn struct {
	net.PacketConn
	password     []byte
	readBuf      []byte
	writeBuf     []byte
	readScratch  []byte
	writeScratch []byte
	readMu       sync.Mutex
	writeMu      sync.Mutex
}

func wrapSalamander(conn net.PacketConn, password string) (net.PacketConn, error) {
	if len(password) < salamanderMinPassword {
		return nil, errSalamanderPassword
	}
	return &salamanderConn{
		PacketConn:   conn,
		password:     []byte(password),
		readBuf:      make([]byte, salamanderBufferSize),
		writeBuf:     make([]byte, salamanderBufferSize),
		readScratch:  make([]byte, 0, len(password)+salamanderSaltLen),
		writeScratch: make([]byte, 0, len(password)+salamanderSaltLen),
	}, nil
}

func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, addr, err := c.PacketConn.ReadFrom(c.readBuf)
		if n <= 0 {
			return 0, addr, err
		}
		n = deobfuscateSalamander(c.password, c.readBuf[:n], p, c.readScratch)
		if n > 0 || err != nil {
			return n, addr, err
		}
		// Spec: discard invalid packets and keep reading.
	}
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(c.writeBuf) < salamanderSaltLen+len(p) {
		return 0, errors.New("Hysteria salamander packet is too large")
	}
	if _, err := rand.Read(c.writeBuf[:salamanderSaltLen]); err != nil {
		return 0, err
	}
	n := obfuscateSalamander(c.password, c.writeBuf[:salamanderSaltLen], p, c.writeBuf, c.writeScratch)
	if n == 0 {
		return 0, errors.New("Hysteria salamander packet is too large")
	}
	if _, err := c.PacketConn.WriteTo(c.writeBuf[:n], addr); err != nil {
		return 0, err
	}
	// quic-go compares the count with the original QUIC packet, not the wire size.
	return len(p), nil
}

func (c *salamanderConn) SetReadBuffer(bytes int) error {
	setter, ok := c.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of receive buffer size")
	}
	return setter.SetReadBuffer(bytes)
}

func (c *salamanderConn) SetWriteBuffer(bytes int) error {
	setter, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of send buffer size")
	}
	return setter.SetWriteBuffer(bytes)
}
