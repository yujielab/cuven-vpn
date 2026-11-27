// Package iptunnel implements Cuven's authenticated IP tunnel over QUIC.
package iptunnel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ALPN          = "cuven-ip/1"
	MTU           = 1280
	tokenSize     = 32
	authTimeout   = 8 * time.Second
	closeNormal   = 0
	closeRejected = 1
	authAccepted  = 1
	authIPv6      = 2
	queueCapacity = 64
)

var (
	ErrAuthentication = errors.New("Cuven IP tunnel authentication failed")
	ErrInvalidPacket  = errors.New("invalid IP packet")
)

// Token is a secret generated independently for a client enrollment.
type Token [tokenSize]byte

func ParseToken(text string) (Token, error) {
	var token Token
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	defer clear(decoded)
	if err != nil || len(decoded) != len(token) {
		return token, errors.New("Cuven token must be 32 bytes in unpadded base64url")
	}
	copy(token[:], decoded)
	if token == (Token{}) {
		return token, errors.New("Cuven token must be nonzero")
	}
	return token, nil
}

// Session sends original IPv4 and IPv6 packets after mutual authentication.
type Session struct {
	connection *quic.Conn
	packets    chan []byte
	sequence   atomic.Uint32
	ipv6       bool
}

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:       true,
		HandshakeIdleTimeout:  authTimeout,
		MaxIdleTimeout:        45 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	}
}

func Dial(ctx context.Context, address string, token Token, tlsConfig *tls.Config) (*Session, error) {
	if token == (Token{}) || tlsConfig == nil || tlsConfig.InsecureSkipVerify {
		return nil, ErrAuthentication
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{ALPN}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	transport := quicConfig()
	transport.MaxIncomingStreams = -1
	startup, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	connection, err := quic.DialAddr(startup, address, config, transport)
	if err != nil {
		return nil, err
	}
	dual, err := authenticateClient(startup, connection, token)
	if err != nil {
		_ = connection.CloseWithError(closeRejected, "authentication failed")
		return nil, err
	}
	return newSession(connection, dual), nil
}

func Listen(address string, tlsConfig *tls.Config) (*quic.Listener, error) {
	if tlsConfig == nil {
		return nil, errors.New("Cuven gateway requires a TLS certificate")
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{ALPN}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	return quic.ListenAddr(address, config, quicConfig())
}

// Authenticate accepts a single token proof on an established QUIC connection.
// The proof is bound to the TLS session by exporter keying material.
func Authenticate(ctx context.Context, connection *quic.Conn, token Token, dual bool) (*Session, error) {
	if err := authenticateServer(ctx, connection, token, dual); err != nil {
		_ = connection.CloseWithError(closeRejected, "authentication failed")
		return nil, err
	}
	return newSession(connection, dual), nil
}

func tokenProof(connection *quic.Conn, token Token) ([]byte, error) {
	state := connection.ConnectionState()
	if token == (Token{}) || state.Used0RTT || !state.SupportsDatagrams.Remote ||
		state.TLS.NegotiatedProtocol != ALPN || !state.TLS.HandshakeComplete {
		return nil, ErrAuthentication
	}
	binding, err := state.TLS.ExportKeyingMaterial("EXPORTER-Cuven-IP-v1", nil, tokenSize)
	if err != nil {
		return nil, ErrAuthentication
	}
	defer clear(binding)
	mac := hmac.New(sha256.New, token[:])
	mac.Write(binding)
	return mac.Sum(nil), nil
}

func authenticateClient(ctx context.Context, connection *quic.Conn, token Token) (bool, error) {
	proof, err := tokenProof(connection, token)
	if err != nil {
		return false, err
	}
	defer clear(proof)
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return false, err
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()) })
	defer stop()
	if _, err := stream.Write(proof); err != nil {
		return false, err
	}
	if err := stream.Close(); err != nil {
		return false, err
	}
	var reply [1]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil ||
		(reply[0] != authAccepted && reply[0] != authAccepted|authIPv6) {
		return false, ErrAuthentication
	}
	stream.CancelRead(0)
	return reply[0]&authIPv6 != 0, nil
}

func authenticateServer(ctx context.Context, connection *quic.Conn, token Token, dual bool) error {
	ctx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	expected, err := tokenProof(connection, token)
	if err != nil {
		return err
	}
	defer clear(expected)
	stream, err := connection.AcceptStream(ctx)
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()) })
	defer stop()
	var proof [tokenSize]byte
	defer clear(proof[:])
	if _, err := io.ReadFull(stream, proof[:]); err != nil || !hmac.Equal(proof[:], expected) {
		return ErrAuthentication
	}
	stream.CancelRead(0)
	response := byte(authAccepted)
	if dual {
		response |= authIPv6
	}
	if _, err := stream.Write([]byte{response}); err != nil {
		return err
	}
	return stream.Close()
}

func newSession(connection *quic.Conn, dual bool) *Session {
	session := &Session{connection: connection, packets: make(chan []byte, queueCapacity), ipv6: dual}
	go session.receive()
	return session
}

func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case packet, ok := <-s.packets:
		if !ok {
			return nil, io.EOF
		}
		return packet, nil
	}
}

func (s *Session) TryReadPacket() []byte {
	select {
	case packet := <-s.packets:
		return packet
	default:
		return nil
	}
}

func (s *Session) Done() <-chan struct{} { return s.connection.Context().Done() }

func (s *Session) IPv6Enabled() bool { return s.ipv6 }

func (s *Session) Stats() quic.ConnectionStats { return s.connection.ConnectionStats() }

func (s *Session) Close() error { return s.connection.CloseWithError(closeNormal, "") }
