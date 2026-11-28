// Package iptunnel implements Cuven's authenticated IP tunnel over QUIC.
package iptunnel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ALPN          = "cuven-ip/2"
	legacyALPN    = "cuven-ip/1"
	MTU           = 1500
	LegacyMTU     = 1280
	tokenSize     = 32
	authTimeout   = 8 * time.Second
	closeNormal   = 0
	closeRejected = 1
	authAccepted  = 1
	authIPv6      = 2
	queueCapacity = 64
)

var (
	ErrAuthentication  = errors.New("Cuven IP tunnel authentication failed")
	ErrGatewayBusy     = errors.New("Cuven gateway already serves a session")
	ErrGatewayRejected = fmt.Errorf("%w: gateway rejected handshake", ErrAuthentication)
	ErrInvalidPacket   = errors.New("invalid IP packet")
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
	mtu        int
}

func quicConfig() *quic.Config {
	return &quic.Config{
		// A mobile path can shrink to IPv6's minimum MTU without a change
		// of addresses or a usable ICMP signal through NAT64. quic-go
		// retains its probed size on that path. Keep outer datagrams within
		// the QUIC minimum in both directions for the entire session.
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: true,
		EnableDatagrams:         true,
		HandshakeIdleTimeout:    authTimeout,
		MaxIdleTimeout:          45 * time.Second,
		KeepAlivePeriod:         15 * time.Second,
		MaxIncomingStreams:      1,
		MaxIncomingUniStreams:   -1,
	}
}

func Dial(ctx context.Context, address string, token Token, tlsConfig *tls.Config) (*Session, error) {
	if token == (Token{}) || tlsConfig == nil || tlsConfig.InsecureSkipVerify {
		return nil, ErrAuthentication
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{ALPN, legacyALPN}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.SessionTicketsDisabled = true
	transport := quicConfig()
	transport.MaxIncomingStreams = -1
	startup, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	connection, err := quic.DialAddr(startup, address, config, transport)
	if err != nil {
		return nil, dialError(err)
	}
	dual, err := authenticateClient(startup, connection, token)
	if err != nil {
		_ = connection.CloseWithError(closeRejected, "authentication failed")
		return nil, dialError(err)
	}
	return newSession(connection, dual), nil
}

// Cuven IP v1 uses the same QUIC application error code for an occupied
// gateway and a rejected handshake. Recognize only its two defined reasons.
func dialError(err error) error {
	var closed *quic.ApplicationError
	if errors.As(err, &closed) && closed.Remote && closed.ErrorCode == closeRejected {
		switch closed.ErrorMessage {
		case "gateway busy":
			return ErrGatewayBusy
		case "authentication failed":
			return ErrGatewayRejected
		}
	}
	return err
}

// Listener owns the UDP socket and QUIC listener for one gateway.
type Listener struct {
	*quic.Listener
	closeAll func() error
}

func (l *Listener) Close() error { return l.closeAll() }

func Listen(address string, tlsConfig *tls.Config) (*Listener, error) {
	if tlsConfig == nil {
		return nil, errors.New("Cuven gateway requires a TLS certificate")
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{ALPN, legacyALPN}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.SessionTicketsDisabled = true
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{
		Conn:                socket,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	listener, err := transport.Listen(config, quicConfig())
	if err != nil {
		_ = transport.Close()
		_ = socket.Close()
		return nil, err
	}
	closeAll := sync.OnceValue(func() error {
		return errors.Join(listener.Close(), transport.Close(), socket.Close())
	})
	return &Listener{Listener: listener, closeAll: closeAll}, nil
}

// Authenticate accepts a single token proof on an established QUIC connection.
// The proof is bound to the TLS session by exporter keying material.
func Authenticate(ctx context.Context, connection *quic.Conn, token Token, dual bool) (*Session, error) {
	return AuthenticateWithAdmission(ctx, connection, token, dual, nil)
}

// AuthenticateWithAdmission calls admit synchronously after verifying the token
// and before acknowledging the client. The caller owns any acquired reservation,
// including when writing the acknowledgement subsequently fails.
func AuthenticateWithAdmission(ctx context.Context, connection *quic.Conn, token Token, dual bool, admit func() bool) (*Session, error) {
	if err := authenticateServer(ctx, connection, token, dual, admit); err != nil {
		reason := "authentication failed"
		if errors.Is(err, ErrGatewayBusy) {
			reason = "gateway busy"
		}
		_ = connection.CloseWithError(closeRejected, reason)
		return nil, err
	}
	return newSession(connection, dual), nil
}

func tokenProof(connection *quic.Conn, token Token) ([]byte, error) {
	state := connection.ConnectionState()
	if token == (Token{}) || state.Used0RTT || !state.SupportsDatagrams.Remote ||
		(state.TLS.NegotiatedProtocol != ALPN && state.TLS.NegotiatedProtocol != legacyALPN) || !state.TLS.HandshakeComplete ||
		state.TLS.CurveID != tls.X25519MLKEM768 {
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
	if _, err := io.ReadFull(stream, reply[:]); err != nil {
		return false, err
	}
	if reply[0] != authAccepted && reply[0] != authAccepted|authIPv6 {
		return false, ErrAuthentication
	}
	stream.CancelRead(0)
	return reply[0]&authIPv6 != 0, nil
}

func authenticateServer(ctx context.Context, connection *quic.Conn, token Token, dual bool, admit func() bool) error {
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
	if admit != nil && !admit() {
		return ErrGatewayBusy
	}
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
	mtu := LegacyMTU
	if connection.ConnectionState().TLS.NegotiatedProtocol == ALPN {
		mtu = MTU
	}
	session := &Session{connection: connection, packets: make(chan []byte, queueCapacity), ipv6: dual, mtu: mtu}
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

// PacketMTU returns the inner IP limit agreed in the authenticated TLS handshake.
func (s *Session) PacketMTU() int { return s.mtu }

func (s *Session) IPv6Enabled() bool { return s.ipv6 }

func (s *Session) Stats() quic.ConnectionStats { return s.connection.ConnectionStats() }

func (s *Session) Close() error { return s.connection.CloseWithError(closeNormal, "") }
