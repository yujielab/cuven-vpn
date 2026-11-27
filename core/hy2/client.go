// Package hy2 implements the Hysteria 2 proxy protocol over standard QUIC.
package hy2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	authURL         = "https://hysteria/auth"
	authStatusOK    = 233
	protocolError   = 0x101
	noError         = 0x100
	handshakeBudget = 15 * time.Second
)

// Config separates the UDP endpoint from the TLS server identity. A nil RootCAs
// uses the platform trust store. A zero receive rate asks for congestion control.
type Config struct {
	Address               string
	Auth                  string
	ServerName            string
	RootCAs               *x509.CertPool
	ReceiveBytesPerSecond uint64
	RequirePostQuantum    bool
	InsecureTLS           bool
	SalamanderPassword    string
}

// Client owns one authenticated QUIC connection for all streams and sessions.
type Client struct {
	connection *quic.Conn
	udpEnabled bool

	sessionsMu  sync.Mutex
	sessions    map[uint32]*UDPSession
	nextSession uint32
	queuedBytes atomic.Int64
}

// Dial establishes TLS and authenticates before admitting proxy traffic.
func Dial(ctx context.Context, config Config) (*Client, error) {
	if config.InsecureTLS && config.RequirePostQuantum {
		return nil, errors.New("strict post-quantum Hysteria requires TLS certificate verification")
	}
	if err := validateAddress(config.Address); err != nil {
		return nil, fmt.Errorf("server endpoint: %w", err)
	}
	if len(config.Auth) == 0 || len(config.Auth) > 4096 {
		return nil, errors.New("invalid Hysteria authentication credential length")
	}
	for i := range len(config.Auth) {
		if config.Auth[i] < 0x20 || config.Auth[i] == 0x7f {
			return nil, errors.New("Hysteria authentication contains an invalid header character")
		}
	}
	host, port, _ := net.SplitHostPort(config.Address)
	if config.ServerName == "" {
		config.ServerName = host
		if address, err := netip.ParseAddr(host); err == nil {
			config.ServerName = address.WithZone("").String()
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, handshakeBudget)
	defer cancel()
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		RootCAs:            config.RootCAs,
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: config.InsecureTLS, // Explicit per-profile compatibility setting.
	}
	if config.RequirePostQuantum {
		tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}
	connection, err := dialQUIC(dialCtx, host, port, tlsConfig, &quic.Config{
		EnableDatagrams:                true,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          8,
		InitialStreamReceiveWindow:     256 << 10,
		MaxStreamReceiveWindow:         2 << 20,
		InitialConnectionReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow:     8 << 20,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                25 * time.Second,
	}, config.SalamanderPassword)
	if err != nil {
		return nil, fmt.Errorf("connect QUIC: %w", err)
	}
	udpEnabled, err := authenticate(dialCtx, connection, config)
	if err != nil {
		_ = connection.CloseWithError(protocolError, "authentication failed")
		return nil, err
	}
	client := &Client{
		connection: connection,
		udpEnabled: udpEnabled && connection.ConnectionState().SupportsDatagrams.Remote,
	}
	if client.udpEnabled {
		client.sessions = make(map[uint32]*UDPSession)
		go client.receiveDatagrams()
	}
	return client, nil
}

func authenticate(ctx context.Context, connection *quic.Conn, config Config) (bool, error) {
	// Bind the HTTP/3 request to the same connection as the raw streams and
	// DATAGRAM frames. HTTP Datagram framing is deliberately left disabled.
	transport := http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Hysteria-Auth", config.Auth)
	request.Header.Set("Hysteria-CC-RX", strconv.FormatUint(config.ReceiveBytesPerSecond, 10))
	request.Header.Set("Hysteria-Padding", randomPadding(256, 2048))
	response, err := transport.NewClientConn(connection).RoundTrip(request)
	if err != nil {
		return false, fmt.Errorf("Hysteria authentication request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != authStatusOK {
		return false, fmt.Errorf("Hysteria authentication rejected (HTTP %d)", response.StatusCode)
	}
	return response.Header.Get("Hysteria-UDP") == "true", nil
}

// OpenTCP opens a single proxy stream. The context covers stream establishment
// and the proxy response. The returned connection has its own deadlines.
func (c *Client) OpenTCP(ctx context.Context, address string) (net.Conn, error) {
	if err := validateAddress(address); err != nil {
		return nil, err
	}
	stream, err := c.connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	finished := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = stream.SetDeadline(time.Now())
		close(finished)
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if _, err = stream.Write(encodeTCPRequest(address)); err == nil {
		err = readTCPResponse(stream)
	}
	if !stopCancellation() {
		<-finished
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelWrite(0)
		stream.CancelRead(0)
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return &tcpConnection{Stream: stream, client: c}, nil
}

// Done is closed when the QUIC connection can no longer proxy traffic.
func (c *Client) Done() <-chan struct{} { return c.connection.Context().Done() }

// UDPEnabled reports whether the server can relay datagrams on this connection.
func (c *Client) UDPEnabled() bool { return c.udpEnabled }

// Close tears down the connection and unblocks all streams and UDP sessions.
func (c *Client) Close() error { return c.connection.CloseWithError(noError, "") }

type tcpConnection struct {
	*quic.Stream
	client      *Client
	closeMu     sync.Mutex
	writeClosed bool
}

func (c *tcpConnection) LocalAddr() net.Addr  { return c.client.connection.LocalAddr() }
func (c *tcpConnection) RemoteAddr() net.Addr { return c.client.connection.RemoteAddr() }

func (c *tcpConnection) CloseWrite() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return c.Stream.Close()
}

func (c *tcpConnection) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.Stream.CancelRead(0)
	if !c.writeClosed {
		c.writeClosed = true
		c.Stream.CancelWrite(0)
	}
	return nil
}

func validateAddress(address string) error {
	if len(address) == 0 || len(address) > maxAddressLength {
		return errors.New("invalid proxy address length")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.New("address must include a host and port")
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return errors.New("invalid proxy port")
	}
	return nil
}

func randomPadding(minimum, maximum int) string {
	// Base64 gives header-safe random bytes. Use the first two random bytes to
	// vary the padding length while keeping the allocation close to the final size.
	var size [2]byte
	_, _ = rand.Read(size[:])
	length := minimum + (int(size[0])<<8|int(size[1]))%(maximum-minimum)
	buf := make([]byte, (length*3+3)/4)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)[:length]
}
