package wg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yujielab/cuven-vpn/core/cuventransport"
)

type https3Carrier struct {
	socket *net.UDPConn
	conn   *quic.Conn
	stream *http3.RequestStream

	ctx      context.Context
	cancel   context.CancelFunc
	incoming chan []byte
	writeMu  sync.Mutex
	close    sync.Once
}

func dialHTTPS3Relay(ctx context.Context, endpoint netip.AddrPort, port uint16, authority, serverName string, roots *x509.CertPool, relayKey []byte) (*relaySession, error) {
	host, endpointPort, _ := net.SplitHostPort(authority)
	if serverName == "" {
		serverName = host
		if addr, err := netip.ParseAddr(serverName); err == nil {
			serverName = addr.WithZone("").String()
		}
	}
	network := "udp6"
	if endpoint.Addr().Is4() {
		network = "udp4"
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, err
	}
	var connection *quic.Conn
	keepOpen := false
	defer func() {
		if !keepOpen {
			if connection != nil {
				_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			}
			_ = socket.Close()
		}
	}()
	connection, err = quic.Dial(ctx, socket, net.UDPAddrFromAddrPort(endpoint), &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{
		EnableDatagrams:                true,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          8,
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         256 << 10,
		InitialConnectionReceiveWindow: 256 << 10,
		MaxConnectionReceiveWindow:     1 << 20,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                25 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 TLS handshake: %w", err)
	}

	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	})
	defer stopCancellation()
	transport := http3.Transport{
		EnableDatagrams:        true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	client := transport.NewClientConn(connection)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-connection.Context().Done():
		return nil, context.Cause(connection.Context())
	case <-client.ReceivedSettings():
		settings := client.Settings()
		if !settings.EnableExtendedConnect || !settings.EnableDatagrams ||
			!connection.ConnectionState().SupportsDatagrams.Remote {
			return nil, errors.New("Cuven HTTPS/3 relay does not support CONNECT-UDP datagrams")
		}
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 open request stream: %w", err)
	}
	tlsState := connection.ConnectionState().TLS
	authorization, err := cuventransport.HTTPS3Authorization(relayKey, tlsState)
	if err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 session authorization: %w", err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  cuventransport.ConnectUDPProtocol,
		URL: &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(serverName, endpointPort),
			Path:   cuventransport.ConnectUDPPath,
		},
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{cuventransport.ConnectUDPCapsuleValue},
			"Authorization":             []string{authorization},
		},
	}
	if err := stream.SendRequestHeader(request); err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 CONNECT-UDP request: %w", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 CONNECT-UDP response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Cuven HTTPS/3 relay rejected CONNECT-UDP (HTTP %d)", response.StatusCode)
	}
	if strings.TrimSpace(response.Header.Get(http3.CapsuleProtocolHeader)) != cuventransport.ConnectUDPCapsuleValue {
		return nil, errors.New("Cuven HTTPS/3 relay did not negotiate the capsule protocol")
	}
	codec, err := cuventransport.NewHTTPS3Codec(relayKey, tlsState, stream.StreamID())
	if err != nil {
		return nil, fmt.Errorf("Cuven HTTPS/3 session key: %w", err)
	}
	if !stopCancellation() {
		return nil, ctx.Err()
	}

	liveCtx, cancel := context.WithCancel(connection.Context())
	carrier := &https3Carrier{
		socket: socket, conn: connection, stream: stream, ctx: liveCtx,
		cancel: cancel, incoming: make(chan []byte, packetQueueSize),
	}
	keepOpen = true
	go carrier.receiveDatagrams()
	go carrier.receiveCapsules()
	return &relaySession{relayCarrier: carrier, codec: codec}, nil
}

func (s *https3Carrier) receiveDatagrams() {
	defer s.Close()
	for {
		data, err := s.stream.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		if envelope, ok := cuventransport.ParseConnectUDPDatagram(data); ok {
			s.enqueue(envelope)
		}
	}
}

func (s *https3Carrier) receiveCapsules() {
	defer s.Close()
	parser := http3.NewCapsuleParser(s.stream)
	var scratch [cuventransport.MaxDatagramSize]byte
	for {
		envelope, err := cuventransport.ReadConnectUDPCapsule(parser, scratch[:])
		if err != nil {
			return
		}
		if len(s.incoming) < cap(s.incoming) {
			s.enqueue(slices.Clone(envelope))
		}
	}
}

func (s *https3Carrier) enqueue(envelope []byte) {
	select {
	case s.incoming <- envelope:
	default:
	}
}

func (s *https3Carrier) readPacket(_ []byte) ([]byte, error) {
	select {
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	case packet := <-s.incoming:
		return packet, nil
	}
}

func (s *https3Carrier) writePacket(packet []byte) error {
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return cuventransport.SendConnectUDP(s.stream, packet)
}

func (s *https3Carrier) localPort() uint16 {
	return uint16(s.socket.LocalAddr().(*net.UDPAddr).Port)
}

func (s *https3Carrier) Close() error {
	s.close.Do(func() {
		s.cancel()
		_ = s.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		_ = s.socket.Close()
	})
	return nil
}
