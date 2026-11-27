package cuventransport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const https3RequestTimeout = 5 * time.Second

// ServeHTTPS3Relay owns listener and runs a fixed-target HTTP/3 CONNECT-UDP
// service. It accepts only version 2 inner envelopes on the configured route.
func ServeHTTPS3Relay(ctx context.Context, listener *net.UDPConn, config *tls.Config, cfg RelayConfig) error {
	if listener == nil {
		return errors.New("HTTPS/3 relay requires a bound UDP socket")
	}
	defer listener.Close()
	if config == nil || (len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil) {
		return errors.New("HTTPS/3 relay requires a TLS certificate")
	}
	if cfg.Version != 0 && cfg.Version != Version2 {
		return errors.New("HTTPS/3 relay requires Cuven envelope version 2")
	}
	if err := applyRelayDefaults(&cfg); err != nil {
		return err
	}
	relay := &https3Relay{
		key: bytes.Clone(cfg.Key), upstream: net.UDPAddrFromAddrPort(cfg.Upstream), idleTimeout: cfg.IdleTimeout,
		slots: make(chan struct{}, cfg.MaxPeers), replays: newReplayCache(replayCapacity),
	}
	connections := make(chan struct{}, max(8, cfg.MaxPeers))
	transport := &quic.Transport{
		Conn: listener,
		VerifySourceAddress: func(net.Addr) bool {
			return len(connections) >= cap(connections)/2
		},
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case connections <- struct{}{}:
				context.AfterFunc(ctx, func() { <-connections })
				return ctx, nil
			default:
				return nil, errors.New("HTTPS/3 connection limit reached")
			}
		},
	}
	defer transport.Close()
	tlsConfig := config.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	quicListener, err := transport.Listen(http3.ConfigureTLSConfig(tlsConfig), &quic.Config{
		EnableDatagrams:                true,
		HandshakeIdleTimeout:           https3RequestTimeout,
		MaxIdleTimeout:                 max(15*time.Second, cfg.IdleTimeout),
		MaxIncomingStreams:             16,
		MaxIncomingUniStreams:          8,
		InitialStreamReceiveWindow:     64 * 1024,
		MaxStreamReceiveWindow:         256 * 1024,
		InitialConnectionReceiveWindow: 128 * 1024,
		MaxConnectionReceiveWindow:     512 * 1024,
	})
	if err != nil {
		return err
	}
	defer quicListener.Close()
	server := &http3.Server{
		Handler:           http.HandlerFunc(relay.serveHTTP),
		EnableDatagrams:   true,
		MaxHeaderBytes:    8192,
		ReadHeaderTimeout: https3RequestTimeout,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			return context.WithValue(ctx, https3ConnKey{}, &https3Connection{conn: conn})
		},
	}
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	err = server.ServeListener(quicListener)
	server.Close()
	return relayReadError(ctx, err)
}

type https3Relay struct {
	key         []byte
	upstream    *net.UDPAddr
	idleTimeout time.Duration
	slots       chan struct{}
	mu          sync.Mutex
	replays     *replayCache
}

type https3ConnKey struct{}

type https3Connection struct {
	conn    *quic.Conn
	claimed atomic.Bool
}

func (h *https3Relay) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Home</title><h1>Home</h1></html>\n")
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
		return
	}
	if r.Method != http.MethodConnect || r.Proto != ConnectUDPProtocol || path != ConnectUDPPath || r.TLS == nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get(http3.CapsuleProtocolHeader) != ConnectUDPCapsuleValue {
		http.NotFound(w, r)
		return
	}
	authorization, err := HTTPS3Authorization(h.key, *r.TLS)
	if err != nil || !hmac.Equal([]byte(authorization), []byte(r.Header.Get("Authorization"))) {
		http.NotFound(w, r)
		return
	}
	conn := r.Context().Value(https3ConnKey{}).(*https3Connection)
	if !conn.claimed.CompareAndSwap(false, true) {
		http.Error(w, "one CONNECT-UDP stream per connection", http.StatusConflict)
		return
	}
	defer conn.claimed.Store(false)
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "relay busy", http.StatusServiceUnavailable)
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	codec, err := NewHTTPS3Codec(h.key, *r.TLS, stream.StreamID())
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
		return
	}
	w.Header().Set(http3.CapsuleProtocolHeader, ConnectUDPCapsuleValue)
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return
	}
	h.forward(r.Context(), conn.conn, stream, codec)
}

func (h *https3Relay) forward(parent context.Context, conn *quic.Conn, stream *http3.Stream, codec *Codec) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	})
	var workers sync.WaitGroup
	var peer *net.UDPConn
	defer func() {
		cancel()
		if peer != nil {
			peer.Close()
		}
		workers.Wait()
		stop()
	}()

	var sendMu sync.Mutex
	send := func(kind Kind, data []byte, probeSize int) error {
		var packet []byte
		var err error
		if kind == ProbeAck {
			packet, err = codec.sealProbeAck(data, probeSize)
		} else {
			packet, err = codec.Seal(ServerToClient, kind, data)
		}
		if err != nil {
			return err
		}
		sendMu.Lock()
		defer sendMu.Unlock()
		return SendConnectUDP(stream, packet)
	}

	incoming := make(chan []byte, 16)
	workers.Go(func() {
		defer cancel()
		for {
			packet, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if envelope, ok := ParseConnectUDPDatagram(packet); ok {
				select {
				case incoming <- envelope:
				default:
				}
			}
		}
	})
	workers.Go(func() {
		defer cancel()
		parser := http3.NewCapsuleParser(stream)
		var scratch [MaxDatagramSize]byte
		for {
			packet, err := ReadConnectUDPCapsule(parser, scratch[:])
			if err != nil {
				return
			}
			select {
			case incoming <- bytes.Clone(packet):
			case <-ctx.Done():
				return
			}
		}
	})

	var cleartext [MaxDatagramSize]byte
	activity := time.AfterFunc(https3RequestTimeout, cancel)
	defer activity.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-incoming:
			kind, payload, err := codec.OpenTo(ClientToServer, cleartext[:0], packet)
			if err != nil {
				continue
			}
			if kind == Probe {
				if err := send(ProbeAck, payload, len(packet)); err != nil {
					return
				}
				continue
			}
			if !isWireGuardFrame(payload) || !h.addNonce(codec.nonce(packet)) {
				continue
			}
			if peer == nil {
				peer, err = net.DialUDP("udp", nil, h.upstream)
				if err != nil {
					return
				}
				workers.Go(func() {
					defer cancel()
					var response [MaxPayloadSize + 1]byte
					for {
						n, err := peer.Read(response[:])
						if err != nil {
							return
						}
						if isWireGuardFrame(response[:n]) && send(Data, response[:n], 0) != nil {
							return
						}
					}
				})
			}
			if _, err := peer.Write(payload); err != nil {
				return
			}
			activity.Reset(h.idleTimeout)
		}
	}
}

func (h *https3Relay) addNonce(nonce []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.replays.add(nonce)
}
