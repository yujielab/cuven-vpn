package wg

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yujielab/cuven-vpn/core/cuventransport"
	"golang.zx2c4.com/wireguard/conn"
)

type probeAttempt struct {
	token [cuventransport.TokenSize]byte
	ack   chan struct{}
}

type relayCarrier interface {
	readPacket([]byte) ([]byte, error)
	writePacket([]byte) error
	localPort() uint16
	Close() error
}

type relaySession struct {
	relayCarrier
	codec *cuventransport.Codec
}

type relayDial func(uint16) (*relaySession, error)

type relayBind struct {
	endpoint *conn.StdNetEndpoint
	dial     relayDial

	mu     sync.Mutex
	socket *relaySession
	waiter atomic.Pointer[probeAttempt]
}

var _ conn.Bind = (*relayBind)(nil)

func newRelayBind(endpoint netip.AddrPort, dial relayDial) *relayBind {
	return &relayBind{endpoint: &conn.StdNetEndpoint{AddrPort: endpoint}, dial: dial}
}

func (b *relayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.dial == nil {
		return nil, 0, net.ErrClosed
	}
	dial := b.dial
	// A reconnect creates a fresh Tunnel and reconnects with the latest
	// network settings. Release the startup closure after this attempt.
	b.dial = nil
	socket, err := dial(port)
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	var datagram [cuventransport.MaxDatagramSize + 1]byte
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(packets[0]) < cuventransport.MaxPayloadSize {
			return 0, io.ErrShortBuffer
		}
		for {
			packet, err := socket.readPacket(datagram[:])
			if err != nil {
				return 0, err
			}
			kind, payload, err := socket.codec.OpenTo(cuventransport.ServerToClient, packets[0][:0], packet)
			if err != nil {
				continue
			}
			switch kind {
			case cuventransport.Data:
				sizes[0] = len(payload)
				endpoints[0] = b.endpoint
				return 1, nil
			case cuventransport.ProbeAck:
				wait := b.waiter.Load()
				if wait != nil && bytes.Equal(wait.token[:], payload) && b.waiter.CompareAndSwap(wait, nil) {
					close(wait.ack)
				}
			}
		}
	}
	return []conn.ReceiveFunc{receive}, socket.localPort(), nil
}

func (b *relayBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}

func (b *relayBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint != b.endpoint.AddrPort {
		return nil, errors.New("WireGuard endpoint must match the Cuven relay")
	}
	return b.endpoint, nil
}

func (b *relayBind) BatchSize() int { return packetBatchSize }

func (b *relayBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("Cuven relay does not support packet markings")
	}
	return nil
}

func (b *relayBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	if endpoint != b.endpoint {
		return conn.ErrWrongEndpointType
	}
	for _, data := range buffers {
		if err := b.send(cuventransport.Data, data); err != nil {
			return err
		}
	}
	return nil
}

func (b *relayBind) send(kind cuventransport.Kind, payload []byte) error {
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	packet, err := socket.codec.Seal(cuventransport.ClientToServer, kind, payload)
	if err != nil {
		return err
	}
	return socket.writePacket(packet)
}

type udpCarrier struct {
	*net.UDPConn
}

func dialUDPRelay(endpoint netip.AddrPort, port uint16) (relayCarrier, error) {
	socket, err := net.DialUDP("udp", &net.UDPAddr{Port: int(port)}, net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		return nil, err
	}
	return &udpCarrier{UDPConn: socket}, nil
}

func (s *udpCarrier) readPacket(buffer []byte) ([]byte, error) {
	for {
		n, err := s.Read(buffer)
		// The socket remains usable if a probe arrived before the relay
		// started and an ICMP rejection reached the socket.
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return buffer[:n], err
		}
	}
}

func (s *udpCarrier) writePacket(packet []byte) error {
	_, err := s.Write(packet)
	return err
}

func (s *udpCarrier) localPort() uint16 {
	return uint16(s.LocalAddr().(*net.UDPAddr).Port)
}

func (b *relayBind) probe(ctx context.Context) error {
	wait := &probeAttempt{ack: make(chan struct{})}
	if _, err := rand.Read(wait.token[:]); err != nil {
		return err
	}
	b.waiter.Store(wait)
	defer b.waiter.CompareAndSwap(wait, nil)
	retry := time.NewTicker(350 * time.Millisecond)
	defer retry.Stop()
	for {
		if err := b.send(cuventransport.Probe, wait.token[:]); errors.Is(err, net.ErrClosed) {
			return err
		}
		select {
		case <-wait.ack:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("Cuven relay probe: %w", ctx.Err())
		case <-retry.C:
		}
	}
}
