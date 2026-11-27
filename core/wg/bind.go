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

type relayBind struct {
	endpoint *conn.StdNetEndpoint
	codec    *cuventransport.Codec

	mu     sync.Mutex
	socket *net.UDPConn
	waiter atomic.Pointer[probeAttempt]
}

var _ conn.Bind = (*relayBind)(nil)

func newRelayBind(endpoint netip.AddrPort, codec *cuventransport.Codec) *relayBind {
	return &relayBind{endpoint: &conn.StdNetEndpoint{AddrPort: endpoint}, codec: codec}
}

func (b *relayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	socket, err := net.DialUDP("udp", &net.UDPAddr{Port: int(port)}, net.UDPAddrFromAddrPort(b.endpoint.AddrPort))
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
			n, err := socket.Read(datagram[:])
			if errors.Is(err, syscall.ECONNREFUSED) {
				// A connected UDP socket can report ICMP after an early
				// probe while the relay is starting. It remains usable.
				continue
			}
			if err != nil {
				return 0, err
			}
			kind, payload, err := b.codec.OpenTo(cuventransport.ServerToClient, packets[0][:0], datagram[:n])
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
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
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
	packet, err := b.codec.Seal(cuventransport.ClientToServer, kind, payload)
	if err != nil {
		return err
	}
	_, err = socket.Write(packet)
	return err
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
