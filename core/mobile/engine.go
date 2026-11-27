// Package mobile exposes the VPN packet tunnel to iOS through gomobile.
package mobile

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/yujielab/cuven-vpn/core/hy2"
	"github.com/yujielab/cuven-vpn/core/tunnel"
	"github.com/yujielab/cuven-vpn/core/wg"
)

const (
	maxBatchPackets = 64
	packetHeaderLen = 2
	minMTU          = 1280
	maxMTU          = 9000
)

var (
	errEngineUsed     = errors.New("packet engine has already been used")
	errEngineInactive = errors.New("packet engine is inactive")
	errInvalidBatch   = errors.New("invalid packet batch")
	errInvalidRate    = errors.New("HY2 receive rate must be nonnegative")
	errInvalidMTU     = errors.New("tunnel MTU must be between 1280 and 9000")
)

type engineState uint8

const (
	engineIdle engineState = iota
	engineStarting
	engineRunning
	engineStopped
)

// Engine owns one VPN session and its packet pipeline.
// Create a new engine for each connection attempt.
type Engine struct {
	mu     sync.Mutex
	state  engineState
	cancel context.CancelFunc
	live   *session
}

type session struct {
	ctx       context.Context
	transport io.Closer
	tunnel    packetTunnel
	mtu       int
	policy    packetPolicy
}

type packetPolicy struct {
	blockLAN      bool
	blockPlainDNS bool
}

type packetTunnel interface {
	WritePacket([]byte) error
	ReadPacket(context.Context) ([]byte, error)
	TryReadPacket() []byte
	Close() error
}

// NewEngine constructs an idle packet engine for the native tunnel provider.
func NewEngine() *Engine { return &Engine{} }

// Start establishes the transport and initializes the IP stack. Stop may be
// called concurrently to cancel startup. The address includes the server port.
func (e *Engine) Start(address, auth, serverName string, receiveBytesPerSecond, mtu int64, requirePostQuantum, blockLAN, highSecurity bool) error {
	if receiveBytesPerSecond < 0 {
		return errInvalidRate
	}
	policy := packetPolicy{blockPlainDNS: highSecurity}
	return e.start(mtu, policy, func(ctx context.Context) (packetTunnel, io.Closer, error) {
		client, err := hy2.Dial(ctx, hy2.Config{
			Address:               address,
			Auth:                  auth,
			ServerName:            serverName,
			ReceiveBytesPerSecond: uint64(receiveBytesPerSecond),
			RequirePostQuantum:    requirePostQuantum,
		})
		if err != nil {
			return nil, nil, err
		}
		if !client.UDPEnabled() {
			_ = client.Close()
			return nil, nil, errors.New("the Hysteria 2 server must allow UDP for tunnel DNS")
		}
		stack, err := tunnel.Open(ctx, client, tunnel.Options{MTU: uint32(mtu), BlockLAN: blockLAN})
		if err != nil {
			_ = client.Close()
			return nil, nil, err
		}
		return stack, client, nil
	})
}

// StartWireGuard connects to the Cuven relay and awaits the peer handshake.
// Keys are 32 bytes encoded as padded base64. An empty PSK omits it.
// HTTPS/3 uses a relay with a matching v2 envelope and a trusted certificate.
func (e *Engine) StartWireGuard(endpoint, privateKey, peerPublicKey, presharedKey, transportKey string, mtu int64, blockLAN, camouflage, https3 bool, serverName string) error {
	policy := packetPolicy{blockLAN: blockLAN, blockPlainDNS: camouflage}
	return e.start(mtu, policy, func(ctx context.Context) (packetTunnel, io.Closer, error) {
		stack, err := wg.Open(ctx, wg.Config{
			Endpoint:      endpoint,
			PrivateKey:    privateKey,
			PeerPublicKey: peerPublicKey,
			PresharedKey:  presharedKey,
			TransportKey:  transportKey,
			Camouflage:    camouflage,
			HTTPS3:        https3,
			ServerName:    serverName,
		}, int(mtu))
		return stack, nil, err
	})
}

func (e *Engine) start(mtu int64, policy packetPolicy, open func(context.Context) (packetTunnel, io.Closer, error)) error {
	if mtu < minMTU || mtu > maxMTU {
		return errInvalidMTU
	}

	e.mu.Lock()
	if e.state != engineIdle {
		e.mu.Unlock()
		return errEngineUsed
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.state = engineStarting
	e.cancel = cancel
	e.mu.Unlock()

	stack, transport, err := open(ctx)
	if err != nil {
		e.Stop()
		return err
	}
	live := &session{ctx: ctx, transport: transport, tunnel: stack, mtu: int(mtu), policy: policy}

	e.mu.Lock()
	if e.state == engineStopped {
		e.mu.Unlock()
		live.close()
		return context.Canceled
	}
	e.live = live
	e.state = engineRunning
	e.mu.Unlock()
	return nil
}

// WriteBatch injects up to 64 raw packets encoded as big-endian uint16 length
// followed by the packet bytes. It validates the framing before injecting packets.
func (e *Engine) WriteBatch(batch []byte) error {
	live := e.current()
	if live == nil {
		return errEngineInactive
	}

	var packets [maxBatchPackets][]byte
	count, err := decodeBatch(batch, live.mtu, &packets)
	if err != nil {
		return err
	}
	for _, packet := range packets[:count] {
		if (live.policy.blockLAN && tunnel.IsLANPacket(packet)) ||
			(live.policy.blockPlainDNS && tunnel.RejectPlainDNS(packet)) {
			continue
		}
		if err := live.tunnel.WritePacket(packet); err != nil && !errors.Is(err, tunnel.ErrInvalidPacket) {
			return err
		}
	}
	return nil
}

// ReadBatch blocks for one packet, then drains immediately available packets
// up to the batch limit. A single native reader preserves packet order.
func (e *Engine) ReadBatch() ([]byte, error) {
	live := e.current()
	if live == nil {
		return nil, errEngineInactive
	}
	first, err := live.tunnel.ReadPacket(live.ctx)
	if err != nil {
		return nil, err
	}

	var packets [maxBatchPackets][]byte
	packets[0] = first
	count := 1
	size := packetHeaderLen + len(first)
	for count < len(packets) {
		packet := live.tunnel.TryReadPacket()
		if packet == nil {
			break
		}
		packets[count] = packet
		count++
		size += packetHeaderLen + len(packet)
	}
	batch := make([]byte, 0, size)
	for _, packet := range packets[:count] {
		batch = binary.BigEndian.AppendUint16(batch, uint16(len(packet)))
		batch = append(batch, packet...)
	}
	return batch, nil
}

// Stop cancels startup and pending packet reads, then closes the transport and
// packet stack. Once stopped, the engine cannot be restarted.
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel, live := e.cancel, e.live
	e.cancel = nil
	e.live = nil
	e.state = engineStopped
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if live != nil {
		live.close()
	}
}

func (e *Engine) current() *session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.live
}

func (s *session) close() {
	if s.transport != nil {
		_ = s.transport.Close()
	}
	_ = s.tunnel.Close()
}

func decodeBatch(batch []byte, mtu int, packets *[maxBatchPackets][]byte) (int, error) {
	count := 0
	for len(batch) > 0 {
		if count == len(packets) || len(batch) < packetHeaderLen {
			return 0, errInvalidBatch
		}
		size := int(binary.BigEndian.Uint16(batch))
		batch = batch[packetHeaderLen:]
		if size == 0 || size > mtu || size > len(batch) {
			return 0, errInvalidBatch
		}
		packets[count] = batch[:size:size]
		count++
		batch = batch[size:]
	}
	return count, nil
}
