// Package mobile exposes the VPN packet tunnel to iOS through gomobile.
package mobile

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/yujielab/cuven-vpn/core/iptunnel"
	"github.com/yujielab/cuven-vpn/core/packetpolicy"
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
	mu             sync.Mutex
	state          engineState
	cancel         context.CancelFunc
	live           *session
	rejectPlainDNS bool
}

type session struct {
	ctx    context.Context
	tunnel packetTunnel
	mtu    int
	policy packetPolicy
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

// RequireEncryptedDNS enables plaintext DNS filtering for any transport.
// Configure it before starting the engine.
func (e *Engine) RequireEncryptedDNS() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != engineIdle {
		return errEngineUsed
	}
	e.rejectPlainDNS = true
	return nil
}

// RTTMilliseconds returns the measured smoothed tunnel RTT, or -1 without a sample.
func (e *Engine) RTTMilliseconds() int64 {
	live := e.current()
	if live == nil {
		return -1
	}
	tunnel, ok := live.tunnel.(*iptunnel.Session)
	if !ok {
		return -1
	}
	rtt := tunnel.Stats().SmoothedRTT
	if rtt <= 0 {
		return -1
	}
	return int64(rtt / time.Millisecond)
}

// StartCuven opens the native authenticated Cuven IP tunnel.
func (e *Engine) StartCuven(endpoint, accessToken, serverName string, requireIPv6, blockLAN bool) error {
	token, err := iptunnel.ParseToken(accessToken)
	if err != nil {
		return err
	}
	defer clear(token[:])
	return e.start(iptunnel.MTU, packetPolicy{blockLAN: blockLAN}, func(ctx context.Context) (packetTunnel, error) {
		session, err := iptunnel.Dial(ctx, endpoint, token, &tls.Config{ServerName: serverName})
		if err == nil && requireIPv6 && !session.IPv6Enabled() {
			_ = session.Close()
			return nil, errors.New("Cuven gateway does not support IPv6")
		}
		return session, err
	})
}

func (e *Engine) start(mtu int64, policy packetPolicy, open func(context.Context) (packetTunnel, error)) error {
	if mtu < minMTU || mtu > maxMTU {
		return errInvalidMTU
	}

	e.mu.Lock()
	if e.state != engineIdle {
		e.mu.Unlock()
		return errEngineUsed
	}
	policy.blockPlainDNS = policy.blockPlainDNS || e.rejectPlainDNS
	ctx, cancel := context.WithCancel(context.Background())
	e.state = engineStarting
	e.cancel = cancel
	e.mu.Unlock()

	stack, err := open(ctx)
	if err != nil {
		e.Stop()
		return err
	}
	live := &session{ctx: ctx, tunnel: stack, mtu: int(mtu), policy: policy}

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
		if (live.policy.blockLAN && packetpolicy.IsLANPacket(packet)) ||
			(live.policy.blockPlainDNS && packetpolicy.RejectPlainDNS(packet)) {
			continue
		}
		if err := live.tunnel.WritePacket(packet); err != nil && !errors.Is(err, iptunnel.ErrInvalidPacket) {
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
