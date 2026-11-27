package cuventransport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxPeers = 64
	maxRelayPeers   = 256
	defaultPeerIdle = time.Minute
	replayCapacity  = 65536
)

// RelayConfig configures a UDP listener with one deployment key.
type RelayConfig struct {
	Key         []byte
	Upstream    netip.AddrPort
	MaxPeers    int
	IdleTimeout time.Duration
	Version     Version
}

// ServeRelay owns listener and forwards authenticated envelopes to a loopback
// WireGuard endpoint. Separate upstream sockets let WireGuard authenticate each
// source address change using its own packet counters and handshake timestamps.
func ServeRelay(ctx context.Context, listener *net.UDPConn, cfg RelayConfig) error {
	if listener == nil {
		return errors.New("relay requires a bound UDP socket")
	}
	defer listener.Close()
	if !cfg.Upstream.Addr().Unmap().IsLoopback() || cfg.Upstream.Port() == 0 {
		return errors.New("WireGuard upstream must be a loopback IP address with a nonzero port")
	}
	if cfg.MaxPeers == 0 {
		cfg.MaxPeers = defaultMaxPeers
	}
	if cfg.MaxPeers < 1 || cfg.MaxPeers > maxRelayPeers {
		return errors.New("relay peer limit must be between 1 and 256")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultPeerIdle
	}
	if cfg.IdleTimeout < time.Second {
		return errors.New("relay peer idle timeout must be at least one second")
	}
	if cfg.Version == 0 {
		cfg.Version = Version1
	}
	codec, err := NewCodecVersion(cfg.Key, cfg.Version)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	peers := make(map[netip.AddrPort]*relayPeer, cfg.MaxPeers)
	slots := make(chan struct{}, cfg.MaxPeers)
	var workers sync.WaitGroup
	defer func() {
		listener.Close()
		for _, peer := range peers {
			peer.conn.Close()
		}
		workers.Wait()
	}()

	var packet [MaxDatagramSize + 1]byte
	var cleartext [MaxDatagramSize]byte
	var nextSweep time.Time
	replays := newReplayCache(replayCapacity)
	upstream := net.UDPAddrFromAddrPort(cfg.Upstream)
	for {
		now := time.Now()
		if !now.Before(nextSweep) {
			for remote, peer := range peers {
				if peer.closed.Load() || now.Sub(peer.lastActive) >= cfg.IdleTimeout {
					peer.conn.Close()
					delete(peers, remote)
				}
			}
			nextSweep = now.Add(time.Second)
			if err := listener.SetReadDeadline(nextSweep); err != nil {
				return relayReadError(ctx, err)
			}
		}
		n, remote, err := listener.ReadFromUDPAddrPort(packet[:])
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return relayReadError(ctx, err)
		}
		kind, payload, err := codec.OpenTo(ClientToServer, cleartext[:0], packet[:n])
		if err != nil {
			continue
		}
		if kind == Probe {
			if ack, err := codec.sealProbeAck(payload, n); err == nil {
				_, _ = listener.WriteToUDPAddrPort(ack, remote)
			}
			continue
		}
		if !isWireGuardFrame(payload) || !replays.add(codec.nonce(packet[:n])) {
			continue
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		peer := peers[remote]
		if peer == nil || peer.closed.Load() {
			if peer != nil {
				delete(peers, remote)
			}
			if len(peers) >= cfg.MaxPeers {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			conn, err := net.DialUDP("udp", nil, upstream)
			if err != nil {
				<-slots
				continue
			}
			peer = &relayPeer{conn: conn, lastActive: time.Now()}
			peers[remote] = peer
			workers.Go(func() {
				defer func() { <-slots }()
				peer.reply(listener, remote, codec)
			})
		}
		if _, err := peer.conn.Write(payload); err == nil {
			peer.lastActive = time.Now()
		}
	}
}

func relayReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type relayPeer struct {
	conn       *net.UDPConn
	lastActive time.Time
	closed     atomic.Bool
}

func (p *relayPeer) reply(listener *net.UDPConn, remote netip.AddrPort, codec *Codec) {
	defer p.closed.Store(true)
	defer p.conn.Close()
	var packet [MaxPayloadSize + 1]byte
	for {
		size, err := p.conn.Read(packet[:])
		if err != nil {
			return
		}
		payload := packet[:size]
		if !isWireGuardFrame(payload) {
			continue
		}
		data, err := codec.Seal(ServerToClient, Data, payload)
		if err == nil {
			_, _ = listener.WriteToUDPAddrPort(data, remote)
		}
	}
}

func isWireGuardFrame(payload []byte) bool {
	if len(payload) < 4 || len(payload) > MaxPayloadSize {
		return false
	}
	switch binary.LittleEndian.Uint32(payload[:4]) {
	case 1:
		return len(payload) == 148
	case 2:
		return len(payload) == 92
	case 3:
		return len(payload) == 64
	case 4:
		return len(payload) >= 32
	default:
		return false
	}
}

type packetNonce [headerSize - nonceStart]byte

// replayCache covers the most recent authenticated data nonces across all
// source addresses. WireGuard independently enforces end-to-end replay checks.
type replayCache struct {
	ring []packetNonce
	seen map[packetNonce]struct{}
	next int
}

func newReplayCache(capacity int) *replayCache {
	return &replayCache{
		ring: make([]packetNonce, 0, capacity),
		seen: make(map[packetNonce]struct{}, capacity),
	}
}

func (r *replayCache) add(nonce []byte) bool {
	key := packetNonce(nonce)
	if _, duplicate := r.seen[key]; duplicate {
		return false
	}
	if len(r.ring) == cap(r.ring) {
		delete(r.seen, r.ring[r.next])
		r.ring[r.next] = key
		r.next = (r.next + 1) % len(r.ring)
	} else {
		r.ring = append(r.ring, key)
	}
	r.seen[key] = struct{}{}
	return true
}
