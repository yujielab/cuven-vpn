// Package wg runs an in-memory WireGuard device over the Cuven UDP relay.
package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/yujielab/cuven-vpn/core/cuventransport"
	"github.com/yujielab/cuven-vpn/core/tunnel"
	"golang.zx2c4.com/wireguard/device"
)

const (
	startupTimeout = 16 * time.Second
	relayTimeout   = 4 * time.Second
	healthInterval = 25 * time.Second
	healthTimeout  = 8 * time.Second
	wireGuardMTU   = (cuventransport.MaxPayloadSize - device.MessageTransportSize) / 16 * 16
)

type Config struct {
	Endpoint      string
	PrivateKey    string
	PeerPublicKey string
	PresharedKey  string
	TransportKey  string
}

type Tunnel struct {
	device *device.Device
	tun    *memoryTUN
	bind   *relayBind
	cancel context.CancelFunc
}

// Open authenticates the relay and the WireGuard peer before returning. The
// tunnel closes when ctx is canceled, Close is called, or a health probe fails.
func Open(ctx context.Context, cfg Config, mtu int) (*Tunnel, error) {
	if mtu < 1280 || mtu > wireGuardMTU {
		return nil, fmt.Errorf("Cuven tunnel MTU must be between 1280 and %d", wireGuardMTU)
	}

	privateKey, err := decodeKey(cfg.PrivateKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard private key")
	}
	publicKey, err := decodeKey(cfg.PeerPublicKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard peer public key")
	}
	sharedKey, err := decodeKey(cfg.TransportKey)
	if err != nil {
		return nil, errors.New("invalid Cuven relay key")
	}
	var pskLine string
	if cfg.PresharedKey != "" {
		psk, err := decodeKey(cfg.PresharedKey)
		if err != nil {
			return nil, errors.New("invalid WireGuard preshared key")
		}
		pskLine = "preshared_key=" + hex.EncodeToString(psk[:]) + "\n"
	}
	codec, err := cuventransport.NewCodec(sharedKey[:])
	if err != nil {
		return nil, err
	}

	starting, stopStart := context.WithTimeout(ctx, startupTimeout)
	defer stopStart()
	endpoints, err := resolveEndpoints(starting, cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		t, usable, err := openEndpoint(starting, ctx, endpoint, codec, mtu, privateKey, publicKey, pskLine)
		if err == nil {
			return t, nil
		}
		if usable || starting.Err() != nil {
			return nil, err
		}
	}
	return nil, errors.New("Cuven relay did not answer an authenticated probe")
}

func openEndpoint(starting, lifetime context.Context, endpoint netip.AddrPort, codec *cuventransport.Codec, mtu int, privateKey, publicKey [32]byte, pskLine string) (*Tunnel, bool, error) {
	tun := newMemoryTUN(mtu)
	bind := newRelayBind(endpoint, codec)
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	applied := false
	defer func() {
		if !applied {
			dev.Close()
		}
	}()
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\n%sallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey[:]), endpoint, pskLine)
	if err := dev.IpcSet(cfg); err != nil {
		return nil, true, errors.New("could not configure WireGuard peer")
	}
	if err := dev.Up(); err != nil {
		return nil, false, err
	}

	probeCtx, stopProbe := context.WithTimeout(starting, relayTimeout)
	err := bind.probe(probeCtx)
	stopProbe()
	if err != nil {
		return nil, false, err
	}
	if err := waitForHandshake(starting, dev); err != nil {
		return nil, true, err
	}

	ctx, cancel := context.WithCancel(lifetime)
	t := &Tunnel{device: dev, tun: tun, bind: bind, cancel: cancel}
	applied = true
	go t.monitor(ctx)
	return t, true, nil
}

func waitForHandshake(ctx context.Context, dev *device.Device) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		state, err := dev.IpcGet()
		if err != nil {
			return errors.New("could not inspect WireGuard peer state")
		}
		// The upstream device exposes handshake time through its UAPI. Do
		// not retain or log the configuration snapshot, which includes keys.
		for line := range strings.SplitSeq(state, "\n") {
			if seconds, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && seconds != "0" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("WireGuard peer handshake: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

func (t *Tunnel) monitor(ctx context.Context) {
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	defer t.device.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, healthTimeout)
			err := t.bind.probe(probeCtx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (t *Tunnel) WritePacket(packet []byte) error {
	if !validIPPacket(packet) || len(packet) > t.tun.mtu {
		return tunnel.ErrInvalidPacket
	}
	return t.tun.inject(packet)
}

func (t *Tunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.tun.done:
		return nil, net.ErrClosed
	case packet := <-t.tun.egress:
		return packet, nil
	}
}

func (t *Tunnel) TryReadPacket() []byte {
	select {
	case <-t.tun.done:
		return nil
	default:
	}
	select {
	case packet := <-t.tun.egress:
		return packet
	default:
		return nil
	}
}

func (t *Tunnel) Done() <-chan struct{} {
	return t.tun.done
}

func (t *Tunnel) Close() error {
	t.cancel()
	t.device.Close()
	return nil
}

func resolveEndpoints(ctx context.Context, endpoint string) ([]netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return nil, errors.New("Cuven relay endpoint must contain a host and port")
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return nil, errors.New("invalid Cuven relay port")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(addr.Unmap(), uint16(value))}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve Cuven relay: %w", err)
	}
	endpoints := make([]netip.AddrPort, 0, min(len(addresses), 3))
	for _, addr := range addresses {
		endpoints = append(endpoints, netip.AddrPortFrom(addr.Unmap(), uint16(value)))
		if len(endpoints) == cap(endpoints) {
			break
		}
	}
	return endpoints, nil
}

func decodeKey(encoded string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(decoded) != len(key) {
		return key, errors.New("key must contain 32 bytes in Base64")
	}
	copy(key[:], decoded)
	clear(decoded)
	if key == [32]byte{} {
		return key, errors.New("key must not be all zeros")
	}
	return key, nil
}
