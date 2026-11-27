// Package tunnel translates packets from an iOS packet flow to Hysteria 2 relays.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/yujielab/cuven-vpn/core/hy2"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	defaultMTU      = 1280
	maxPacketSize   = 65535 + header.IPv6MinimumSize
	packetQueueSize = 256
	tcpFlowLimit    = 96
	udpFlowLimit    = 64
	tcpBufferSize   = 64 << 10
)

var (
	ErrClosed        = errors.New("packet tunnel closed")
	ErrInvalidPacket = errors.New("invalid IP packet")
)

type Options struct {
	// MTU must match the packet tunnel interface. Zero selects 1280.
	MTU uint32
	// BlockLAN rejects local TCP and UDP destinations before creating a relay.
	BlockLAN bool
}

type Tunnel struct {
	relay    relayTransport
	ctx      context.Context
	cancel   context.CancelFunc
	stack    *stack.Stack
	link     *channel.Endpoint
	nic      tcpip.NICID
	blockLAN bool

	inputMu   sync.Mutex
	closeOnce sync.Once
	flowMu    sync.Mutex
	flows     sync.WaitGroup
	tcpSlots  chan struct{}
	udpSlots  chan struct{}
}

type relayTransport struct {
	openTCP func(context.Context, string) (net.Conn, error)
	openUDP func() (udpSession, error)
	done    <-chan struct{}
}

// Open starts a packet pipeline on an authenticated client. The caller owns client.
func Open(ctx context.Context, client *hy2.Client, options Options) (*Tunnel, error) {
	if client == nil {
		return nil, errors.New("missing Hysteria 2 client")
	}
	return open(ctx, relayTransport{
		openTCP: client.OpenTCP,
		openUDP: func() (udpSession, error) { return client.OpenUDP() },
		done:    client.Done(),
	}, options)
}

func open(ctx context.Context, relay relayTransport, options Options) (*Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.MTU == 0 {
		options.MTU = defaultMTU
	}
	if options.MTU < defaultMTU || options.MTU > 65535 {
		return nil, fmt.Errorf("unsupported tunnel MTU %d", options.MTU)
	}
	ctx, cancel := context.WithCancel(ctx)
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t := &Tunnel{
		relay: relay,
		ctx:   ctx, cancel: cancel,
		stack: st, link: channel.New(packetQueueSize, options.MTU, ""), nic: st.NextNICID(),
		blockLAN: options.BlockLAN,
		tcpSlots: make(chan struct{}, tcpFlowLimit),
		udpSlots: make(chan struct{}, udpFlowLimit),
	}
	if err := t.configure(); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("configure IP stack: %s", err)
	}
	go func() {
		select {
		case <-relay.done:
		case <-ctx.Done():
		}
		_ = t.Close()
	}()
	return t, nil
}

func (t *Tunnel) configure() tcpip.Error {
	st := t.stack
	// The iOS extension has its own memory budget. Bound both directions of
	// each split TCP flow so a slow remote stream applies backpressure.
	tcpSend := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: tcpBufferSize, Max: tcpBufferSize}
	tcpReceive := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: tcpBufferSize, Max: tcpBufferSize}
	for _, opt := range []tcpip.SettableTransportProtocolOption{&tcpSend, &tcpReceive} {
		if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return err
		}
	}
	tcpForwarder := tcp.NewForwarder(st, tcpBufferSize, 32, t.forwardTCP)
	udpForwarder := udp.NewForwarder(st, t.forwardUDP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	if err := st.CreateNIC(t.nic, t.link); err != nil {
		return err
	}
	// Transparent forwarding accepts any destination and emits replies with
	// the original destination as their source.
	if err := st.SetPromiscuousMode(t.nic, true); err != nil {
		return err
	}
	if err := st.SetSpoofing(t.nic, true); err != nil {
		return err
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: t.nic},
		{Destination: header.IPv6EmptySubnet, NIC: t.nic},
	})
	return nil
}

// WritePacket injects one raw IPv4 or IPv6 packet. It takes a copy before
// returning so the caller can reuse its buffer immediately.
func (t *Tunnel) WritePacket(packet []byte) error {
	if len(packet) == 0 || len(packet) > maxPacketSize {
		return ErrInvalidPacket
	}
	var proto tcpip.NetworkProtocolNumber
	switch {
	case packet[0]>>4 == 4 && len(packet) >= header.IPv4MinimumSize:
		proto = ipv4.ProtocolNumber
	case packet[0]>>4 == 6 && len(packet) >= header.IPv6MinimumSize:
		proto = ipv6.ProtocolNumber
	default:
		return ErrInvalidPacket
	}

	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if t.ctx.Err() != nil {
		return ErrClosed
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	t.link.InjectInbound(proto, pkt)
	pkt.DecRef()
	return nil
}

// ReadPacket waits for a packet to return to the OS.
func (t *Tunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	if t.ctx.Err() != nil {
		return nil, ErrClosed
	}
	if pkt := t.link.ReadContext(ctx); pkt != nil {
		return copyPacket(pkt), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrClosed
}

// TryReadPacket immediately returns the next queued packet or nil.
func (t *Tunnel) TryReadPacket() []byte {
	if t.ctx.Err() != nil {
		return nil
	}
	if pkt := t.link.Read(); pkt != nil {
		return copyPacket(pkt)
	}
	return nil
}

func copyPacket(pkt *stack.PacketBuffer) []byte {
	defer pkt.DecRef()
	out := make([]byte, 0, pkt.Size())
	views, offset := pkt.AsViewList()
	for view := views.Front(); view != nil; view = view.Next() {
		data := view.AsSlice()
		if offset >= len(data) {
			offset -= len(data)
			continue
		}
		out = append(out, data[offset:]...)
		offset = 0
	}
	return out
}

func (t *Tunnel) beginFlow(slots chan struct{}) bool {
	t.flowMu.Lock()
	defer t.flowMu.Unlock()
	if t.ctx.Err() != nil {
		return false
	}
	select {
	case slots <- struct{}{}:
		t.flows.Add(1)
		return true
	default:
		return false
	}
}

func (t *Tunnel) endFlow(slots chan struct{}) {
	<-slots
	t.flows.Done()
}

// Close is safe to call concurrently and unblocks packet readers.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		// A flow that observed the old context must register with the wait
		// group before we can start waiting for teardown.
		t.flowMu.Lock()
		t.flowMu.Unlock()
		t.inputMu.Lock()
		t.link.Close()
		_ = t.stack.RemoveNIC(t.nic)
		t.inputMu.Unlock()
		t.stack.Close()
		t.flows.Wait()
		t.stack.Wait()
	})
	return nil
}
