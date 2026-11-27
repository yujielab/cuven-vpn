package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tcpOpenTimeout = 10 * time.Second
	udpIdleTimeout = 60 * time.Second
	dnsIdleTimeout = 10 * time.Second
	udpBufferSize  = 65535
	udpSocketSize  = 16 << 10
)

var tcpBuffers = sync.Pool{New: func() any { return new([16 << 10]byte) }}

type udpSession interface {
	Send([]byte, string) error
	Receive(context.Context) ([]byte, string, error)
	Close() error
}

func destination(id stack.TransportEndpointID) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return netip.AddrPortFrom(addr.Unmap(), id.LocalPort)
}

func (t *Tunnel) forwardTCP(request *tcp.ForwarderRequest) {
	address := destination(request.ID())
	if (t.blockLAN && IsLocalDestination(address.Addr())) || !t.beginFlow(t.tcpSlots) {
		request.Complete(t.ctx.Err() == nil)
		return
	}
	defer t.endFlow(t.tcpSlots)

	var events waiter.Queue
	endpoint, err := request.CreateEndpoint(&events)
	request.Complete(err != nil && t.ctx.Err() == nil)
	if err != nil {
		return
	}
	local := gonet.NewTCPConn(&events, endpoint)
	defer local.Close()

	ctx, cancel := context.WithTimeout(t.ctx, tcpOpenTimeout)
	remote, openErr := t.relay.openTCP(ctx, address.String())
	cancel()
	if openErr != nil {
		endpoint.Abort()
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(t.ctx, func() {
		endpoint.Abort()
		_ = remote.Close()
	})
	defer stop()

	sends := make(chan error, 1)
	go func() { sends <- copyTCP(remote, local) }()
	if err := copyTCP(local, remote); err != nil {
		endpoint.Abort()
		_ = remote.Close()
	}
	if err := <-sends; err != nil {
		endpoint.Abort()
	}
}

func copyTCP(dst, src net.Conn) error {
	buf := tcpBuffers.Get().(*[16 << 10]byte)
	defer tcpBuffers.Put(buf)
	_, err := io.CopyBuffer(dst, src, buf[:])
	if err == nil {
		// Keep the read side alive after sending FIN on a split connection.
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			err = half.CloseWrite()
		} else {
			err = dst.Close()
		}
	}
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	}
	return err
}

func (t *Tunnel) forwardUDP(request *udp.ForwarderRequest) bool {
	address := destination(request.ID())
	if (t.blockLAN && IsLocalDestination(address.Addr())) || !t.beginFlow(t.udpSlots) {
		return false
	}
	session, err := t.relay.openUDP()
	if err != nil {
		t.endFlow(t.udpSlots)
		return false
	}
	var events waiter.Queue
	endpoint, endpointErr := request.CreateEndpoint(&events)
	if endpointErr != nil {
		_ = session.Close()
		t.endFlow(t.udpSlots)
		return false
	}
	endpoint.SocketOptions().SetReceiveBufferSize(udpSocketSize, false)
	local := gonet.NewUDPConn(&events, endpoint)
	go t.relayUDP(local, session, address)
	return true
}

// Hysteria datagram sessions are scoped to one local UDP 4-tuple. This keeps
// concurrent requests from the same device isolated and preserves DNS replies.
func (t *Tunnel) relayUDP(local *gonet.UDPConn, session udpSession, address netip.AddrPort) {
	defer t.endFlow(t.udpSlots)
	defer session.Close()
	defer local.Close()
	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()

	started := time.Now()
	var activity atomic.Int64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer local.Close()
		for ctx.Err() == nil {
			payload, source, err := session.Receive(ctx)
			if err != nil {
				return
			}
			from, err := netip.ParseAddrPort(source)
			if err != nil || netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) != address {
				continue
			}
			if _, err := local.Write(payload); err == nil {
				activity.Store(int64(time.Since(started)))
			}
		}
	}()

	idle := udpIdleTimeout
	if address.Port() == 53 {
		idle = dnsIdleTimeout
	}
	_ = local.SetReadDeadline(started.Add(idle))
	buf := make([]byte, udpBufferSize)
	target := address.String()
	for ctx.Err() == nil {
		n, err := local.Read(buf)
		if err == nil {
			activity.Store(int64(time.Since(started)))
			// A lost or oversized datagram is isolated to this UDP write.
			_ = session.Send(buf[:n], target)
			continue
		}
		if !os.IsTimeout(err) {
			break
		}
		deadline := started.Add(time.Duration(activity.Load()) + idle)
		if time.Until(deadline) <= 0 {
			break
		}
		_ = local.SetReadDeadline(deadline)
	}
	cancel()
	_ = local.Close()
	<-readerDone
}
