package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestPacketFlow(t *testing.T) {
	ctx := t.Context()
	var tcpDials chan netip.AddrPort = make(chan netip.AddrPort, 4)
	pipe, err := open(ctx, relayTransport{
		openTCP: func(ctx context.Context, address string) (net.Conn, error) {
			addr, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, err
			}
			tcpDials <- addr
			target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), addr.Port())
			return (&net.Dialer{}).DialContext(ctx, "tcp4", target.String())
		},
		openUDP: func() (udpSession, error) { return make(echoSession, 4), nil },
	}, Options{BlockLAN: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipe.Close() })
	for _, test := range []struct {
		name    string
		source  string
		target  string
		private string
		proto   tcpip.NetworkProtocolNumber
		route   tcpip.Subnet
	}{
		{"IPv4", "198.18.0.1", "192.0.2.1", "192.168.1.1", ipv4.ProtocolNumber, header.IPv4EmptySubnet},
		{"IPv6", "fd31:6375:7665::1", "2001:db8::1", "fd00::1", ipv6.ProtocolNumber, header.IPv6EmptySubnet},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, nic := connectPacketPeer(t, ctx, pipe, test.proto, test.route, netip.MustParseAddr(test.source))
			target := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(test.target).AsSlice())}

			t.Run("TCP half-close", func(t *testing.T) {
				target.Port = startTCPEchoAfterFIN(t)
				flow, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				stream, err := gonet.DialTCPWithBind(flow, app, tcpip.FullAddress{}, target, test.proto)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				deadline, _ := flow.Deadline()
				_ = stream.SetDeadline(deadline)
				want := bytes.Repeat([]byte("packet-flow-tcp"), 2200)
				if _, err := stream.Write(want); err != nil {
					t.Fatal(err)
				}
				if err := stream.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(stream)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("TCP half-close echo got %d of %d bytes: %v", len(got), len(want), err)
				}
				wantAddr := netip.AddrPortFrom(netip.MustParseAddr(test.target), target.Port)
				if got := <-tcpDials; got != wantAddr {
					t.Fatalf("TCP destination = %v, want %v", got, wantAddr)
				}
			})

			t.Run("UDP reply", func(t *testing.T) {
				target.Port = 53
				socket, err := gonet.DialUDP(app, nil, &target, test.proto)
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
				want := bytes.Repeat([]byte{'U'}, 1200)
				if _, err := socket.Write(want); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				n, err := socket.Read(got)
				if err != nil || n != len(want) || !bytes.Equal(got, want) {
					t.Fatalf("UDP echo got %d of %d bytes: %v", n, len(want), err)
				}
			})

			t.Run("LAN rejection", func(t *testing.T) {
				flow, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				private := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(test.private).AsSlice()), Port: 80}
				stream, err := gonet.DialTCPWithBind(flow, app, tcpip.FullAddress{}, private, test.proto)
				if err == nil {
					_ = stream.Close()
					t.Fatal("LAN SYN was admitted")
				}
				if flow.Err() != nil {
					t.Fatalf("LAN SYN should be reset promptly: %v", err)
				}
				select {
				case dial := <-tcpDials:
					t.Fatalf("LAN SYN opened remote TCP flow to %v", dial)
				default:
				}
			})
		})
	}
}

// connectPacketPeer models NEPacketTunnelFlow with a separate IP stack.
func connectPacketPeer(t *testing.T, ctx context.Context, pipe *Tunnel, proto tcpip.NetworkProtocolNumber, route tcpip.Subnet, source netip.Addr) (*stack.Stack, tcpip.NICID) {
	t.Helper()
	app := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(256, 1280, "")
	ctx, cancel := context.WithCancel(ctx)
	var pumps sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		pumps.Wait()
		link.Close()
		app.Destroy()
	})
	id := app.NextNICID()
	if err := app.CreateNIC(id, link); err != nil {
		t.Fatal(err)
	}
	if err := app.AddProtocolAddress(id, tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(source.AsSlice()),
			PrefixLen: source.BitLen(),
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	app.SetRouteTable([]tcpip.Route{{Destination: route, NIC: id}})

	pumps.Go(func() {
		for ctx.Err() == nil {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			_ = pipe.WritePacket(view.AsSlice())
			view.Release()
			pkt.DecRef()
		}
	})
	pumps.Go(func() {
		for ctx.Err() == nil {
			data, err := pipe.ReadPacket(ctx)
			if err != nil {
				return
			}
			if data[0]>>4 == 4 && proto != ipv4.ProtocolNumber || data[0]>>4 == 6 && proto != ipv6.ProtocolNumber {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			link.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	})
	return app, id
}

func startTCPEchoAfterFIN(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		payload, err := io.ReadAll(io.LimitReader(connection, 64<<10))
		if err == nil {
			_, _ = connection.Write(payload)
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

type echoDatagram struct {
	address string
	payload []byte
}

type echoSession chan echoDatagram

func (s echoSession) Send(payload []byte, address string) error {
	// Inject an unrelated source first. Only the actual peer may send a reply.
	s <- echoDatagram{"127.0.0.1:53", []byte("unrelated sender")}
	s <- echoDatagram{address, bytes.Clone(payload)}
	return nil
}

func (s echoSession) Receive(ctx context.Context) ([]byte, string, error) {
	select {
	case packet := <-s:
		return packet.payload, packet.address, nil
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

func (s echoSession) Close() error { return nil }
