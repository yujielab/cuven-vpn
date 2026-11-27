//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yujielab/cuven-vpn/core/iptunnel"
	"github.com/yujielab/cuven-vpn/core/linkhealth"
	"github.com/yujielab/cuven-vpn/core/packetpolicy"
	"golang.org/x/sys/unix"
)

func main() {
	listen := flag.String("listen", ":4433", "UDP listen address")
	cert := flag.String("tls-cert", "", "TLS certificate chain")
	key := flag.String("tls-key", "", "TLS private key")
	tokenPath := flag.String("token-file", "", "file containing the client's enrollment token")
	modelPath := flag.String("model-file", "", "optional local link health model")
	dual := flag.Bool("ipv6", false, "forward IPv6 for the enrolled client")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *listen, *cert, *key, *tokenPath, *modelPath, *dual); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, listen, cert, key, tokenPath, modelPath string, dual bool) error {
	var model *linkhealth.Model
	if modelPath != "" {
		var err error
		model, err = linkhealth.Load(modelPath)
		if err != nil {
			return fmt.Errorf("load link health model: %w", err)
		}
	}
	info, err := os.Stat(tokenPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128 || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("gateway requires a private regular token file")
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	token, err := iptunnel.ParseToken(strings.TrimSpace(string(data)))
	clear(data)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	device, err := openTUN(ctx, dual)
	if err != nil {
		return err
	}
	defer device.Close()
	listener, err := iptunnel.Listen(listen, &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := notifyReady(); err != nil {
		return fmt.Errorf("notify systemd: %w", err)
	}
	return serve(ctx, listener, device, token, dual, model)
}

func notifyReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err = connection.Write([]byte("READY=1"))
	return err
}

func openTUN(ctx context.Context, dual bool) (*os.File, error) {
	const name = "cuven0"
	request, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	device := os.NewFile(uintptr(fd), "/dev/net/tun")
	commands := [][]string{
		{"addr", "add", "10.66.0.1/30", "dev", name},
	}
	if dual {
		commands = append(commands, []string{"-6", "addr", "add", "fd66::1/126", "dev", name, "nodad"})
	}
	commands = append(commands, []string{"link", "set", "dev", name, "mtu", "1280", "up"})
	for _, args := range commands {
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			_ = device.Close()
			return nil, fmt.Errorf("configure %s: %w: %s", name, err, out)
		}
	}
	return device, nil
}

func serve(ctx context.Context, listener *iptunnel.Listener, device *os.File, token iptunnel.Token, dual bool, model *linkhealth.Model) error {
	var active atomic.Pointer[iptunnel.Session]
	peer4 := netip.MustParseAddr("10.66.0.2")
	peer6 := netip.MustParseAddr("fd66::2")
	isPeer := func(address netip.Addr) bool { return address == peer4 || (dual && address == peer6) }
	pumpErr := make(chan error, 1)
	go func() {
		var buffer [iptunnel.MTU + 1]byte
		for {
			n, err := device.Read(buffer[:])
			if err != nil {
				pumpErr <- err
				_ = listener.Close()
				return
			}
			_, dest, valid := iptunnel.PacketAddresses(buffer[:n])
			if peer := active.Load(); peer != nil && valid && isPeer(dest) {
				_ = peer.WritePacket(buffer[:n])
			}
		}
	}()
	defer func() {
		if peer := active.Swap(nil); peer != nil {
			_ = peer.Close()
		}
		_ = device.Close()
	}()
	slot := make(chan struct{}, 1)
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case err := <-pumpErr:
				return err
			default:
				return err
			}
		}
		select {
		case slot <- struct{}{}:
		default:
			_ = connection.CloseWithError(1, "gateway busy")
			continue
		}
		go func() {
			defer func() { <-slot }()
			peer, err := iptunnel.Authenticate(ctx, connection, token, dual)
			if err != nil {
				return
			}
			active.Store(peer)
			defer peer.Close()
			defer active.CompareAndSwap(peer, nil)
			if model != nil {
				go monitorLink(peer, model)
			}
			for {
				packet, err := peer.ReadPacket(ctx)
				if err != nil {
					return
				}
				src, dest, valid := iptunnel.PacketAddresses(packet)
				if valid && isPeer(src) && publicDestination(dest) && !packetpolicy.RejectPlainDNS(packet) {
					if _, err := device.Write(packet); err != nil {
						return
					}
				}
			}
		}()
	}
}

var excludedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicDestination(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || packetpolicy.IsLocalDestination(address) || address.Is4In6() {
		return false
	}
	for _, prefix := range excludedIPv4 {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func monitorLink(peer *iptunnel.Session, model *linkhealth.Model) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	previous := peer.Stats()
	sustained := 0
	for {
		select {
		case <-peer.Done():
			return
		case <-ticker.C:
			stats := peer.Stats()
			sent := stats.PacketsSent - previous.PacketsSent
			var lost uint64
			if stats.PacketsLost > previous.PacketsLost {
				lost = stats.PacketsLost - previous.PacketsLost
			}
			previous = stats
			if sent < 10 || stats.MinRTT <= 0 || stats.SmoothedRTT <= 0 {
				sustained = 0
				continue
			}
			score := model.Score(
				float64(stats.SmoothedRTT)/float64(time.Millisecond),
				float64(stats.MinRTT)/float64(time.Millisecond),
				float64(stats.MeanDeviation)/float64(time.Millisecond),
				float64(lost)/float64(sent),
			)
			if score >= 0.8 {
				sustained++
				if sustained == 3 {
					log.Printf("sustained Cuven link degradation, model score %.2f", score)
				}
			} else {
				sustained = 0
			}
		}
	}
}
