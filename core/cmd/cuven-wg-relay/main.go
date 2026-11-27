package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yujielab/cuven-vpn/core/cuventransport"
)

func main() {
	listen := flag.String("listen", ":51821", "Cuven envelope UDP listen address")
	upstream := flag.String("upstream", "127.0.0.1:51820", "WireGuard loopback UDP endpoint")
	maxPeers := flag.Int("max-peers", 64, "maximum concurrent upstream sessions")
	idle := flag.Duration("idle-timeout", time.Minute, "evict a session after this much time without client data")
	version := flag.Int("envelope-version", 1, "Cuven envelope version (1 or 2)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *listen, *upstream, *maxPeers, *idle, *version); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, listen, upstream string, maxPeers int, idle time.Duration, version int) error {
	if version != int(cuventransport.Version1) && version != int(cuventransport.Version2) {
		return errors.New("-envelope-version must be 1 or 2")
	}
	key, err := decodeRelayKey(os.Getenv("CUVEN_RELAY_KEY"))
	if err != nil {
		return err
	}
	upstreamAddress, err := netip.ParseAddrPort(upstream)
	if err != nil {
		return errors.New("-upstream requires a loopback IP address and port")
	}
	listenAddress, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", listenAddress)
	if err != nil {
		return err
	}
	log.Printf("Cuven WireGuard relay listening on %s using envelope version %d", conn.LocalAddr(), version)
	return cuventransport.ServeRelay(ctx, conn, cuventransport.RelayConfig{
		Key: key, Upstream: upstreamAddress, MaxPeers: maxPeers, IdleTimeout: idle,
		Version: cuventransport.Version(version),
	})
}

func decodeRelayKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		key, err = base64.RawStdEncoding.Strict().DecodeString(value)
	}
	var zero [cuventransport.KeySize]byte
	if err != nil || len(key) != cuventransport.KeySize || bytes.Equal(key, zero[:]) {
		return nil, errors.New("CUVEN_RELAY_KEY must contain a 32-byte nonzero key in standard base64")
	}
	return key, nil
}
