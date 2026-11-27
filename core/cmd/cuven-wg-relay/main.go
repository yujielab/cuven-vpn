package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

type relayOptions struct {
	listen      string
	upstream    string
	maxPeers    int
	idle        time.Duration
	version     int
	https3      bool
	certificate string
	privateKey  string
}

func main() {
	var opts relayOptions
	flag.StringVar(&opts.listen, "listen", ":51821", "UDP listen address")
	flag.StringVar(&opts.upstream, "upstream", "127.0.0.1:51820", "WireGuard loopback UDP endpoint")
	flag.IntVar(&opts.maxPeers, "max-peers", 64, "maximum concurrent upstream sessions")
	flag.DurationVar(&opts.idle, "idle-timeout", time.Minute, "evict a session after this much time without client data")
	flag.IntVar(&opts.version, "envelope-version", 0, "envelope version (defaults to 1 for raw UDP and 2 for HTTPS/3)")
	flag.BoolVar(&opts.https3, "https3", false, "serve Cuven v2 over HTTP/3 CONNECT-UDP")
	flag.StringVar(&opts.certificate, "tls-cert", "", "certificate chain PEM for HTTPS/3")
	flag.StringVar(&opts.privateKey, "tls-key", "", "certificate private key PEM for HTTPS/3")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, opts); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, opts relayOptions) error {
	version := opts.version
	if version == 0 {
		version = int(cuventransport.Version1)
		if opts.https3 {
			version = int(cuventransport.Version2)
		}
	}
	if version != int(cuventransport.Version1) && version != int(cuventransport.Version2) {
		return errors.New("-envelope-version must be 1 or 2")
	}

	var tlsConfig *tls.Config
	if opts.https3 {
		if version != int(cuventransport.Version2) {
			return errors.New("-https3 requires envelope version 2")
		}
		if opts.certificate == "" || opts.privateKey == "" {
			return errors.New("-https3 requires -tls-cert and -tls-key")
		}
		pair, err := tls.LoadX509KeyPair(opts.certificate, opts.privateKey)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	} else if opts.certificate != "" || opts.privateKey != "" {
		return errors.New("-tls-cert and -tls-key require -https3")
	}

	key, err := decodeRelayKey(os.Getenv("CUVEN_RELAY_KEY"))
	if err != nil {
		return err
	}
	upstream, err := netip.ParseAddrPort(opts.upstream)
	if err != nil || !upstream.Addr().Unmap().IsLoopback() || upstream.Port() == 0 {
		return errors.New("-upstream requires a loopback IP address and port")
	}
	address, err := net.ResolveUDPAddr("udp", opts.listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}

	config := cuventransport.RelayConfig{
		Key: key, Upstream: upstream, MaxPeers: opts.maxPeers, IdleTimeout: opts.idle,
		Version: cuventransport.Version(version),
	}
	if opts.https3 {
		log.Printf("Cuven WireGuard relay listening on %s using HTTPS/3 and envelope version 2", conn.LocalAddr())
		return cuventransport.ServeHTTPS3Relay(ctx, conn, tlsConfig, config)
	}
	log.Printf("Cuven WireGuard relay listening on %s using raw UDP and envelope version %d", conn.LocalAddr(), version)
	return cuventransport.ServeRelay(ctx, conn, config)
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
