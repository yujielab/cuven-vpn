// Probe the gateway created by the private systemd integration fixture.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yujielab/cuven-vpn/core/iptunnel"
)

func main() {
	if err := probe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probe() error {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	defer clear(data)
	token, err := iptunnel.ParseToken(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	defer clear(token[:])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := iptunnel.Dial(ctx, "127.0.0.1:4433", token, &tls.Config{ServerName: "gateway.example"})
	if err != nil {
		return err
	}
	defer peer.Close()
	if peer.PacketMTU() != iptunnel.MTU {
		return fmt.Errorf("gateway negotiated MTU %d, expected %d", peer.PacketMTU(), iptunnel.MTU)
	}
	return nil
}
