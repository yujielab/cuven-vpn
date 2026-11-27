package hy2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/quic-go/quic-go"
)

const (
	addressAttemptDelay = 250 * time.Millisecond
	maxAddressAttempts  = 4
)

func dialQUIC(ctx context.Context, host, port string, tlsConfig *tls.Config, config *quic.Config, salamander string) (*quic.Conn, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return dialQUICAddr(ctx, address, port, tlsConfig, config, salamander)
	}
	// Resolve before allocating UDP sockets so DNS shares the connection deadline.
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("Hysteria server has no IP addresses")
	}
	if len(addresses) == 1 {
		return dialQUICAddr(ctx, addresses[0], port, tlsConfig, config, salamander)
	}
	// Prefer the system resolver's first result and stagger the other family
	// next. A broken IPv6 or IPv4 path will cost one short delay on mobile.
	for index := 1; index < len(addresses); index++ {
		if addresses[index].Unmap().Is4() != addresses[0].Unmap().Is4() {
			otherFamily := addresses[index]
			copy(addresses[2:index+1], addresses[1:index])
			addresses[1] = otherFamily
			break
		}
	}
	addresses = addresses[:min(len(addresses), maxAddressAttempts)]
	return raceQUIC(ctx, addresses, port, tlsConfig, config, salamander)
}

func dialQUICAddr(ctx context.Context, address netip.Addr, port string, tlsConfig *tls.Config, config *quic.Config, salamander string) (*quic.Conn, error) {
	if salamander == "" {
		return quic.DialAddr(ctx, net.JoinHostPort(address.String(), port), tlsConfig, config)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	address = address.Unmap()
	network := "udp6"
	if address.Is4() {
		network = "udp4"
	}
	socket, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	wrapped, err := obfs.WrapPacketConnSalamander(socket, []byte(salamander))
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	config = config.Clone()
	config.InitialPacketSize = 1200
	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(portNumber)))
	connection, err := quic.Dial(ctx, wrapped, remote, tlsConfig, config)
	if err != nil {
		_ = wrapped.Close()
		return nil, err
	}
	context.AfterFunc(connection.Context(), func() { _ = wrapped.Close() })
	return connection, nil
}

func raceQUIC(ctx context.Context, addresses []netip.Addr, port string, tlsConfig *tls.Config, config *quic.Config, salamander string) (*quic.Conn, error) {
	type result struct {
		connection *quic.Conn
		err        error
	}
	attempts, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result)
	for index, address := range addresses {
		go func() {
			if index > 0 {
				timer := time.NewTimer(time.Duration(index) * addressAttemptDelay)
				defer timer.Stop()
				select {
				case <-attempts.Done():
					return
				case <-timer.C:
				}
			}
			connection, err := dialQUICAddr(attempts, address, port, tlsConfig, config.Clone(), salamander)
			select {
			case results <- result{connection: connection, err: err}:
			case <-attempts.Done():
				if connection != nil {
					_ = connection.CloseWithError(noError, "")
				}
			}
		}()
	}
	var firstError error
	for range addresses {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case attempt := <-results:
			if attempt.err == nil {
				return attempt.connection, nil
			}
			if firstError == nil {
				firstError = attempt.err
			}
		}
	}
	return nil, firstError
}
