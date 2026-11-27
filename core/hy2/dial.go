package hy2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	addressAttemptDelay = 250 * time.Millisecond
	maxAddressAttempts  = 4
)

func dialQUIC(ctx context.Context, host, port string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	if _, err := netip.ParseAddr(host); err == nil {
		return quic.DialAddr(ctx, net.JoinHostPort(host, port), tlsConfig, config)
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
		return quic.DialAddr(ctx, net.JoinHostPort(addresses[0].String(), port), tlsConfig, config)
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
	return raceQUIC(ctx, addresses, port, tlsConfig, config)
}

func raceQUIC(ctx context.Context, addresses []netip.Addr, port string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
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
			connection, err := quic.DialAddr(attempts, net.JoinHostPort(address.String(), port), tlsConfig, config.Clone())
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
