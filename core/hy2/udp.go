package hy2

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	maxUDPSessions     = 256
	udpSessionQueue    = 16
	maxQueuedUDPBytes  = 2 << 20
	maxFragmentPackets = 32
	fragmentLifetime   = 3 * time.Second
)

// UDPSession gives each local UDP flow a distinct relay port on the server.
// It does not own a separate QUIC connection.
type UDPSession struct {
	client   *Client
	id       uint32
	nextID   atomic.Uint64
	incoming chan udpMessage
	closed   chan struct{}
}

// OpenUDP reserves a session ID on the authenticated connection. IDs are
// never reused during the life of the connection.
func (c *Client) OpenUDP() (*UDPSession, error) {
	if !c.udpEnabled {
		return nil, errors.New("Hysteria server does not support UDP relay")
	}
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	select {
	case <-c.Done():
		return nil, net.ErrClosed
	default:
	}
	if len(c.sessions) >= maxUDPSessions || c.nextSession == ^uint32(0) {
		return nil, errors.New("Hysteria UDP session limit reached")
	}
	c.nextSession++
	session := &UDPSession{
		client: c, id: c.nextSession,
		incoming: make(chan udpMessage, udpSessionQueue),
		closed:   make(chan struct{}),
	}
	c.sessions[session.id] = session
	return session, nil
}

// Send relays a UDP payload. Delivery is best-effort. Fragmentation keeps
// oversized payloads within the maximum offered by the active QUIC path.
func (s *UDPSession) Send(payload []byte, address string) error {
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	if err := validateAddress(address); err != nil {
		return err
	}
	if len(payload) > maxUDPPayload {
		return errInvalidDatagram
	}
	// SendDatagram copies the frame before queueing it. Reuse scratch storage
	// for a regular mobile-MTU datagram and for every outgoing fragment.
	var scratch [1500]byte
	message := udpMessage{sessionID: s.id, fragmentCount: 1, address: address, payload: payload}
	err := s.client.connection.SendDatagram(message.encode(scratch[:0]))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	fragmentSize := int(tooLarge.MaxDatagramPayloadSize) - message.headerSize()
	if fragmentSize <= 0 {
		return err
	}
	count := (len(payload) + fragmentSize - 1) / fragmentSize
	if count < 2 || count > 255 {
		return err
	}
	message.packetID = uint16((s.nextID.Add(1)-1)%65535 + 1)
	message.fragmentCount = uint8(count)
	for index := range count {
		message.fragmentIndex = uint8(index)
		start := index * fragmentSize
		message.payload = payload[start:min(start+fragmentSize, len(payload))]
		if err := s.client.connection.SendDatagram(message.encode(scratch[:0])); err != nil {
			return err
		}
	}
	return nil
}

// Receive waits for the next complete relayed datagram and its source address.
func (s *UDPSession) Receive(ctx context.Context) ([]byte, string, error) {
	select {
	case <-s.closed:
		return nil, "", net.ErrClosed
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case message := <-s.incoming:
		s.client.queuedBytes.Add(-int64(len(message.payload)))
		return message.payload, message.address, nil
	}
}

// Close releases local state. Hysteria servers expire UDP sessions on idle.
func (s *UDPSession) Close() error {
	c := s.client
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions[s.id] == s {
		delete(c.sessions, s.id)
		s.closeQueue()
	}
	return nil
}

func (s *UDPSession) closeQueue() {
	close(s.closed)
	for {
		select {
		case message := <-s.incoming:
			s.client.queuedBytes.Add(-int64(len(message.payload)))
		default:
			return
		}
	}
}

func (c *Client) receiveDatagrams() {
	defer func() {
		c.sessionsMu.Lock()
		defer c.sessionsMu.Unlock()
		for _, session := range c.sessions {
			session.closeQueue()
		}
		clear(c.sessions)
	}()
	fragments := make(fragmentBuffer)
	for {
		packet, err := c.connection.ReceiveDatagram(c.connection.Context())
		if err != nil {
			return
		}
		message, err := decodeUDP(packet)
		if err != nil {
			continue
		}
		c.sessionsMu.Lock()
		if session := c.sessions[message.sessionID]; session != nil {
			if complete, ok := fragments.complete(time.Now(), message); ok {
				c.enqueueDatagram(session, complete)
			}
		}
		c.sessionsMu.Unlock()
	}
}

func (c *Client) enqueueDatagram(session *UDPSession, message udpMessage) {
	bytes := int64(len(message.payload))
	if c.queuedBytes.Load()+bytes > maxQueuedUDPBytes {
		return
	}
	c.queuedBytes.Add(bytes)
	select {
	case session.incoming <- message:
	default:
		c.queuedBytes.Add(-bytes)
	}
}

type fragmentKey struct {
	sessionID uint32
	packetID  uint16
}

type fragmentPacket struct {
	address string
	expires time.Time
	parts   [][]byte
	bytes   int
	count   int
}

type fragmentBuffer map[fragmentKey]*fragmentPacket

func (f fragmentBuffer) complete(now time.Time, message udpMessage) (udpMessage, bool) {
	if message.fragmentCount == 1 {
		return message, true
	}
	if len(message.payload) == 0 {
		return udpMessage{}, false
	}
	key := fragmentKey{message.sessionID, message.packetID}
	packet := f[key]
	if packet == nil || !now.Before(packet.expires) {
		for key, old := range f {
			if !now.Before(old.expires) {
				delete(f, key)
			}
		}
		if len(f) >= maxFragmentPackets {
			return udpMessage{}, false
		}
		packet = &fragmentPacket{
			address: message.address,
			expires: now.Add(fragmentLifetime),
			parts:   make([][]byte, message.fragmentCount),
		}
		f[key] = packet
	}
	if len(packet.parts) != int(message.fragmentCount) || packet.address != message.address ||
		packet.parts[message.fragmentIndex] != nil {
		return udpMessage{}, false
	}
	if packet.bytes+len(message.payload) > maxUDPPayload {
		delete(f, key)
		return udpMessage{}, false
	}
	packet.parts[message.fragmentIndex] = slices.Clone(message.payload)
	packet.bytes += len(message.payload)
	packet.count++
	if packet.count != len(packet.parts) {
		return udpMessage{}, false
	}
	delete(f, key)
	message.payload = make([]byte, 0, packet.bytes)
	for _, part := range packet.parts {
		message.payload = append(message.payload, part...)
	}
	return message, true
}
