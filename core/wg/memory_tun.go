package wg

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	packetBatchSize = 8
	packetQueueSize = 128
)

type memoryTUN struct {
	mtu     int
	ingress chan []byte
	egress  chan []byte
	done    chan struct{}
	events  chan tun.Event
	close   sync.Once
}

var _ tun.Device = (*memoryTUN)(nil)

func newMemoryTUN(mtu int) *memoryTUN {
	return &memoryTUN{
		mtu:     mtu,
		ingress: make(chan []byte, packetQueueSize),
		egress:  make(chan []byte, packetQueueSize),
		done:    make(chan struct{}),
		events:  make(chan tun.Event),
	}
}

func (t *memoryTUN) File() *os.File           { return nil }
func (t *memoryTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *memoryTUN) Name() (string, error)    { return "Cuven", nil }
func (t *memoryTUN) Events() <-chan tun.Event { return t.events }
func (t *memoryTUN) BatchSize() int           { return packetBatchSize }

func (t *memoryTUN) Close() error {
	t.close.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func (t *memoryTUN) inject(packet []byte) error {
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}
	// Avoid allocating when a blocked peer has filled the queue. Only the
	// app's single packet-pump writer submits outgoing packets.
	if len(t.ingress) == cap(t.ingress) {
		return nil
	}
	select {
	case t.ingress <- slices.Clone(packet):
		return nil
	case <-t.done:
		return net.ErrClosed
	default:
		return nil
	}
}

func (t *memoryTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	var packet []byte
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case packet = <-t.ingress:
	}
	for index, buffer := range buffers {
		if len(buffer)-offset < len(packet) {
			return index, io.ErrShortBuffer
		}
		sizes[index] = copy(buffer[offset:], packet)
		if index == len(buffers)-1 {
			return len(buffers), nil
		}
		select {
		case <-t.done:
			return index + 1, os.ErrClosed
		case packet = <-t.ingress:
		default:
			return index + 1, nil
		}
	}
	return 0, nil
}

func (t *memoryTUN) Write(buffers [][]byte, offset int) (int, error) {
	for index, buffer := range buffers {
		select {
		case <-t.done:
			return index, os.ErrClosed
		default:
		}
		if len(t.egress) == cap(t.egress) || len(buffer)-offset > t.mtu {
			continue
		}
		select {
		case t.egress <- slices.Clone(buffer[offset:]):
		case <-t.done:
			return index, os.ErrClosed
		default:
		}
	}
	return len(buffers), nil
}

func validIPPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		headerSize := int(packet[0]&0x0f) * 4
		return headerSize >= 20 && headerSize <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
	case 6:
		return len(packet) >= 40 && int(binary.BigEndian.Uint16(packet[4:6]))+40 == len(packet)
	default:
		return false
	}
}
