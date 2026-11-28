package iptunnel

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	frameWhole byte = iota
	frameFirst
	frameLast
)

const (
	fragmentSize     = 1024
	fragmentHeader   = 5
	reassemblySlots  = 64
	reassemblyWindow = time.Second
)

// PacketAddresses validates the IP header and returns its original addresses.
func PacketAddresses(packet []byte) (src, dst netip.Addr, ok bool) {
	if len(packet) == 0 || len(packet) > MTU {
		return src, dst, false
	}
	switch packet[0] >> 4 {
	case 4:
		header := int(packet[0]&0x0f) * 4
		if header < 20 || len(packet) < header || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return src, dst, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return src, dst, false
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return src, dst, false
	}
}

func (s *Session) WritePacket(packet []byte) error {
	if _, _, ok := PacketAddresses(packet); !ok || len(packet) > s.mtu {
		return ErrInvalidPacket
	}
	var frame [fragmentHeader + fragmentSize]byte
	if len(packet) <= fragmentSize {
		frame[0] = frameWhole
		size := copy(frame[1:], packet)
		return s.connection.SendDatagram(frame[:size+1])
	}
	id := s.sequence.Add(1)
	binary.BigEndian.PutUint32(frame[1:fragmentHeader], id)
	frame[0] = frameFirst
	copy(frame[fragmentHeader:], packet[:fragmentSize])
	if err := s.connection.SendDatagram(frame[:]); err != nil {
		return err
	}
	frame[0] = frameLast
	size := copy(frame[fragmentHeader:], packet[fragmentSize:])
	return s.connection.SendDatagram(frame[:fragmentHeader+size])
}

type fragmentPair struct {
	started time.Time
	first   []byte
	last    []byte
}

type reassembler struct {
	pending map[uint32]fragmentPair
}

func (r *reassembler) unpack(frame []byte, now time.Time) []byte {
	if len(frame) < 2 {
		return nil
	}
	if frame[0] == frameWhole {
		if len(frame)-1 <= fragmentSize {
			return frame[1:]
		}
		return nil
	}
	if len(frame) <= fragmentHeader {
		return nil
	}
	payload := frame[fragmentHeader:]
	switch frame[0] {
	case frameFirst:
		if len(payload) != fragmentSize {
			return nil
		}
	case frameLast:
		if len(payload) > MTU-fragmentSize {
			return nil
		}
	default:
		return nil
	}
	id := binary.BigEndian.Uint32(frame[1:fragmentHeader])
	pair, found := r.pending[id]
	if !found || now.Sub(pair.started) >= reassemblyWindow {
		pair = fragmentPair{started: now}
	}
	if frame[0] == frameFirst {
		pair.first = payload
	} else {
		pair.last = payload
	}
	if pair.first == nil || pair.last == nil {
		if r.pending == nil {
			r.pending = make(map[uint32]fragmentPair)
		}
		if !found && len(r.pending) == reassemblySlots {
			// Make room for a new incomplete packet only when all slots are occupied.
			var oldestID uint32
			var oldestTime time.Time
			for otherID, other := range r.pending {
				if oldestTime.IsZero() || other.started.Before(oldestTime) {
					oldestID, oldestTime = otherID, other.started
				}
			}
			delete(r.pending, oldestID)
		}
		r.pending[id] = pair
		return nil
	}
	packet := make([]byte, len(pair.first)+len(pair.last))
	copy(packet, pair.first)
	copy(packet[fragmentSize:], pair.last)
	delete(r.pending, id)
	return packet
}

func (s *Session) receive() {
	defer close(s.packets)
	var fragments reassembler
	for {
		frame, err := s.connection.ReceiveDatagram(s.connection.Context())
		if err != nil {
			return
		}
		packet := fragments.unpack(frame, time.Now())
		if _, _, ok := PacketAddresses(packet); !ok || len(packet) > s.mtu {
			continue
		}
		select {
		case s.packets <- packet:
		default:
		}
	}
}
