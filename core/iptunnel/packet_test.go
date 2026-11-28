package iptunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func fragmentFrames(id uint32, packet []byte) (first, last []byte) {
	frame := func(kind byte, data []byte) []byte {
		b := make([]byte, fragmentHeader+len(data))
		b[0] = kind
		binary.BigEndian.PutUint32(b[1:], id)
		copy(b[fragmentHeader:], data)
		return b
	}
	return frame(frameFirst, packet[:fragmentSize]), frame(frameLast, packet[fragmentSize:])
}

func TestReassemblyKeepsDelayedFragmentsAcrossCompletedPackets(t *testing.T) {
	for _, lastFirst := range []bool{false, true} {
		var receiver reassembler
		now := time.Now()
		delayed := testPacket6(MTU)
		delayed[100], delayed[fragmentSize+1] = 17, 33
		early, late := fragmentFrames(1, delayed)
		if lastFirst {
			early, late = late, early
		}
		if got := receiver.unpack(early, now); got != nil {
			t.Fatal("one fragment completed a packet")
		}
		for id := uint32(2); id <= reassemblySlots+2; id++ {
			packet := testPacket4(1280)
			packet[100], packet[fragmentSize+1] = byte(id), byte(id)
			first, last := fragmentFrames(id, packet)
			now = now.Add(time.Millisecond)
			if receiver.unpack(first, now) != nil || !bytes.Equal(receiver.unpack(last, now), packet) {
				t.Fatalf("interleaved packet %d did not match", id)
			}
		}
		if got := receiver.unpack(late, now); !bytes.Equal(got, delayed) {
			t.Errorf("last-first=%t: lost the complete delayed packet with only two incomplete packets at once", lastFirst)
		}
	}
}

func TestReassemblyExpiresIncompletePackets(t *testing.T) {
	var receiver reassembler
	packet := testPacket6(1280)
	first, last := fragmentFrames(42, packet)
	now := time.Now()
	if receiver.unpack(first, now) != nil || receiver.unpack(last, now.Add(reassemblyWindow)) != nil {
		t.Fatal("fragments across the expiry boundary were joined")
	}
	if got := receiver.unpack(first, now.Add(reassemblyWindow+time.Millisecond)); !bytes.Equal(got, packet) {
		t.Fatal("fresh fragments did not complete after expiry")
	}
}

func TestReassemblyRetainsOnlyNewestIncompletePacketsAtCapacity(t *testing.T) {
	var receiver reassembler
	now := time.Now()
	packet := testPacket4(1280)
	for id := uint32(0); id <= reassemblySlots; id++ {
		first, _ := fragmentFrames(id, packet)
		if receiver.unpack(first, now.Add(time.Duration(id)*time.Millisecond)) != nil {
			t.Fatal("a first fragment completed an IP packet")
		}
	}
	now = now.Add(reassemblySlots * time.Millisecond)
	for id := uint32(1); id <= reassemblySlots; id++ {
		_, last := fragmentFrames(id, packet)
		if got := receiver.unpack(last, now); !bytes.Equal(got, packet) {
			t.Fatalf("lost in-capacity packet %d", id)
		}
	}
	_, oldest := fragmentFrames(0, packet)
	if receiver.unpack(oldest, now) != nil {
		t.Fatal("completed a packet older than the capacity limit")
	}
}
