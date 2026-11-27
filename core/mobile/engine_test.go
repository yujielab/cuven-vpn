package mobile

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDecodeBatch(t *testing.T) {
	batch := []byte{0, 3, 0x45, 1, 2, 0, 2, 0x60, 3}
	var packets [maxBatchPackets][]byte
	count, err := decodeBatch(batch, 1380, &packets)
	if err != nil || count != 2 || !bytes.Equal(packets[0], batch[2:5]) || !bytes.Equal(packets[1], batch[7:]) {
		t.Fatalf("decodeBatch returned %d packets, %v", count, err)
	}

	limit := bytes.Repeat([]byte{0, 1, 0x45}, maxBatchPackets)
	if count, err := decodeBatch(limit, 1380, &packets); err != nil || count != maxBatchPackets {
		t.Fatalf("valid maximum batch returned %d packets, %v", count, err)
	}
}

func TestDecodeRejectsMalformedBatches(t *testing.T) {
	oversize := make([]byte, 1381+packetHeaderLen)
	binary.BigEndian.PutUint16(oversize, 1381)

	for name, batch := range map[string][]byte{
		"truncated header":  {0, 1, 0x45, 0},
		"truncated payload": {0, 2, 0x45},
		"empty record":      {0, 0},
		"above MTU":         oversize,
		"too many packets":  bytes.Repeat([]byte{0, 1, 0x45}, maxBatchPackets+1),
	} {
		t.Run(name, func(t *testing.T) {
			var packets [maxBatchPackets][]byte
			count, err := decodeBatch(batch, 1380, &packets)
			if count != 0 || !errors.Is(err, errInvalidBatch) {
				t.Fatalf("decodeBatch returned %d packets, %v", count, err)
			}
		})
	}
}

func TestStopBeforeStart(t *testing.T) {
	engine := NewEngine()
	engine.Stop()
	engine.Stop()
	if err := engine.Start("127.0.0.1:443", "test", "localhost", 0, 1380, false, false); !errors.Is(err, errEngineUsed) {
		t.Fatalf("Start after Stop returned %v", err)
	}
	if _, err := engine.ReadBatch(); !errors.Is(err, errEngineInactive) {
		t.Fatalf("ReadBatch after Stop returned %v", err)
	}
	if err := engine.WriteBatch(nil); !errors.Is(err, errEngineInactive) {
		t.Fatalf("WriteBatch after Stop returned %v", err)
	}
}

func TestStopCancelsStartup(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	defer engine.Stop()
	started := make(chan error, 1)
	go func() {
		started <- engine.Start(socket.LocalAddr().String(), "test", "localhost", 0, 1380, false, false)
	}()
	var packet [2048]byte
	if _, _, err := socket.ReadFrom(packet[:]); err != nil {
		t.Fatalf("waiting for transport dial: %v", err)
	}

	engine.Stop()
	select {
	case err := <-started:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Start returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not unblock after Stop")
	}
}
