//go:build linux

package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyReady(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify")
	receiver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	t.Setenv("NOTIFY_SOCKET", socket)

	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var notice [64]byte
	n, _, err := receiver.ReadFromUnix(notice[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := string(notice[:n]); got != "READY=1" {
		t.Fatalf("unexpected readiness notification %q", got)
	}
}
