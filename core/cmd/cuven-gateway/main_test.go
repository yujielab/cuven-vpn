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

func TestPendingHandshakesDoNotOwnTheSession(t *testing.T) {
	admission := sessionAdmission{pending: make(chan struct{}, 2)}
	if !admission.beginHandshake() || !admission.beginHandshake() || admission.beginHandshake() {
		t.Fatal("pending handshakes exceeded or underused their budget")
	}
	// The second handshake completes first; it can claim the session while the first is pending.
	if !admission.claimSession() {
		t.Fatal("pending handshake prevented a verified peer from connecting")
	}
	<-admission.pending
	if admission.claimSession() || admission.beginHandshake() {
		t.Fatal("another handshake could displace the active session")
	}
	<-admission.pending
	admission.occupied.Store(false)
	if !admission.beginHandshake() || !admission.claimSession() {
		t.Fatal("could not reconnect after the prior session ended")
	}
}
