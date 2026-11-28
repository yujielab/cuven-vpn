//go:build linux

package main

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yujielab/cuven-vpn/core/iptunnel"
	"golang.org/x/sys/unix"
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

func TestReadTokenFile(t *testing.T) {
	token := iptunnel.Token{1}
	text := base64.RawURLEncoding.EncodeToString(token[:])
	dir := t.TempDir()
	for _, tc := range []struct {
		name   string
		data   string
		mode   os.FileMode
		wantOK bool
	}{
		{"private", text + "\n", 0600, true},
		{"read-only credential", text, 0400, true},
		{"size limit", text + strings.Repeat(" ", 128-len(text)), 0600, true},
		{"oversize", text + strings.Repeat(" ", 129-len(text)), 0600, false},
		{"group readable", text, 0640, false},
		{"invalid", "invalid", 0600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			got, err := readTokenFile(path)
			if (err == nil) != tc.wantOK || (tc.wantOK && got != token) {
				t.Fatalf("unexpected token result (error %v)", err)
			}
		})
	}
	alias := filepath.Join(dir, "configured-symlink")
	if err := os.Symlink(filepath.Join(dir, "private"), alias); err != nil {
		t.Fatal(err)
	}
	if got, err := readTokenFile(alias); err != nil || got != token {
		t.Fatalf("private credential symlink: %v", err)
	}
	if _, err := readTokenFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	fifo := filepath.Join(dir, "pipe")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readTokenFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("checking a FIFO blocked waiting for a writer")
	}
}
