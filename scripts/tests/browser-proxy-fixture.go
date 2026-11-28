// Browser integration fixture. The only permitted tunnel leads to the private
// loopback HTTPS origin created by this process.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"
)

const originName = "cuven-browser.test"

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func certificate(dir string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Cuven ephemeral simulator CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}), 0600))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: originName},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{originName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	must(err)
	return tls.Certificate{Certificate: [][]byte{der, root}, PrivateKey: leafKey}
}

func start(handler http.HandlerFunc, identity tls.Certificate) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}}
	server.StartTLS()
	return server
}

func main() {
	dir := os.Args[1]
	identity := certificate(dir)
	origin := start(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != originName || r.Method != http.MethodGet || r.URL.Path != "/proof" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<title>Cuven HTTPS fixture</title><p>Private proxy path verified</p>")
	}, identity)
	defer origin.Close()

	proxy := start(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != originName+":443" {
			http.Error(w, "fixture destination only", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", origin.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			http.Error(w, "offline", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(30 * time.Second))
		upstream.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := rw.Flush(); err != nil {
			return
		}
		go func() { io.Copy(upstream, rw); upstream.Close() }()
		io.Copy(client, upstream)
	}, identity)
	defer proxy.Close()
	must(os.WriteFile(filepath.Join(dir, "proxy"), []byte(proxy.URL), 0600))
	select {}
}
