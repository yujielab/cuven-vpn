#!/usr/bin/env python3
"""Verify the real connection source on an HTTPS server you control."""

import argparse
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv6Address, ip_address
import json
import secrets
import socket
import ssl
from urllib.parse import urlsplit


class CheckHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if not compare_digest(self.path.encode("utf-8"), self.server.secret_path):
            self.send_error(404)
            return
        peer = ip_address(self.client_address[0])
        if isinstance(peer, IPv6Address) and peer.ipv4_mapped:
            peer = peer.ipv4_mapped
        response = json.dumps({
            "observed_ip": str(peer),
            "address_family": peer.version,
            "matches_expected_vpn_egress": peer in self.server.expected,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(response)


class CheckServer(HTTPServer):
    def __init__(self, listen, port, tls, expected, path):
        self.address_family = socket.AF_INET6 if listen.version == 6 else socket.AF_INET
        self.tls = tls
        self.expected = expected
        self.secret_path = path.encode("ascii")
        super().__init__((str(listen), port), CheckHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except (ssl.SSLError, OSError):
            connection.close()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True, type=ip_address)
    parser.add_argument("--port", default=9443, type=int)
    parser.add_argument("--url", required=True, help="HTTPS URL matching the server certificate")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--expect-ip", required=True, action="append", type=ip_address)
    args = parser.parse_args()
    parsed = urlsplit(args.url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            (parsed.port or 443) != args.port):
        parser.error("--url must be a bare HTTPS origin with the listening port")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(args.cert, args.key)
    path = "/" + secrets.token_urlsafe(24)
    with CheckServer(args.listen, args.port, tls, set(args.expect_ip), path) as server:
        print("Open privately:", args.url.rstrip("/") + path, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
