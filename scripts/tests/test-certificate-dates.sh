#!/usr/bin/env bash
set -euo pipefail
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
gateway=''
if (( $# )); then gateway=$(realpath -- "$1"); fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
umask 077

# Sign short fixtures at explicit UTC dates without relying on a public CA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=fixture-ca -days 3 -keyout ca.key -out ca.crt >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=gateway.example -keyout leaf.key -out leaf.csr >/dev/null 2>&1
touch database
echo 01 >serial
cat >ca.conf <<'CONFIG'
[ca]
default_ca = fixture
[fixture]
database = database
new_certs_dir = .
certificate = ca.crt
private_key = ca.key
serial = serial
default_md = sha256
policy = names
unique_subject = no
[names]
commonName = supplied
CONFIG

issue() {
    openssl ca -config ca.conf -batch -notext -in leaf.csr -out "$1" \
        -startdate "$(date -u -d "$2" +%Y%m%d%H%M%SZ)" \
        -enddate "$(date -u -d "$3" +%Y%m%d%H%M%SZ)" >/dev/null 2>&1
}
issue current.pem '1 hour ago' '1 hour'
issue expired.pem '2 hours ago' '1 hour ago'
issue future.pem '1 hour' '2 hours'
bash "$src/deploy/check-certificate-dates.sh" current.pem
for file in expired.pem future.pem; do
    if bash "$src/deploy/check-certificate-dates.sh" "$file"; then
        echo "Accepted out-of-validity certificate $file" >&2
        exit 1
    fi
done

if [[ -n "$gateway" ]]; then
    # The date fixtures deliberately have only a Common Name.
    check() { "$gateway" -check-tls -tls-cert "$1" -tls-key "$2" -tls-name "$3"; }
    reject() { if check "$@"; then echo "Unexpected certificate acceptance: $1" >&2; exit 1; fi; }
    reject current.pem leaf.key gateway.example
    openssl req -x509 -key leaf.key -days 1 -subj /CN=unused.example \
        -addext 'subjectAltName=DNS:*.gateway.example,IP:192.0.2.7,IP:2001:db8::7' \
        -addext 'extendedKeyUsage=serverAuth' -out server.pem
    for name in node.gateway.example 192.0.2.7 2001:db8::7; do check server.pem leaf.key "$name"; done
    reject server.pem leaf.key deep.node.gateway.example
    reject server.pem leaf.key 192.0.2.8
    reject server.pem leaf.key 2001:::7
    reject server.pem ca.key node.gateway.example
    openssl req -x509 -key leaf.key -days 1 -subj /CN=unused.example \
        -addext 'subjectAltName=DNS:gateway.example,DNS:192.0.2.7' -out dns.pem
    check dns.pem leaf.key gateway.example
    reject dns.pem leaf.key 192.0.2.7
    openssl req -x509 -key leaf.key -days 1 -subj /CN=unused.example \
        -addext 'subjectAltName=DNS:gateway.example' -addext 'extendedKeyUsage=clientAuth' -out client.pem
    reject client.pem leaf.key gateway.example
    reject client.pem leaf.key ''
fi
