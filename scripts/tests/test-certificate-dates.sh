#!/usr/bin/env bash
set -euo pipefail
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
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
