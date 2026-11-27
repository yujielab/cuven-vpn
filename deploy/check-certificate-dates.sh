#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
cert=${1:?Specify the TLS certificate file}
fail() { printf '%s\n' "$*" >&2; exit 1; }

start=$(openssl x509 -in "$cert" -noout -startdate) || fail '无法读取网关 TLS 证书。'
start_time=$(date -u -d "${start#notBefore=}" +%s) || fail '无法读取证书生效时间。'
(( start_time <= $(date -u +%s) )) || fail '网关证书尚未生效，请核对 VPS 的 UTC 时间和证书有效期。'
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null || fail '网关证书已过期，请续签或更换证书。'
