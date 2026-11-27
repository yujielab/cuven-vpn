#!/usr/bin/env bash
# Called by setup-gateway.sh under the installation lock.
set -euo pipefail
umask 077
state=/etc/cuven-gateway
service=cuven-gateway.service
binary=$state/cuven-gateway
backup=$state/.upgrade-previous
cert=${1:?Specify the configured certificate}
key=${2:?Specify the configured key}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf '%s\n' "$*" >&2; exit 1; }

[[ -f "$binary" && ! -L "$binary" && -s "$state/token" ]] || fail '已有网关程序或令牌不完整，请先检查安装状态。'
if [[ -e "$backup" || -L "$backup" ]]; then
    [[ -f "$backup" && ! -L "$backup" ]] || fail '网关升级备份路径异常，请先检查安装状态。'
fi
cert_key=$(openssl x509 -in "$cert" -noout -pubkey) || fail '无法读取已配置的证书。'
tls_key=$(openssl pkey -in "$key" -passin pass: -pubout) || fail '无法读取已配置的 TLS 私钥。'
[[ "$cert_key" == "$tls_key" ]] || fail '当前磁盘上的网关证书与私钥不匹配，请先修复证书。'

work=$(mktemp -d "$state/.upgrade.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
shipped=$repo/bin/cuven-gateway-$(uname -m)
if [[ -f "$shipped" ]]; then
    install -m 0700 "$shipped" "$work/new"
else
    command -v go >/dev/null || fail '请使用自带二进制的独立安装器，或安装 Go 1.26.3 或更高版本。'
    (cd "$repo/core" && go build -mod=readonly -trimpath -o "$work/new" ./cmd/cuven-gateway)
fi
if cmp -s "$work/new" "$binary" && [[ ! -e "$backup" ]]; then
    printf '%s\n' '网关程序已是本版本。'
    exit 0
fi

# Preserve the original executable across an interruption between replacement
# and systemd readiness. A repeated --upgrade completes that pending restart.
if [[ ! -e "$backup" ]]; then ln -T -- "$binary" "$backup"; fi
was_active=false
if systemctl is-active --quiet "$service"; then was_active=true; fi
mv -fT -- "$work/new" "$binary"
if systemctl restart "$service"; then
    rm -- "$backup"
    printf '%s\n' '网关程序已更新，服务已就绪。'
    exit 0
fi
mv -fT -- "$backup" "$binary"
if "$was_active"; then
    systemctl restart "$service" || fail '已恢复原程序，服务启动失败。请查看 journalctl -u cuven-gateway。'
else
    systemctl stop "$service" || fail '已恢复原程序，请检查服务状态。'
fi
fail '新程序启动失败，已恢复原网关程序。'
