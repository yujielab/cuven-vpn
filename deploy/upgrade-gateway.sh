#!/usr/bin/env bash
# Called under the gateway installation lock.
set -euo pipefail
umask 077
state=/etc/cuven-gateway
service=cuven-gateway.service
binary=$state/cuven-gateway
record=$state/.upgrade-recovery
legacy=$state/.upgrade-previous
fail() { printf '%s\n' "$*" >&2; exit 1; }
present() { [[ -e "$1" || -L "$1" ]]; }

recover_only=false
if [[ "${1:-}" == --recover ]]; then
    recover_only=true
    if ! present "$record" && ! present "$legacy"; then exit 0; fi
fi
work=$(mktemp -d "$state/.upgrade.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT

# Publish the executable and its original service state together before swapping
# binaries. The hard link remains valid while systemd or a retry uses either ELF.
save_previous() {
    mkdir -m 0700 "$work/pending"
    ln -T -- "$1" "$work/pending/binary"
    if systemctl is-active --quiet "$service"; then
        echo active >"$work/pending/service-state"
    else
        echo inactive >"$work/pending/service-state"
    fi
    mv -T -- "$work/pending" "$record"
}
restore_previous() {
    local original_state pid
    [[ -d "$record" && ! -L "$record" && -f "$record/binary" && ! -L "$record/binary" &&
       -f "$record/service-state" && ! -L "$record/service-state" ]] || fail '程序升级恢复记录不完整，请保留并检查。'
    original_state=$(cat "$record/service-state")
    [[ "$original_state" == active || "$original_state" == inactive ]] || fail '无法读取升级前的网关状态。'
    if [[ ! "$binary" -ef "$record/binary" ]]; then
        ln -T -- "$record/binary" "$work/restore"
        mv -fT -- "$work/restore" "$binary"
    fi
    if [[ "$original_state" == active ]]; then
        pid=$(systemctl show "$service" --property=MainPID --value 2>/dev/null) || pid=''
        if ! [[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/$pid/exe" -ef "$record/binary" ]] ||
           ! systemctl is-active --quiet "$service"; then
            systemctl restart "$service" || fail '已恢复原程序，服务仍未启动。请检查日志后重运行安装器。'
        fi
    else
        systemctl stop "$service" || fail '已恢复原程序，请检查服务状态后重运行安装器。'
    fi
    mv -T -- "$record" "$(mktemp -d "$work/restored.XXXXXXXX")"
}

# Older releases saved just the ELF. Preserve the observable service state
# when adopting that record; those installers did not persist its earlier state.
if present "$legacy"; then
    [[ -f "$legacy" && ! -L "$legacy" ]] || fail '网关升级备份路径异常，请先检查安装状态。'
    if ! present "$record"; then save_previous "$legacy"; fi
    [[ "$legacy" -ef "$record/binary" ]] || fail '发现互不匹配的升级备份，请保留并检查。'
    rm -- "$legacy"
fi
if present "$record"; then
    restore_previous
    printf '%s\n' '已恢复中断升级前的网关程序和服务状态。'
fi
if "$recover_only"; then exit 0; fi

cert=${1:?Specify the configured certificate}
key=${2:?Specify the configured key}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -f "$binary" && ! -L "$binary" && -s "$state/token" ]] || fail '已有网关程序或令牌不完整，请先检查安装状态。'
cert_key=$(openssl x509 -in "$cert" -noout -pubkey) || fail '无法读取已配置的证书。'
tls_key=$(openssl pkey -in "$key" -passin pass: -pubout) || fail '无法读取已配置的 TLS 私钥。'
[[ "$cert_key" == "$tls_key" ]] || fail '当前磁盘上的网关证书与私钥不匹配，请先修复证书。'

shipped=$repo/bin/cuven-gateway-$(uname -m)
if [[ -f "$shipped" ]]; then
    install -m 0700 "$shipped" "$work/new"
else
    command -v go >/dev/null || fail '请使用自带二进制的独立安装器，或安装 Go 1.26.11 或更高版本。'
    (cd "$repo/core" && go build -mod=readonly -trimpath -o "$work/new" ./cmd/cuven-gateway)
fi
if cmp -s "$work/new" "$binary"; then
    printf '%s\n' '网关程序已是本版本。'
    exit 0
fi

save_previous "$binary"
mv -fT -- "$work/new" "$binary"
if systemctl restart "$service"; then
    mv -T -- "$record" "$work/committed"
    printf '%s\n' '网关程序已更新，服务已就绪。'
    exit 0
fi
restore_previous
fail '新程序启动失败，已恢复原网关程序和服务状态。'
