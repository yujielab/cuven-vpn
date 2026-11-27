#!/usr/bin/env bash
# Both callers hold the gateway installation lock.
set -euo pipefail
umask 077
state=/etc/cuven-gateway
service=cuven-gateway.service
unit=/etc/systemd/system/$service
backup=$state/.reconfigure-previous
files=("$state/firewall.nft" "$state/forwarding.conf" "$state/cuven-gateway" "$state/gateway-name" "$unit")
fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ "${1:-}" == save ]]; then
    snapshot=${2:?Missing snapshot directory}
    forwarding=${3:?Missing proposed forwarding settings}
    [[ ! -e "$backup" && ! -L "$backup" ]] || fail '发现尚未恢复的网关配置。'
    mkdir -m 0700 "$snapshot"
    for file in "${files[@]}"; do
        name=${file##*/}
        if [[ -e "$file" || -L "$file" ]]; then
            cp -a --reflink=auto -- "$file" "$snapshot/$name"
        else
            touch "$snapshot/$name.absent"
        fi
    done
    if systemctl is-active --quiet "$service"; then touch "$snapshot/was-active"; fi
    systemctl is-enabled "$service" >"$snapshot/enablement" || true
    # Save only the table and the sysctl settings the new unit can change.
    tables=$(nft list tables inet)
    printf 'add table inet cuven_gateway\ndelete table inet cuven_gateway\n' >"$snapshot/live.nft"
    if grep -Fxq 'table inet cuven_gateway' <<<"$tables"; then
        nft --stateless list table inet cuven_gateway >>"$snapshot/live.nft"
    fi
    while IFS='=' read -r key _; do
        value=$(sysctl -n "$key")
        printf '%s=%s\n' "$key" "$value"
    done <"$forwarding" >"$snapshot/sysctls"
    printf '%s\n' 1 >"$snapshot/version"
    mv -T -- "$snapshot" "$backup"
    exit 0
fi

[[ "${1:-}" == restore ]] || fail 'Unknown configuration recovery operation'
[[ -e "$backup" || -L "$backup" ]] || exit 0
[[ -d "$backup" && ! -L "$backup" && -f "$backup/version" && $(cat "$backup/version") == 1 &&
   -f "$backup/live.nft" && -f "$backup/sysctls" && -f "$backup/enablement" ]] ||
    fail '网关恢复记录不完整，请保留并检查 /etc/cuven-gateway/.reconfigure-previous。'

work=$(mktemp -d "$state/.restore.XXXXXXXX")
unit_work=''
trap 'rm -rf -- "$work"; if [[ -n "$unit_work" ]]; then rm -rf -- "$unit_work"; fi' EXIT
unit_work=$(mktemp -d /etc/systemd/system/.cuven-restore.XXXXXXXX)
# Prepare every file before touching the live configuration. Keep the snapshot
# until the previous service state has been restored, including on a retry.
for file in "${files[@]}"; do
    name=${file##*/}
    if [[ -e "$backup/$name" || -L "$backup/$name" ]]; then
        [[ ! -e "$backup/$name.absent" ]] || fail "网关恢复记录中的 $name 状态冲突。"
        target=$work
        if [[ "$file" == "$unit" ]]; then target=$unit_work; fi
        cp -a --reflink=auto -- "$backup/$name" "$target/$name"
    elif [[ ! -f "$backup/$name.absent" ]]; then
        fail "网关恢复记录缺少 $name，请保留备份。"
    fi
done
if [[ -f "$backup/restart-attempted" ]]; then systemctl stop "$service"; fi
for file in "${files[@]}"; do
    name=${file##*/}
    if [[ -f "$backup/$name.absent" ]]; then
        rm -f -- "$file"
    elif [[ "$file" == "$unit" ]]; then
        mv -fT -- "$unit_work/$name" "$file"
    else
        mv -fT -- "$work/$name" "$file"
    fi
done
systemctl daemon-reload
if [[ -f "$backup/enable-attempted" ]]; then
    case "$(cat "$backup/enablement")" in
        disabled) systemctl disable "$service" ;;
        enabled-runtime) systemctl disable "$service"; systemctl enable --runtime "$service" ;;
    esac
fi
if [[ -f "$backup/restart-attempted" ]]; then
    nft --file "$backup/live.nft"
    while IFS='=' read -r key value; do
        if [[ "$key" == net/ipv6/conf/*/accept_ra && ! -e "/proc/sys/$key" ]]; then continue; fi
        current=$(sysctl -n "$key")
        if [[ "$current" != "$value" ]]; then sysctl -q -w "$key=$value"; fi
    done <"$backup/sysctls"
    if [[ -f "$backup/was-active" ]]; then systemctl start "$service"; fi
fi
mv -T -- "$backup" "$work/restored"
printf '%s\n' '已恢复之前的网关配置和服务状态。'
