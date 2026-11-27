#!/usr/bin/env bash
# Exercise the generated unit under a real systemd manager with a private network
# namespace. The unit and credentials exist only for the duration of the test.
set -euo pipefail
umask 077
binary=$(realpath "${1:?Specify the compiled Linux gateway}")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $EUID == 0 && -x "$binary" && -d /run/systemd/system && -c /dev/net/tun ]]
for tool in ip nft sysctl openssl unshare systemctl systemd-analyze; do command -v "$tool" >/dev/null; done

work=$(mktemp -d /var/lib/cuven-service-test.XXXXXXXX)
name=${work##*/}
unit="$name.service"
unit_file="/run/systemd/system/$unit"
cleanup() {
    local outcome=$?
    if [[ "$outcome" != 0 && -e "$unit_file" ]]; then
        journalctl -u "$unit" --no-pager -n 15 || true
    fi
    if [[ -e "$unit_file" ]]; then
        systemctl stop "$unit" || true
        rm -f -- "$unit_file"
        systemctl daemon-reload
    fi
    ip netns delete "$name" 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT
ip netns add "$name"
in_network() { nsenter --net="/run/netns/$name" -- "$@"; }
in_network ip link set lo up
in_network ip link add wan0 type veth peer name wanpeer
in_network ip link set wan0 up
in_network ip link set wanpeer up
in_network ip address add 198.51.100.1/24 dev wan0
in_network ip route add default dev wan0
mkdir -p "$work"/{pkg/bin,pkg/deploy,etc/systemd/system,etc/alternatives,locks,shim}
# Ubuntu's /usr/bin/awk resolves via a symlink in /etc.
ln -s "$(readlink -f "$(command -v awk)")" "$work/etc/alternatives/awk"
install -m 0700 "$binary" "$work/pkg/bin/cuven-gateway-$(uname -m)"
cp "$repo"/deploy/*.sh "$work/pkg/deploy/"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=gateway.example -addext subjectAltName=DNS:gateway.example -days 1 \
    -keyout "$work/qa.key" -out "$work/qa.crt" >/dev/null 2>&1

# Stage the exact installer output without registering the production unit.
cat >"$work/shim/systemctl" <<'SHIM'
#!/bin/sh
case "$1" in daemon-reload|enable|restart) exit 0 ;; *) exit 2 ;; esac
SHIM
chmod 0700 "$work/shim/systemctl"
in_network unshare --mount --propagation private -- bash -eu -c '
    work=$1
    mount --bind "$work/etc" /etc
    mount --bind "$work/locks" /run/lock
    PATH="$work/shim:$PATH" bash "$work/pkg/deploy/install-gateway.sh" \
        --domain gateway.example --cert "$work/qa.crt" --key "$work/qa.key"
' bash "$work"

# Retain the generated credentials, sandbox, readiness and pre-start commands.
# Scope the paths and network to this fixture before handing it to PID 1.
sed -e "s|/etc/cuven-gateway|$work/etc/cuven-gateway|g" \
    -e "/^\[Service\]$/a NetworkNamespacePath=/run/netns/$name" \
    "$work/etc/systemd/system/cuven-gateway.service" >"$unit_file"
chmod 0644 "$unit_file"
systemd-analyze verify "$unit_file"
systemctl daemon-reload
check_service() {
    systemctl is-active --quiet "$unit"
    [[ $(systemctl show "$unit" -p Type --value) == notify ]]
    local pid
    pid=$(systemctl show "$unit" -p MainPID --value)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]]
    [[ $(stat -Lc '%d:%i' "/proc/$pid/ns/net") == "$(stat -Lc '%d:%i' "/run/netns/$name")" ]]
    in_network ip link show cuven0 >/dev/null
    in_network nft list table inet cuven_gateway >/dev/null
    [[ $(in_network sysctl -n net.ipv4.ip_forward) == 1 ]]
    in_network ss -Hlun | grep -q ':4433 '
}
systemctl start "$unit"
check_service
first_pid=$(systemctl show "$unit" -p MainPID --value)
token_before=$(sha256sum "$work/etc/cuven-gateway/token")
systemctl restart "$unit"
check_service
[[ "$first_pid" != "$(systemctl show "$unit" -p MainPID --value)" ]]
[[ "$token_before" == "$(sha256sum "$work/etc/cuven-gateway/token")" ]]
systemctl stop "$unit"
if in_network ip link show cuven0 >/dev/null 2>&1; then
    echo "Tunnel interface remained after service stop" >&2
    exit 1
fi
echo "Verified systemd readiness, credential loading, nftables, TUN, restart and stop in the private network namespace."
