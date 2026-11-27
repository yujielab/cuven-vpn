#!/usr/bin/env bash
# Exercise the generated unit under a real systemd manager with a private network
# namespace. The unit and credentials exist only for the duration of the test.
set -euo pipefail
umask 077
binary=$(realpath "${1:?Specify the compiled Linux gateway}")
probe=$(realpath "${2:?Specify the compiled client probe}")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $EUID == 0 && -x "$binary" && -d /run/systemd/system && -c /dev/net/tun ]]
for tool in ip nft sysctl openssl unshare systemctl systemd-analyze python3; do command -v "$tool" >/dev/null; done

work=$(mktemp -d /var/lib/cuven-service-test.XXXXXXXX)
name=${work##*/}
unit="$name.service"
unit_file="/run/systemd/system/$unit"
port_holder=
cleanup() {
    local outcome=$?
    if [[ -n "$port_holder" ]]; then kill "$port_holder" 2>/dev/null || true; wait "$port_holder" 2>/dev/null || true; fi
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

openssl req -x509 -key "$work/qa.key" -days 1 -subj /CN=other.example -addext subjectAltName=DNS:other.example -out "$work/other.crt"
openssl req -x509 -key "$work/qa.key" -subj /CN=gateway.example -days 1 -out "$work/legacy.crt"

# Stage the exact installer output without registering the production unit.
cat >"$work/shim/systemctl" <<'SHIM'
#!/bin/sh
if [ -n "${CUVEN_TEST_LIVE_WORK:-}" ]; then
    case "$1" in
        daemon-reload)
            "$CUVEN_TEST_LIVE_WORK/publish-unit" "$CUVEN_TEST_LIVE_WORK"
            exec /usr/bin/systemctl daemon-reload ;;
        start|stop|restart|is-active)
            action=$1
            shift
            if [ "${1:-}" = --quiet ]; then shift; fi
            [ "$1" = cuven-gateway.service ] || exit 2
            exec /usr/bin/systemctl "$action" "${CUVEN_TEST_LIVE_WORK##*/}.service" ;;
        is-enabled) echo disabled; exit 1 ;;
        *) exit 2 ;;
    esac
fi
if [ "$1" = restart ] && [ -e "$CUVEN_TEST_RESTART_FAULT" ]; then
    rm -- "$CUVEN_TEST_RESTART_FAULT"
    exit 75
fi
case "$1" in daemon-reload|enable|restart|is-active) exit 0 ;; *) exit 2 ;; esac
SHIM
cat >"$work/shim/install" <<'SHIM'
#!/usr/bin/env bash
if [[ -e "$CUVEN_TEST_FAULT" && "${!#}" == */firewall.nft ]]; then
    rm -f -- "$CUVEN_TEST_FAULT"
    exit 75
fi
exec /usr/bin/install "$@"
SHIM
chmod 0700 "$work/shim/systemctl" "$work/shim/install"
# Hold an unrelated UDP port in the fixture network during reconfiguration.
in_network python3 -c '
import pathlib, signal, socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
    listener.bind(("127.0.0.1", 0))
    pathlib.Path(sys.argv[1]).write_text(str(listener.getsockname()[1]))
    signal.pause()
' "$work/occupied-port" &
port_holder=$!
for _ in {1..100}; do [[ ! -s "$work/occupied-port" ]] || break; sleep 0.02; done
[[ -s "$work/occupied-port" ]]

in_network unshare --mount --propagation private -- bash -eu -c '
    work=$1
    mount --bind "$work/etc" /etc
    mount --bind "$work/locks" /run/lock
    export PATH="$work/shim:$PATH" CUVEN_TEST_FAULT="$work/fail-once" CUVEN_TEST_RESTART_FAULT="$work/fail-restart"
    args=(--domain gateway.example --port 4433 --cert "$work/qa.crt" --key "$work/qa.key" --ipv4-only)
    setup(){ bash "$work/pkg/deploy/setup-gateway.sh" "${args[@]}" "$@"; }
    # A CN-only certificate is rejected before an enrollment or live unit exists.
    if setup --cert "$work/legacy.crt"; then exit 1; fi
    [[ ! -e /etc/cuven-gateway && ! -e /etc/systemd/system/cuven-gateway.service ]]
    touch "$CUVEN_TEST_FAULT"
    if setup; then exit 1; else [[ $? == 75 ]]; fi
    [[ ! -e /etc/cuven-gateway && ! -e /etc/systemd/system/cuven-gateway.service ]]
    setup
    [[ $(cat /etc/cuven-gateway/gateway-name) == gateway.example ]]
    cp "$work/qa.crt" "$work/original.crt"
    cp "$work/other.crt" "$work/qa.crt"
    if bash "$work/pkg/deploy/setup-gateway.sh" --upgrade; then exit 1; fi
    cp "$work/original.crt" "$work/qa.crt"
    bash "$work/pkg/deploy/setup-gateway.sh" --upgrade
    token_before=$(sha256sum /etc/cuven-gateway/token)
    setup
    if setup --port 4513; then exit 1; fi
    saved_files=$(sha256sum /etc/cuven-gateway/{token,firewall.nft,forwarding.conf,cuven-gateway,gateway-name} /etc/systemd/system/cuven-gateway.service)
    if setup --reconfigure --port "$(cat "$work/occupied-port")" >"$work/collision.log" 2>&1; then exit 1; fi
    grep -Fq "无法绑定网关 UDP 地址" "$work/collision.log"
    [[ "$saved_files" == "$(sha256sum /etc/cuven-gateway/{token,firewall.nft,forwarding.conf,cuven-gateway,gateway-name} /etc/systemd/system/cuven-gateway.service)" ]]
    mv /etc/cuven-gateway/token "$work/saved-token"
    if setup --reconfigure --port 4513 >"$work/missing-token.log" 2>&1; then exit 1; fi
    grep -Fq "未找到原接入令牌" "$work/missing-token.log"
    [[ ! -e /etc/cuven-gateway/token && ! -e /etc/cuven-gateway/.reconfigure-previous ]]
    mv "$work/saved-token" /etc/cuven-gateway/token
    # Model an older installed ELF while retaining the packaged release bytes.
    printf test >>/etc/cuven-gateway/cuven-gateway
    old_program=$(sha256sum /etc/cuven-gateway/cuven-gateway)
    touch "$CUVEN_TEST_RESTART_FAULT"
    if setup --upgrade; then exit 1; fi
    [[ "$old_program" == "$(sha256sum /etc/cuven-gateway/cuven-gateway)" ]]
    setup --upgrade
    cmp "$work/pkg/bin/cuven-gateway-$(uname -m)" /etc/cuven-gateway/cuven-gateway
    [[ ! -e /etc/cuven-gateway/.upgrade-previous ]]
    [[ "$token_before" == "$(sha256sum /etc/cuven-gateway/token)" ]]
' bash "$work"

# Retain the generated credentials, sandbox, readiness and pre-start commands.
# Scope the paths and network to this fixture before handing it to PID 1.
cat >"$work/publish-unit" <<'PUBLISH'
#!/usr/bin/env bash
set -eu
work=$1
name=${work##*/}
source="$work/etc/systemd/system/cuven-gateway.service"
# Fail the proposed unit after nft and sysctl run, before its gateway becomes ready.
filter=()
if grep -Eq '^ExecStart=.* -listen :4513 ' "$source"; then
    filter=(-e '/^ExecStart=/i ExecStartPre=/bin/false')
fi
sed -e "s|/etc/cuven-gateway|$work/etc/cuven-gateway|g" \
    -e "/^\[Service\]$/a NetworkNamespacePath=/run/netns/$name" "${filter[@]}" \
    "$source" >"/run/systemd/system/$name.service"
chmod 0644 "/run/systemd/system/$name.service"
PUBLISH
chmod 0700 "$work/publish-unit"
"$work/publish-unit" "$work"
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
in_network env SSL_CERT_FILE="$work/qa.crt" "$probe" "$work/etc/cuven-gateway/token"
for _ in {1..100}; do
    if [[ $(in_network ip -o link show cuven0) == *" mtu 1500 "* ]]; then break; fi
    sleep .02
done
[[ $(in_network ip -o link show cuven0) == *" mtu 1500 "* ]]
old_rules=$(in_network nft --stateless list table inet cuven_gateway)
in_network unshare --mount --propagation private -- bash -eu -c '
    work=$1
    mount --bind "$work/etc" /etc
    mount --bind "$work/locks" /run/lock
    export PATH="$work/shim:$PATH" CUVEN_TEST_LIVE_WORK="$work" CUVEN_TEST_FAULT="$work/unused"
    installed=(/etc/cuven-gateway/{token,firewall.nft,forwarding.conf,cuven-gateway,gateway-name} /etc/systemd/system/cuven-gateway.service)
    previous=$(sha256sum "${installed[@]}")
    if bash "$work/pkg/deploy/setup-gateway.sh" --reconfigure --domain gateway.example --port 4513 \
        --cert "$work/qa.crt" --key "$work/qa.key" --ipv4-only >"$work/late-error.log" 2>&1; then exit 1; fi
    grep -Fq "Gateway startup failed" "$work/late-error.log"
    grep -Fq "已恢复之前的网关配置和服务状态" "$work/late-error.log"
    [[ "$previous" == "$(sha256sum "${installed[@]}")" && ! -e /etc/cuven-gateway/.reconfigure-previous ]]
' bash "$work"
check_service
[[ "$old_rules" == "$(in_network nft --stateless list table inet cuven_gateway)" ]]
in_network env SSL_CERT_FILE="$work/qa.crt" "$probe" "$work/etc/cuven-gateway/token"
echo "Verified recovery after a late systemd start failure and authenticated again on the old port."
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
