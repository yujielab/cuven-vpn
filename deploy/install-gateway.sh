#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: sudo deploy/install-gateway.sh --domain HOST --cert PATH --key PATH [--port N] [--ipv6] [--model PATH] [--allow-source CIDR]
Run on a Debian or Ubuntu VPS with systemd. Put a trusted TLS certificate and
its private key on the VPS before running the installer.
EOF
}

fail() { printf '%s\n' "$*" >&2; exit 1; }

domain='' cert='' key='' model='' port=4433 dual=false
allow4=() allow6=()
while (($#)); do
    case "$1" in
        --help) usage; exit 0 ;;
        --ipv6) dual=true; shift ;;
        --domain|--cert|--key|--port|--model|--allow-source)
            (($# >= 2)) || fail "$1 requires a value"
            case "$1" in
                --domain) domain="$2" ;;
                --cert) cert="$2" ;;
                --key) key="$2" ;;
                --model) model="$2" ;;
                --port) port="$2" ;;
                --allow-source)
                    if [[ "$2" == *:* && "$2" =~ ^[0-9a-fA-F:.]+/[0-9]{1,3}$ ]]; then
                        allow6+=("$2")
                    elif [[ "$2" =~ ^[0-9.]+/[0-9]{1,2}$ ]]; then
                        allow4+=("$2")
                    else
                        fail 'Use an IPv4 or IPv6 CIDR for --allow-source'
                    fi
                    ;;
            esac
            shift 2 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
model_arg=''
model_credential=''
if [[ -n "$model" ]]; then
    [[ "$model" =~ ^/[a-zA-Z0-9._/-]+$ && -r "$model" ]] || fail 'Use a readable absolute model path without spaces'
    model_arg="-model-file %d/link-model"
    model_credential="LoadCredential=link-model:$model"
fi
[[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || fail 'Enter the certificate domain'
[[ "$port" =~ ^[0-9]{1,5}$ ]] || fail 'Enter a UDP port from 1 to 65535'
((10#$port >= 1 && 10#$port <= 65535)) || fail 'Enter a UDP port from 1 to 65535'
port=$((10#$port))
for path in "$cert" "$key"; do
    [[ "$path" =~ ^/[a-zA-Z0-9._/-]+$ && -f "$path" && -r "$path" ]] ||
        fail 'Use readable absolute certificate paths without spaces'
done
((EUID == 0)) || fail 'Run as root using sudo'
[[ -d /run/systemd/system ]] || fail 'The gateway requires systemd'
[[ -c /dev/net/tun ]] || fail 'Enable the TUN device on this VPS'

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state=/etc/cuven-gateway
unit=/etc/systemd/system/cuven-gateway.service
exec 9>/run/lock/cuven-gateway-install.lock
flock -n 9 || fail 'Another gateway installation is running'

if [[ -e "$state" && ! -f "$state/install-version" ]]; then
    fail "$state already exists. Keep the existing configuration and inspect it before installing."
fi
if [[ -e "$unit" && ! -f "$state/install-version" ]]; then
    fail "$unit already exists. Keep the existing service and inspect it before installing."
fi

binary="$repo/bin/cuven-gateway-$(uname -m)"
if [[ ! -f "$binary" ]]; then
    command -v go >/dev/null || fail 'Use the standalone installer or install Go 1.26.3 or newer'
fi
if ! command -v nft >/dev/null || ! command -v ip >/dev/null ||
    ! command -v openssl >/dev/null || ! command -v sysctl >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables iproute2 openssl procps
fi
bash "$repo/deploy/check-certificate-dates.sh" "$cert"
openssl x509 -in "$cert" -noout -checkhost "$domain" |
    grep -Fxq "Hostname $domain does match certificate" || fail 'TLS certificate name does not match'
certificate_public_key="$(openssl x509 -in "$cert" -noout -pubkey)"
tls_public_key="$(openssl pkey -in "$key" -passin pass: -pubout)" || fail 'Use an unencrypted TLS private key'
[[ "$certificate_public_key" == "$tls_public_key" ]] || fail 'TLS certificate and private key do not match'
if [[ ! -f "$state/install-version" ]] && nft list table inet cuven_gateway >/dev/null 2>&1; then
    fail 'The nftables table cuven_gateway already exists'
fi

outbound_interface() {
    local family="$1" target="$2" interface
    interface="$(ip "$family" route get "$target" | awk 'NR == 1 {for (i=1; i<NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
    [[ "$interface" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$interface" != lo && "$interface" != cuven0 ]] ||
        fail "No usable ${family#-} egress interface"
    printf '%s\n' "$interface"
}
wan4="$(outbound_interface -4 1.1.1.1)"
wan6=''
if "$dual"; then wan6="$(outbound_interface -6 2606:4700:4700::1111)"; fi

staging="$(mktemp -d /etc/.cuven-gateway.XXXXXX)"
trap 'rm -rf -- "$staging"' EXIT
if [[ -f "$binary" ]]; then
    install -m 0700 "$binary" "$staging/cuven-gateway"
else
    (cd "$repo/core" && go build -mod=readonly -trimpath -o "$staging/cuven-gateway" ./cmd/cuven-gateway)
fi

cat >"$staging/firewall.nft" <<EOF
add table inet cuven_gateway
delete table inet cuven_gateway
table inet cuven_gateway {
    set private4 {
        type ipv4_addr
        flags interval
        elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 }
    }
    set private6 {
        type ipv6_addr
        flags interval
        elements = { ::/96, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 }
    }
    chain input {
        type filter hook input priority -20; policy accept;
        iifname "cuven0" drop
EOF
if ((${#allow4[@]} + ${#allow6[@]})); then
    if ((${#allow4[@]})); then
        allow4_list="$(IFS=,; printf '%s' "${allow4[*]}")"
        printf '        udp dport %s ip saddr != { %s } drop\n' "$port" "$allow4_list" >>"$staging/firewall.nft"
    else
        printf '        udp dport %s meta nfproto ipv4 drop\n' "$port" >>"$staging/firewall.nft"
    fi
    if ((${#allow6[@]})); then
        allow6_list="$(IFS=,; printf '%s' "${allow6[*]}")"
        printf '        udp dport %s ip6 saddr != { %s } drop\n' "$port" "$allow6_list" >>"$staging/firewall.nft"
    else
        printf '        udp dport %s meta nfproto ipv6 drop\n' "$port" >>"$staging/firewall.nft"
    fi
fi
cat >>"$staging/firewall.nft" <<EOF
        udp dport $port ct state new limit rate over 200/second burst 400 packets drop
    }
    chain tunnel_mss {
        # cuven0 MTU is 1280. Allow for the fixed IP and TCP headers (RFC 6691).
        meta nfproto ipv4 tcp option maxseg size > 1240 tcp option maxseg size set 1240
        meta nfproto ipv6 tcp option maxseg size > 1220 tcp option maxseg size set 1220
    }
    chain forward {
        type filter hook forward priority -20; policy accept;
        iifname "cuven0" ip daddr @private4 drop
        iifname "cuven0" ip6 daddr @private6 drop
        iifname "cuven0" tcp flags & syn == syn jump tunnel_mss
        oifname "cuven0" tcp flags & syn == syn jump tunnel_mss
        iifname "cuven0" oifname "$wan4" ip saddr 10.66.0.2 accept
        iifname "$wan4" oifname "cuven0" ip daddr 10.66.0.2 ct state established,related accept
EOF
if "$dual"; then
    cat >>"$staging/firewall.nft" <<EOF
        iifname "cuven0" oifname "$wan6" ip6 saddr fd66::2 accept
        iifname "$wan6" oifname "cuven0" ip6 daddr fd66::2 ct state established,related accept
EOF
fi
cat >>"$staging/firewall.nft" <<EOF
        iifname "cuven0" drop
        oifname "cuven0" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        iifname "cuven0" oifname "$wan4" ip saddr 10.66.0.2 masquerade
EOF
if "$dual"; then
    printf '        iifname "cuven0" oifname "%s" ip6 saddr fd66::2 masquerade\n' "$wan6" >>"$staging/firewall.nft"
fi
printf '    }\n}\n' >>"$staging/firewall.nft"
nft --check --file "$staging/firewall.nft"

printf '%s\n' 'net.ipv4.ip_forward=1' >"$staging/forwarding.conf"
if "$dual"; then
    case "$(sysctl -n "net/ipv6/conf/$wan6/accept_ra")" in
        1|2) printf 'net/ipv6/conf/%s/accept_ra=2\n' "$wan6" >>"$staging/forwarding.conf" ;;
    esac
    printf '%s\n' 'net.ipv6.conf.all.forwarding=1' >>"$staging/forwarding.conf"
fi

bash "$repo/deploy/install-certbot-hook.sh" "$cert" "$key"

install -d -m 0700 "$state"
if [[ ! -e "$state/token" ]]; then
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' >"$staging/token"
    install -m 0600 "$staging/token" "$state/token"
fi
install -m 0600 "$staging/firewall.nft" "$state/firewall.nft"
install -m 0600 "$staging/forwarding.conf" "$state/forwarding.conf"
install -m 0700 "$staging/cuven-gateway" "$state/cuven-gateway.new"
mv -f "$state/cuven-gateway.new" "$state/cuven-gateway"
printf '%s\n' 1 >"$state/install-version"

cat >"$staging/cuven-gateway.service" <<EOF
[Unit]
Description=Cuven IP gateway
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
LoadCredential=certificate:$cert
LoadCredential=private-key:$key
LoadCredential=token:$state/token
$model_credential
ExecStartPre=/usr/sbin/nft --file $state/firewall.nft
ExecStartPre=/usr/sbin/sysctl --load $state/forwarding.conf
ExecStart=$state/cuven-gateway -listen :$port -tls-cert %d/certificate -tls-key %d/private-key -token-file %d/token -ipv6=$dual $model_arg
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$staging/cuven-gateway.service" "$unit"
systemctl daemon-reload
systemctl enable cuven-gateway.service
systemctl restart cuven-gateway.service || fail 'Gateway startup failed. Check journalctl -u cuven-gateway.'
printf 'Cuven IP gateway: %s:%s (UDP)\nIPv6 forwarding: %s\nEnrollment token file: %s/token\n' "$domain" "$port" "$dual" "$state"
