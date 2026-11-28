#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
ask() {
    printf '%s ' "$1" >&2
    local answer
    IFS= read -r answer || fail '输入已结束。自动安装请传入 --domain，申请新证书时加 --accept-terms。'
    printf '%s' "$answer"
}
# Read the configured certificate through the administrator's local session.
if [[ ${1:-} == --show-pin ]]; then
    (( $# == 1 && EUID == 0 )) || fail '请单独运行 sudo bash cuven-vps-install.sh --show-pin。'
    unit=/etc/systemd/system/cuven-gateway.service
    [[ -f /etc/cuven-gateway/install-version && -r "$unit" ]] || fail '未找到已安装的 Cuven 网关。'
    exec 9>/run/lock/cuven-gateway-install.lock
    flock -s 9
    cert=$(sed -n 's/^LoadCredential=certificate://p' "$unit")
    [[ -f "$cert" && -r "$cert" ]] || fail '无法读取已配置的网关证书。'
    pin=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER |
        openssl dgst -sha256 -binary | openssl base64 -A) || fail '无法计算网关公钥指纹。'
    printf '%s\n' "$pin"
    exit 0
fi
domain='' port='' family=auto cert='' key='' email=''
accept_terms=false reconfigure=false upgrade=false update_mss=false
while (($#)); do
    case "$1" in
        --domain|--port|--cert|--key|--email)
            [[ -n "${2:-}" && "$2" != --* ]] || fail "$1 缺少参数。"
            case "$1" in
                --domain) domain=$2 ;;
                --port) port=$2 ;;
                --cert) cert=$2 ;;
                --key) key=$2 ;;
                --email) email=$2 ;;
            esac
            shift 2 ;;
        --help) printf '%s\n' 'setup-gateway.sh [--domain HOST] [--accept-terms] [--email EMAIL] [--port PORT] [--cert PATH --key PATH] [--ipv6|--ipv4-only] [--reconfigure|--upgrade] [--update-mss] 或 --show-pin'; exit 0 ;;
        --accept-terms) accept_terms=true; shift ;;
        --ipv6) family=6; shift ;;
        --ipv4-only) family=4; shift ;;
        --upgrade) upgrade=true; shift ;;
        --update-mss) update_mss=true; shift ;;
        --reconfigure) reconfigure=true; shift ;;
        *) fail "未知选项 $1，请查看 --help。" ;;
    esac
done
if "$upgrade" && "$reconfigure"; then fail '--upgrade 和 --reconfigure 不能同时使用。'; fi
if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || fail '端口必须是数字。'
    port=$((10#$port))
    (( port >= 1 && port <= 65535 )) || fail '端口必须在 1 到 65535 之间。'
fi
((EUID == 0)) || fail '请使用 sudo bash 运行安装器。'
[[ -d /run/systemd/system && -c /dev/net/tun ]] || fail '需要已启动 systemd 并启用 /dev/net/tun 的 Linux VPS。'
command -v apt-get >/dev/null || fail '此安装器支持 Debian 和 Ubuntu。'
installer_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
printf '%s\n' 'Cuven IP 网关安装与启动'
if [[ -f /etc/cuven-gateway/install-version ]] && ! "$reconfigure"; then
    exec 9>/run/lock/cuven-gateway-install.lock
    flock -n 9 || fail '另一个网关安装进程正在运行。'
    source "$installer_dir/gateway-preflight.sh"
    recover_gateway_installation
    unit=/etc/systemd/system/cuven-gateway.service
    current_cert=$(sed -n 's/^LoadCredential=certificate://p' "$unit")
    current_key=$(sed -n 's/^LoadCredential=private-key://p' "$unit")
    changed() { fail '更改已有网关参数时请加 --reconfigure。'; }
    if [[ -n "$cert" || -n "$key" ]]; then
        [[ "$cert" == "$current_cert" && "$key" == "$current_key" ]] || changed
    fi
    if [[ -n "$port" ]]; then
        grep -Eq "^ExecStart=.* -listen :$port([[:space:]]|$)" "$unit" || changed
    fi
    if [[ "$family" != auto ]]; then
        expected_ipv6=false
        if [[ "$family" == 6 ]]; then expected_ipv6=true; fi
        grep -Eq "^ExecStart=.* -ipv6=$expected_ipv6([[:space:]]|$)" "$unit" || changed
    fi
    bash "$installer_dir/check-certificate-dates.sh" "$current_cert"
    if [[ -z "$domain" && -f /etc/cuven-gateway/gateway-name ]]; then
        IFS= read -r domain </etc/cuven-gateway/gateway-name
        [[ -n "$domain" ]] || fail '已保存的网关名称为空，请显式指定 --domain。'
    fi
    gateway_check -check-tls -tls-cert "$current_cert" -tls-key "$current_key" -tls-name "$domain"
    bash "$installer_dir/install-certbot-hook.sh" "$current_cert" "$current_key"
    if "$update_mss" && ! command -v python3 >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
    fi
    if "$upgrade"; then bash "$installer_dir/upgrade-gateway.sh" "$current_cert" "$current_key"; fi
    systemctl enable --now cuven-gateway.service
    systemctl is-active cuven-gateway.service
    if "$update_mss"; then python3 "$installer_dir/update-gateway-mss.py"; fi
    hook=/etc/letsencrypt/renewal-hooks/deploy/50-cuven-gateway
    if [[ -f /etc/cuven-gateway/.certbot-reload-pending && -x "$hook" &&
          "$current_cert" == /etc/letsencrypt/live/*/fullchain.pem ]] &&
          grep -Fxq '# Managed by Cuven gateway.' "$hook"; then
        RENEWED_LINEAGE="${current_cert%/fullchain.pem}" "$hook" --retry
    fi
    printf '%s\n' '已有配置已启用，接入令牌保存在 /etc/cuven-gateway/token。'
    exit 0
fi
if [[ -z "$domain" ]]; then domain=$(ask '请输入指向本机的网关域名'); fi
if [[ "$domain" == *:* ]]; then
    [[ "$domain" =~ ^[0-9a-fA-F:.]+$ && -n "$cert" && -n "$key" ]] || fail '使用 IPv6 网关地址时请提供包含该 IP 的证书和私钥。'
else
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && "$domain" == *.* ]] || fail '域名格式无效。'
fi
port=${port:-4433}
if [[ -n "$cert" || -n "$key" ]]; then
    [[ -r "$cert" && -r "$key" ]] || fail '--cert 和 --key 需要同时指定可读文件。'
else
    live="/etc/letsencrypt/live/$domain"
    cert="$live/fullchain.pem"
    key="$live/privkey.pem"
    if [[ ! -r "$cert" || ! -r "$key" ]]; then
        printf '%s\n' '将使用 HTTP-01 签发证书。网关域名应指向本机，公网 TCP 80 须可用，域名会进入公开证书透明度日志。'
        if ! "$accept_terms"; then
            agree=$(ask "同意 Let's Encrypt 服务条款（https://letsencrypt.org/repository/）并申请证书？[y/N]")
            [[ "$agree" =~ ^([yY]|[yY][eE][sS]|是)$ ]] || fail '已取消证书申请。'
        fi
        contact=(--register-unsafely-without-email)
        if [[ -n "$email" ]]; then contact=(--email "$email"); fi
        if ! command -v certbot >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
        fi
        certbot certonly --standalone --non-interactive --agree-tos "${contact[@]}" \
            --cert-name "$domain" -d "$domain"
        if systemctl cat certbot.timer >/dev/null 2>&1; then
            systemctl enable --now certbot.timer
        fi
    fi
fi
args=(--domain "$domain" --port "$port" --cert "$cert" --key "$key")
if [[ "$family" == auto ]]; then
    if ! command -v ip >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2
    fi
    route=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null || true)
    if [[ "$route" =~ [[:space:]]src[[:space:]][23][[:xdigit:]]{3}: ]]; then family=6; else family=4; fi
fi
if [[ "$family" == 6 ]]; then args+=(--ipv6); fi
printf '正在安装 %s，UDP %s，IPv%s 出口。\n' "$domain" "$port" "$family"
bash "$installer_dir/install-gateway.sh" "${args[@]}"
systemctl is-active --quiet cuven-gateway.service || fail '服务尚未就绪。请查看 journalctl -u cuven-gateway。'
printf '客户端网关 %s，UDP %s。读取接入令牌请运行 sudo cat /etc/cuven-gateway/token。\n' "$domain" "$port"
