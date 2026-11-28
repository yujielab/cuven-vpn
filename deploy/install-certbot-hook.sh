#!/usr/bin/env bash
set -euo pipefail

# Custom certificates stay under their owner's renewal process.
cert=$1 key=$2
lineage=${cert%/fullchain.pem}
[[ "$cert" == "$lineage/fullchain.pem" && "$key" == "$lineage/privkey.pem" &&
   "$lineage" =~ ^/etc/letsencrypt/live/[a-zA-Z0-9._-]+$ ]] || exit 0
[[ -f "/etc/letsencrypt/renewal/${lineage##*/}.conf" ]] || exit 0

directory=/etc/letsencrypt/renewal-hooks/deploy
hook=$directory/50-cuven-gateway
validator=${directory%/*}/.cuven-enrollment-validator
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$directory"
stage=$(mktemp -d "${directory%/*}/.cuven-gateway.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
temporary=$stage/hook
cat > "$temporary" <<'HOOK'
#!/bin/sh
# Managed by Cuven gateway.
set -eu
unit=/etc/systemd/system/cuven-gateway.service
lineage=${RENEWED_LINEAGE:-}
matches_gateway() {
    [ -n "$lineage" ] && [ -f "$unit" ] &&
        grep -Fxq -- "LoadCredential=certificate:$lineage/fullchain.pem" "$unit" &&
        grep -Fxq -- "LoadCredential=private-key:$lineage/privkey.pem" "$unit"
}
matches_gateway || exit 0
lock=/run/lock/cuven-gateway-install.lock
# An installer retry inherits its existing, locked file description.
if ! [ /proc/self/fd/9 -ef "$lock" ]; then exec 9>"$lock"; fi
flock -x 9
# The service may have been reconfigured while this renewal was waiting.
matches_gateway || exit 0

# Earlier installers saved this hook in the Certbot lineage itself.
legacy='/bin/sh -c "if systemctl is-active --quiet cuven-gateway.service; then systemctl restart cuven-gateway.service; fi"'
if sed -n '/^\[renewalparams\]$/,/^\[/p' "/etc/letsencrypt/renewal/${lineage##*/}.conf" |
    grep -Fxq -e "renew_hook = '$legacy'" -e "renew_hook = $legacy"; then
    exit 0
fi
systemctl is-active --quiet cuven-gateway.service || exit 0
pending=/etc/cuven-gateway/.certbot-reload-pending
generation() { systemctl show cuven-gateway.service --property=InvocationID --value; }
if [ "${1:-}" = --retry ]; then
    [ -f "$pending" ] || exit 0
    current=$(generation)
    [ -n "$current" ] || exit 1
    if [ "$(cat "$pending")" != "$current $lineage" ]; then
        # A newer service invocation has already loaded its credentials.
        rm -f -- "$pending"
        exit 0
    fi
fi
validate_credentials() {
    validator=/etc/letsencrypt/renewal-hooks/.cuven-enrollment-validator
    "$validator" -check-token -token-file /etc/cuven-gateway/token || return 1
    name_file=/etc/cuven-gateway/gateway-name
    name=''
    if [ -e "$name_file" ] || [ -L "$name_file" ]; then
        if ! IFS= read -r name <"$name_file" || [ -z "$name" ]; then
            echo '无法读取已配置的网关证书名称。' >&2
            return 1
        fi
    fi
    "$validator" -check-tls -tls-cert "$lineage/fullchain.pem" -tls-key "$lineage/privkey.pem" -tls-name "$name"
}
if ! validate_credentials; then
    if current=$(generation) && [ -n "$current" ]; then
        record=$(mktemp /etc/cuven-gateway/.certbot-pending.XXXXXXXX)
        trap 'rm -f -- "$record"' EXIT
        printf '%s %s\n' "$current" "$lineage" > "$record"
        mv -fT -- "$record" "$pending"
    fi
    echo '续签证书尚未载入。请按上方错误修复网关凭据，然后重新运行网关安装器或此续签钩子。' >&2
    exit 1
fi
systemctl try-restart cuven-gateway.service
rm -f -- "$pending"
HOOK
if [[ -L "$hook" || ( -e "$hook" && ! -f "$hook" ) ]]; then
    echo "Unexpected file type at $hook" >&2
    exit 1
fi
if [[ -f "$hook" ]]; then
    grep -Fxq '# Managed by Cuven gateway.' "$hook" || { echo "Existing hook at $hook belongs to another installer" >&2; exit 1; }
fi
if [[ -L "$validator" || ( -e "$validator" && ! -f "$validator" ) ]]; then
    echo "Unexpected file type at $validator" >&2
    exit 1
fi

# Keep the parser accessible after a self-extracting installer removes its
# temporary directory. A legacy gateway can keep running its original binary.
candidate=${3:-}
if [[ -z "$candidate" ]]; then
    candidate="$repo/bin/cuven-gateway-$(uname -m)"
    if [[ ! -x "$candidate" ]]; then
        candidate=$stage/source-validator
        (cd "$repo/core" && go build -mod=readonly -trimpath -o "$candidate" ./cmd/cuven-gateway)
    fi
fi
[[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || { echo "无法安装接入令牌校验程序。" >&2; exit 1; }
if [[ ! -x "$validator" ]] || ! cmp -s -- "$candidate" "$validator"; then
    if ! ln -T -- "$candidate" "$stage/validator" 2>/dev/null; then
        install -m 0700 "$candidate" "$stage/validator"
    fi
    mv -fT -- "$stage/validator" "$validator"
fi
if [[ ! -x "$hook" ]] || ! cmp -s "$temporary" "$hook"; then
    chmod 0755 "$temporary"
    mv -fT -- "$temporary" "$hook"
fi
config="/etc/letsencrypt/renewal/${lineage##*/}.conf"
if grep -Fq 'systemctl restart cuven-gateway.service' "$config"; then
    python3 "$repo/deploy/migrate-certbot-hook.py" "$config"
fi
