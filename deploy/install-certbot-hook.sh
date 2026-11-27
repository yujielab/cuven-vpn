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
mkdir -p "$directory"
temporary=$(mktemp "${directory%/*}/.cuven-gateway.XXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT
cat > "$temporary" <<'HOOK'
#!/bin/sh
# Managed by Cuven gateway.
set -eu
unit=/etc/systemd/system/cuven-gateway.service
lineage=${RENEWED_LINEAGE:-}
[ -n "$lineage" ] && [ -f "$unit" ] || exit 0
grep -Fxq -- "LoadCredential=certificate:$lineage/fullchain.pem" "$unit" || exit 0
grep -Fxq -- "LoadCredential=private-key:$lineage/privkey.pem" "$unit" || exit 0

# Earlier installers saved this hook in the Certbot lineage itself.
legacy='/bin/sh -c "if systemctl is-active --quiet cuven-gateway.service; then systemctl restart cuven-gateway.service; fi"'
if grep -Fxq -e "renew_hook = '$legacy'" -e "renew_hook = $legacy" "/etc/letsencrypt/renewal/${lineage##*/}.conf"; then
    exit 0
fi
exec systemctl try-restart cuven-gateway.service
HOOK
if [[ -L "$hook" || ( -e "$hook" && ! -f "$hook" ) ]]; then
    echo "Unexpected file type at $hook" >&2
    exit 1
fi
if [[ -f "$hook" ]]; then
    if cmp -s "$temporary" "$hook" && [[ -x "$hook" ]]; then exit 0; fi
    grep -Fxq '# Managed by Cuven gateway.' "$hook" || { echo "Existing hook at $hook belongs to another installer" >&2; exit 1; }
fi
chmod 0755 "$temporary"
mv -f -- "$temporary" "$hook"
