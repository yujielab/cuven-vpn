#!/usr/bin/env bash
set -euo pipefail

# This fixture writes to a fresh /etc mounted inside the disposable CI container.
[[ -f /.dockerenv && ! -e /etc/letsencrypt && ! -e /etc/systemd/system/cuven-gateway.service ]]
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
base=/etc/letsencrypt
lineage=$base/live/gateway.example
hook=$base/renewal-hooks/deploy/50-cuven-gateway
unit=/etc/systemd/system/cuven-gateway.service
config=$base/renewal/gateway.example.conf
mkdir -p "$base/renewal" /etc/systemd/system /tmp/cuven-bin
touch "$config" /tmp/cuven-active /tmp/cuven-restarts
cat > /tmp/cuven-bin/systemctl <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = try-restart ] && [ "$2" = cuven-gateway.service ] || exit 2
if [ -f /tmp/cuven-active ]; then echo restart >> /tmp/cuven-restarts; fi
SH
chmod +x /tmp/cuven-bin/systemctl
export PATH="/tmp/cuven-bin:$PATH"
bash "$src/deploy/install-certbot-hook.sh" /etc/custom.crt /etc/custom.key
test ! -e "$hook"
for pass in 1 2; do
    bash "$src/deploy/install-certbot-hook.sh" "$lineage/fullchain.pem" "$lineage/privkey.pem"
done
test -x "$hook"
printf 'LoadCredential=certificate:%s/fullchain.pem\nLoadCredential=private-key:%s/privkey.pem\n' "$lineage" "$lineage" > "$unit"
RENEWED_LINEAGE=$base/live/other.example "$hook"
test ! -s /tmp/cuven-restarts
RENEWED_LINEAGE=$lineage "$hook"
test "$(wc -l < /tmp/cuven-restarts)" -eq 1
rm /tmp/cuven-active
RENEWED_LINEAGE=$lineage "$hook"
test "$(wc -l < /tmp/cuven-restarts)" -eq 1
touch /tmp/cuven-active
cat > "$config" <<'CONF'
[renewalparams]
renew_hook = '/bin/sh -c "if systemctl is-active --quiet cuven-gateway.service; then systemctl restart cuven-gateway.service; fi"'
CONF
RENEWED_LINEAGE=$lineage "$hook"
test "$(wc -l < /tmp/cuven-restarts)" -eq 1
echo 'Verified Certbot hook installation, lineage matching and legacy hook handoff.'
