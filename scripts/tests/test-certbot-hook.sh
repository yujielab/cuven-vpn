#!/usr/bin/env bash
set -euo pipefail
umask 077

# All hook installation, credential and service paths must be private fixtures.
[[ $(findmnt -n -o FSTYPE /etc) == tmpfs && $(findmnt -n -o FSTYPE /tmp) == tmpfs ]]
[[ ! -e /etc/letsencrypt && ! -e /etc/systemd/system/cuven-gateway.service ]]
candidate=$(realpath "${1:?Specify the built gateway}")
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
base=/etc/letsencrypt
lineage=$base/live/gateway.example
hook=$base/renewal-hooks/deploy/50-cuven-gateway
unit=/etc/systemd/system/cuven-gateway.service
config=$base/renewal/gateway.example.conf
state=/etc/cuven-gateway
mkdir -p /run/lock "$base/renewal" /etc/systemd/system /tmp/cuven-bin "$state"
touch "$config" /tmp/cuven-active /tmp/cuven-restarts
printf '%s\n' first > /tmp/invocation
cat > /tmp/cuven-bin/systemctl <<'STUB'
#!/bin/sh
set -eu
case "$*" in
    "is-active --quiet cuven-gateway.service") test -f /tmp/cuven-active ;;
    "show cuven-gateway.service --property=InvocationID --value") cat /tmp/invocation ;;
    "try-restart cuven-gateway.service") if [ -f /tmp/cuven-active ]; then echo restart >> /tmp/cuven-restarts; fi ;;
    *) exit 2 ;;
esac
STUB
chmod +x /tmp/cuven-bin/systemctl
export PATH="/tmp/cuven-bin:$PATH"
installer=$src/deploy/install-certbot-hook.sh
bash "$installer" /etc/custom.crt /etc/custom.key "$candidate"
test ! -e "$hook"
apply() { bash "$installer" "$lineage/fullchain.pem" "$lineage/privkey.pem" "$candidate"; }
renew() { RENEWED_LINEAGE=$lineage "$hook" "$@"; }
count() { test "$(wc -l < /tmp/cuven-restarts)" -eq "$1"; }

apply
apply
test -x "$hook"
printf 'LoadCredential=certificate:%s/fullchain.pem\nLoadCredential=private-key:%s/privkey.pem\n' "$lineage" "$lineage" > "$unit"
(
    exec 8>/run/lock/cuven-gateway-install.lock
    flock -x 8
    RENEWED_LINEAGE=$base/live/other.example timeout 2 "$hook" 8>&-
)
count 0
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > /tmp/original-token
for damage in missing empty invalid mode; do
    case "$damage" in
        missing) rm -f "$state/token" ;;
        empty) : > "$state/token" ;;
        invalid) printf 'invalid-private-fixture' > "$state/token" ;;
        mode) install -m 0644 /tmp/original-token "$state/token" ;;
    esac
    if renew >/tmp/rejected 2>&1; then exit 1; fi
    grep -Fq "续签证书尚未载入" /tmp/rejected
    if grep -Fq 'invalid-private-fixture' /tmp/rejected; then exit 1; fi
    count 0
    test "$(cat "$state/.certbot-reload-pending")" = "first $lineage"
done
rm /tmp/cuven-active
renew
count 0
touch /tmp/cuven-active
install -m 0600 /tmp/original-token "$state/token"
renew --retry
count 1
test ! -e "$state/.certbot-reload-pending"
renew --retry
count 1
mv "$state/token" /tmp/saved-token
if renew >/dev/null 2>&1; then exit 1; fi
mv /tmp/saved-token "$state/token"
printf 'second\n' > /tmp/invocation
renew --retry
count 1
test ! -e "$state/.certbot-reload-pending"

# Preserve administrator-owned settings and comments when retiring our exact
# legacy restart command. An interrupted migration can safely be retried.
cat > "$config" <<'CONF'
# keep this comment
[renewalparams]
pre_hook = /opt/my-pre-hook
post_hook = /opt/my-post-hook
CONF
cp "$config" /tmp/expected.conf
cat >> "$config" <<'CONF'
renew_hook = '/bin/sh -c "if systemctl is-active --quiet cuven-gateway.service; then systemctl restart cuven-gateway.service; fi"'
CONF
chmod 0640 "$config"
python3 - "$installer" "$lineage" "$candidate" "$config" <<'PY'
import fcntl
from pathlib import Path
import subprocess
import sys
installer, lineage, candidate, path = sys.argv[1:]
p = Path(path)
data = p.read_bytes()
with (p.parent.parent / ".certbot.lock").open("w") as lock:
    fcntl.lockf(lock, fcntl.LOCK_EX)
    result = subprocess.run(["bash", installer, lineage + "/fullchain.pem", lineage + "/privkey.pem", candidate], capture_output=True)
    assert result.returncode and p.read_bytes() == data
PY
apply
cmp "$config" /tmp/expected.conf
test "$(stat -c %a "$config")" = 640
apply
renew
count 2
echo 'Verified that matching renewals preserve the live gateway on bad enrollment, load after repair, and migrate only the exact legacy hook.'
