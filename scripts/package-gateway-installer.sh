#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?Specify the output .sh file}
stage=$(mktemp -d)
bundle=$(mktemp -- "${output}.XXXXXX")
trap 'rm -rf -- "$stage"; rm -f -- "$bundle"' EXIT
mkdir -p "$stage/bin" "$stage/deploy"
cp "$repo/deploy/"{setup-gateway,install-gateway,install-certbot-hook,check-certificate-dates}.sh "$stage/deploy/"
for arch in amd64 arm64; do
    case "$arch" in amd64) machine=x86_64 ;; arm64) machine=aarch64 ;; esac
    (cd "$repo/core" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build \
        -buildvcs=false -mod=readonly -trimpath -ldflags='-s -w' -o "$stage/bin/cuven-gateway-$machine" ./cmd/cuven-gateway)
done
tar -czf "$stage/payload" -C "$stage" bin deploy
digest=$(sha256sum "$stage/payload")
write_bundle() {
    cat <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --help ]]; then
    cat <<'HELP'
sudo bash cuven-vps-install.sh
sudo bash cuven-vps-install.sh --domain vpn.example.com --accept-terms
Debian / Ubuntu，x86_64 和 aarch64。默认 UDP 4433，自动检测 IPv6。
--accept-terms 同意 Let's Encrypt 服务条款并授权签发证书（https://letsencrypt.org/repository/）。
--email EMAIL 可选 ACME 联系邮箱。--cert PATH --key PATH 使用已有证书。
--port PORT、--ipv6 或 --ipv4-only 可覆盖网络默认值。
已有安装默认沿用当前配置并启动。--reconfigure 按所给参数重建服务及防火墙，替换原有来源限制和模型设置。
HELP
    exit 0
fi
case "$(uname -sm)" in 'Linux x86_64'|'Linux aarch64') ;; *) echo '此安装器支持 Linux x86_64 和 aarch64。' >&2; exit 1 ;; esac
((EUID == 0)) || exec sudo -- bash "$0" "$@"
umask 077
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
line=$(LC_ALL=C awk '/^__CUVEN_ARCHIVE__$/ {print NR+1; exit}' "$0")
tail -n +"$line" -- "$0" > "$stage/payload"
LAUNCHER
# $stage is evaluated on the VPS by the generated launcher.
# shellcheck disable=SC2016
    printf '(cd "$stage" && echo "%s  payload" | sha256sum -c --status) || { echo "安装包校验失败。" >&2; exit 1; }\n' "${digest%% *}"
    cat <<'LAUNCHER'
tar -xzf "$stage/payload" -C "$stage"
bash "$stage/deploy/setup-gateway.sh" "$@"
exit 0
__CUVEN_ARCHIVE__
LAUNCHER
    cat "$stage/payload"
}
write_bundle > "$bundle"
chmod 0755 "$bundle"
mv -f -- "$bundle" "$output"
