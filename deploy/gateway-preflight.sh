#!/usr/bin/env bash
# Shared by the installed-gateway paths in both installer entry points.
gateway_check() {
    local repo binary
    repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    binary="$repo/bin/cuven-gateway-$(uname -m)"
    if [[ -x "$binary" ]]; then
        "$binary" "$@"
    else
        go -C "$repo/core" run -mod=readonly ./cmd/cuven-gateway "$@"
    fi
}

recover_gateway_installation() {
    local dir token=/etc/cuven-gateway/token
    dir=$(dirname -- "${BASH_SOURCE[0]}")
    [[ -f "$token" && -s "$token" ]] || fail '未找到原接入令牌或文件为空，请先恢复 /etc/cuven-gateway/token。'
    # Recovery can stop a working process whose token still exists in memory.
    # Verify that its successor can load the original credential first.
    gateway_check -check-token -token-file "$token"
    bash "$dir/gateway-config-rollback.sh" restore
    bash "$dir/upgrade-gateway.sh" --recover
}
