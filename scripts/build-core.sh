#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$(uname -s)" != Darwin ]]; then
    echo "Building CuvenCore.xcframework requires macOS with Xcode." >&2
    exit 1
fi

if ! command -v go >/dev/null || ! go env GOVERSION >/dev/null; then
    echo "Install the Go toolchain declared in core/go.mod." >&2
    exit 1
fi

if ! xcrun --sdk iphoneos --show-sdk-path >/dev/null ||
   ! xcrun --sdk iphonesimulator --show-sdk-path >/dev/null; then
    echo "Select an Xcode installation that includes the iOS and simulator SDKs." >&2
    exit 1
fi

vendor_dir="$repo_dir/Vendor"
mkdir -p "$vendor_dir"
build_dir="$(mktemp -d "$vendor_dir/.cuven-build.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

export GOBIN="$build_dir/bin"
export PATH="$GOBIN:$PATH"

cd "$repo_dir/core"
go install -mod=readonly golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
gomobile bind -target=ios,iossimulator -iosversion=17.0 -trimpath \
    -o "$build_dir/CuvenCore.xcframework" ./mobile

framework="$vendor_dir/CuvenCore.xcframework"
rm -rf "$framework"
mv "$build_dir/CuvenCore.xcframework" "$framework"
echo "Built $framework"
