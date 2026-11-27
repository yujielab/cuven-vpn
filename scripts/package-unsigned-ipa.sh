#!/usr/bin/env bash
# Package an unsigned iOS IPA from a Release Cuven.app.
# Usage: package-unsigned-ipa.sh [Cuven.app] [output.ipa]
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_path="${1:-$repo_dir/DerivedData/Build/Products/Release-iphoneos/Cuven.app}"
ipa_path="${2:-$repo_dir/build/Cuven-unsigned.ipa}"

app_path="${app_path%/}"
ipa_path="${ipa_path%/}"

if [[ ! -d "$app_path" ]]; then
    echo "App bundle not found: $app_path" >&2
    exit 1
fi
if [[ "$(basename "$app_path")" != "Cuven.app" ]]; then
    echo "Expected a Cuven.app bundle, got $(basename "$app_path")" >&2
    exit 1
fi
if [[ "$ipa_path" != *.ipa ]]; then
    echo "Output must use an .ipa suffix: $ipa_path" >&2
    exit 1
fi
if [[ -d "$ipa_path" ]]; then
    echo "IPA output is a directory: $ipa_path" >&2
    exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
    echo "zip is required to package the IPA." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to verify the IPA layout." >&2
    exit 1
fi

# macOS copyfile otherwise adds AppleDouble files beside bundle entries.
export COPYFILE_DISABLE=1
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1

stage=""
cleanup() {
    if [[ -n "$stage" && -d "$stage" ]]; then
        rm -rf "$stage"
    fi
}
trap cleanup EXIT
stage="$(mktemp -d "${TMPDIR:-/tmp}/cuven-ipa.XXXXXX")"

parent="$(cd "$(dirname "$app_path")" && pwd)"
app_path="$parent/$(basename "$app_path")"
payload_app="$stage/Payload/Cuven.app"
mkdir -p "$stage/Payload"

if command -v ditto >/dev/null 2>&1; then
    ditto --norsrc "$app_path" "$payload_app"
else
    cp -R "$app_path" "$payload_app"
fi

extension="$payload_app/PlugIns/CuvenTunnel.appex"
if [[ ! -d "$extension" || -L "$extension" ]]; then
    echo "Embedded packet tunnel not found at PlugIns/CuvenTunnel.appex" >&2
    exit 1
fi

profiles="$(find "$payload_app" -name 'embedded.mobileprovision' -print)"
if [[ -n "$profiles" ]]; then
    echo "Refusing to package a bundle that contains a provisioning profile:" >&2
    printf '%s\n' "$profiles" >&2
    exit 1
fi

require_regular() {
    local path="$1"
    local label="$2"
    if [[ -L "$path" || ! -f "$path" ]]; then
        echo "Missing $label: $path" >&2
        exit 1
    fi
    if [[ ! -s "$path" ]]; then
        echo "$label is empty: $path" >&2
        exit 1
    fi
}

require_regular "$payload_app/Info.plist" "app Info.plist"
require_regular "$payload_app/Cuven" "app executable"
require_regular "$extension/Info.plist" "tunnel Info.plist"
require_regular "$extension/CuvenTunnel" "tunnel executable"

if [[ ! -x "$payload_app/Cuven" ]]; then
    echo "App executable is not executable: $payload_app/Cuven" >&2
    exit 1
fi
if [[ ! -x "$extension/CuvenTunnel" ]]; then
    echo "Tunnel executable is not executable: $extension/CuvenTunnel" >&2
    exit 1
fi
if ! python3 -I -c 'import pathlib, sys; data = pathlib.Path(sys.argv[1]).read_bytes(); raise SystemExit(0 if b"com.apple.networkextension.packet-tunnel" in data else 1)' "$extension/Info.plist"; then
    echo "CuvenTunnel Info.plist does not declare a packet-tunnel provider" >&2
    exit 1
fi

# Drop Finder metadata from the staging copy. The source build product is left untouched.
find "$payload_app" \( -name .DS_Store -o -name '__MACOSX' -o -name '._*' \) -prune -exec rm -rf {} +

mkdir -p "$(dirname "$ipa_path")"
ipa_dir="$(cd "$(dirname "$ipa_path")" && pwd)"
ipa_path="$ipa_dir/$(basename "$ipa_path")"
case "$ipa_path" in
    "$stage"|"$stage"/*)
        echo "IPA output must be outside the staging directory: $ipa_path" >&2
        exit 1
        ;;
esac
rm -f "$ipa_path"

if ! (
    cd "$stage"
    zip -r -y -q -X "$ipa_path" Payload
); then
    rm -f "$ipa_path"
    exit 1
fi

if ! python3 -I - "$ipa_path" "$payload_app" <<'PY'
import os
import stat
import sys
import zipfile
from pathlib import Path

ipa_path = sys.argv[1]
app_root = Path(sys.argv[2])
prefix = "Payload/Cuven.app/"
executables = {
    "Cuven",
    "PlugIns/CuvenTunnel.appex/CuvenTunnel",
}
required = executables | {
    "Info.plist",
    "PlugIns/CuvenTunnel.appex/Info.plist",
}


def fail(message):
    raise SystemExit(message)


def collect(root: Path):
    files = {}
    dirs = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for dirname in dirnames:
            child = current / dirname
            rel = child.relative_to(root).as_posix()
            if child.is_symlink():
                files[rel] = ("symlink", os.readlink(child))
            else:
                kept.append(dirname)
                dirs.add(rel)
        dirnames[:] = kept
        for filename in filenames:
            child = current / filename
            rel = child.relative_to(root).as_posix()
            if child.is_symlink():
                files[rel] = ("symlink", os.readlink(child))
            elif child.is_file():
                files[rel] = ("file", child)
            else:
                fail(f"Unsupported file in app bundle: {rel}")
    return files, dirs


def chunks_equal(archive, info, path: Path) -> bool:
    with archive.open(info, "r") as zipped, path.open("rb") as disk:
        while True:
            left = zipped.read(1024 * 1024)
            right = disk.read(1024 * 1024)
            if left != right:
                return False
            if not left:
                return True


files, dirs = collect(app_root)
missing = sorted(required - set(files))
if missing:
    fail("App bundle is missing: " + ", ".join(missing))

with zipfile.ZipFile(ipa_path) as archive:
    corrupt = archive.testzip()
    if corrupt is not None:
        fail(f"Corrupt IPA entry: {corrupt}")

    seen_names = set()
    seen_files = set()
    seen_dirs = set()
    plist = None

    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        if name in seen_names:
            fail(f"Duplicate IPA entry: {name}")
        seen_names.add(name)
        parts = [part for part in name.split("/") if part]
        if name.startswith("/") or ".." in parts:
            fail(f"Unsafe IPA path: {name}")
        base = parts[-1] if parts else ""
        if (
            base in {".DS_Store", "__MACOSX"}
            or base.startswith("._")
            or name.endswith(".mobileprovision")
            or base == "embedded.mobileprovision"
        ):
            fail(f"IPA contains metadata that does not belong in an unsigned package: {name}")

        mode = info.external_attr >> 16
        is_dir = name.endswith("/") or stat.S_ISDIR(mode)
        if name in {"Payload/", "Payload/Cuven.app", "Payload/Cuven.app/"}:
            if not is_dir:
                fail(f"Expected a directory: {name}")
            continue
        if not name.startswith(prefix):
            fail(f"IPA entry is outside Payload/Cuven.app: {name}")

        rel = name[len(prefix):]
        if is_dir:
            rel = rel.rstrip("/")
            if rel not in dirs or (app_root / rel).is_symlink():
                fail(f"IPA directory does not match the app bundle: {name}")
            seen_dirs.add(rel)
            continue

        item = files.get(rel)
        if item is None:
            fail(f"IPA contains an unexpected entry: {name}")
        kind, payload = item
        if kind == "symlink":
            if not stat.S_ISLNK(mode):
                fail(f"IPA did not store a symlink: {name} (mode {mode:06o})")
            if archive.read(info) != os.fsencode(payload):
                fail(f"IPA symlink target changed: {name}")
        else:
            if not stat.S_ISREG(mode):
                fail(f"IPA entry is not a regular file: {name} (mode {mode:06o})")
            if not chunks_equal(archive, info, payload):
                fail(f"IPA content differs from the app bundle: {name}")
            if rel in executables and (mode & 0o111) == 0:
                fail(f"IPA executable is not marked executable: {name} (mode {mode:06o})")
        if rel == "PlugIns/CuvenTunnel.appex/Info.plist":
            plist = archive.read(info)
        seen_files.add(rel)

    missing_files = sorted(set(files) - seen_files)
    missing_dirs = sorted(dirs - seen_dirs)
    if missing_files or missing_dirs:
        detail = ", ".join(missing_files + [path + "/" for path in missing_dirs])
        fail("IPA is missing app bundle entries: " + detail)
    if plist is None or b"com.apple.networkextension.packet-tunnel" not in plist:
        fail("CuvenTunnel Info.plist does not declare a packet-tunnel provider")

print(f"Verified unsigned IPA layout ({len(seen_files)} files): {ipa_path}")
PY
then
    rm -f "$ipa_path"
    exit 1
fi

bytes="$(wc -c < "$ipa_path" | tr -d '[:space:]')"
echo "Wrote unsigned IPA ($bytes bytes): $ipa_path"
