"""Install the current test build and verify both installed Mach-O UUIDs."""
import filecmp
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time


def verify_binaries(pairs):
    # Simulator installations normally contain exact copies. Only a re-signed
    # or thinned executable needs Apple's slower debug-tool inspection.
    changed = [(source, target) for source, target in pairs if not filecmp.cmp(source, target, shallow=False)]
    if not changed:
        return
    paths = [path.resolve() for pair in changed for path in pair]
    output = subprocess.check_output(["xcrun", "dwarfdump", "--uuid", *map(str, paths)], text=True, timeout=100)
    uuids = {path: set() for path in paths}
    for value, arch, filename in re.findall(r"^UUID: ([0-9A-Fa-f-]{36}) \(([^)]+)\) (.+)$", output, flags=re.M):
        if Path(filename) in uuids:
            uuids[Path(filename)].add((value.lower(), arch))
    for source, target in changed:
        built = uuids[source.resolve()]
        installed = uuids[target.resolve()]
        if not installed or not installed.issubset(built):
            raise RuntimeError(f"Simulator installed a different build of {source.name}")


def install(device, app):
    identifier = plistlib.loads((app / "Info.plist").read_bytes())["CFBundleIdentifier"]
    started = time.monotonic()
    try:
        subprocess.run(["xcrun", "simctl", "install", device, str(app)], check=True, timeout=420)
        print(f"simctl install returned after {time.monotonic() - started:.1f}s", flush=True)
    except subprocess.TimeoutExpired:
        # CoreSimulator may finish installing before its command-line client returns.
        print("simctl install timed out. Checking the installed app and extension.", flush=True)
    path = subprocess.check_output(
        ["xcrun", "simctl", "get_app_container", device, identifier, "app"], text=True, timeout=45
    ).strip()
    if not path or not Path(path).is_dir():
        raise RuntimeError("CoreSimulator did not report an installed application")
    pairs = []
    for bundle in (Path("."), Path("PlugIns/CuvenTunnel.appex")):
        info = plistlib.loads((app / bundle / "Info.plist").read_bytes())
        executable = bundle / info["CFBundleExecutable"]
        pairs.append((app / executable, Path(path) / executable))
    verify_binaries(pairs)
    print("Verified the installed app and Packet Tunnel against this build.", flush=True)


if __name__ == "__main__":
    install(os.environ["SIMULATOR_ID"], Path(sys.argv[1]))
