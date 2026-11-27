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
    installed = None
    try:
        subprocess.run(["xcrun", "simctl", "install", device, str(app)], check=True, timeout=420)
        print(f"simctl install returned after {time.monotonic() - started:.1f}s", flush=True)
        # On a successful install the default simulator device set normally
        # contains one matching bundle. Avoid launching another slow simctl.
        containers = Path.home() / "Library/Developer/CoreSimulator/Devices" / device / "data/Containers/Bundle/Application"
        matches = []
        for candidate in containers.glob("*/*.app/Info.plist"):
            try:
                with candidate.open("rb") as info:
                    bundle_id = plistlib.load(info).get("CFBundleIdentifier")
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if bundle_id == identifier:
                matches.append(candidate.parent)
        if len(matches) == 1:
            installed = matches[0]
    except subprocess.TimeoutExpired:
        # CoreSimulator may finish installing before its command-line client returns.
        print("simctl install timed out. Checking the installed app and extension.", flush=True)
    if installed is None:
        path = subprocess.check_output(
            ["xcrun", "simctl", "get_app_container", device, identifier, "app"], text=True, timeout=120
        ).strip()
        if not path or not Path(path).is_dir():
            raise RuntimeError("CoreSimulator did not report an installed application")
        installed = Path(path)
    pairs = []
    for bundle in (Path("."), Path("PlugIns/CuvenTunnel.appex")):
        info = plistlib.loads((app / bundle / "Info.plist").read_bytes())
        executable = bundle / info["CFBundleExecutable"]
        pairs.append((app / executable, installed / executable))
    verify_binaries(pairs)
    print("Verified the installed app and Packet Tunnel against this build.", flush=True)


if __name__ == "__main__":
    install(os.environ["SIMULATOR_ID"], Path(sys.argv[1]))
