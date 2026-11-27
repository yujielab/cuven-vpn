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


def install_on_device(device, app):
    command = ["xcrun", "simctl", "install", device, str(app)]
    deadline = time.monotonic() + 420
    for attempt in range(2):
        try:
            result = subprocess.run(command, stderr=subprocess.PIPE, text=True,
                                    timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # CoreSimulator can finish installing before its client returns.
            print("simctl install timed out. Checking the installed app and extension.", flush=True)
            return False
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="", flush=True)
        if result.returncode == 0:
            return True
        if (attempt or "domain=com.apple.CoreSimulator.SimError, code=405" not in result.stderr
                or "current state: Shutdown" not in result.stderr):
            result.check_returncode()
        print("The selected simulator shut down after boot. Booting the same device and retrying installation.", flush=True)
        subprocess.run(["xcrun", "simctl", "bootstatus", device, "-b"], check=True,
                       timeout=min(180, max(0, deadline - time.monotonic())))


def install(device, app):
    identifier = plistlib.loads((app / "Info.plist").read_bytes())["CFBundleIdentifier"]
    started = time.monotonic()
    installed = None
    if install_on_device(device, app):
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
