"""Install the current test build and verify both installed Mach-O UUIDs."""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time


def binary_uuid(binary):
    output = subprocess.check_output(["xcrun", "dwarfdump", "--uuid", str(binary)], text=True, timeout=20)
    values = set(re.findall(r"^UUID: ([0-9A-Fa-f-]{36}) \(([^)]+)\)", output, flags=re.M))
    if not values:
        raise RuntimeError(f"Missing Mach-O UUID for {binary.name}")
    return values


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
    for bundle in (Path("."), Path("PlugIns/CuvenTunnel.appex")):
        info = plistlib.loads((app / bundle / "Info.plist").read_bytes())
        executable = bundle / info["CFBundleExecutable"]
        if binary_uuid(app / executable) != binary_uuid(Path(path) / executable):
            raise RuntimeError(f"Simulator installed a different build of {executable.name}")
    print("Verified installed app and Packet Tunnel build UUIDs.", flush=True)


if __name__ == "__main__":
    install(os.environ["SIMULATOR_ID"], Path(sys.argv[1]))
