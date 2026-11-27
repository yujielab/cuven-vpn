#!/usr/bin/env python3
"""Select an iOS simulator for CI, creating a device if the runtime has none."""

import json
import subprocess
import sys


def select(inventory, model, version):
    runtimes = [
        runtime for runtime in inventory["runtimes"]
        if runtime.get("isAvailable") and runtime.get("version") == version
        and runtime["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")
    ]
    types = {t["identifier"] for t in inventory["devicetypes"] if t["name"] == model}
    for runtime in runtimes:
        for device in inventory["devices"].get(runtime["identifier"], []):
            if device.get("isAvailable") and (
                device.get("deviceTypeIdentifier") in types or device["name"] == model
            ):
                return device["udid"]
    if not types or not runtimes:
        raise SystemExit(f"Missing {model} device type or available iOS {version} runtime "
                         f"(matching types: {sorted(types)}, runtimes: {[r['identifier'] for r in runtimes]})")
    for runtime in runtimes:
        for kind in sorted(types):
            made = subprocess.run(
                ["xcrun", "simctl", "create", model, kind, runtime["identifier"]],
                text=True, capture_output=True, timeout=60,
            )
            if made.returncode == 0 and made.stdout.strip():
                return made.stdout.strip()
            print(f"simctl create on {runtime['identifier']}: {made.stderr.strip()}", file=sys.stderr)
    raise SystemExit(f"Could not create {model} on iOS {version}")


if __name__ == "__main__":
    model, version = sys.argv[1:]
    inventory = json.loads(subprocess.check_output(["xcrun", "simctl", "list", "-j"]))
    print(select(inventory, model, version))
