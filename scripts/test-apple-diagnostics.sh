#!/usr/bin/env bash
set -euo pipefail

# Exercise the shared model and Apple's error types on macOS without booting a simulator.
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/Sources/Cuven" "$stage/Tests/CuvenTests"
cp "$repo"/ios/Shared/*.swift "$repo"/ios/App/{DisconnectDiagnostic,TunnelRTTMeasurement,SavedTunnelProfile}.swift "$stage/Sources/Cuven/"
cp "$repo"/ios/Tests/{VPNProfileTests,DisconnectDiagnosticTests,TunnelRTTMeasurementTests,GatewayEndpointsTests,SavedTunnelProfileTests}.swift "$stage/Tests/CuvenTests/"
cat >"$stage/Package.swift" <<'SWIFT'
// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "Cuven",
    platforms: [.macOS(.v13)],
    targets: [.target(name: "Cuven"), .testTarget(name: "CuvenTests", dependencies: ["Cuven"])]
)
SWIFT
xcrun swift test --package-path "$stage"
