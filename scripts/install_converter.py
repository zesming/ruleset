#!/usr/bin/env python3
"""Download a fixed official Mihomo asset; verify its archive before execution."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import platform
import urllib.request
from pathlib import Path

VERSION = "v1.19.17"
ASSETS = {
    "linux-amd64": (
        "mihomo-linux-amd64-v1-v1.19.17.gz",
        "6b682c9e6ba114581b7d803d64d2c0fe11188689e2f6bddfa091cc2267f0c8ca",
    ),
    "darwin-arm64": (
        "mihomo-darwin-arm64-v1.19.17.gz",
        "c5f87073ad6b5c904d3e70365a8ea6f6f6621b7145cffad9001162cafe1842ef",
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    system = platform.system().lower()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    name, digest = ASSETS[f"{system}-{machine}"]
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{name}"
    request = urllib.request.Request(url, headers={"User-Agent": "zesming-ruleset-converter/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        content = response.read(20 * 1024 * 1024 + 1)
    if hashlib.sha256(content).hexdigest() != digest:
        raise SystemExit("Official converter archive failed SHA-256 verification")
    binary = gzip.decompress(content)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(binary)
    args.output.chmod(0o700)
    print(f"Verified Mihomo {VERSION} for {system}-{machine}")


if __name__ == "__main__":
    main()
