#!/usr/bin/env python3
"""Opt-in macOS/Apple Silicon smoke test using a diskless Alpine Linux VM.

Downloads an Alpine kernel/initramfs over HTTPS, builds a static guest client and
an ad-hoc-signed VZ launcher, then runs the real Go proxy. No existing VM, disk,
share, credential, approval store, or host network configuration is touched.
Only example.com and cache.nixos.org requests are automatically approved.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import platform
import struct
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.request


def pack(base, guest, ca, output):
    archive = bytearray()

    def entry(name, data, mode):
        encoded = name.encode() + b"\0"
        fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        archive.extend(b"070701" + b"".join(f"{v:08x}".encode() for v in fields))
        archive.extend(encoded)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))

    entry("init", Path(guest).read_bytes(), 0o100755)
    entry("etc/vzm-ca.pem", Path(ca).read_bytes(), 0o100644)
    entry("TRAILER!!!", b"", 0)
    Path(output).write_bytes(Path(base).read_bytes() + gzip.compress(archive))


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/vzm-network-smoke")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("requires Apple Silicon macOS with Virtualization.framework")
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    args.cache.mkdir(parents=True, exist_ok=True)
    for name in ["vmlinuz-virt", "initramfs-virt"]:
        path = args.cache / name
        if not path.exists():
            url = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot/" + name
            print("Downloading", url, flush=True)
            with urllib.request.urlopen(url, timeout=90) as response:
                path.write_bytes(response.read())
    # Alpine arm64 kernels can be EFI zboot images. VZ needs the raw Linux
    # Image, not the EFI decompressor. The zboot header describes its payload.
    kernel = (args.cache / "vmlinuz-virt").read_bytes()
    if kernel[4:8] == b"zimg":
        offset, size = struct.unpack_from("<II", kernel, 8)
        if kernel[24:28] != b"gzip":
            raise SystemExit("unsupported Alpine zboot compression")
        kernel = gzip.decompress(kernel[offset:offset + size])
    if kernel[56:60] != b"ARMd":
        raise SystemExit("not a raw arm64 Linux kernel")
    (args.cache / "Image").write_bytes(kernel)
    with tempfile.TemporaryDirectory(prefix="vzm-vz-", dir="/tmp") as temporary:
        work = Path(temporary)
        subprocess.run(["go", "build", "-o", str(work / "proxy"), "."], cwd=root / "proxy", check=True)
        env = dict(os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0")
        subprocess.run(["go", "build", "-o", str(work / "guest"), str(here / "guest.go")], cwd=root / "proxy", env=env, check=True)
        subprocess.run(["swiftc", "-parse-as-library", str(root / "vzm/Sources/Runtime/PrivateNetwork.swift"), str(here / "Boot.swift"), "-o", str(work / "boot")], check=True)
        subprocess.run(["codesign", "-s", "-", "-f", "--entitlements", str(root / "vzm/vzm.entitlements"), str(work / "boot")], check=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(work / "a.sock"))
        listener.listen()
        listener.settimeout(0.2)
        stopping = threading.Event()
        approvals = []
        activity = []

        def approve():
            while not stopping.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn, conn.makefile("rb") as stream:
                    request = json.loads(stream.readline())
                    if request["type"] == "NETWORK_ACTIVITY":
                        activity.append(request)
                        continue
                    approvals.append(request)
                    allowed = request["domain"] in ("example.com", "cache.nixos.org")
                    conn.sendall((json.dumps({"id": request["id"], "approved": allowed, "substitutions": {}}) + "\n").encode())

        thread = threading.Thread(target=approve, daemon=True)
        thread.start()
        try:
            result = subprocess.run([
                str(work / "boot"), str(args.cache / "Image"), str(args.cache / "initramfs-virt"),
                str(work / "guest"), str(work / "proxy"), str(work), sys.executable, str(here / "run.py"),
            ], capture_output=True, text=True, timeout=110)
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            print("Approval events:", [(r["type"], r["domain"]) for r in approvals])
            print("Activity batches:", len(activity))
            if result.returncode != 0 or "VZM NETWORK SMOKE PASS" not in result.stdout:
                raise SystemExit("Linux VM network smoke test FAILED")
            assert any(r["type"] == "CONNECT" for r in approvals)
            assert any(r["type"] == "REQUEST" for r in approvals)
            assert any(r["domain"] == "denied.example" for r in approvals)
            assert sum(r["uploadBytes"] for r in activity) > 0
            assert sum(r["downloadBytes"] for r in activity) > 0
            print("Linux VM network smoke test PASSED")
        finally:
            stopping.set()
            thread.join(timeout=2)
            listener.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--pack":
        pack(*sys.argv[2:])
    else:
        run()
