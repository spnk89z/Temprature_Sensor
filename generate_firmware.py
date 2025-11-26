#!/usr/bin/env python3
"""
Simple firmware generator: creates a small binary file for testing/placeholder purposes.
Usage: python generate_firmware.py --version 1.2.0 --output firmware.bin
"""
import argparse
import datetime
import hashlib
import subprocess
import base64
import os


def build_firmware(output_file: str, version: str, size_kb: int = 4):
    # Create a small binary header with version and timestamp
    header = b"FIRMWAREv1\x00"
    version_bytes = version.encode("utf-8")[:16].ljust(16, b"\x00")
    timestamp = datetime.datetime.utcnow().isoformat().encode("utf-8")[:32].ljust(32, b"\x00")

    # Payload: simple pattern with version embedded
    payload = (b"\xAA\x55\x00\xFF" * (size_kb * 256))[: size_kb * 1024]
    # Put some readable info in the payload for debugging
    info = f"Version:{version};GeneratedUTC:{datetime.datetime.utcnow().isoformat()}".encode("utf-8")
    # Embed info near the beginning of payload
    payload = info.ljust(64, b"\x00") + payload[64:]

    content = header + version_bytes + timestamp + payload

    with open(output_file, "wb") as f:
        f.write(content)

    # compute sha256
    sha256 = hashlib.sha256(content).hexdigest()
    size = len(content)
    return sha256, size


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a firmware binary for testing")
    parser.add_argument("--version", type=str, default="0.0.1", help="Firmware semantic version")
    parser.add_argument("--output", type=str, default="firmware.bin", help="Output firmware filename")
    parser.add_argument("--size-kb", type=int, default=4, help="Size of the firmware binary in KB")
    parser.add_argument("--private-key", type=str, default=None, help="Optional path to an ECDSA P-256 private key PEM to sign the binary")

    args = parser.parse_args()
    sha256, size = build_firmware(args.output, args.version, args.size_kb)
    print(f"Generated {args.output} (size={size} bytes) sha256={sha256}")

    # Optionally sign if a private key is provided
    if args.private_key:
        sig_out = args.output + ".sig.der"
        # Use openssl to create ECDSA signature (DER)
        cmd = ["openssl", "dgst", "-sha256", "-sign", args.private_key, "-out", sig_out, args.output]
        subprocess.check_call(cmd)
        with open(sig_out, 'rb') as sf:
            b64 = base64.b64encode(sf.read()).decode('ascii')
        print(f"Signature (DER, base64): {b64}")
        # Keep signature file
        print(f"Signature written to {sig_out}")
