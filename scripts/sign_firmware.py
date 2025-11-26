#!/usr/bin/env python3
"""
sign_firmware.py - Sign a firmware binary using ECDSA P-256 (SHA256)

This script requires openssl on PATH.

Usage:
  python3 scripts/sign_firmware.py --bin firmware.bin --key private.pem --out firmware.bin.sig
  python3 scripts/sign_firmware.py --bin firmware.bin --key private.pem --out-base64 # prints base64 to stdout

It produces a DER-encoded signature file and can output the Base64 signature (for insertion into version.json).

This script will also compute SHA256 and size to help update `version.json`.
"""
import argparse
import subprocess
import hashlib
import base64
import os
import sys


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            h.update(data)
    return h.hexdigest(), os.path.getsize(path)


def sign_with_openssl(bin_path, key_path, sig_path):
    # Create DER signature using openssl ECDSA signature (raw signature in ASN.1/DER)
    cmd = ["openssl", "dgst", "-sha256", "-sign", key_path, "-out", sig_path, bin_path]
    subprocess.check_call(cmd)


def base64_of_file(file_path):
    with open(file_path, 'rb') as f:
        b = f.read()
    return base64.b64encode(b).decode('ascii')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--bin', required=True, help='path to firmware binary')
    p.add_argument('--key', required=True, help='path to private key PEM')
    p.add_argument('--out', required=False, help='output signature file (DER)')
    p.add_argument('--out-base64', action='store_true', help='print base64 signature to stdout')
    args = p.parse_args()

    sha, size = sha256_of_file(args.bin)
    if args.out:
        sign_with_openssl(args.bin, args.key, args.out)
        print(f"Signed to {args.out}")
    else:
        # In-memory signing and printing to base64
        import tempfile
        tf = tempfile.NamedTemporaryFile(delete=False)
        tf.close()
        try:
            sign_with_openssl(args.bin, args.key, tf.name)
            print(base64_of_file(tf.name))
        finally:
            try:
                os.unlink(tf.name)
            except Exception:
                pass
    print(f"sha256={sha} size={size}")
