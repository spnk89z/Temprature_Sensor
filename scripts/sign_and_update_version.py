#!/usr/bin/env python3
"""
Sign a compiled firmware binary, compute sha256, and update version.json

Usage: python3 scripts/sign_and_update_version.py --bin firmware_3.6.0-ULTIMUM.bin --version 3.6.0-ULTIMUM --key private.pem --json version.json

This updates version.json with fields: version, bin, filename, sha256, size, build_date (iso), sig (base64 signature)
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import datetime


def sha256_of_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            h.update(data)
    return h.hexdigest(), os.path.getsize(path)


def sign_with_openssl(bin_path, key_path, out_der):
    cmd = ["openssl", "dgst", "-sha256", "-sign", key_path, "-out", out_der, bin_path]
    subprocess.check_call(cmd)


def base64_of_file(file_path):
    with open(file_path, 'rb') as f:
        b = f.read()
    return base64.b64encode(b).decode('ascii')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--bin', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--key', required=True)
    p.add_argument('--json', required=True, default='version.json')
    p.add_argument('--raw-base-url', required=False, default=None, help='Base URL to raw file location if needed, e.g. https://raw.githubusercontent.com/owner/repo/main')
    args = p.parse_args()

    sha, size = sha256_of_file(args.bin)
    der = args.bin + '.sig.der'
    sign_with_openssl(args.bin, args.key, der)
    b64 = base64_of_file(der)

    # Build JSON and update file
    bin_filename = os.path.basename(args.bin)
    bin_url = bin_filename
    if args.raw_base_url:
        bin_url = args.raw_base_url.rstrip('/') + '/' + bin_filename

    out_doc = {
      'version': args.version,
      'bin': bin_url,
      'filename': bin_filename,
      'sha256': sha,
      'size': size,
      'build_date': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
      'sig': b64,
      'sig_algo': 'ECDSA-P256-SHA256'
    }

    with open(args.json, 'w') as f:
        json.dump(out_doc, f, indent=2)

    print(f"Updated {args.json}")
    print(out_doc)
