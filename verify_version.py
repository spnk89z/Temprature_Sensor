#!/usr/bin/env python3
import json
import hashlib
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest(), f.tell()


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--pub', default='scripts/public.pem', help='public key PEM file for signature verification')
    args = p.parse_args()
    with open('version.json', 'r') as vf:
        version = json.load(vf)
    f = version['filename']
    sha, size = sha256sum(f)
    print('Computed sha256:', sha)
    print('version.json sha256:', version['sha256'])
    print('size:', size, 'json size:', version['size'])
    match = sha == version ['sha256'] and size == version['size']
    print('MATCH:', match)
    if 'sig' in version and 'sig_algo' in version:
        print('Signature present, verifying...')
        sig_b64 = version['sig']
        sig = base64.b64decode(sig_b64)
        pubkey_pem = None
        try:
            with open(args.pub, 'rb') as pf:
                pubkey_pem = pf.read()
        except Exception:
            print('No scripts/public.pem found to verify signature. Please provide the public key at scripts/public.pem')
        if pubkey_pem:
            pubkey = load_pem_public_key(pubkey_pem)
            try:
                with open(version['filename'], 'rb') as f:
                    file_data = f.read()
                # compute digest and verify
                pubkey.verify(sig, file_data, ec.ECDSA(SHA256()))
                print('Signature OK')
            except InvalidSignature:
                print('INVALID SIGNATURE')
            except Exception as e:
                print('Signature verification failed:', e)
