#!/bin/bash
# Utility: generate ECDSA P-256 keypair using openssl
# Produces private.pem and public.pem (PEM with public key) in current directory

set -euo pipefail

PRIV="private.pem"
PUB="public.pem"

if [[ -f "$PRIV" || -f "$PUB" ]]; then
  echo "Error: private.pem or public.pem already exists in current directory"
  exit 1
fi

# create private key
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV"
# public key
openssl ec -in "$PRIV" -pubout -out "$PUB"

echo "Generated $PRIV and $PUB"
