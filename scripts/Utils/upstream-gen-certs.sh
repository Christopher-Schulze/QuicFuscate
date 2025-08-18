#!/usr/bin/env bash
# Description: Generate certificates

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT_DIR"

BASE=
if [ -d libs/patched_quiche ]; then BASE=libs/patched_quiche
elif [ -d libs/vanilla_quiche ]; then BASE=libs/vanilla_quiche
else echo 'quiche sources not found under libs/'; exit 2
fi

DIR="$BASE/quiche/examples"
if [ ! -d "$DIR" ]; then echo "examples dir not found: $DIR"; exit 3; fi
if ! command -v openssl >/dev/null 2>&1; then echo 'openssl not installed'; exit 4; fi

cd "$DIR"
openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
openssl req -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj '/C=GB/CN=quic.tech'
openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt
openssl verify -CAfile rootca.crt cert.crt
cp cert.crt cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
rm -f cert.csr rootca.srl

echo "[gen-certs] Wrote: $PWD/cert.crt $PWD/cert.key (and cert-big.crt); CA: $PWD/rootca.crt $PWD/rootca.key"
