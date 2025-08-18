#!/usr/bin/env bash
# Description: Endpoint smoke test

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT_DIR"

BASE=
if [ -d libs/patched_quiche ]; then BASE=libs/patched_quiche
elif [ -d libs/vanilla_quiche ]; then BASE=libs/vanilla_quiche
else echo 'quiche sources not found under libs/'; exit 2
fi

CERT_DIR="$BASE/quiche/examples"
CERT="$CERT_DIR/cert.crt"
KEY="$CERT_DIR/cert.key"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Missing $CERT or $KEY. Run 'upstream-gen-certs.sh' first."
  exit 3
fi

cd "$BASE"
echo '[build] quiche_apps'
cargo build -p quiche_apps

SRV_LOG=$(mktemp)
CLIENT_DIR=$(mktemp -d)
WWW_DIR=$(mktemp -d)
echo 'hello quiche' > "$WWW_DIR/index.html"

echo "[server] starting (log: $SRV_LOG)"
target/debug/quiche-server --listen 127.0.0.1:4433 --root "$WWW_DIR" --cert "$CERT" --key "$KEY" --no-retry --max-active-cids 8 --disable-gso --disable-pacing > "$SRV_LOG" 2>&1 & SRV_PID=$!
sleep 1

echo '[client] GET /'
target/debug/quiche-client --no-verify --dump-responses "$CLIENT_DIR" https://127.0.0.1:4433/ || true

kill "$SRV_PID" >/dev/null 2>&1 || true

echo '[client] downloads:'
ls -l "$CLIENT_DIR" || true

echo '[server] last 10 lines:'
tail -n 10 "$SRV_LOG" || true
