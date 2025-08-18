#!/usr/bin/env bash
# Description: Generate fuzz seeds
# Purpose: Generate fuzz seeds using upstream quiche server/client and optionally minimize corpora

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT_DIR"

BASE=
if [ -d libs/patched_quiche ]; then BASE=libs/patched_quiche
elif [ -d libs/vanilla_quiche ]; then BASE=libs/vanilla_quiche
else echo 'quiche sources not found under libs/'; exit 2
fi

cd "$BASE"
if [ ! -d fuzz ]; then echo "fuzz/ dir not found under $BASE"; exit 3; fi

CLIENT_DIR=$(mktemp -d)
SERVER_DIR=$(mktemp -d)
cleanup() {
  echo 'Cleaning up...'
  rm -rf "$CLIENT_DIR" "$SERVER_DIR"
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo '[build] quiche_apps (features=fuzzing)'
cargo build --features fuzzing -p quiche_apps

echo '[server] starting...'
target/debug/quiche-server --cert fuzz/cert.crt --key fuzz/cert.key --dump-packets "$SERVER_DIR" & SRV_PID=$!
sleep 1

echo '[client] running...'
RUST_LOG=trace target/debug/quiche-client --no-verify https://127.0.0.1:4433 --dump-packets "$CLIENT_DIR" || true

mkdir -p fuzz/corpus/packet_recv_client fuzz/corpus/packet_recv_server
cat "$CLIENT_DIR"/*.pkt > fuzz/corpus/packet_recv_client/seed || true
cat "$SERVER_DIR"/*.pkt > fuzz/corpus/packet_recv_server/seed || true

if cargo +nightly -V >/dev/null 2>&1; then
  if cargo +nightly fuzz --help >/dev/null 2>&1; then
    echo '[minimize] packet_recv_client'
    cargo +nightly fuzz cmin -Oa packet_recv_client || true
    echo '[minimize] packet_recv_server'
    cargo +nightly fuzz cmin -Oa packet_recv_server || true
  else
    echo 'cargo-fuzz not installed. Install: cargo +nightly install cargo-fuzz'
  fi
else
  echo 'Rust nightly not available; skipping corpus minimization.'
fi

echo '[done] Seeds under fuzz/corpus/*'
