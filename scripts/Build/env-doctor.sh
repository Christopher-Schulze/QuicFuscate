#!/usr/bin/env bash
# Environment diagnostics and toolchain verification
# Description: Environment doctor
# Purpose: Show CPU/OS/Toolchain/time availability and QUICFUSCATE_* env

set -e

# Resolve repo root (this script lives at scripts/new/, so two levels up)
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT_DIR"

echo '=== Host Info ==='
uname -a || true
sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu 2>/dev/null || true

echo '=== Toolchain ==='
rustc -V || true
cargo -V || true
if command -v gtime >/dev/null 2>&1; then echo 'gtime: OK'; else echo 'gtime: missing'; fi
if /usr/bin/time -v true >/dev/null 2>&1; then echo '/usr/bin/time -v: OK'; else echo '/usr/bin/time -v: missing or unsupported'; fi

echo '=== Env (QUICFUSCATE_*) ==='
env | grep -E '^QUICFUSCATE_' || echo '(none)'
