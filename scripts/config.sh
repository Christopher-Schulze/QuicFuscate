#!/bin/bash
# Zentrale Konfiguration für Quiche-Optimierungen

# Pfade
QUICHE_DIR="${QUICHE_DIR:-$(pwd)/libs/patched_quiche}
PROJECT_ROOT="$(pwd)"
LOG_DIR="${PROJECT_ROOT}/logs"
PATCH_DIR="${PROJECT_ROOT}/patches"
BENCH_DIR="${PROJECT_ROOT}/benchmarks"
PGO_DIR="${PROJECT_ROOT}/target/pgo"

# Build-Einstellungen
OPTIMIZATION_LEVEL=3
LTO_MODE="fat"  # fat, thin oder off
CODEGEN_UNITS=1
PANIC_STRATEGY="abort"  # oder "unwind"

# CPU-Architektur
CPU_ARCH="$(uname -m)"
case "$CPU_ARCH" in
    x86_64)
        CPU_FEATURES="+aes,+ssse3,+sse4.1,+sse4.2,+avx,+avx2,+fma,+bmi2"
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        CPU_FEATURES="+aes,+sha2,+crc,+lse"
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    *)
        CPU_FEATURES=""
        TARGET=""
        ;;
esac

# Features
ENABLE_PGO=true
ENABLE_LTO=true
ENABLE_ASSEMBLY=true
ENABLE_HARDENING=true

# Netzwerkoptimierungen
NET_TCP_RMEM="4096 87380 16777216"
NET_TCP_WMEM="4096 65536 16777216"
NET_TCP_RMEM_MAX=16777216
NET_TCP_WMEM_MAX=16777216
NET_CORE_SOMAXCONN=65535

# Logging
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
LOG_FILE="${LOG_DIR}/quiche_optimize_$(date +%Y%m%d_%H%M%S).log"

# Sicherheit
SECURITY_CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
SECURITY_LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack"

# Exportiere alle Variablen
export QUICHE_DIR PROJECT_ROOT LOG_DIR PATCH_DIR BENCH_DIR PGO_DIR
export OPTIMIZATION_LEVEL LTO_MODE CODEGEN_UNITS PANIC_STRATEGY
export CPU_ARCH CPU_FEATURES TARGET
export ENABLE_PGO ENABLE_LTO ENABLE_ASSEMBLY ENABLE_HARDENING
export NET_TCP_RMEM NET_TCP_WMEM NET_TCP_RMEM_MAX NET_TCP_WMEM_MAX NET_CORE_SOMAXCONN

# Erstelle Verzeichnisse
mkdir -p "$LOG_DIR" "$PATCH_DIR" "$BENCH_DIR" "$PGO_DIR"
