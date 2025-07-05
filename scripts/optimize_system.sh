#!/bin/bash
# System Optimization Script
set -e

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[OPTIMIZE]${NC} $1"
}

optimize_network() {
    log "Optimiere Netzwerkeinstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log "Bitte als root ausführen für volle Optimierungen"
        return
    fi
    
    # TCP Optimierungen
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.ipv4.tcp_fastopen=3
    
    # UDP Optimierungen
    sysctl -w net.core.netdev_max_backlog=100000
    sysctl -w net.core.somaxconn=65535
}

optimize_system() {
    log "Optimiere Systemeinstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log "Bitte als root ausführen für volle Optimierungen"
        return
    }
    
    # Dateideskriptoren
    ulimit -n 1048576
    sysctl -w fs.file-max=1048576
    
    # Speicherverwaltung
    sysctl -w vm.swappiness=10
    sysctl -w vm.vfs_cache_pressure=50
}

optimize_rust() {
    log "Optimiere Rust-Build-Einstellungen..."
    
    # Erstelle/überschreibe Cargo-Konfig
    mkdir -p ~/.cargo
    cat > ~/.cargo/config.toml << EOF
[build]
rustflags = [
    "-C", "opt-level=3",
    "-C", "target-cpu=native",
    "-C", "lto=thin",
    "-C", "codegen-units=1",
    "-C", "panic=abort",
]

[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+ssse3,+sse4.1,+sse4.2,+avx,+avx2,+fma",
]

[target.aarch64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+sha2,+crc,+lse",
]
EOF
}

main() {
    log "Starte Systemoptimierung..."
    
    optimize_rust
    
    if [ "$1" = "--full" ]; then
        optimize_network
        optimize_system
    else
        log "Führe nur grundlegende Optimierungen durch. Verwende --full für Systemoptimierungen (benötigt root)"
    fi
    
    log "Optimierung abgeschlossen!"
}

main "$@"
