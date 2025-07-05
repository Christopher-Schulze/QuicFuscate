#!/bin/bash
# Quiche Optimize Master Script
set -e

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Hilfsfunktionen
log() {
    echo -e "${GREEN}[QUICHE-OPTIMIZE]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Überprüfe Voraussetzungen
check_requirements() {
    log "Prüfe Voraussetzungen..."
    
    # Notwendige Tools
    local required=("cargo" "git" "make" "cmake" "cc" "ld")
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd ist nicht installiert!"
        fi
    done
    
    # Rust Version
    local rust_version=$(rustc --version | awk '{print $2}')
    if [[ ! "$rust_version" =~ ^1\.(6[0-9]|[7-9][0-9])\..*$ ]]; then
        log "Warnung: Nicht getestete Rust-Version: $rust_version (empfohlen: 1.60+)"
    fi
}

# Führe alle Optimierungsschritte aus
run_optimizations() {
    local full_optimize=$1
    
    log "Starte Quiche-Optimierung..."
    
    # 1. Aktualisiere Abhängigkeiten
    log "Schritt 1/6: Aktualisiere Abhängigkeiten..."
    ./scripts/update_deps.sh
    
    # 2. Konfiguriere Quiche
    log "Schritt 2/6: Konfiguriere Quiche..."
    ./scripts/configure_quiche.sh
    
    # 3. Wende Patches an
    log "Schritt 3/6: Wende Patches an..."
    ./scripts/manage_patches.sh apply
    
    # 4. Optimiere System (nur mit --full)
    if [ "$full_optimize" = "--full" ]; then
        log "Schritt 4/6: Optimiere System... (benötigt root)"
        sudo ./scripts/optimize_system.sh --full || 
            log "Systemoptimierung fehlgeschlagen, fahre fort..."
    else
        log "Schritt 4/6: Systemoptimierung übersprungen (verwende --full für volle Optimierung)"
        ./scripts/optimize_system.sh
    fi
    
    # 5. Baue optimierte Version
    log "Schritt 5/6: Baue optimierte Version..."
    (
        cd libs/patched_quiche/quiche
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=thin -C codegen-units=1"
        cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored"
    )
    
    # 6. Führe Benchmarks aus
    log "Schritt 6/6: Führe Benchmarks aus..."
    ./scripts/benchmark.sh
    
    log "Optimierung abgeschlossen!"
}

# Hauptfunktion
main() {
    local full_optimize=""
    
    # Parameter auswerten
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                full_optimize="--full"
                shift
                ;;
            *)
                error "Unbekannter Parameter: $1"
                ;;
        esac
    done
    
    check_requirements
    run_optimizations "$full_optimize"
}

# Starte Skript
main "$@"
