#!/bin/bash

# optimize_quiche.sh - Optimiert die quiche-Bibliothek für QuicFuscate

set -e

# Farben für die Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Basisverzeichnisse
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
QUICHE_DIR="${BASE_DIR}/libs/patched_quiche/quiche"
LOG_FILE="${BASE_DIR}/logs/quiche_optimization.log"

# Logging-Funktion
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "info") echo -e "[${timestamp}] [INFO] ${message}" | tee -a "$LOG_FILE" ;;
        "warn") echo -e "${YELLOW}[${timestamp}] [WARN] ${message}${NC}" | tee -a "$LOG_FILE" ;;
        "error") echo -e "${RED}[${timestamp}] [ERROR] ${message}${NC}" | tee -a "$LOG_FILE" ;;
        "success") echo -e "${GREEN}[${timestamp}] [SUCCESS] ${message}${NC}" | tee -a "$LOG_FILE" ;;
        *) echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE" ;;
    esac
}

# Überprüfen der Voraussetzungen
check_requirements() {
    log "info" "Überprüfe Voraussetzungen..."
    
    # Prüfe, ob Rust installiert ist
    if ! command -v rustc &> /dev/null; then
        log "error" "Rust ist nicht installiert. Bitte installieren Sie Rust zuerst."
        exit 1
    fi
    
    # Prüfe Rust-Version
    RUST_VERSION=$(rustc --version | awk '{print $2}')
    if [[ "$(printf '%s\n' "1.82.0" "$RUST_VERSION" | sort -V | head -n1)" != "1.82.0" ]]; then
        log "warn" "Die Rust-Version $RUST_VERSION ist älter als die empfohlene Version 1.82.0"
    else
        log "info" "Rust-Version: $RUST_VERSION (OK)"
    fi
    
    # Weitere Voraussetzungen prüfen
    for cmd in cargo cmake perl; do
        if ! command -v $cmd &> /dev/null; then
            log "error" "$cmd ist nicht installiert. Bitte installieren Sie $cmd."
            exit 1
        fi
    done
}

# Bereinigung der quiche-Bibliothek
clean_quiche() {
    log "info" "Bereinige quiche-Bibliothek..."
    
    # Lösche Build- und Target-Verzeichnisse
    cd "$QUICHE_DIR"
    cargo clean
    
    # Entferne nicht benötigte Dateien
    rm -rf target
    
    log "success" "Bereinigung abgeschlossen."
}

# Optimierung der Build-Konfiguration
optimize_build() {
    log "info" "Optimiere Build-Konfiguration..."
    
    cd "$QUICHE_DIR"
    
    # Aktualisiere Cargo.lock
    cargo update
    
    # Führe einen optimierten Build durch
    RUSTFLAGS='-C target-cpu=native -C opt-level=3' \
    cargo build --release --features "boringssl-vendored"
    
    log "success" "Build-Optimierung abgeschlossen."
}

# Hauptfunktion
main() {
    # Log-Verzeichnis erstellen
    mkdir -p "$(dirname "$LOG_FILE")"
    
    log "info" "Starte Optimierung der quiche-Bibliothek für QuicFuscate"
    log "info" "Log-Datei: $LOG_FILE"
    
    # Voraussetzungen prüfen
    check_requirements
    
    # Bereinigung durchführen
    clean_quiche
    
    # Build optimieren
    optimize_build
    
    log "success" "Optimierung der quiche-Bibliothek erfolgreich abgeschlossen!"
}

# Hauptprogramm ausführen
main "$@"
