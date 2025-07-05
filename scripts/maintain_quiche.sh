#!/bin/bash
# Wartungsskript für die Quiche-Integration in QuicFuscate

set -euo pipefail

# Farben für die Ausgabe
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Pfade
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICHE_DIR="${SCRIPT_DIR}/../libs/patched_quiche"
PATCH_DIR="${SCRIPT_DIR}/../libs/patches"

# Hilfsfunktionen
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Prüft, ob ein Befehl verfügbar ist
check_command() {
    if ! command -v "$1" &> /dev/null; then
        error "Befehl nicht gefunden: $1"
    fi
}

# Aktualisiert das quiche-Repository
update_quiche() {
    log "Aktualisiere quiche-Repository..."
    
    if [ ! -d "$QUICHE_DIR/.git" ]; then
        error "Quiche-Repository nicht gefunden unter $QUICHE_DIR"
    fi
    
    pushd "$QUICHE_DIR" > /dev/null
    
    # Hole die neuesten Änderungen
    git fetch origin
    
    # Zeige aktuelle Version
    CURRENT_COMMIT=$(git rev-parse --short HEAD)
    LATEST_COMMIT=$(git rev-parse --short origin/HEAD)
    
    if [ "$CURRENT_COMMIT" = "$LATEST_COMMIT" ]; then
        log "Quiche ist bereits auf dem neuesten Stand (Commit: $CURRENT_COMMIT)"
    else
        log "Aktualisiere quiche von $CURRENT_COMMIT auf $LATEST_COMMIT..."
        git checkout main
        git pull origin main
    fi
    
    popd > /dev/null
}

# Wendet lokale Patches an
apply_patches() {
    log "Wende lokale Patches an..."
    
    if [ ! -d "$PATCH_DIR" ]; then
        warn "Kein patches-Verzeichnis gefunden. Überspringe Patches."
        return 0
    fi
    
    local patch_count=0
    
    pushd "$QUICHE_DIR" > /dev/null
    
    # Zähle und wende Patches an
    for patch_file in "$PATCH_DIR"/*.patch; do
        if [ -f "$patch_file" ]; then
            log "Wende Patch an: $(basename "$patch_file")"
            if ! git apply --check "$patch_file" 2>/dev/null; then
                warn "Patch kann nicht angewendet werden: $(basename "$patch_file")"
                continue
            fi
            git apply "$patch_file"
            patch_count=$((patch_count + 1))
        fi
    done
    
    popd > /dev/null
    
    log "$patch_count Patches erfolgreich angewendet."
}

# Führt einen sauberen Build durch
clean_build() {
    log "Starte sauberen Build..."
    
    pushd "$QUICHE_DIR" > /dev/null
    
    # Bereinige vor dem Build
    cargo clean
    
    # Baue mit optimierten Einstellungen
    RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=thin -C codegen-units=1" \
    cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored"
    
    popd > /dev/null
}

# Zeigt die Hilfe an
show_help() {
    echo "Verwendung: $0 [BEFEHL]"
    echo ""
    echo "Befehle:"
    echo "  update     Aktualisiert das quiche-Repository"
    echo "  patch      Wendet lokale Patches an"
    echo "  build      Führt einen sauberen Build durch"
    echo "  all        Führt alle Schritte aus (update, patch, build)"
    echo "  help       Zeigt diese Hilfe an"
    echo ""
    echo "Beispiele:"
    echo "  $0 update     # Nur aktualisieren"
    echo "  $0 all        # Kompletter Update- und Build-Vorgang"
}

# Hauptfunktion
main() {
    # Prüfe Voraussetzungen
    check_command git
    check_command cargo
    
    # Verarbeite Befehlszeilenargumente
    local command="${1:-help}"
    
    case "$command" in
        update)
            update_quiche
            ;;
        patch)
            apply_patches
            ;;
        build)
            clean_build
            ;;
        all)
            update_quiche
            apply_patches
            clean_build
            ;;
        help|--help|-h|*)
            show_help
            ;;
    esac
}

# Starte Skript
main "$@"
