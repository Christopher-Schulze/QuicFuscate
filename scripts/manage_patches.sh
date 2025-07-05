#!/bin/bash
# Patch Management Script
set -e

# Konfiguration
TARGET_DIR="libs/patched_quiche"
PATCH_DIR="patches"

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Hilfsfunktionen
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Erstelle neuen Patch
create_patch() {
    local patch_name=$1
    if [ -z "$patch_name" ]; then
        error "Bitte geben Sie einen Patch-Namen an"
    fi
    
    log "Erstelle Patch: $patch_name"
    
    # Prüfe Änderungen
    if ! (cd "$TARGET_DIR" && git diff --quiet); then
        # Erstelle Patch
        mkdir -p "$PATCH_DIR"
        (cd "$TARGET_DIR" && git diff > "../${PATCH_DIR}/${patch_name}.patch")
        log "Patch erstellt: ${PATCH_DIR}/${patch_name}.patch"
    else
        error "Keine Änderungen zum Patchen gefunden"
    fi
}

# Wende alle Patches an
apply_all_patches() {
    log "Wende alle Patches an..."
    
    if [ -d "$PATCH_DIR" ]; then
        for patch in "${PATCH_DIR}"/*.patch; do
            if [ -f "$patch" ]; then
                log "Wende Patch an: $(basename "$patch")"
                (cd "$TARGET_DIR" && git apply --whitespace=nowarn "../$patch" || 
                 error "Fehler beim Anwenden von $patch")
            fi
        done
    else
        log "Kein Patch-Verzeichnis gefunden"
    fi
}

# Zeige Hilfe
show_help() {
    echo "Verwendung: $0 [BEFEHL] [OPTIONEN]"
    echo ""
    echo "Befehle:"
    echo "  create NAME    Erstellt einen neuen Patch mit dem angegebenen Namen"
    echo "  apply         Wendet alle verfügbaren Patches an"
    echo "  help          Zeigt diese Hilfe an"
    echo ""
    echo "Beispiele:"
    echo "  $0 create meine-aenderungen"
    echo "  $0 apply"
}

# Hauptfunktion
main() {
    local cmd=$1
    shift
    
    case $cmd in
        create)
            create_patch "$@"
            ;;
        apply)
            apply_all_patches
            ;;
        help|*)
            show_help
            ;;
    esac
}

# Starte Skript
main "$@"
