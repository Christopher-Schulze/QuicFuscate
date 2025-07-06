#!/bin/bash
# Quiche Workflow Manager - Steuert den gesamten Quiche-Integrationsprozess

set -euo pipefail

# Farben für die Ausgabe
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Hilfsfunktionen
log() {
    echo -e "${BLUE}[QUICHE]${NC} $1"
}

success() {
    echo -e "${GREEN}[ERFOLG]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNUNG]${NC} $1"
}

error() {
    echo -e "${RED}[FEHLER]${NC} $1" >&2
    exit 1
}

# Konfiguration
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBS_DIR="$BASE_DIR/libs"
PATCHED_DIR="$LIBS_DIR/patched_quiche"
# Directory containing patch files (*.patch)
PATCHES_DIR="$LIBS_DIR/patches"
LOG_DIR="$LIBS_DIR/logs"
STATE_FILE="$BASE_DIR/.quiche_workflow_state"
BUILD_TYPE="release"
MIRROR_URL="https://github.com/cloudflare/quiche.git"

# Make quiche available to Cargo
export QUICHE_PATH="$PATCHED_DIR/quiche"

# Erstelle benötigte Verzeichnisse
mkdir -p "$LOG_DIR" "$PATCHES_DIR" "$PATCHED_DIR"

# Lade den aktuellen Status
load_state() {
    if [ -f "$STATE_FILE" ]; then
        . "$STATE_FILE"
    else
        # Standardwerte
        LAST_STEP="none"
        BUILD_TYPE="${BUILD_TYPE:-release}"
    fi
}

# Speichere den aktuellen Status
save_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    cat > "$STATE_FILE" << EOF
LAST_STEP="$1"
BUILD_TYPE="$BUILD_TYPE"
EOF
}

# Führe einen Befehl mit Logging aus
run_command() {
    local step_name="$1"
    local command_str="$2"
    local log_file="$LOG_DIR/${step_name}_$(date +%Y%m%d_%H%M%S).log"
    
    log "Starte: $step_name"
    log "Befehl: $command_str"
    log "Log-Ausgabe: $log_file"
    
    # Führe den Befehl aus und leite die Ausgabe um
    if eval "$command_str" 2>&1 | tee "$log_file"; then
        success "$step_name erfolgreich abgeschlossen"
        return 0
    else
        local exit_code="${PIPESTATUS[0]}"
        error "$step_name fehlgeschlagen mit Code $exit_code. Siehe Log: $log_file"
        return 1
    fi
}

# Schritt 1: Quiche herunterladen
fetch_quiche() {
    local log_file="$LOG_DIR/fetch_quiche_$(date +%Y%m%d_%H%M%S).log"
    
    log "Starte Herunterladen von quiche..."
    log "Quelle: $MIRROR_URL"
    log "Ziel: $PATCHED_DIR"

    mkdir -p "$PATCHED_DIR"

    if git -C "$BASE_DIR" submodule status libs/patched_quiche >/dev/null 2>&1; then
        log "Initialisiere Submodul libs/patched_quiche..."
        run_command "Submodul aktualisieren" \
            "git submodule set-url libs/patched_quiche \"$MIRROR_URL\" && git submodule update --init libs/patched_quiche"
    fi

    if [ -e "$PATCHED_DIR/.git" ]; then
        log "Repository existiert bereits, aktualisiere..."
        run_command "Aktualisieren des Quiche-Repositories" \
            "(cd \"$PATCHED_DIR\" && git fetch --all && git reset --hard origin/HEAD)"
    else
        run_command "Klonen des Quiche-Repositories" \
            "git clone --depth 1 \"$MIRROR_URL\" \"$PATCHED_DIR\""
    fi
    
    success "Quiche erfolgreich heruntergeladen und vorbereitet"
    return 0
}

# Schritt 2: Patches anwenden
apply_patches() {
    log "Starte Anwenden der Patches..."
    
    if [ ! -d "$PATCHES_DIR" ] || [ -z "$(ls -A "$PATCHES_DIR"/*.patch 2>/dev/null)" ]; then
        warn "Keine Patch-Dateien in $PATCHES_DIR gefunden"
        return 0
    fi
    
    # Erstelle Backup
    local backup_dir="$PATCHED_DIR.backup_$(date +%Y%m%d_%H%M%S)"
    run_command "Erstelle Backup vor dem Patchen" \
        "cp -r \"$PATCHED_DIR\" \"$backup_dir\""
    
    # Wende Patches an
    local patch_count=0
    for patch_file in "$PATCHES_DIR"/*.patch; do
        if [ -f "$patch_file" ]; then
            patch_count=$((patch_count + 1))
            log "Wende Patch an: $(basename "$patch_file")"
            
            if ! (cd "$PATCHED_DIR" && patch -p1 --no-backup-if-mismatch -r - < "$patch_file"); then
                error "Fehler beim Anwenden von $(basename "$patch_file")"
            fi
        fi
    done
    
    if [ $patch_count -gt 0 ]; then
        success "$patch_count Patches erfolgreich angewendet"
    else
        warn "Keine Patch-Dateien im .patch-Format gefunden"
    fi

    # Stelle sicher, dass das Build-Verzeichnis existiert
    local build_dir="$PATCHED_DIR/target"
    if [ -d "$build_dir" ]; then
        log "Build-Verzeichnis bereits vorhanden: $build_dir"
    else
        log "Erstelle Build-Verzeichnis: $build_dir"
        mkdir -p "$build_dir"
    fi
}

# Schritt 3: Quiche bauen
build_quiche() {
    log "Starte Build im $BUILD_TYPE-Modus..."
    
    # Setze Build-Flags
    local cargo_flags=""
    if [ "$BUILD_TYPE" = "release" ]; then
        cargo_flags="--release"
        # Verwende nur LTO, wenn es nicht zu Konflikten führt
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
        # Füge LTO über Cargo.toml oder Umgebungsvariablen hinzu, falls benötigt
        export CARGO_PROFILE_RELEASE_LTO=true
    else
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
        export CARGO_PROFILE_DEV_DEBUG=false  # Deaktiviere Debug-Informationen für schnellere Builds
    fi
    
    # Wechsle ins Quiche-Verzeichnis
    pushd "$PATCHED_DIR" > /dev/null || error "Konnte nicht in $PATCHED_DIR wechseln"
    
    # Führe den Build durch
    run_command "Cargo Build" "cargo build $cargo_flags"
    
    # Erstelle symbolischen Link auf die letzte Version
    local target_dir="$PATCHED_DIR/target/$BUILD_TYPE"
    local latest_link="$PATCHED_DIR/target/latest"
    
    rm -f "$latest_link"
    ln -s "$BUILD_TYPE" "$latest_link"
    
    success "Build erfolgreich abgeschlossen"
    log "- Ausgabeverzeichnis: $target_dir"
    log "- Symbolischer Link: $latest_link -> $BUILD_TYPE"
    
    popd > /dev/null || return 1
}

# Schritt 4: Tests durchführen
test_quiche() {
    log "Starte Tests..."
    
    pushd "$PATCHED_DIR" > /dev/null || error "Konnte nicht in $PATCHED_DIR wechseln"
    
    # Führe Tests durch
    run_command "Cargo Test" "cargo test"
    run_command "Cargo Check" "cargo check --all-targets"
    
    # Optional: Clippy und Formatierung prüfen
    if command -v cargo-clippy >/dev/null 2>&1; then
        run_command "Clippy Prüfung" "cargo clippy -- -D warnings"
    else
        warn "cargo-clippy nicht gefunden, überspringe Clippy-Prüfung"
    fi
    
    if command -v cargo-fmt >/dev/null 2>&1; then
        run_command "Formatprüfung" "cargo fmt -- --check"
    else
        warn "cargo-fmt nicht gefunden, überspringe Formatprüfung"
    fi
    
    popd > /dev/null || return 1
    
    success "Alle Tests erfolgreich abgeschlossen"
}

# Zeige Hilfetext
show_help() {
    echo "Verwendung: $0 [OPTIONEN]"
    echo "Steuert den Quiche-Integrationsprozess"
    echo
    echo "Optionen:"
    echo "  -t, --type TYPE     Build-Typ (release|debug), Standard: release"
    echo "  -m, --mirror URL    Git-Repository-URL für quiche"
    echo "  -s, --step SCHRITT  Bestimmten Schritt ausführen (fetch|patch|build|test)"
    echo "  -h, --help          Zeige diese Hilfe"
    echo
    echo "Verfügbare Schritte:"
    echo "  fetch      Quiche herunterladen"
    echo "  patch      Patches anwenden"
    echo "  build      Quiche bauen"
    echo "  test       Tests durchführen"
    exit 0
}

# Hauptfunktion
main() {
    # Lade Konfiguration
    load_state
    
    # Verarbeite Befehlszeilenargumente
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --type|-t)
                if [ -z "${2:-}" ]; then
                    error "Kein Build-Typ angegeben. Verwende --type release|debug"
                fi
                BUILD_TYPE="$2"
                shift 2
                ;;
            --mirror|-m)
                if [ -z "${2:-}" ]; then
                    error "Keine Repository-URL angegeben"
                fi
                MIRROR_URL="$2"
                shift 2
                ;;
            --step|-s)
                if [ -z "${2:-}" ]; then
                    error "Kein Schritt angegeben. Verwende --step fetch|patch|build|test"
                fi
                START_STEP="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                ;;
            *)
                error "Unbekannte Option: $1"
                ;;
        esac
    done
    
    # Funktion zum Ausführen eines einzelnen Schritts
    run_step() {
        local step="$1"
        case "$step" in
            "fetch") 
                log "Führe Schritt aus: fetch (Quiche herunterladen)"
                fetch_quiche
                ;;
            "patch") 
                log "Führe Schritt aus: patch (Patches anwenden)"
                apply_patches
                ;;
            "build") 
                log "Führe Schritt aus: build (Quiche bauen)"
                build_quiche
                ;;
            "test") 
                log "Führe Schritt aus: test (Tests durchführen)"
                test_quiche
                ;;
            *) 
                error "Unbekannter Schritt: $step. Gültige Schritte: fetch, patch, build, test"
                ;;
        esac
    }
    
    # Führe die Schritte basierend auf den Argumenten aus
    if [ -n "${START_STEP:-}" ]; then
        # Führe nur den angegebenen Schritt aus
        run_step "$START_STEP"
    else
        # Führe alle Schritte nacheinander aus
        log "Starte kompletten Workflow..."
        
        # Definiere die Reihenfolge der Schritte
        local steps_order=("fetch" "patch" "build" "test")
        
        # Führe jeden Schritt aus
        for step in "${steps_order[@]}"; do
            if ! run_step "$step"; then
                error "Fehler im Schritt: $step"
            fi
        done
    fi
    
    # Workflow abgeschlossen
    save_state "completed"
    success "Quiche-Workflow erfolgreich abgeschlossen!"
}

# Hauptprogramm
main "$@"

exit 0
