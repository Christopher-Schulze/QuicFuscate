#!/bin/bash
# Quiche Workflow Manager - Steuert den gesamten Quiche-Integrationsprozess

set -euo pipefail
trap 'error "Unerwarteter Fehler in ${FUNCNAME:-main} (Zeile $LINENO)"' ERR

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

# Prüft, ob eine Internetverbindung besteht
check_internet() {
    if command -v curl >/dev/null 2>&1; then
        curl -Is --connect-timeout 5 "$MIRROR_URL" >/dev/null 2>&1 && return 0
    elif command -v wget >/dev/null 2>&1; then
        wget -q --spider --timeout=5 "$MIRROR_URL" >/dev/null 2>&1 && return 0
    elif command -v ping >/dev/null 2>&1; then
        ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && return 0
    fi
    error "Keine Internetverbindung erkannt. Bitte Verbindung prüfen."
}

# Fragt den Benutzer, ob ein Vorgang wiederholt werden soll
ask_retry() {
    read -r -p "Erneut versuchen? [j/N] " answer
    [[ "$answer" =~ ^[Jj]$ ]]
}

# Determines the current quiche commit for logging.
detect_quiche_version() {
    if [ -d "$PATCHED_DIR/.git" ]; then
        QUICHE_VERSION=$(git -C "$PATCHED_DIR" rev-parse --short HEAD)
        log "Quiche-Version: $QUICHE_VERSION"
    else
        QUICHE_VERSION="unknown"
    fi
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

# Ensure the quiche submodule exists and is initialized
init_submodule() {
    if [ ! -d "$PATCHED_DIR/.git" ]; then
        log "Initialisiere Submodul libs/patched_quiche"
        git submodule set-url libs/patched_quiche "$MIRROR_URL" 2>/dev/null || true
        git submodule update --init --recursive libs/patched_quiche
    fi
}

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

    init_submodule

    # Ensure quiche sources are present and initialized
    if [ ! -d "$PATCHED_DIR/quiche" ] || [ ! -d "$PATCHED_DIR/.git" ]; then
        warn "Quiche-Verzeichnis fehlt oder Submodul nicht initialisiert: $PATCHED_DIR/quiche"
        fetch_quiche || error "Automatisches Herunterladen fehlgeschlagen. Bitte $0 --step fetch ausführen."
    fi
    detect_quiche_version
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

    # Prüfe, ob das verwendete Kommando existiert
    local cmd=( $command_str )
    if ! command -v "${cmd[0]}" >/dev/null 2>&1; then
        error "Kommando nicht gefunden: ${cmd[0]}"
    fi

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

# Prüft, ob benötigte Programme installiert sind
check_dependencies() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        error "Fehlende Abhängigkeiten: ${missing[*]}. Bitte installieren und erneut ausführen."
    fi
}

# Stelle ein zuvor erstelltes Backup wieder her
rollback_backup() {
    local backup_dir="$1"
    if [ -d "$backup_dir" ]; then
        log "Rolle auf Backup $backup_dir zurück..."
        rm -rf "$PATCHED_DIR"
        mv "$backup_dir" "$PATCHED_DIR"
        success "Backup wiederhergestellt"
    else
        warn "Kein Backup zum Zurückrollen gefunden ($backup_dir)"
    fi
}

# Behandelt Fehlermeldungen beim Patchen und bietet optional einen erneuten Versuch an
patch_failure() {
    local message="$1"
    local backup_dir="$2"
    local detail="${3:-}"
    warn "$message"
    [ -n "$detail" ] && {
        warn "$detail"
        [ -f "$detail" ] && tail -n 20 "$detail"
    }
    if ask_retry; then
        rollback_backup "$backup_dir"
        apply_patches
    else
        rollback_backup "$backup_dir"
        error "Patchvorgang abgebrochen: $message"
    fi
}

fetch_quiche() {
    local log_file

    if [ -d "$PATCHED_DIR/quiche" ]; then
        log "Quiche-Verzeichnis bereits vorhanden: $PATCHED_DIR/quiche"
        return 0
    fi
    
    log "Starte Herunterladen von quiche..."
    log "Quelle: $MIRROR_URL"
    log "Ziel: $PATCHED_DIR"
    check_internet

    mkdir -p "$PATCHED_DIR"

    if git -C "$BASE_DIR" submodule status libs/patched_quiche >/dev/null 2>&1; then
        log "Initialisiere Submodul libs/patched_quiche..."
        run_command "Submodul aktualisieren" \
            "git submodule set-url libs/patched_quiche \"$MIRROR_URL\" && git submodule update --init --recursive libs/patched_quiche"
    fi

    if [ -e "$PATCHED_DIR/.git" ]; then
        log "Repository existiert bereits, aktualisiere..."
        run_command "Aktualisieren des Quiche-Repositories" \
            "(cd \"$PATCHED_DIR\" && git fetch --all && git reset --hard origin/HEAD)"
        run_command "Submodule einbinden" \
            "(cd \"$PATCHED_DIR\" && git submodule update --init --recursive)"
    else
        local attempt=0
        while true; do
            attempt=$((attempt + 1))
            log_file="$LOG_DIR/clone_attempt_${attempt}_$(date +%Y%m%d_%H%M%S).log"
            log "Klonen des Quiche-Repositories (Versuch $attempt)"
            if git clone --depth 1 "$MIRROR_URL" "$PATCHED_DIR" >"$log_file" 2>&1; then
                git -C "$PATCHED_DIR" submodule update --init --recursive >>"$log_file" 2>&1
                break
            fi
            warn "Klonen fehlgeschlagen. Details siehe $log_file"
            if ask_retry; then
                rm -rf "$PATCHED_DIR"
                continue
            else
                error "Klonen des Quiche-Repositories abgebrochen"
            fi
        done
    fi

    detect_quiche_version

    if [ ! -d "$PATCHED_DIR/quiche" ]; then
        error "Quiche-Verzeichnis konnte nach dem Klonen nicht gefunden werden"
    fi

    success "Quiche erfolgreich heruntergeladen und vorbereitet"
    return 0
}

# Schritt 2: Patches anwenden
apply_patches() {
    log "Starte Anwenden der Patches..."
    check_dependencies git patch
    
    if [ ! -d "$PATCHES_DIR" ] || [ -z "$(ls -A "$PATCHES_DIR"/*.patch 2>/dev/null)" ]; then
        warn "Keine Patch-Dateien in $PATCHES_DIR gefunden"
        return 0
    fi
    
    # Erstelle Backup
    local backup_dir="$PATCHED_DIR.backup_$(date +%Y%m%d_%H%M%S)"
    run_command "Erstelle Backup vor dem Patchen" \
        "cp -r \"$PATCHED_DIR\" \"$backup_dir\""
    
    # Reihenfolge der Patches kontrollieren
    local ordered=()
    if [ -f "$PATCHES_DIR/series" ]; then
        mapfile -t ordered < "$PATCHES_DIR/series"
    else
        ordered=( $(ls "$PATCHES_DIR"/*.patch 2>/dev/null | sort -V | xargs -n1 basename) )
    fi

    local patch_count=0
    for name in "${ordered[@]}"; do
        local patch_file="$PATCHES_DIR/$name"
        [ -f "$patch_file" ] || continue
        patch_count=$((patch_count + 1))
        log "Wende Patch an: $name"
        local patch_log="$LOG_DIR/patch_${name}_$(date +%Y%m%d_%H%M%S).log"
        if ! (cd "$PATCHED_DIR" && patch -p1 --no-backup-if-mismatch -r - < "$patch_file" >"$patch_log" 2>&1); then
            patch_failure "Fehler beim Anwenden von $name" "$backup_dir" "$patch_log"
        fi
    done
    
    if [ $patch_count -gt 0 ]; then
        success "$patch_count Patches erfolgreich angewendet"
        if ! verify_patches; then
            patch_failure "Patch-Verifikation fehlgeschlagen" "$backup_dir"
        fi
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

# Schritt 3: Patches verifizieren
verify_patches() {
    log "Starte Verifikation der Patches..."

    if [ ! -d "$PATCHES_DIR" ] || [ -z "$(ls -A "$PATCHES_DIR"/*.patch 2>/dev/null)" ]; then
        warn "Keine Patch-Dateien in $PATCHES_DIR gefunden"
        return 0
    fi

    pushd "$PATCHED_DIR" > /dev/null || error "Konnte nicht in $PATCHED_DIR wechseln"

    for patch_file in "$PATCHES_DIR"/*.patch; do
        if [ -f "$patch_file" ]; then
            log "Prüfe Patch: $(basename \"$patch_file\")"
            patch --dry-run -p1 < "$patch_file" >/dev/null || error "Patch $(basename \"$patch_file\") konnte nicht verifiziert werden"
        fi
    done

    if [ -n "$(git status --porcelain)" ]; then
        git status --porcelain
        error "Unerwartete Änderungen im Arbeitsverzeichnis nach dem Patchen"
    fi

    popd > /dev/null || return 1

    success "Alle Patches erfolgreich verifiziert"
}

# Schritt 4: Quiche bauen
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

    if ls "$target_dir"/libquiche* >/dev/null 2>&1 || ls "$target_dir"/deps/libquiche* >/dev/null 2>&1; then
        success "Build erfolgreich abgeschlossen"
    else
        error "Erwartete Build-Artefakte fehlen im $target_dir"
    fi
    log "- Ausgabeverzeichnis: $target_dir"
    log "- Symbolischer Link: $latest_link -> $BUILD_TYPE"
    
    popd > /dev/null || return 1
}

# Schritt 5: Tests durchführen
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
    echo "  -s, --step SCHRITT  Bestimmten Schritt ausführen (fetch|patch|verify_patches|build|test)"
    echo "  -h, --help          Zeige diese Hilfe"
    echo
    echo "Verfügbare Schritte:"
    echo "  fetch          Quiche herunterladen"
    echo "  patch          Patches anwenden"
    echo "  verify_patches Patches überprüfen"
    echo "  build          Quiche bauen"
    echo "  test           Tests durchführen"
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
                    error "Kein Schritt angegeben. Verwende --step fetch|patch|verify_patches|build|test"
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
            "verify_patches")
                log "Führe Schritt aus: verify_patches (Patches überprüfen)"
                verify_patches
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
                error "Unbekannter Schritt: $step. Gültige Schritte: fetch, patch, verify_patches, build, test"
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
        local steps_order=("fetch" "patch" "verify_patches" "build" "test")
        
        # Führe jeden Schritt aus
        for step in "${steps_order[@]}"; do
            if ! run_step "$step"; then
                error "Fehler im Schritt: $step"
            fi
        done
    fi
    
    # Workflow abgeschlossen
    save_state "completed"
    rm -f "$STATE_FILE"
    success "Quiche-Workflow erfolgreich abgeschlossen!"
}

# Hauptprogramm
main "$@"

exit 0
