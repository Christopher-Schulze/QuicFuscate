#!/bin/bash
# Erweitertes Build-Skript mit Cross-Compilation-Unterstützung

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Funktionen
setup_cross_compilation() {
    local target=$1
    
    case "$target" in
        "x86_64-unknown-linux-gnu")
            export CC="x86_64-linux-gnu-gcc"
            export CXX="x86_64-linux-gnu-g++"
            ;;
        "aarch64-unknown-linux-gnu")
            export CC="aarch64-linux-gnu-gcc"
            export CXX="aarch64-linux-gnu-g++"
            ;;
        *)
            log_error "Nicht unterstütztes Ziel: $target"
            return 1
            ;;
    esac
    
    log_info "Cross-Compilation für $target eingerichtet"
    return 0
}

build_target() {
    local target=$1
    local features=$2
    
    log_info "Baue für $target mit Features: $features"
    
    # Setup Cross-Compilation
    setup_cross_compilation "$target" || return 1
    
    # Baue mit optimierten Flags
    (
        cd "$QUICHE_DIR"
        RUSTFLAGS="-C target-cpu=native -C opt-level=$OPTIMIZATION_LEVEL -C lto=$LTO_MODE $RUSTFLAGS" \
        cargo build --release --target "$target" --features "$features"
    )
    
    return $?
}

# Hauptfunktion
main() {
    local target="${1:-$TARGET}"
    local features="${2:-ffi bbr pktinfo qlog boringssl-vendored}"
    
    log_info "Starte erweiterten Build für $target..."
    
    # Baue für das angegebene Ziel
    if ! build_target "$target" "$features"; then
        log_error "Build fehlgeschlagen für $target"
        return 1
    fi
    
    log_info "Build erfolgreich abgeschlossen für $target"
    return 0
}

# Starte Skript
main "$@"
