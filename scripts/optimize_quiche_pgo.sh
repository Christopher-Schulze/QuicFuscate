#!/bin/bash
# Erweitertes Optimierungsskript mit PGO-Unterstützung

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Funktionen
setup_pgo() {
    if [ "$ENABLE_PGO" = true ]; then
        log_info "Aktiviere PGO (Profile Guided Optimization)"
        
        # Prüfe auf erforderliche Tools
        if ! command -v perf &> /dev/null; then
            log_warn "perf ist nicht installiert. PGO kann nicht verwendet werden."
            ENABLE_PGO=false
            return 1
        fi
        
        export CARGO_PROFILE_RELEASE_LTO="off"
        export RUSTFLAGS="-Cprofile-generate=$PGO_DATA"
        
        return 0
    fi
    return 1
}

build_with_pgo() {
    if [ "$ENABLE_PGO" = true ]; then
        log_info "Baue mit PGO-Profil..."
        
        # Erstelle Verzeichnis für PGO-Daten
        mkdir -p "$PGO_DIR"
        
        # Erste Phase: Sammle Profildaten
        log_info "Phase 1/2: Sammle Profildaten..."
        (
            cd "$QUICHE_DIR"
            RUSTFLAGS="-Cprofile-generate=$PGO_DIR" \
            cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored"
        )
        
        # Führe Benchmarks mit Profiling aus
        log_info "Führe Benchmarks für PGO aus..."
        ./scripts/benchmark.sh
        
        # Zweite Phase: Baue mit Profildaten
        log_info "Phase 2/2: Baue mit PGO-Daten..."
        (
            cd "$QUICHE_DIR"
            RUSTFLAGS="-Cprofile-use=$PGO_DIR -Cllvm-args=-pgo-warn-missing-function" \
            cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored"
        )
        
        # Bereinige PGO-Daten
        rm -rf "$PGO_DIR"
    fi
}

# Hauptfunktion
main() {
    log_info "Starte erweiterte Optimierung..."
    
    # CPU-Governor auf Performance setzen
    if [ "$(id -u)" -eq 0 ]; then
        log_info "Setze CPU-Governor auf Performance..."
        for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo "performance" | sudo tee "$gov" >/dev/null
        done
    fi
    
    # Baue mit PGO wenn aktiviert
    if setup_pgo; then
        build_with_pgo
    else
        # Normales Build ohne PGO
        log_info "Baue ohne PGO..."
        (
            cd "$QUICHE_DIR"
            RUSTFLAGS="-C target-cpu=native -C opt-level=$OPTIMIZATION_LEVEL -C lto=$LTO_MODE" \
            cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored"
        )
    fi
    
    log_info "Optimierung abgeschlossen!"
}

# Starte Skript
main "$@"
