#!/bin/bash
# Master-Skript für die vollständige Optimierung

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Funktionen
show_usage() {
    echo "Verwendung: $0 [OPTIONEN]"
    echo "Optimiere und baue die quiche-Bibliothek mit erweiterten Einstellungen"
    echo ""
    echo "Optionen:"
    echo "  --full           Führe alle Optimierungen durch (inkl. Systemoptimierungen)"
    echo "  --pgo            Aktiviere Profile Guided Optimization (PGO)"
    echo "  --test           Führe Tests nach dem Build durch"
    echo "  --benchmark      Führe Benchmarks durch"
    echo "  --target TARGET  Zielplattform (default: $TARGET)"
    echo "  --help           Zeige diese Hilfe an"
    echo ""
    exit 0
}

check_dependencies() {
    log_info "Überprüfe Abhängigkeiten..."
    
    local missing_deps=0
    
    # Notwendige Tools
    for cmd in cargo rustc rustup git jq; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Fehlendes Tool: $cmd"
            missing_deps=$((missing_deps + 1))
        fi
    done
    
    # Optionale Tools
    for cmd in perf numactl; do
        if ! command -v "$cmd" &> /dev/null; then
            log_warn "Optionales Tool fehlt: $cmd (manche Funktionen sind eingeschränkt)"
        fi
    done
    
    if [ $missing_deps -gt 0 ]; then
        log_fatal "$missing_deps erforderliche Abhängigkeiten fehlen. Bitte installieren Sie diese zuerst."
    fi
}

setup_environment() {
    log_info "Richte Build-Umgebung ein..."
    
    # Rust Toolchain
    rustup toolchain install stable
    rustup default stable
    
    # Nightly für einige Optimierungen
    rustup toolchain install nightly --component rust-src rustc-dev llvm-tools-preview
    
    # Benötigte Komponenten
    rustup component add rustfmt clippy
    
    # Cargo-Plugins
    cargo install cargo-update cargo-bloat cargo-udeps
    
    # Für PGO
    if [ "$ENABLE_PGO" = true ]; then
        cargo install cargo-pgo
    fi
    
    # Für Fuzzing
    if [ "$ENABLE_FUZZING" = true ]; then
        cargo install cargo-fuzz
    fi
}

run_optimizations() {
    local full_optimization=$1
    
    log_info "Starte Optimierungen..."
    
    # Systemoptimierungen
    if [ "$full_optimization" = true ]; then
        log_info "Führe vollständige Systemoptimierungen durch..."
        sudo "$(dirname "$0")/optimize_system_advanced.sh" --all
    else
        log_info "Führe grundlegende Optimierungen durch..."
        "$(dirname "$0")/optimize_system_advanced.sh"
    fi
    
    # PGO durchführen
    if [ "$ENABLE_PGO" = true ]; then
        log_info "Führe PGO (Profile Guided Optimization) durch..."
        "$(dirname "$0")/optimize_quiche_pgo.sh"
    else
        # Normales Build
        log_info "Baue mit Standard-Optimierungen..."
        "$(dirname "$0")/build_advanced.sh"
    fi
}

run_tests() {
    log_info "Starte Tests..."
    "$(dirname "$0")/test_advanced.sh"
    return $?
}

run_benchmarks() {
    log_info "Starte Benchmarks..."
    "$(dirname "$0")/benchmark_advanced.sh"
    return $?
}

# Hauptfunktion
main() {
    local full_optimization=false
    local run_tests_flag=false
    local run_benchmarks_flag=false
    
    # Parameter verarbeiten
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                full_optimization=true
                shift
                ;;
            --pgo)
                ENABLE_PGO=true
                shift
                ;;
            --test)
                run_tests_flag=true
                shift
                ;;
            --benchmark)
                run_benchmarks_flag=true
                shift
                ;;
            --target)
                TARGET="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                ;;
            *)
                log_error "Unbekannter Parameter: $1"
                show_usage
                ;;
        esac
    done
    
    # Starte Optimierungen
    check_dependencies
    setup_environment
    run_optimizations "$full_optimization"
    
    # Tests durchführen
    if [ "$run_tests_flag" = true ]; then
        if ! run_tests; then
            log_error "Tests fehlgeschlagen"
            exit 1
        fi
    fi
    
    # Benchmarks durchführen
    if [ "$run_benchmarks_flag" = true ]; then
        if ! run_benchmarks; then
            log_warn "Benchmarks haben Warnungen zurückgegeben"
        fi
    fi
    
    log_info "Alle Optimierungen abgeschlossen!"
    
    # Zusammenfassung anzeigen
    echo ""
    echo "=== ZUSAMMENFASSUNG ==="
    echo "- Optimierungen: $([ "$full_optimization" = true ] && echo "Vollständig" || echo "Standard")"
    echo "- PGO: $([ "$ENABLE_PGO" = true ] && echo "Aktiviert" || echo "Deaktiviert")"
    echo "- Tests: $([ "$run_tests_flag" = true ] && echo "Durchgeführt" || echo "Übersprungen")"
    echo "- Benchmarks: $([ "$run_benchmarks_flag" = true ] && echo "Durchgeführt" || echo "Übersprungen")"
    echo "- Zielplattform: $TARGET"
    echo "- Log-Datei: $LOG_FILE"
    echo "======================="
    echo ""
}

# Starte Skript
main "$@"
