#!/bin/bash
# Erweitertes Testskript mit automatischer Fehlererkennung

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Funktionen
run_tests() {
    local test_type=$1
    local test_cmd=""
    
    case "$test_type" in
        "unit")
            test_cmd="cargo test --release --lib -- --test-threads=1"
            ;;
        "integration")
            test_cmd="cargo test --release --tests -- --test-threads=1"
            ;;
        "doc")
            test_cmd="cargo test --release --doc"
            ;;
        *)
            log_error "Unbekannter Testtyp: $test_type"
            return 1
            ;;
    esac
    
    log_info "Starte $test_type-Tests..."
    
    # Führe Tests mit Zeitmessung aus
    local start_time=$(date +%s)
    
    (
        cd "$QUICHE_DIR"
        eval "$test_cmd"
    )
    
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $exit_code -eq 0 ]; then
        log_info "$test_type-Tests erfolgreich abgeschlossen in ${duration}s"
        return 0
    else
        log_error "$test_type-Tests fehlgeschlagen nach ${duration}s (Exit-Code: $exit_code)"
        return $exit_code
    fi
}

run_fuzz_tests() {
    if ! command -v cargo-fuzz &> /dev/null; then
        log_warn "cargo-fuzz nicht installiert. Überspringe Fuzzing-Tests."
        return 0
    fi
    
    log_info "Starte Fuzzing-Tests..."
    
    (
        cd "$QUICHE_DIR/fuzz"
        cargo fuzz run fuzz_target_1 -- -max_total_time=60
    )
    
    return $?
}

run_benchmarks() {
    log_info "Starte Benchmarks..."
    
    ./scripts/benchmark_advanced.sh
    
    return $?
}

# Hauptfunktion
main() {
    local all_passed=true
    
    # Führe verschiedene Testtypen aus
    for test_type in unit integration doc; do
        if ! run_tests "$test_type"; then
            all_passed=false
        fi
    done
    
    # Führe Fuzzing-Tests aus
    if ! run_fuzz_tests; then
        all_passed=false
    fi
    
    # Führe Benchmarks aus
    if ! run_benchmarks; then
        all_passed=false
    fi
    
    # Zusammenfassung
    if $all_passed; then
        log_info "Alle Tests erfolgreich abgeschlossen!"
        return 0
    else
        log_error "Einige Tests sind fehlgeschlagen!"
        return 1
    fi
}

# Starte Skript
main "$@"
