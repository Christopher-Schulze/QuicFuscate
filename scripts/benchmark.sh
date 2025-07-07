#!/bin/bash
# Benchmark Script für Quiche
set -e

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Konfiguration
BENCH_DIR="benchmarks"
LOG_FILE="${BENCH_DIR}/benchmark_$(date +%Y%m%d_%H%M%S).log"

# Hilfsfunktionen
log() {
    echo -e "${GREEN}[BENCHMARK]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

run_benchmark() {
    local name=$1
    local cmd=$2
    
    log "Starte Benchmark: $name"
    log "Befehl: $cmd"
    
    # Führe Benchmark aus
    local start_time=$(date +%s%N)
    eval "$cmd" >> "$LOG_FILE" 2>&1
    local exit_code=$?
    local end_time=$(date +%s%N)
    
    # Berechne Dauer
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    if [ $exit_code -eq 0 ]; then
        log "Benchmark abgeschlossen: ${duration}ms"
    else
        log "Fehler beim Benchmark (Exit-Code: $exit_code)"
    fi
    
    echo "----------------------------------------" >> "$LOG_FILE"
}

# Hauptfunktion
main() {
    # Erstelle Verzeichnis für Benchmarks
    mkdir -p "$BENCH_DIR"
    
    log "Starte Benchmark-Suite..."
    
    # 1. Build-Zeit
    run_benchmark "Clean Build" "cargo clean && time cargo build --release"
    
    # 2. Laufzeit-Tests
    run_benchmark "Unit Tests" "cargo test --release -- --nocapture"

    # XDP specific tests if feature available
    run_benchmark "XDP Socket" "cargo test --release --test xdp_socket --features xdp -- --nocapture"
    
    # 3. Performance-Tests
    if [ -f "target/release/quiche-client" ] && [ -f "target/release/quiche-server" ]; then
        # Starte Server im Hintergrund
        ./target/release/quiche-server --listen [::]:4433 --root . --cert tests/cert.crt --key tests/cert.key &
        SERVER_PID=$!
        
        # Warte kurz, bis der Server startet
        sleep 2
        
        # Führe Client-Tests aus
        run_benchmark "HTTP/3 Request" 
            "time ./target/release/quiche-client \
            --no-verify https://localhost:4433/README.md"
        
        # Beende Server
        kill $SERVER_PID
    else
        log "Benchmark-Server oder -Client nicht gefunden"
    fi
    
    log "Benchmark abgeschlossen. Details in $LOG_FILE"
}

# Starte Skript
main "$@"
