#!/bin/bash
# Erweitertes Benchmark-Skript mit detaillierten Metriken

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Globale Variablen
BENCHMARK_RESULTS="${BENCH_DIR}/benchmark_results_$(date +%Y%m%d_%H%M%S).json"
PERF_STAT_FILE="${BENCH_DIR}/perf_stat_$(date +%Y%m%d_%H%M%S).txt"

# Funktionen
run_benchmark() {
    local name=$1
    local cmd=$2
    
    log_info "Starte Benchmark: $name"
    log_debug "Befehl: $cmd"
    
    # Starte System-Monitoring
    start_monitoring "${name}_monitor"
    
    # Führe Benchmark mit Zeitmessung aus
    local start_time=$(date +%s%N)
    eval "$cmd"
    local exit_code=$?
    local end_time=$(date +%s%N)
    
    # Beende Monitoring
    stop_monitoring "${name}_monitor"
    
    # Berechne Metriken
    local duration_ns=$((end_time - start_time))
    local duration_ms=$((duration_ns / 1000000))
    
    # Sammle Systemmetriken
    local cpu_usage=$(get_cpu_usage "${name}_monitor")
    local mem_usage=$(get_memory_usage "${name}_monitor")
    
    # Speichere Ergebnisse
    local result=$(jq -n \
        --arg name "$name" \
        --arg cmd "$cmd" \
        --arg duration_ns "$duration_ns" \
        --arg duration_ms "$duration_ms" \
        --arg exit_code "$exit_code" \
        --arg cpu_usage "$cpu_usage" \
        --arg mem_usage "$mem_usage" \
        '{
            name: $name,
            command: $cmd,
            duration_ns: $duration_ns,
            duration_ms: $duration_ms,
            exit_code: $exit_code,
            cpu_usage: $cpu_usage,
            memory_usage: $mem_usage,
            timestamp: now | todate
        }')
    
    # Füge Ergebnis zur Gesamtausgabe hinzu
    if [ ! -f "$BENCHMARK_RESULTS" ]; then
        echo "[]" > "$BENCHMARK_RESULTS"
    fi
    
    jq --argjson result "$result" '. + [$result]' "$BENCHMARK_RESULTS" > "${BENCHMARK_RESULTS}.tmp"
    mv "${BENCHMARK_RESULTS}.tmp" "$BENCHMARK_RESULTS"
    
    log_info "Benchmark abgeschlossen: ${duration_ms}ms (CPU: ${cpu_usage}%, RAM: ${mem_usage}MB)"
}

start_monitoring() {
    local prefix=$1
    
    # Starte Hintergrundprozesse für CPU- und Speicherüberwachung
    (vmstat 1 > "${BENCH_DIR}/${prefix}_vmstat.log") & VMSTAT_PID=$!
    (free -ms 1 > "${BENCH_DIR}/${prefix}_mem.log") & MEM_PID=$!
    
    # Starte perf stat für detaillierte CPU-Metriken
    if command -v perf &> /dev/null; then
        (perf stat -e instructions,cycles,cache-misses,cache-references,branch-misses -a sleep 3600 2> "$PERF_STAT_FILE") & PERF_PID=$!
    fi
    
    # Speichere PIDs für späteren Zugriff
    eval "${prefix}_VMSTAT_PID=$VMSTAT_PID"
    eval "${prefix}_MEM_PID=$MEM_PID"
    [ -n "$PERF_PID" ] && eval "${prefix}_PERF_PID=$PERF_PID"
}

stop_monitoring() {
    local prefix=$1
    
    # Beende Überwachungsprozesse
    kill "${!prefix_VMSTAT_PID}" 2>/dev/null || true
    kill "${!prefix_MEM_PID}" 2>/dev/null || true
    [ -n "${!prefix_PERF_PID}" ] && kill "${!prefix_PERF_PID}" 2>/dev/null || true
    
    # Warte auf das Ende der Prozesse
    wait "${!prefix_VMSTAT_PID}" 2>/dev/null || true
    wait "${!prefix_MEM_PID}" 2>/dev/null || true
    [ -n "${!prefix_PERF_PID}" ] && wait "${!prefix_PERF_PID}" 2>/dev/null || true
}

get_cpu_usage() {
    local prefix=$1
    local vmstat_log="${BENCH_DIR}/${prefix}_vmstat.log"
    
    if [ -f "$vmstat_log" ]; then
        # Berechne die durchschnittliche CPU-Auslastung in Prozent
        local cpu_usage=$(awk 'NR>2 {idle+=$15; total+=$13+$14+$15+$16} END {print 100 - (idle*100)/total}' "$vmstat_log" 2>/dev/null)
        printf "%.1f" "$cpu_usage"
    else
        echo "0.0"
    fi
}

get_memory_usage() {
    local prefix=$1
    local mem_log="${BENCH_DIR}/${prefix}_mem.log"
    
    if [ -f "$mem_log" ]; then
        # Berechne den durchschnittlichen Speicherverbrauch in MB
        local avg_mem=$(awk 'NR>1 {sum+=$3; count++} END {print sum/count}' "$mem_log" 2>/dev/null)
        printf "%.1f" "$avg_mem"
    else
        echo "0.0"
    fi
}

# Hauptfunktion
main() {
    log_info "Starte erweiterte Benchmarks..."
    
    # Erstelle Ausgabeverzeichnis
    mkdir -p "$BENCH_DIR"
    
    # Führe verschiedene Benchmarks aus
    run_benchmark "build_time" "cd $QUICHE_DIR && cargo clean && cargo build --release"
    
    # Weitere Benchmarks hier hinzufügen...
    
    log_info "Benchmark-Ergebnisse gespeichert in: $BENCHMARK_RESULTS"
    log_info "Perf-Statistiken gespeichert in: $PERF_STAT_FILE"
}

# Starte Skript
main "$@"
