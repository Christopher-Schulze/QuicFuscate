#!/bin/bash
# Erweiterte Systemoptimierungen für maximale Leistung

# Lade Konfiguration und Logging
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/logger.sh"

# Funktionen
optimize_network() {
    log_info "Optimiere Netzwerkeinstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Bitte als root ausführen für volle Netzwerkoptimierungen"
        return 1
    fi
    
    # TCP Optimierungen
    sysctl -w net.core.rmem_max="$NET_TCP_RMEM_MAX"
    sysctl -w net.core.wmem_max="$NET_TCP_WMEM_MAX"
    sysctl -w net.ipv4.tcp_rmem="$NET_TCP_RMEM"
    sysctl -w net.ipv4.tcp_wmem="$NET_TCP_WMEM"
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.ipv4.tcp_fastopen=3
    sysctl -w net.core.somaxconn="$NET_CORE_SOMAXCONN"
    
    # UDP Optimierungen
    sysctl -w net.core.netdev_max_backlog=100000
    
    # Weitere Optimierungen
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=15
    
    # Für hohe Anzahl an Verbindungen
    sysctl -w fs.file-max=1000000
    ulimit -n 1000000
    
    log_info "Netzwerkoptimierungen abgeschlossen"
}

optimize_cpu() {
    log_info "Optimiere CPU-Einstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Bitte als root ausführen für CPU-Optimierungen"
        return 1
    }
    
    # CPU-Governor auf Performance setzen
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo "performance" | tee "$cpu" >/dev/null || true
    done
    
    # CPU-Auslastung optimieren
    sysctl -w kernel.sched_autogroup_enabled=1
    sysctl -w kernel.sched_migration_cost_ns=5000000
    sysctl -w kernel.sched_min_granularity_ns=10000000
    
    # IRQ-Ausgleich für bessere Netzwerkleistung
    for irq in /proc/irq/*/smp_affinity; do
        echo 7 > "$irq" 2>/dev/null || true
    done
    
    log_info "CPU-Optimierungen abgeschlossen"
}

optimize_memory() {
    log_info "Optimiere Speichereinstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Bitte als root ausführen für Speicheroptimierungen"
        return 1
    }
    
    # Transparent Huge Pages
    echo "madvise" > /sys/kernel/mm/transparent_hugepage/enabled
    echo 1 > /sys/kernel/mm/transparent_hugepage/defrag
    
    # Speicherverwaltung
    sysctl -w vm.swappiness=10
    sysctl -w vm.vfs_cache_pressure=50
    sysctl -w vm.dirty_ratio=10
    sysctl -w vm.dirty_background_ratio=5
    
    # NUMA-Optimierungen
    if command -v numactl &> /dev/null; then
        for node in $(numactl --hardware | grep 'available' | cut -d' ' -f2); do
            echo 0 > "/sys/devices/system/node/node${node}/hugepages/hugepages-2048kB/nr_hugepages"
            echo 1024 > "/sys/devices/system/node/node${node}/hugepages/hugepages-1048576kB/nr_hugepages"
        done
    fi
    
    log_info "Speicheroptimierungen abgeschlossen"
}

optimize_disk() {
    log_info "Optimiere Festplatten-Einstellungen..."
    
    # Nur mit Root-Rechten
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Bitte als root ausführen für Festplatten-Optimierungen"
        return 1
    }
    
    # I/O Scheduler für SSDs
    for disk in /sys/block/sd*/queue/scheduler; do
        echo "none" > "$disk" 2>/dev/null || true
    done
    
    # Schreibcache optimieren
    for disk in /sys/block/sd*; do
        echo 2 > "${disk}/queue/rq_affinity" 2>/dev/null || true
        echo 256 > "${disk}/queue/nr_requests" 2>/dev/null || true
        echo 0 > "${disk}/queue/rotational" 2>/dev/null || true
        echo 0 > "${disk}/queue/add_random" 2>/dev/null || true
    done
    
    # Dateisystem-Einstellungen
    sysctl -w fs.file-max=1000000
    sysctl -w fs.nr_open=1000000
    
    log_info "Festplatten-Optimierungen abgeschlossen"
}

# Hauptfunktion
main() {
    local optimize_all=false
    
    # Parameter auswerten
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                optimize_all=true
                shift
                ;;
            *)
                log_error "Unbekannter Parameter: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "Starte Systemoptimierungen..."
    
    # Führe Optimierungen aus
    optimize_network
    
    if [ "$optimize_all" = true ]; then
        optimize_cpu
        optimize_memory
        optimize_disk
    else
        log_info "Nur Netzwerkoptimierungen durchgeführt. Verwende --all für volle Optimierung."
    fi
    
    log_info "Systemoptimierungen abgeschlossen!"
}

# Starte Skript
main "$@"
