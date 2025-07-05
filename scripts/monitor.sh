#!/bin/bash
# System Monitoring für Quiche
set -e

# Konfiguration
LOG_DIR="monitoring"
INTERVAL=5  # Sekunden
DURATION=60  # Sekunden

# Farben
GREEN='\033[0;32m'
NC='\033[0m'

# Hilfsfunktionen
log() {
    echo -e "${GREEN}[MONITOR]${NC} $1"
}

# Hauptfunktion
main() {
    mkdir -p "$LOG_DIR"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local cpu_log="${LOG_DIR}/cpu_${timestamp}.log"
    local mem_log="${LOG_DIR}/mem_${timestamp}.log"
    local net_log="${LOG_DIR}/net_${timestamp}.log"
    
    log "Starte Systemüberwachung für ${DURATION} Sekunden..."
    log "Logs werden in ${LOG_DIR}/ gespeichert"
    
    # Starte Hintergrundprozesse
    vmstat $INTERVAL > "$cpu_log" &
    VMSTAT_PID=$!
    
    free -s $INTERVAL > "$mem_log" &
    FREE_PID=$!
    
    if command -v ifstat &> /dev/null; then
        ifstat -t -n -i lo $INTERVAL > "$net_log" &
        IFSTAT_PID=$!
    else
        log "ifstat nicht gefunden, Netzwerküberwachung deaktiviert"
    fi
    
    # Warte die angegebene Dauer
    sleep $DURATION
    
    # Beende Hintergrundprozesse
    kill $VMSTAT_PID $FREE_PID $IFSTAT_PID 2>/dev/null || true
    
    log "Überwachung abgeschlossen"
    
    # Zeige Zusammenfassung
    echo -e "\n${GREEN}=== Systemübersicht ===${NC}"
    echo "CPU-Auslastung: $cpu_log"
    echo "Speichernutzung: $mem_log"
    [ -n "$IFSTAT_PID" ] && echo "Netzwerknutzung: $net_log"
}

# Starte Skript
main "$@"
