#!/bin/bash
# Erweitertes Logging-System

# Lade Konfiguration
source "$(dirname "$0")/config.sh"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log-Levels
LOG_LEVEL_NUM=0
case "$LOG_LEVEL" in
    "DEBUG") LOG_LEVEL_NUM=4 ;;
    "INFO")  LOG_LEVEL_NUM=3 ;;
    "WARN")  LOG_LEVEL_NUM=2 ;;
    "ERROR") LOG_LEVEL_NUM=1 ;;
    "FATAL") LOG_LEVEL_NUM=0 ;;
esac

# Funktionen
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Bestimme Farben und Level-Nummer
    local color=""
    local level_num=0
    
    case "$level" in
        "DEBUG") 
            color="${BLUE}"
            level_num=4
            ;;
        "INFO")
            color="${GREEN}"
            level_num=3
            ;;
        "WARN")
            color="${YELLOW}"
            level_num=2
            ;;
        "ERROR"|"FATAL")
            color="${RED}"
            level_num=1
            ;;
        *)
            color="${NC}"
            level_num=0
            ;;
    esac
    
    # Nur loggen, wenn Level hoch genug ist
    if [ $level_num -le $LOG_LEVEL_NUM ]; then
        # Log in Datei
        echo -e "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
        
        # Log in Konsole (nur wenn nicht stumm geschaltet)
        if [ -z "$SILENT" ]; then
            echo -e "${color}[${level}]${NC} ${message}"
        fi
    fi
    
    # Bei FATAL Fehler beenden
    if [ "$level" = "FATAL" ]; then
        exit 1
    fi
}

# Hilfsfunktionen
log_debug() { log "DEBUG" "$1"; }
log_info()  { log "INFO"  "$1"; }
log_warn()  { log "WARN"  "$1"; }
log_error() { log "ERROR" "$1"; }
log_fatal() { log "FATAL" "$1"; }

# Debug-Informationen
log_system_info() {
    log_debug "=== Systeminformationen ==="
    log_debug "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)"
    log_debug "Kernel: $(uname -r)"
    log_debug "Memory: $(free -h | grep Mem | awk '{print $2}')"
    log_debug "Disk: $(df -h / | tail -1 | awk '{print $2}')"
    log_debug "=========================="
}

# Funktion zum Messen der Ausführungszeit
start_timer() {
    local var_name=$1
    eval "${var_name}_START=$(date +%s.%N)"
}

stop_timer() {
    local var_name=$1
    local end_time=$(date +%s.%N)
    local start_time_var="${var_name}_START"
    local start_time=${!start_time_var}
    
    local duration=$(echo "$end_time - $start_time" | bc)
    log_info "Ausführungszeit für $var_name: ${duration} Sekunden"
    
    # Speichere die Dauer in einer globalen Variable
    eval "${var_name}_DURATION=$duration"
}

export -f log log_debug log_info log_warn log_error log_fatal log_system_info start_timer stop_timer

# Initiales Log
log_info "Logging-System initialisiert"
log_system_info
