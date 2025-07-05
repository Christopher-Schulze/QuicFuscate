#!/bin/bash
# Update Dependencies Script
set -e

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[UPDATE]${NC} $1"
}

update_rust() {
    log "Aktualisiere Rust-Toolchain..."
    rustup update
}

update_cargo_packages() {
    log "Aktualisiere Cargo-Pakete..."
    cargo update
    
    # Aktualisiere spezifische Werkzeuge
    local tools=(
        "cargo-audit"
        "cargo-udeps"
        "cargo-outdated"
        "cargo-geiger"
    )
    
    for tool in "${tools[@]}"; do
        log "Aktualisiere $tool..."
        cargo install $tool --force || true
    done
}

update_system_deps() {
    log "Aktualisiere Systemabhängigkeiten..."
    
    # Für macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew update
            brew upgrade
        fi
    # Für Ubuntu/Debian
    elif [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt upgrade -y
    fi
}

check_vulnerabilities() {
    log "Prüfe auf Sicherheitslücken..."
    if command -v cargo-audit &> /dev/null; then
        cargo audit
    else
        log "cargo-audit nicht installiert. Installiere..."
        cargo install cargo-audit
        cargo audit
    fi
}

main() {
    log "Starte Update der Abhängigkeiten..."
    
    update_rust
    update_cargo_packages
    update_system_deps
    check_vulnerabilities
    
    log "Alle Abhängigkeiten wurden erfolgreich aktualisiert!"
}

main "$@"
