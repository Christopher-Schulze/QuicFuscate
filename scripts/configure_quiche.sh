#!/bin/bash
# Konfiguration für optimierte Quiche-Builds
set -e

# Farben
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[CONFIG]${NC} $1"
}

configure_quiche() {
    local quiche_dir="libs/patched_quiche/quiche"
    
    if [ ! -d "$quiche_dir" ]; then
        log "Quiche-Verzeichnis nicht gefunden: $quiche_dir"
        return 1
    fi
    
    log "Konfiguriere Quiche für optimierte Builds..."
    
    # Erstelle .cargo/config.toml im Quiche-Verzeichnis
    mkdir -p "$quiche_dir/.cargo"
    cat > "$quiche_dir/.cargo/config.toml" << 'EOF'
[build]
rustflags = [
    "-C", "opt-level=3",
    "-C", "lto=thin",
    "-C", "codegen-units=1",
    "-C", "panic=abort",
    "-C", "target-cpu=native",
    "-C", "link-arg=-fuse-ld=lld",
]

[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+ssse3,+sse4.1,+sse4.2,+avx,+avx2,+fma",
]

[target.aarch64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+sha2,+crc,+lse",
]
EOF

    # Aktualisiere Cargo.toml mit optimierten Features
    sed -i.bak 's/^default = \["boringssl-vendored"\]/default = ["ffi", "bbr", "pktinfo", "qlog"]\noptimized = ["ffi", "bbr", "pktinfo", "qlog", "boringssl-vendored"]/' "$quiche_dir/Cargo.toml"
    
    log "Konfiguration abgeschlossen!"
}

# Hauptfunktion
main() {
    configure_quiche
}

# Starte Skript
main "$@"
