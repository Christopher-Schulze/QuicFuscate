#!/bin/bash
# Quiche Update & Optimize Script
set -e

# Konfiguration
QUICHE_REPO="https://github.com/cloudflare/quiche.git"
TARGET_DIR="libs/patched_quiche"
PATCH_DIR="patches"

# Farben für die Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Hilfsfunktionen
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Prüfe Voraussetzungen
check_requirements() {
    log_info "Prüfe Voraussetzungen..."
    command -v cargo >/dev/null 2>&1 || log_error "Rust/Cargo nicht gefunden!"
    command -v git >/dev/null 2>&1 || log_error "Git nicht gefunden!"
    command -v make >/dev/null 2>&1 || log_warn "make nicht gefunden, Build könnte fehlschlagen"
    command -v cmake >/dev/null 2>&1 || log_warn "cmake nicht gefunden, Build könnte fehlschlagen"
}

# Erstelle Verzeichnisstruktur
setup_dirs() {
    mkdir -p "$TARGET_DIR"
    mkdir -p "$PATCH_DIR"
}

# Aktualisiere quiche
update_quiche() {
    log_info "Aktualisiere quiche..."
    
    if [ ! -d "$TARGET_DIR/.git" ]; then
        git clone --depth 1 "$QUICHE_REPO" "$TARGET_DIR" || log_error "Quiche konnte nicht geklont werden"
    else
        (cd "$TARGET_DIR" && git fetch --all && git reset --hard origin/HEAD) || log_error "Quiche konnte nicht aktualisiert werden"
    fi
}

# Wende Patches an
apply_patches() {
    log_info "Wende Patches an..."
    
    if [ -d "$PATCH_DIR" ] && [ "$(ls -A $PATCH_DIR/*.patch 2>/dev/null)" ]; then
        for patch in "$PATCH_DIR"/*.patch; do
            log_info "Wende Patch an: $(basename "$patch")"
            (cd "$TARGET_DIR" && git apply --whitespace=nowarn "../$patch") || log_warn "Patch fehlgeschlagen: $patch"
        done
    else
        log_warn "Keine Patches gefunden in $PATCH_DIR"
    fi
}

# Konfiguriere Build
configure_build() {
    log_info "Konfiguriere Build..."
    
    # Erstelle .cargo/config.toml falls nicht vorhanden
    mkdir -p "$TARGET_DIR/.cargo"
    cat > "$TARGET_DIR/.cargo/config.toml" << EOF
[build]
rustflags = [
    "-C", "target-cpu=native",
    "-C", "opt-level=3",
    "-C", "lto=yes",
    "-C", "codegen-units=1",
    "-C", "panic=abort",
    "-C", "link-arg=-fuse-ld=lld",
]

[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+ssse3,+sse4.1,+sse4.2,+avx,+avx2",
]

[target.aarch64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+aes,+sha2",
]
EOF

    # Aktualisiere Cargo.toml mit Optimierungen
    sed -i.bak 's/^default = \["boringssl-vendored"\]/default = ["ffi", "bbr", "pktinfo", "qlog"]\noptimized = ["ffi", "bbr", "pktinfo", "qlog", "boringssl-vendored"]/' "$TARGET_DIR/Cargo.toml"
}

# Baue optimierte Version
build_optimized() {
    log_info "Baue optimierte Version..."
    
    export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=yes -C codegen-units=1"
    export CARGO_PROFILE_RELEASE_LTO=true
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    
    (cd "$TARGET_DIR" && \
     cargo build --release --features "ffi bbr pktinfo qlog boringssl-vendored") || log_error "Build fehlgeschlagen"
}

# Hauptfunktion
main() {
    check_requirements
    setup_dirs
    update_quiche
    apply_patches
    configure_build
    build_optimized
    
    log_info "Quiche erfolgreich aktualisiert und optimiert!"
}

# Starte Skript
main "$@"
