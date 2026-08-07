#!/usr/bin/env bash
# Description: Build/deploy helper: build-server-bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

usage() {
  cat <<'EOF'
Usage: build-server-bundle.sh --binary PATH [options]

Build a distributable server bundle tarball (binary + admin web assets + ops files).

This is intended for Linux server deployments that should not require Bun/Rust toolchains
at install time.

Bundle contents:
- bin/quicfuscate
- share/admin-web/ (static assets)
- ops/quicfuscate-server.service
- ops/install-server-linux.sh
- ops/server-linux.default.toml

Required:
  --binary PATH        Path to a quicfuscate binary to bundle

Optional:
  --assets PATH        Admin web assets dir (default: ./assets/web-admin)
  --out-dir PATH       Output directory (default: ./scripts/out/build)
  --name NAME          Bundle base name (default: quicfuscate-server-bundle)

Example:
  ./scripts/build/build-server-bundle.sh \
    --binary ./target/release/quicfuscate \
    --assets ./assets/web-admin
EOF
}

die() { echo "error: $*" >&2; exit 1; }

main() {
  local binary=""
  local assets="$PROJECT_ROOT/assets/web-admin"
  local out_dir="$PROJECT_ROOT/scripts/out/build"
  local name="quicfuscate-server-bundle"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --binary) binary="${2:-}"; shift 2 ;;
      --assets) assets="${2:-}"; shift 2 ;;
      --out-dir) out_dir="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      *) die "unknown arg: $1" ;;
    esac
  done

  [[ -n "$binary" ]] || die "--binary is required"
  [[ -f "$binary" ]] || die "binary not found: $binary"
  [[ -f "$assets/index.html" ]] || die "assets missing: $assets/index.html (run ./scripts/build/build-web-admin.sh first)"
  [[ -f "$PROJECT_ROOT/scripts/install/quicfuscate-server.service" ]] || die "missing: $PROJECT_ROOT/scripts/install/quicfuscate-server.service"
  [[ -f "$PROJECT_ROOT/scripts/install/install-server-linux.sh" ]] || die "missing: $PROJECT_ROOT/scripts/install/install-server-linux.sh"
  [[ -f "$PROJECT_ROOT/config/server-linux.default.toml" ]] || die "missing: $PROJECT_ROOT/config/server-linux.default.toml"

  mkdir -p "$out_dir"

  # The release version has one owner and the bundle must not be able to ship without it.
  # Masking the extraction with `|| true` and substituting the literal "unknown" produced a
  # distributable tarball whose filename and provenance identified no validated product version,
  # which the release workflow's separate gate does not prevent when this helper is invoked
  # directly.
  local version
  version="$(awk -F '"' '/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/ {print $2; exit}' \
    "$PROJECT_ROOT/Cargo.toml")"
  [[ -n "$version" ]] || die "cannot read the release version from $PROJECT_ROOT/Cargo.toml"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$ ]] \
    || die "release version is not semantic versioned: $version"

  # Cross-check against the shared release-version owner so the bundle cannot disagree with the
  # audited product identity.
  if [[ -x "$PROJECT_ROOT/scripts/audits/verify-release-version.sh" ]]; then
    "$PROJECT_ROOT/scripts/audits/verify-release-version.sh" >/dev/null \
      || die "release version audit failed; refusing to stage a bundle"
  fi

  local ts
  ts="$(date +%Y%m%d_%H%M%S)"

  local stage
  stage="${out_dir}/${name}-${version}-${ts}"
  mkdir -p "$stage/bin" "$stage/share/admin-web" "$stage/ops"

  cp -a "$binary" "$stage/bin/quicfuscate"
  chmod 0755 "$stage/bin/quicfuscate"

  cp -a "$assets/." "$stage/share/admin-web/"
  cp -a "$PROJECT_ROOT/scripts/install/quicfuscate-server.service" "$stage/ops/quicfuscate-server.service"
  cp -a "$PROJECT_ROOT/scripts/install/install-server-linux.sh" "$stage/ops/install-server-linux.sh"
  cp -a "$PROJECT_ROOT/config/server-linux.default.toml" "$stage/ops/server-linux.default.toml"

  local tarball
  tarball="${out_dir}/${name}-${version}-${ts}.tar.gz"
  tar -C "$out_dir" -czf "$tarball" "$(basename "$stage")"

  echo "bundle: $tarball"
}

main "$@"
