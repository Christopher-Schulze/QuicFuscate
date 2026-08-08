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

# SHA-256 of a file, using whichever tool the host provides.
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "error: no sha256 tool available (need sha256sum or shasum)" >&2
    return 1
  fi
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

  # Prove the staged binary is actually usable before it is packaged. A bundle whose service
  # binary is not executable, or is not the binary that was built, only fails at install or
  # startup time on the operator's machine.
  local staged_binary="$stage/bin/quicfuscate"
  [[ -f "$staged_binary" ]] || die "staged binary is missing: $staged_binary"
  [[ -x "$staged_binary" ]] || die "staged binary is not executable: $staged_binary"

  local source_hash staged_hash
  source_hash="$(hash_file "$binary")"
  staged_hash="$(hash_file "$staged_binary")"
  [[ "$source_hash" == "$staged_hash" ]] \
    || die "staged binary does not match the built binary: $source_hash != $staged_hash"

  # Direct execution proof. Skipped only when the host cannot run the target architecture, which
  # is reported rather than silently treated as success.
  if [[ "$(uname -s)" == "Linux" ]]; then
    "$staged_binary" --version >/dev/null 2>&1 \
      || die "staged binary is not runnable: $staged_binary --version failed"
    echo "binary_execution=verified"
  else
    echo "binary_execution=unavailable host=$(uname -s) reason=cannot execute the Linux target"
  fi

  local tarball
  tarball="${out_dir}/${name}-${version}-${ts}.tar.gz"
  tar -C "$out_dir" -czf "$tarball" "$(basename "$stage")"

  # The packaged file must be the same executable that was verified above.
  local packaged_mode
  packaged_mode="$(tar -tvzf "$tarball" \
    | awk -v path="$(basename "$stage")/bin/quicfuscate" '$NF == path {print $1; exit}')"
  [[ -n "$packaged_mode" ]] || die "tarball does not contain bin/quicfuscate"
  [[ "$packaged_mode" == *x*x*x* ]] \
    || die "packaged binary is not executable in the tarball: mode $packaged_mode"

  echo "bundle: $tarball"
  echo "binary_sha256=$staged_hash"
  echo "packaged_mode=$packaged_mode"
}

main "$@"
