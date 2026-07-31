#!/usr/bin/env bash
# Prove TUN ingress fingerprint normalization on an isolated Linux netns pair.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${QF_FINGERPRINT_BINARY:-${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}}"
BASE_E2E="$SCRIPT_DIR/tun-e2e-netns.sh"
HOOK="$SCRIPT_DIR/fingerprint-runtime-proof-hook.sh"
OUTPUT_DIR="${QF_FINGERPRINT_OUTPUT_DIR:-$PROJECT_ROOT/scripts/out/tests/fingerprint-runtime-proof-$(date +%Y%m%d_%H%M%S)}"
PROFILES_TEXT="${QF_FINGERPRINT_PROFILES:-disabled,linux,windows,macos,android}"
ALLOW_EXISTING_RUNTIME="${QF_FINGERPRINT_ALLOW_EXISTING_RUNTIME:-0}"
NMAP_GATE="${QF_FINGERPRINT_NMAP_GATE:-record}"
BASELINE_PRODUCT_PIDS=""

fail() {
  echo "FAIL: fingerprint runtime proof: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

profile_pattern() {
  case "$1" in
    disabled|linux) printf '%s' 'linux|Linux' ;;
    windows) printf '%s' 'windows|Windows' ;;
    macos) printf '%s' 'mac[ -]?os|darwin|Mac OS' ;;
    android) printf '%s' 'android|Android|linux|Linux' ;;
    *) return 1 ;;
  esac
}

nmap_pattern() {
  case "$1" in
    disabled) printf '%s' 'none' ;;
    linux) printf '%s' 'linux|Linux' ;;
    windows) printf '%s' 'windows|Windows|microsoft|Microsoft' ;;
    macos) printf '%s' 'mac[ -]?os|Mac OS|darwin|Darwin|apple|Apple|iphone|iPhone|ipad|iPad' ;;
    android) printf '%s' 'android|Android' ;;
    *) return 1 ;;
  esac
}

profile_os() {
  case "$1" in
    disabled) printf '%s' linux ;;
    *) printf '%s' "$1" ;;
  esac
}

profile_cli_os() {
  case "$1" in
    macos) printf '%s' mac-os ;;
    *) profile_os "$1" ;;
  esac
}

profile_normalization() {
  if [ "$1" = disabled ]; then
    printf '%s' 0
  else
    printf '%s' 1
  fi
}

if [ "$(uname -s)" != Linux ]; then
  fail "requires Linux network namespaces"
fi
if [ "$(id -u)" -ne 0 ]; then
  fail "requires root"
fi
for command_name in flock ip nmap p0f pgrep python3 sha256sum tcpdump timeout; do
  require_command "$command_name"
done
[ -x "$BINARY" ] || fail "exact artifact is not executable: $BINARY"
[ -x "$BASE_E2E" ] || fail "base TUN harness is not executable: $BASE_E2E"
[ -x "$HOOK" ] || fail "fingerprint hook is not executable: $HOOK"
[ "${OUTPUT_DIR#/}" != "$OUTPUT_DIR" ] || fail "output directory must be absolute: $OUTPUT_DIR"
[ ! -e "$OUTPUT_DIR" ] || fail "refusing to overwrite existing output directory: $OUTPUT_DIR"
case "$ALLOW_EXISTING_RUNTIME" in
  0|1) ;;
  *) fail "QF_FINGERPRINT_ALLOW_EXISTING_RUNTIME must be 0 or 1" ;;
esac
case "$NMAP_GATE" in
  record|match) ;;
  *) fail "QF_FINGERPRINT_NMAP_GATE must be record or match" ;;
esac

mkdir -p "$OUTPUT_DIR"
BASELINE_PRODUCT_PIDS="$(pgrep -x quicfuscate 2>/dev/null | sort -n || true)"
if [ -n "$BASELINE_PRODUCT_PIDS" ] && [ "$ALLOW_EXISTING_RUNTIME" != 1 ]; then
  fail "pre-existing quicfuscate processes require QF_FINGERPRINT_ALLOW_EXISTING_RUNTIME=1"
fi
if ip netns list | grep -Eq '^(ns-srv|ns-cli)([[:space:]]|$)'; then
  fail "unowned ns-srv/ns-cli already exists"
fi

ARTIFACT_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
printf 'schema=quicfuscate.fingerprint-runtime-proof.v1\nartifact_sha256=%s\nbinary=%s\nprofiles=%s\n' \
  "$ARTIFACT_SHA256" "$BINARY" "$PROFILES_TEXT" > "$OUTPUT_DIR/run-manifest.txt"
printf 'p0f_version\n' > "$OUTPUT_DIR/tool-versions.txt"
p0f 2>&1 | head -1 >> "$OUTPUT_DIR/tool-versions.txt" || true
nmap --version | head -3 >> "$OUTPUT_DIR/tool-versions.txt"

IFS=',' read -r -a PROFILES <<< "$PROFILES_TEXT"
[ "${#PROFILES[@]}" -gt 0 ] || fail "no profiles selected"
for profile in "${PROFILES[@]}"; do
  [[ "$profile" =~ ^(disabled|linux|windows|macos|android)$ ]] \
    || fail "unsupported profile: $profile"
  run_dir="$OUTPUT_DIR/$profile"
  mkdir "$run_dir"
  export QF_E2E_HOOK_OUTPUT_DIR="$run_dir"
  export QF_E2E_HOOK_PROFILE="$profile"
  export QF_E2E_READY_HOOK="$HOOK"
  export QF_E2E_BINARY="$BINARY"
  export PROJECT_ROOT
  export QF_E2E_ALLOW_EXISTING_RUNTIME="$ALLOW_EXISTING_RUNTIME"
  export QF_E2E_LOCK_FILE="$run_dir/lock"
  RUN_TOKEN="qf543-${profile}-$$"
  export QF_E2E_ADMIN_SOCKET="/tmp/${RUN_TOKEN}.sock"
  export QF_E2E_QKEY_STORE="/tmp/${RUN_TOKEN}.json"
  PROFILE_OS="$(profile_os "$profile")"
  PROFILE_SERVER_OS="$(profile_cli_os "$profile")"
  PROFILE_NORMALIZATION="$(profile_normalization "$profile")"
  export QUICFUSCATE_OS="$PROFILE_OS"
  export QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION="$PROFILE_NORMALIZATION"
  export QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE=0
  export QF_E2E_SERVER_PROFILE=chrome
  export QF_E2E_SERVER_OS="$PROFILE_SERVER_OS"
  SERVER_CONFIG="$run_dir/server.toml"
  NORMALIZATION_TOML=false
  if [ "$PROFILE_NORMALIZATION" = 1 ]; then
    NORMALIZATION_TOML=true
  fi
  printf '[stealth]\ninitial_browser = "chrome"\ninitial_os = "%s"\nenable_network_fingerprint_normalization = %s\nsuppress_icmp_unreachable = false\n' \
    "$PROFILE_OS" "$NORMALIZATION_TOML" \
    > "$SERVER_CONFIG"
  export QF_E2E_SERVER_CONFIG="$SERVER_CONFIG"
  echo "=== fingerprint profile: $profile ==="
  if ! "$BASE_E2E" >"$run_dir/tun-e2e.log" 2>&1; then
    tail -120 "$run_dir/tun-e2e.log" >&2 || true
    fail "TUN E2E harness failed for profile $profile"
  fi
  cp /tmp/ns-srv.log "$run_dir/server.log"
  cp /tmp/ns-cli.log "$run_dir/client.log"
  p0f_regex="$(profile_pattern "$profile")"
  if ! grep -Eiq "$p0f_regex" "$run_dir/p0f.log" "$run_dir/p0f.stderr.log"; then
    printf 'p0f_gate=fail\n' > "$run_dir/classifier-gates.txt"
    fail "p0f did not classify profile $profile; see $run_dir/p0f.log"
  fi
  nmap_regex="$(nmap_pattern "$profile")"
  if [ "$profile" = disabled ]; then
    nmap_match_status=not-applicable
  elif grep -Eiq "$nmap_regex" "$run_dir/nmap.log"; then
    nmap_match_status=pass
  else
    nmap_match_status=not-matched
  fi
  if [ "$NMAP_GATE" = match ]; then
    nmap_gate_status="$nmap_match_status"
  else
    nmap_gate_status=recorded
  fi
  printf 'p0f_gate=pass\nnmap_gate=%s\nnmap_match=%s\nnmap_expected=%s\nnmap_mode=%s\nnmap_exit=%s\n' \
    "$nmap_gate_status" "$nmap_match_status" "$nmap_regex" "$NMAP_GATE" \
    "$(tr -d '[:space:]' < "$run_dir/nmap.status")" \
    > "$run_dir/classifier-gates.txt"
  if [ "$NMAP_GATE" = match ] && [ "$nmap_gate_status" != pass ]; then
    fail "nmap active OS result did not match profile $profile"
  fi
done

FINAL_PRODUCT_PIDS="$(pgrep -x quicfuscate 2>/dev/null | sort -n || true)"
[ "$FINAL_PRODUCT_PIDS" = "$BASELINE_PRODUCT_PIDS" ] \
  || fail "product process set changed: before=[$BASELINE_PRODUCT_PIDS] after=[$FINAL_PRODUCT_PIDS]"
if ip netns list | grep -Eq '^(ns-srv|ns-cli)([[:space:]]|$)'; then
  fail "network namespace residue remains after fingerprint proof"
fi

printf 'PASS: fingerprint packet/capture/p0f proof complete; active nmap results recorded\nartifact_sha256=%s\nevidence_dir=%s\n' \
  "$ARTIFACT_SHA256" "$OUTPUT_DIR"
