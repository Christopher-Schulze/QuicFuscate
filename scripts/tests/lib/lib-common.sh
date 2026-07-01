#!/usr/bin/env bash
# Description: Shell utility script: lib-common.
set -Eeuo pipefail

# Common helpers for QuicFuscate scripts

if [[ -n "${QUICFUSCATE_DEBUG_SCRIPTS:-}" ]]; then
  set -x
fi

COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'

__ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()    { echo -e "[$(__ts)] ${COLOR_BLUE}>${COLOR_RESET} $*"; }
info()   { echo -e "[$(__ts)] ${COLOR_GREEN}INFO${COLOR_RESET} $*"; }
warn()   { echo -e "[$(__ts)] ${COLOR_YELLOW}WARN${COLOR_RESET} $*"; }
error()  { echo -e "[$(__ts)] ${COLOR_RED}ERROR${COLOR_RESET} $*" >&2; }
die()    { error "$*"; exit 1; }

trap 'error "Command failed: ${BASH_COMMAND}"' ERR

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

require_base64_tool() { require_cmd base64; }

require_sha256_tool() {
  if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    die "Missing required command: shasum or sha256sum"
  fi
}

require_base64_and_sha256_tools() {
  require_base64_tool
  require_sha256_tool
}

set_base64_decode_flag() {
  local var_name="${1:-DEC}"
  local flag="-D"
  if base64 --help 2>&1 | grep -q '\-d'; then
    flag="-d"
  fi
  printf -v "$var_name" '%s' "$flag"
}

set_sha256_cmd() {
  local var_name="${1:-HASH}"
  require_sha256_tool
  local hash_cmd="sha256sum"
  if command -v shasum >/dev/null 2>&1; then
    hash_cmd="shasum -a 256"
  fi
  printf -v "$var_name" '%s' "$hash_cmd"
}

detect_os() {
  case "$(uname -s)" in
    Linux*) echo linux;;
    Darwin*) echo macos;;
    *) echo unknown;;
  esac
}

detect_arch() { uname -m; }

cpu_name() {
  if [[ $(detect_os) == macos ]]; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown-cpu"
  else
    lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +| +$/,"",$2); print $2; exit}' || echo "unknown-cpu"
  fi
}

cpu_cores() {
  nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1
}

mem_total() {
  if command -v free >/dev/null 2>&1; then
    free -h | awk '/Mem:/ {print $2; exit}'
  else
    local bytes
    bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    if [[ "$bytes" != 0 ]]; then awk -v b="$bytes" 'BEGIN{printf "%.1fGB", b/1024/1024/1024}'; else echo "unknown"; fi
  fi
}

disk_free_kib() {
  local path="${1:-.}"
  df -Pk "$path" | awk 'NR==2 {print $4; exit}'
}

has_min_disk_gib() {
  local min_gib="$1"
  local path="${2:-.}"
  local free_kib
  free_kib="$(disk_free_kib "$path")"
  [[ "$free_kib" =~ ^[0-9]+$ ]] || return 1
  (( free_kib >= min_gib * 1024 * 1024 ))
}

warn_if_low_disk_for_step() {
  local min_gib="$1"
  local step="$2"
  local path="${3:-.}"
  if has_min_disk_gib "$min_gib" "$path"; then
    return 0
  fi
  local free_kib
  free_kib="$(disk_free_kib "$path" 2>/dev/null || echo 0)"
  local free_gib
  free_gib="$(awk -v k="$free_kib" 'BEGIN { printf "%.1f", k / 1024 / 1024 }')"
  warn "Skipping ${step}: requires >=${min_gib}GiB free disk, found ${free_gib}GiB at ${path}"
  return 1
}

print_system_banner() {
  echo "==============================================================="
  echo "  System: $(uname -a)"
  echo "  CPU:   $(cpu_name)"
  echo "  Cores: $(cpu_cores)"
  echo "  Memory: $(mem_total)"
  echo "==============================================================="
}

# Prepare artifacts directory
prepare_artifacts() {
  local dir="$1"
  mkdir -p "$dir"
  echo "$dir"
}

# Run a command, tee output to file if LOG_FILE set
run() {
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "DRY-RUN: $*"
    return 0
  fi
  local __start=$(date +%s)
  local __rc=0
  if [[ -n "${LOG_FILE:-}" ]]; then
    "$@" 2>&1 | tee -a "$LOG_FILE"; __rc=${PIPESTATUS[0]}
  else
    "$@"; __rc=$?
  fi
  local __dur=$(( $(date +%s) - __start ))
  # Optional JSON logging per command
  if [[ -n "${JSON:-${JSON_FILE:-}}" ]]; then
    local __jf="${JSON:-${JSON_FILE}}"
    if [[ -f "$__jf" ]]; then
      if [[ -z "${JSON_FIRST_RUN:-}" ]]; then JSON_FIRST_RUN=1; fi
      if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$__jf"; fi
      JSON_FIRST_RUN=0
      local __cmd
      __cmd=$(printf '%q ' "$@" | sed 's/\s$//')
      echo -n '  {"cmd":'"\"$__cmd\""',"rc":'"$__rc"',"duration_sec":'"$__dur"'}' >> "$__jf"
    fi
  fi
  return $__rc
}

# Run cargo with common environment knobs
run_cargo() {
  local cargo_args=("$@")
  local flags=( )
  [[ -n "${RUSTFLAGS_EXTRA:-}" ]] && flags+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}")
  [[ -n "${CARGO_TARGET_DIR:-}" ]] && flags+=("CARGO_TARGET_DIR=${CARGO_TARGET_DIR}")
  if [[ "${cargo_args[0]:-}" == "test" ]]; then
    if [[ -z "${CARGO_FEATURES:-}" ]]; then
      CARGO_FEATURES="rust-tests"
    elif [[ ",${CARGO_FEATURES}," != *",rust-tests,"* ]]; then
      CARGO_FEATURES="${CARGO_FEATURES},rust-tests"
    fi
  fi
  local suffix=( )
  for i in "${!cargo_args[@]}"; do
    if [[ "${cargo_args[$i]}" == "--" ]]; then
      suffix=("${cargo_args[@]:$i}")
      cargo_args=("${cargo_args[@]:0:$i}")
      break
    fi
  done
  if [[ -n "${CARGO_FEATURES:-}" ]]; then
    cargo_args+=("--features" "${CARGO_FEATURES}")
  fi
  if [[ -n "${JOBS:-}" ]]; then
    cargo_args+=("-j" "${JOBS}")
  fi
  if [[ ${#suffix[@]} -gt 0 ]]; then
    cargo_args+=("${suffix[@]}")
  fi
  run env "${flags[@]}" cargo "${cargo_args[@]}"
}

usage_common_flags() {
  cat <<USAGE
  Common flags:
    --output-dir DIR      Artifacts directory (default: scripts/out/<category>/<script>-<ts>)
    --jobs N              Cargo parallel jobs
    --features STR        Extra cargo features (space or comma separated)
    --rustflags STR       Extra RUSTFLAGS (e.g., -C target-cpu=native)
    --fast                Reduce workload (quick smoke subset)
    --dry-run             Print commands without executing
    --verbose             Set QUICFUSCATE_DEBUG_SCRIPTS=1
USAGE
}

# ---------------- JSON + System Meta helpers ----------------

sys_os() { uname -s; }
sys_arch() { uname -m; }
sys_cpu_cores() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }
sys_mem_gb() {
  if command -v free >/dev/null 2>&1; then
    free -b | awk '/Mem:/ {printf "%.1f", $2/1024/1024/1024}';
  else
    local bytes; bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    awk -v b="$bytes" 'BEGIN{printf "%.1f", (b/1024/1024/1024)}'
  fi
}

# Writes a unified JSON header with meta/system info
# Usage: json_begin FILE SUITE_NAME
json_begin() {
  local f="$1"; local suite="$2"
  mkdir -p "$(dirname "$f")"
  {
    echo '{'
    echo '  "schema": "quicfuscate.v1",'
    echo '  "tool": "quicfuscate",'
    echo '  "suite": '"\"$suite\""','
    echo '  "timestamp": '"\"$(date -Iseconds)\""','
    echo '  "system": {'
    echo '    "os": '"\"$(sys_os)\""','
    echo '    "arch": '"\"$(sys_arch)\""','
    echo '    "cpu_cores": '"$(sys_cpu_cores)"','
    echo '    "memory_gb": '"\"$(sys_mem_gb)\""''
    echo '  },'
    echo '  "items": ['
  } > "$f"
}

# Closes the JSON document started by json_begin
json_end() {
  local f="$1"
  echo -e "\n  ]\n}" >> "$f"
}
