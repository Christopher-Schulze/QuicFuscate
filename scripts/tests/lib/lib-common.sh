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

# ---------------- Fail-closed Cargo test discovery helpers ----------------

QF_CARGO_TEST_STATUS=""
QF_CARGO_TEST_COMMAND_STATUS=""
QF_CARGO_TEST_COUNT=0
QF_CARGO_TEST_REASON=""
QF_CARGO_TEST_COMMAND=""
QF_CARGO_TEST_TARGET=""
QF_CARGO_TEST_FEATURE_SET=""
QF_CARGO_TEST_FILTER=""
QF_CARGO_TEST_RAW_OUTPUT=""

qf_json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  printf '%s' "$value"
}

qf_cargo_test_feature_set() {
  local requested="${1:-}"
  requested="${requested// /,}"
  requested="${requested//,,/,}"
  local result=""
  local feature
  local -a feature_parts=()
  local IFS=','
  read -r -a feature_parts <<< "$requested"
  for feature in "${feature_parts[@]}"; do
    [[ -z "$feature" ]] && continue
    if [[ ",${result}," != *",${feature},"* ]]; then
      if [[ -n "$result" ]]; then result+=","; fi
      result+="$feature"
    fi
  done
  if [[ -z "$result" ]]; then
    result="rust-tests"
  elif [[ ",${result}," != *",rust-tests,"* ]]; then
    result+=",rust-tests"
  fi
  printf '%s' "$result"
}

qf_cargo_test_command_line() {
  local feature_set="$1"
  shift
  local -a args=("$@")
  local -a prefix=()
  local -a suffix=()
  local found_separator=0
  local arg
  for arg in "${args[@]}"; do
    if [[ "$arg" == "--" ]]; then
      found_separator=1
    fi
    if (( found_separator )); then
      suffix+=("$arg")
    else
      prefix+=("$arg")
    fi
  done
  local line="cargo test"
  for arg in "${prefix[@]}"; do line+=" $(printf '%q' "$arg")"; done
  line+=" --features $(printf '%q' "$feature_set")"
  if [[ -n "${JOBS:-}" ]]; then line+=" -j $(printf '%q' "$JOBS")"; fi
  for arg in "${suffix[@]}"; do line+=" $(printf '%q' "$arg")"; done
  printf '%s' "$line"
}

qf_cargo_test_metadata_from_args() {
  local -a raw_args=("$@")
  local -a args=()
  if [[ "${raw_args[0]:-}" == "test" ]]; then
    args=("${raw_args[@]:1}")
  else
    args=("${raw_args[@]}")
  fi

  local target="default"
  local test_target_count=0
  local feature_request="${CARGO_FEATURES:-}"
  local filter="<all>"
  local saw_lib=0
  local skip_next=0
  local arg
  local i
  for ((i=0; i<${#args[@]}; i++)); do
    arg="${args[$i]}"
    if (( skip_next )); then
      skip_next=0
      continue
    fi
    case "$arg" in
      --lib)
        saw_lib=1
        target="lib"
        ;;
      --test)
        ((test_target_count+=1))
        target="test:${args[$((i+1))]:-unknown}"
        skip_next=1
        ;;
      --bin)
        target="bin:${args[$((i+1))]:-unknown}"
        skip_next=1
        ;;
      --package)
        skip_next=1
        ;;
      --features)
        feature_request+=",${args[$((i+1))]:-}"
        skip_next=1
        ;;
      --features=*)
        feature_request+=",${arg#--features=}"
        ;;
    esac
  done
  if (( test_target_count > 1 )); then target="multi-test"; fi

  if (( saw_lib )); then
    skip_next=0
    for ((i=0; i<${#args[@]}; i++)); do
      arg="${args[$i]}"
      if [[ "$arg" == "--" ]]; then break; fi
      if (( skip_next )); then
        skip_next=0
        continue
      fi
      case "$arg" in
        --features|--test|--bin|--package)
          skip_next=1
          ;;
        --release|--quiet|--nocapture|--lib|-*)
          ;;
        *)
          filter="$arg"
          break
          ;;
      esac
    done
  fi

  QF_CARGO_TEST_TARGET="$target"
  QF_CARGO_TEST_FEATURE_SET="$(qf_cargo_test_feature_set "$feature_request")"
  QF_CARGO_TEST_FILTER="$filter"
  QF_CARGO_TEST_COMMAND="$(qf_cargo_test_command_line "$QF_CARGO_TEST_FEATURE_SET" "${args[@]}")"
}

qf_cargo_test_classify_output() {
  local mode="$1"
  local output_file="$2"
  local command_status="$3"
  local target="$4"
  local feature_set="$5"
  local filter="$6"
  local command="$7"
  local count=0
  if [[ "$mode" == "discovery" ]]; then
    count="$(awk '/^[[:space:]]*[^[:space:]].*: test[[:space:]]*$/ { count += 1 } END { print count + 0 }' "$output_file")"
  else
    count="$(awk '/^[[:space:]]*running[[:space:]]+[0-9]+[[:space:]]+tests?[[:space:]]*$/ { count += $2 } END { print count + 0 }' "$output_file")"
  fi

  QF_CARGO_TEST_STATUS="PASS"
  QF_CARGO_TEST_COMMAND_STATUS="$command_status"
  QF_CARGO_TEST_COUNT="$count"
  QF_CARGO_TEST_REASON=""
  QF_CARGO_TEST_COMMAND="$command"
  QF_CARGO_TEST_TARGET="$target"
  QF_CARGO_TEST_FEATURE_SET="$feature_set"
  QF_CARGO_TEST_FILTER="$filter"
  QF_CARGO_TEST_RAW_OUTPUT="$output_file"

  if [[ "$command_status" -eq 127 ]]; then
    QF_CARGO_TEST_STATUS="UNAVAILABLE"
    QF_CARGO_TEST_REASON="cargo_command_unavailable"
  elif [[ "$command_status" -ne 0 ]]; then
    QF_CARGO_TEST_STATUS="FAIL"
    QF_CARGO_TEST_REASON="cargo_test_${mode}_command_failed"
  elif [[ "$count" -le 0 ]]; then
    QF_CARGO_TEST_STATUS="FAIL"
    QF_CARGO_TEST_REASON="zero_${mode}_test_count"
  elif [[ "$mode" == "run" ]] && ! grep -Eq 'test result: ok\.' "$output_file"; then
    QF_CARGO_TEST_STATUS="FAIL"
    QF_CARGO_TEST_REASON="missing_successful_test_result"
  fi

  [[ "$QF_CARGO_TEST_STATUS" == "PASS" ]]
}

qf_cargo_test_discover() {
  local output_file="$1"
  local target="$2"
  local feature_set="$3"
  shift 3
  local -a args=("$@")
  local effective_features
  effective_features="$(qf_cargo_test_feature_set "$feature_set")"
  local command
  command="$(qf_cargo_test_command_line "$effective_features" "${args[@]}" -- --list)"
  mkdir -p "$(dirname "$output_file")"
  : > "$output_file"
  local command_status=0
  if CARGO_FEATURES="$effective_features" LOG_FILE="" JSON="" JSON_FILE="" run_cargo test "${args[@]}" -- --list > "$output_file" 2>&1; then
    command_status=0
  else
    command_status=$?
  fi
  qf_cargo_test_classify_output discovery "$output_file" "$command_status" "$target" "$effective_features" "<all>" "$command"
}

qf_cargo_test_run() {
  local output_file="$1"
  local target="$2"
  local feature_set="$3"
  local filter="$4"
  shift 4
  local -a args=("$@")
  local effective_features
  effective_features="$(qf_cargo_test_feature_set "$feature_set")"
  local command
  command="$(qf_cargo_test_command_line "$effective_features" "${args[@]}")"
  mkdir -p "$(dirname "$output_file")"
  : > "$output_file"
  local command_status=0
  if CARGO_FEATURES="$effective_features" LOG_FILE="" JSON="" JSON_FILE="" run_cargo test "${args[@]}" > "$output_file" 2>&1; then
    command_status=0
  else
    command_status=$?
  fi
  cat "$output_file"
  qf_cargo_test_classify_output run "$output_file" "$command_status" "$target" "$effective_features" "$filter" "$command"
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
