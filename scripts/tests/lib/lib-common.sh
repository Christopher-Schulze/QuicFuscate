#!/usr/bin/env bash
# Description: Shell utility script: lib-common.
# shellcheck disable=SC2034
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

# Prepare an artifact directory without allowing an implicit rerun to reuse it.
prepare_artifacts() {
  local dir="$1"
  mkdir -p "$dir"
  if find "$dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    die "refusing to reuse non-empty artifact directory: $dir; choose a new directory"
  fi
  echo "$dir"
}

# Run a command, tee output to file if LOG_FILE set
run() {
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "DRY-RUN: $*"
    return 0
  fi
  local __start
  __start="$(date +%s)"
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
      qf_json_append_object "$__jf" \
        "argv=json:$(qf_json_array "$@")" \
        "environment=json:$(qf_json_environment)" \
        "rc=int:$__rc" \
        "duration_sec=int:$__dur"
    fi
  fi
  return "$__rc"
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

run_cargo_with_env() {
  local -a env_assignments=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    env_assignments+=("$1")
    shift
  done
  if [[ "${1:-}" != "--" ]]; then
    error "run_cargo_with_env requires -- before cargo arguments"
    return 2
  fi
  shift
  local assignment
  for assignment in "${env_assignments[@]}"; do
    if ! [[ "$assignment" =~ ^[a-zA-Z_][a-zA-Z0-9_]*= ]]; then
      error "Invalid environment assignment: ${assignment}"
      return 2
    fi
    if ! validate_control_free_value "environment assignment" "$assignment" 8192; then
      return 2
    fi
  done
  (
    for assignment in "${env_assignments[@]}"; do
      # The full assignment is validated and exported without eval so values keep their argv identity.
      # shellcheck disable=SC2163
      export "$assignment"
    done
    run_cargo "$@"
  )
}

validate_control_free_value() {
  local label="$1"
  local value="$2"
  local max_length="${3:-4096}"
  if [[ "$value" =~ [[:cntrl:]] ]]; then
    error "${label} contains control characters"
    return 2
  fi
  if (( ${#value} > max_length )); then
    error "${label} exceeds the ${max_length}-character limit"
    return 2
  fi
}

validate_positive_int() {
  local label="$1"
  local value="$2"
  local max_value="$3"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    error "${label} must be a positive decimal integer"
    return 2
  fi
  local numeric_value=$((10#$value))
  if (( numeric_value < 1 || numeric_value > max_value )); then
    error "${label} must be between 1 and ${max_value}"
    return 2
  fi
}

validate_nonnegative_int() {
  local label="$1"
  local value="$2"
  local max_value="$3"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    error "${label} must be a non-negative decimal integer"
    return 2
  fi
  local numeric_value=$((10#$value))
  if (( numeric_value > max_value )); then
    error "${label} must be at most ${max_value}"
    return 2
  fi
}

validate_feature_list() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    return 0
  fi
  if ! [[ "$value" =~ ^[[:space:]]*[A-Za-z0-9_.-]+([[:space:],]+[A-Za-z0-9_.-]+)*[[:space:]]*$ ]]; then
    error "${label} contains an invalid feature name or separator"
    return 2
  fi
}

validate_harness_inputs() {
  local output_dir="$1"
  local feature_set="${2:-}"
  local rustflags="${3:-}"
  local jobs="${4:-}"
  local valid=0
  if ! validate_control_free_value "output directory" "$output_dir" 4096; then valid=2; fi
  if ! validate_feature_list "cargo features" "$feature_set"; then valid=2; fi
  if ! validate_control_free_value "RUSTFLAGS_EXTRA" "$rustflags" 8192; then valid=2; fi
  if [[ -n "$jobs" ]] && ! validate_positive_int "jobs" "$jobs" 64; then valid=2; fi
  return "$valid"
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
QF_CARGO_TEST_ARGV_JSON="[]"

qf_json_escape() {
  python3 - "${1:-}" <<'PY'
import json
import sys

encoded = json.dumps(sys.argv[1], ensure_ascii=False)
sys.stdout.write(encoded[1:-1])
PY
}

qf_json_array() {
  python3 - "$@" <<'PY'
import json
import sys

sys.stdout.write(json.dumps(sys.argv[1:], ensure_ascii=False, separators=(",", ":")))
PY
}

qf_json_environment() {
  local -a pairs=()
  local name
  for name in RUSTFLAGS RUSTFLAGS_EXTRA CARGO_FEATURES CARGO_TARGET_DIR JOBS CARGO_BUILD_JOBS \
    QUICFUSCATE_ARTIFACT_POLICY QUICFUSCATE_DEBUG_SCRIPTS; do
    if [[ -n "${!name+x}" ]]; then
      pairs+=("$name=${!name}")
    fi
  done
  if [[ "${#pairs[@]}" -eq 0 ]]; then
    pairs=(__QF_EMPTY_ENVIRONMENT__)
  fi
  python3 - "${pairs[@]}" <<'PY'
import json
import sys

environment = {}
for item in sys.argv[1:]:
    if not item or item == "__QF_EMPTY_ENVIRONMENT__":
        continue
    name, value = item.split("=", 1)
    environment[name] = value
sys.stdout.write(json.dumps(environment, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
PY
}

qf_json_environment_with_assignments() {
  local base_environment
  base_environment="$(qf_json_environment)"
  python3 - "$base_environment" "$@" <<'PY'
import json
import re
import sys

environment = json.loads(sys.argv[1])
for assignment in sys.argv[2:]:
    name, value = assignment.split("=", 1)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise SystemExit(f"invalid environment assignment: {name}")
    environment[name] = value
sys.stdout.write(json.dumps(environment, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
PY
}

qf_json_validate_file() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    with path.open(encoding="utf-8") as handle:
        json.load(handle)
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    print(f"invalid JSON artifact {path}: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

qf_json_append_raw() {
  local file="$1"
  local raw="$2"
  if ! python3 - "$raw" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
except json.JSONDecodeError as error:
    print(f"invalid JSON item: {error}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(value, dict):
    print("JSON artifact items must be objects", file=sys.stderr)
    raise SystemExit(1)
PY
  then
    return 1
  fi
  if [[ "${JSON_FIRST_RUN:-1}" -eq 0 ]]; then
    printf ',\n' >> "$file"
  fi
  JSON_FIRST_RUN=0
  printf '  %s' "$raw" >> "$file"
}

qf_json_object_from_pairs() {
  python3 - "$@" <<'PY'
import json
import math
import sys

def parse_value(raw):
    if raw.startswith("json:"):
        return json.loads(raw[5:])
    if raw.startswith("int:"):
        return int(raw[4:])
    if raw.startswith("float:"):
        value = float(raw[6:])
        if not math.isfinite(value):
            raise ValueError("non-finite float")
        return value
    if raw.startswith("bool:"):
        value = raw[5:].lower()
        if value not in {"true", "false"}:
            raise ValueError("boolean must be true or false")
        return value == "true"
    if raw == "null":
        return None
    return raw

result = {}
try:
    for item in sys.argv[1:]:
        key, raw = item.split("=", 1)
        if not key:
            raise ValueError("JSON item key cannot be empty")
        result[key] = parse_value(raw)
except (ValueError, json.JSONDecodeError) as error:
    print(f"invalid JSON object field: {error}", file=sys.stderr)
    raise SystemExit(1) from error
sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY
}

qf_json_append_object() {
  local file="$1"
  shift
  local -a fields=("$@")
  local field key
  local has_argv=0
  local has_environment=0
  for field in "${fields[@]}"; do
    key="${field%%=*}"
    [[ "$key" == "argv" ]] && has_argv=1
    [[ "$key" == "environment" ]] && has_environment=1
  done
  (( has_argv )) || fields+=("argv=json:[]")
  (( has_environment )) || fields+=("environment=json:{}")
  local object_json
  if ! object_json="$(qf_json_object_from_pairs "${fields[@]}")"; then
    return 1
  fi
  qf_json_append_raw "$file" "$object_json"
}

qf_json_write_object_file() {
  local file="$1"
  shift
  local object_json
  if ! object_json="$(qf_json_object_from_pairs "$@")"; then
    return 1
  fi
  qf_json_write_raw_file "$file" "$object_json"
}

qf_json_write_raw_file() {
  local file="$1"
  local raw="$2"
  local run_id; run_id="$(qf_artifact_run_id)"
  local policy; policy="$(qf_artifact_policy)"
  local normalized
  if ! normalized="$(python3 - "$raw" "$run_id" "$file" "$policy" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
except json.JSONDecodeError as error:
    print(f"invalid JSON artifact: {error}", file=sys.stderr)
    raise SystemExit(1) from error

if isinstance(value, dict) and "artifact" not in value:
    value["artifact"] = {
        "run_id": sys.argv[2],
        "path": sys.argv[3],
        "ownership": "create-new",
        "replacement": sys.argv[4],
    }

sys.stdout.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
PY
)"; then
    return 1
  fi
  mkdir -p "$(dirname "$file")"
  qf_artifact_prepare_file "$file" "$run_id" >/dev/null
  local temp_file; temp_file="$(mktemp "${file}.tmp.XXXXXX")"
  printf '%s\n' "$normalized" > "$temp_file"
  if ! qf_json_validate_file "$temp_file"; then
    rm -f -- "$temp_file"
    return 1
  fi
  if [[ -e "$file" || -L "$file" ]]; then
    rm -f -- "$temp_file"
    die "artifact path appeared during JSON write: $file"
  fi
  mv -- "$temp_file" "$file" || {
    rm -f -- "$temp_file"
    die "could not install JSON artifact: $file"
  }
}

qf_artifact_run_id() {
  python3 - <<'PY'
import uuid

print(uuid.uuid4().hex)
PY
}

qf_artifact_policy() {
  local policy="${QUICFUSCATE_ARTIFACT_POLICY:-create-new}"
  case "$policy" in
    create-new|replace-with-backup) printf '%s' "$policy";;
    *) die "invalid QUICFUSCATE_ARTIFACT_POLICY: $policy";;
  esac
}

qf_artifact_prepare_file() {
  local file="$1"
  local run_id="$2"
  local policy
  policy="$(qf_artifact_policy)"
  if [[ ! -e "$file" && ! -L "$file" ]]; then
    return 0
  fi
  if [[ "$policy" != replace-with-backup ]]; then
    die "refusing to overwrite existing artifact path: $file; choose a new output directory or set QUICFUSCATE_ARTIFACT_POLICY=replace-with-backup"
  fi
  local backup="${file}.previous-${run_id}"
  local backup_suffix=0
  while [[ -e "$backup" || -L "$backup" ]]; do
    backup_suffix=$((backup_suffix + 1))
    backup="${file}.previous-${run_id}-${backup_suffix}"
  done
  mv -- "$file" "$backup" || die "could not preserve existing artifact before replacement: $file"
  printf '%s' "$backup"
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

qf_cargo_test_command_argv_json() {
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
  local -a command=(cargo test "${prefix[@]}" --features "$feature_set")
  if [[ -n "${JOBS:-}" ]]; then
    command+=(-j "$JOBS")
  fi
  command+=("${suffix[@]}")
  qf_json_array "${command[@]}"
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
  QF_CARGO_TEST_ARGV_JSON="$(qf_cargo_test_command_argv_json "$QF_CARGO_TEST_FEATURE_SET" "${args[@]}")"
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
  QF_CARGO_TEST_ARGV_JSON="$(qf_cargo_test_command_argv_json "$effective_features" "${args[@]}" -- --list)"
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
  QF_CARGO_TEST_ARGV_JSON="$(qf_cargo_test_command_argv_json "$effective_features" "${args[@]}")"
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
  local run_id
  run_id="$(qf_artifact_run_id)"
  qf_artifact_prepare_file "$f" "$run_id" >/dev/null
  local policy
  policy="$(qf_artifact_policy)"
  local timestamp; timestamp="$(date -Iseconds)"
  local source_revision; source_revision="$(git rev-parse HEAD 2>/dev/null || printf '%s' unknown)"
  local temp_file; temp_file="$(mktemp "${f}.tmp.XXXXXX")"
  {
    printf '{\n'
    printf '  "schema": "quicfuscate.v1",\n'
    printf '  "tool": "quicfuscate",\n'
    printf '  "suite": "%s",\n' "$(qf_json_escape "$suite")"
    printf '  "timestamp": "%s",\n' "$(qf_json_escape "$timestamp")"
    printf '  "artifact": {"run_id":"%s","path":"%s","ownership":"create-new","replacement":"%s","source_revision":"%s"},\n' \
      "$(qf_json_escape "$run_id")" "$(qf_json_escape "$f")" \
      "$(qf_json_escape "$policy")" "$(qf_json_escape "$source_revision")"
    printf '  "system": {\n'
    printf '    "os": "%s",\n' "$(qf_json_escape "$(sys_os)")"
    printf '    "arch": "%s",\n' "$(qf_json_escape "$(sys_arch)")"
    printf '    "cpu_cores": %s,\n' "$(sys_cpu_cores)"
    printf '    "memory_gb": "%s"\n' "$(qf_json_escape "$(sys_mem_gb)")"
    printf '  },\n'
    printf '  "items": [\n'
  } > "$temp_file" || {
    rm -f -- "$temp_file"
    die "could not initialize JSON artifact: $f"
  }
  if [[ -e "$f" || -L "$f" ]]; then
    rm -f -- "$temp_file"
    die "artifact path appeared during initialization: $f"
  fi
  mv -- "$temp_file" "$f" || {
    rm -f -- "$temp_file"
    die "could not install JSON artifact: $f"
  }
  JSON_FIRST_RUN=1
}

# Closes the JSON document started by json_begin
json_end() {
  local f="$1"
  printf '\n  ]\n}\n' >> "$f"
  qf_json_validate_file "$f"
}
