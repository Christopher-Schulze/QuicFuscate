#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT="$SCRIPT_DIR/audit-result-contract.py"

run_case() {
  local name="$1" expected_status="$2" expected_rc="$3"
  shift 3
  local output rc actual_status actual_exit
  set +e
  output="$(python3 "$CONTRACT" "$@" 2>&1)"
  rc=$?
  set -e
  [[ "$rc" -eq "$expected_rc" ]] || {
    printf 'case %s returned rc=%s, expected %s\n%s\n' "$name" "$rc" "$expected_rc" "$output" >&2
    return 1
  }
  actual_status="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$output")"
  actual_exit="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["exit_code"])' "$output")"
  [[ "$actual_status" == "$expected_status" ]] || {
    printf 'case %s returned status=%s, expected %s\n' "$name" "$actual_status" "$expected_status" >&2
    return 1
  }
  [[ "$actual_exit" -eq "$expected_rc" ]] || {
    printf 'case %s reported exit_code=%s, expected %s\n' "$name" "$actual_exit" "$expected_rc" >&2
    return 1
  }
}

run_case "clean-strict" PASS 0 \
  --mode strict --critical 0 --check-failures 0 --unavailable 0
run_case "critical-finding" FAIL 1 \
  --mode strict --critical 1 --check-failures 0 --unavailable 0
run_case "command-failure" FAIL 1 \
  --mode strict --critical 0 --check-failures 1 --unavailable 0
run_case "missing-dependency-database" UNAVAILABLE 1 \
  --mode strict --critical 0 --check-failures 0 --unavailable 1
run_case "advisory-non-pass" FAIL 0 \
  --mode advisory --critical 1 --check-failures 1 --unavailable 0
run_case "advisory-unavailable" UNAVAILABLE 0 \
  --mode advisory --critical 0 --check-failures 0 --unavailable 1

printf '%s\n' 'PASS: audit result contract fixtures'
