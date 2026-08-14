#!/usr/bin/env bash
# Description: Utility script: util-run-full-suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=1; ONLY="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --only) ONLY="$2"; shift;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--fast] [--full] [--only SCOPES]"; exit 0;;
    *) break;;
  esac; shift
done

validate_scope_selection() {
  qf_validate_scope_selection "$ONLY" "build,core,privilege,desktop,transport,fec,stealth,crypto,optimization,security,frontend,e2e,performance,audits,benchmarks,amx"
}

scope_selected() {
  qf_scope_selected "$ONLY" "$1"
}

validate_scope_selection
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/full-test-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

log "Running full suite into $OUTPUT_DIR"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_full_suite"

qf_json_append_object "$JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "selected_scopes=$ONLY" \
  "command_status=int:0" \
  "raw_output="

run_stealth_bench_preflight() {
  local log_path="$1"
  set +e
  cargo bench --no-run --features benches >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    qf_json_append_object "$JSON" \
      "name=bench-stealth-preflight" "status=PASS" "result=PASS" \
      "command_rc=int:$rc" "evidence=$log_path"
    return 0
  fi
  qf_json_append_object "$JSON" \
    "name=bench-stealth-preflight" "status=FAIL" "result=FAIL" \
    "command_rc=int:$rc" "evidence=$log_path"
  warn "Stealth benchmark preflight failed with rc=$rc; see $log_path"
  return 1
}

run_amx_proof_lane() {
  local output_dir="$1"
  local rc=0
  set +e
  "$SCRIPT_DIR/../suites/test-amx-proof.sh" --output-dir "$output_dir"
  rc=$?
  set -e
  case "$rc" in
    0)
      qf_json_append_object "$JSON" \
        "name=amx-proof-lane" "status=PASS" "result=PASS" \
        "command_rc=int:$rc" "evidence=$output_dir/results.json"
      return 0
      ;;
    2)
      qf_json_append_object "$JSON" \
        "name=amx-proof-lane" "status=UNAVAILABLE" "result=UNAVAILABLE" \
        "command_rc=int:$rc" "evidence=$output_dir/results.json"
      warn "AMX proof lane is explicitly unavailable on this host; see $output_dir/results.json"
      return 0
      ;;
    *)
      qf_json_append_object "$JSON" \
        "name=amx-proof-lane" "status=FAIL" "result=FAIL" \
        "command_rc=int:$rc" "evidence=$output_dir/results.json"
      return "$rc"
      ;;
  esac
}

if [[ "${QUICFUSCATE_BENCH_PREFLIGHT_CONTRACT_TEST:-0}" == "1" ]]; then
  BENCH_STEALTH_PREFLIGHT_LOG="$OUTPUT_DIR/bench-stealth-preflight.log"
  if run_stealth_bench_preflight "$BENCH_STEALTH_PREFLIGHT_LOG"; then
    json_end "$JSON"
    exit 0
  fi
  json_end "$JSON"
  exit 1
fi

run_selected_scope() {
  local scope="$1"
  case "$scope" in
    build)
      if (( FAST )); then
        run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
      else
        run "$SCRIPT_DIR/../build/build-clippy-matrix.sh"
        run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
      fi
      ;;
    core)
      if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_FULL_TEST_COMPILE_GIB:-10}" "scoped core test binary precompile" "$PROJECT_ROOT"; then
        run_cargo test --no-run
      fi
      if (( FAST )); then
        run_cargo test --lib -- --nocapture
      else
        run_cargo test --lib
        run_cargo test --doc
      fi
      run "$SCRIPT_DIR/../suites/test-core.sh" --output-dir "$OUTPUT_DIR/tests-core"
      ;;
    privilege)
      run "$SCRIPT_DIR/../suites/test-privilege-memory-tls-proof.sh" \
        --output-dir "$OUTPUT_DIR/tests-privilege-memory-tls-proof"
      ;;
    desktop)
      run "$SCRIPT_DIR/../suites/test-desktop-webadmin-rust-integration.sh" \
        --output-dir "$OUTPUT_DIR/tests-desktop-webadmin-rust"
      ;;
    transport)
      run "$SCRIPT_DIR/../suites/test-transport.sh" --output-dir "$OUTPUT_DIR/tests-transport"
      ;;
    fec)
      run "$SCRIPT_DIR/../suites/test-fec.sh" --refactor --output-dir "$OUTPUT_DIR/tests-fec"
      run "$SCRIPT_DIR/../suites/test-fec-auto-controller-scenarios.sh" \
        --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-scenarios"
      run "$SCRIPT_DIR/../suites/test-fec-auto-controller-proof.sh" \
        --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-proof"
      run "$SCRIPT_DIR/../suites/test-fec-simulation.sh" \
        --output-dir "$OUTPUT_DIR/tests-fec-sim" $( ((FAST)) && echo --fast )
      run "$SCRIPT_DIR/../suites/test-fec-e2e-loss.sh" \
        --output-dir "$OUTPUT_DIR/tests-fec-e2e-loss" $( ((FAST)) && echo --fast )
      ;;
    stealth)
      run "$SCRIPT_DIR/../suites/test-stealth.sh" --output-dir "$OUTPUT_DIR/tests-stealth" \
        $( ((FAST)) && echo --fast )
      run "$SCRIPT_DIR/../suites/test-stealth-brain.sh" \
        --output-dir "$OUTPUT_DIR/tests-stealth-brain" $( ((FAST)) && echo --fast )
      run "$SCRIPT_DIR/../suites/test-probe-detection.sh" \
        --output-dir "$OUTPUT_DIR/tests-probe-detection" $( ((FAST)) && echo --fast )
      ;;
    crypto)
      run "$SCRIPT_DIR/../suites/test-crypto.sh" --output-dir "$OUTPUT_DIR/tests-crypto" \
        $( ((FAST)) && echo --fast )
      if (( FAST )); then
        run "$SCRIPT_DIR/../fast/test-fast-crypto.sh" --output-dir "$OUTPUT_DIR/fast-crypto"
      else
        run_cargo test --release --lib aes_gcm
        run_cargo test --release --lib aegis128l
      fi
      ;;
    optimization)
      run "$SCRIPT_DIR/../suites/test-optimization.sh" \
        --output-dir "$OUTPUT_DIR/tests-optimization" $( ((FAST)) && echo --fast )
      ;;
    security)
      run "$SCRIPT_DIR/../suites/test-security.sh" --output-dir "$OUTPUT_DIR/tests-security"
      run "$SCRIPT_DIR/../suites/test-security-fuzzing.sh" \
        --output-dir "$OUTPUT_DIR/tests-security-fuzzing"
      ;;
    frontend)
      run "$SCRIPT_DIR/../smoke/smoke-ui-frontends.sh" --output-dir "$OUTPUT_DIR/frontend-smoke"
      ;;
    e2e)
      run "$SCRIPT_DIR/../suites/test-e2e.sh" --output-dir "$OUTPUT_DIR/e2e" \
        $( ((FAST)) && echo --fast )
      run "$SCRIPT_DIR/../suites/test-e2e.sh" --integration \
        --output-dir "$OUTPUT_DIR/e2e-integration" $( ((FAST)) && echo --fast )
      ;;
    performance)
      run "$SCRIPT_DIR/../suites/test-performance-regression.sh" \
        --output-dir "$OUTPUT_DIR/tests-perf" $( ((FAST)) && echo --fast )
      ;;
    audits)
      run "$SCRIPT_DIR/../audits/audit-all-comprehensive.sh" --strict --output-dir "$OUTPUT_DIR/audit"
      run "$SCRIPT_DIR/../../utils/util-analyze-codebase.sh" > "$OUTPUT_DIR/analysis.txt"
      ;;
    benchmarks)
      BENCH_STEALTH_PREFLIGHT_LOG="$OUTPUT_DIR/bench-stealth-preflight.log"
      if run_stealth_bench_preflight "$BENCH_STEALTH_PREFLIGHT_LOG"; then
        run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth.sh" --output-dir "$OUTPUT_DIR/bench-stealth"
        run "$SCRIPT_DIR/../../benchmarks/suites/bench-fec-simulation.sh" --output-dir "$OUTPUT_DIR/bench-fec-sim"
        run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth-brain.sh" --output-dir "$OUTPUT_DIR/bench-stealth-brain"
      else
        json_end "$JSON"
        return 1
      fi
      ;;
    amx)
      if ! run_amx_proof_lane "$OUTPUT_DIR/tests-amx-proof"; then
        return 1
      fi
      ;;
  esac
}

if [[ "$ONLY" != "all" ]]; then
  local_scope=""
  IFS=',' read -r -a selected_scopes <<< "$ONLY"
  for local_scope in "${selected_scopes[@]}"; do
    run_selected_scope "$local_scope"
  done
  echo -e "\n[OK] Scoped suite complete. Scopes: $ONLY. Artifacts: $OUTPUT_DIR"
  json_end "$JSON"
  exit 0
fi

# 1) Build/lint checks (short by default)
if (( FAST )); then
  run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
else
  run "$SCRIPT_DIR/../build/build-clippy-matrix.sh"
  run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
fi

# 2) Core compilation + unit/integration/doc tests
if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_FULL_TEST_COMPILE_GIB:-10}" "full-suite test binary precompile" "$PROJECT_ROOT"; then
  run_cargo test --no-run
fi
if (( FAST )); then
  run_cargo test --lib -- --nocapture
else
  run_cargo test --lib
  run_cargo test --doc
fi

# 3) Core integration suite (run individually, sequential)
run "$SCRIPT_DIR/../suites/test-core.sh" --output-dir "$OUTPUT_DIR/tests-core"
run "$SCRIPT_DIR/../suites/test-privilege-memory-tls-proof.sh" --output-dir "$OUTPUT_DIR/tests-privilege-memory-tls-proof"
run "$SCRIPT_DIR/../suites/test-desktop-webadmin-rust-integration.sh" --output-dir "$OUTPUT_DIR/tests-desktop-webadmin-rust"

# 4) Core suite coverage (run individually, sequential)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../suites/test-transport.sh" --output-dir "$OUTPUT_DIR/tests-transport"
  run "$SCRIPT_DIR/../suites/test-fec.sh" --refactor --output-dir "$OUTPUT_DIR/tests-fec"
  run "$SCRIPT_DIR/../suites/test-stealth.sh" --output-dir "$OUTPUT_DIR/tests-stealth"
  run "$SCRIPT_DIR/../suites/test-profile-overrides.sh" --output-dir "$OUTPUT_DIR/tests-profile-overrides"
  run "$SCRIPT_DIR/../suites/test-profile-fuzz-parity.sh" --output-dir "$OUTPUT_DIR/tests-profile-fuzz-parity"
  run "$SCRIPT_DIR/../suites/test-fec-auto-controller-scenarios.sh" --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-scenarios"
  run "$SCRIPT_DIR/../suites/test-fec-auto-controller-proof.sh" --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-proof"
  run "$SCRIPT_DIR/../suites/test-security.sh" --output-dir "$OUTPUT_DIR/tests-security"
  run "$SCRIPT_DIR/../suites/test-security-fuzzing.sh" --output-dir "$OUTPUT_DIR/tests-security-fuzzing"
  run "$SCRIPT_DIR/../suites/test-e2e-admin-web.sh" --output-dir "$OUTPUT_DIR/tests-e2e-admin-web"
  run "$SCRIPT_DIR/../suites/test-runtime-soak-chaos.sh" --output-dir "$OUTPUT_DIR/tests-runtime-soak-chaos"
else
  run "$SCRIPT_DIR/../suites/test-stealth.sh" --output-dir "$OUTPUT_DIR/tests-stealth" --fast
fi
run "$SCRIPT_DIR/../suites/test-crypto.sh" --output-dir "$OUTPUT_DIR/tests-crypto" $([[ $FAST -eq 1 ]] && echo --fast)
run "$SCRIPT_DIR/../suites/test-optimization.sh" --output-dir "$OUTPUT_DIR/tests-optimization" $([[ $FAST -eq 1 ]] && echo --fast)
if ! run_amx_proof_lane "$OUTPUT_DIR/tests-amx-proof"; then
  json_end "$JSON"
  exit 1
fi

if (( FAST )); then
  # The crypto suite already covers TLS Cover; the FEC helper owns the
  # Wiedemann telemetry smoke that used to be repeated by fast-crypto.
  run "$SCRIPT_DIR/../fast/test-fast-fec.sh" --output-dir "$OUTPUT_DIR/fast-fec"
fi

# 5) Targeted crypto smoke (aligned to test-all coverage)
if (( ! FAST )); then
  run_cargo test --release --lib aes_gcm
  run_cargo test --release --lib aegis128l
fi

# Linux-specific paths
if [[ "$(detect_os 2>/dev/null || echo unknown)" == linux ]]; then
  run_cargo test --release --features io_uring,rust-tests --test rt-transport-uring -- --nocapture
fi

# 6) Matrices (optional but sequential)
run "$SCRIPT_DIR/../suites/test-fec-simulation.sh" --output-dir "$OUTPUT_DIR/tests-fec-sim" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-fec-e2e-loss.sh" --output-dir "$OUTPUT_DIR/tests-fec-e2e-loss" $( ((FAST)) && echo --fast )

run "$SCRIPT_DIR/../suites/test-stealth-brain.sh" --output-dir "$OUTPUT_DIR/tests-stealth-brain" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-probe-detection.sh" --output-dir "$OUTPUT_DIR/tests-probe-detection" $( ((FAST)) && echo --fast )

# 7) E2E
run "$SCRIPT_DIR/../suites/test-e2e.sh" --output-dir "$OUTPUT_DIR/e2e" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-e2e.sh" --integration --output-dir "$OUTPUT_DIR/e2e-integration" $( ((FAST)) && echo --fast )
if (( ! FAST )); then
  run "$SCRIPT_DIR/../smoke/smoke-ui-frontends.sh" --output-dir "$OUTPUT_DIR/frontend-smoke"
fi

# 8) Performance regression (fast reduces scope)
run "$SCRIPT_DIR/../suites/test-performance-regression.sh" --output-dir "$OUTPUT_DIR/tests-perf" $( ((FAST)) && echo --fast )

# 9) Audits + analysis (full profile only)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../audits/audit-all-comprehensive.sh" --strict --output-dir "$OUTPUT_DIR/audit"
  run "$SCRIPT_DIR/../../utils/util-analyze-codebase.sh" > "$OUTPUT_DIR/analysis.txt"
fi

# 10) Dedicated benches (full profile only)
if (( ! FAST )); then
  BENCH_STEALTH_PREFLIGHT_LOG="$OUTPUT_DIR/bench-stealth-preflight.log"
  if run_stealth_bench_preflight "$BENCH_STEALTH_PREFLIGHT_LOG"; then
    run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth.sh" --output-dir "$OUTPUT_DIR/bench-stealth"
  else
    json_end "$JSON"
    exit 1
  fi
  run "$SCRIPT_DIR/../../benchmarks/suites/bench-fec-simulation.sh" --output-dir "$OUTPUT_DIR/bench-fec-sim"
  run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth-brain.sh" --output-dir "$OUTPUT_DIR/bench-stealth-brain"
fi

# 5) Coverage summary (full profile only)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../analysis/analysis-coverage-summary.sh" --output-dir "$OUTPUT_DIR/coverage"
fi

echo -e "\n[OK] Full suite complete. Artifacts: $OUTPUT_DIR"
json_end "$JSON"
