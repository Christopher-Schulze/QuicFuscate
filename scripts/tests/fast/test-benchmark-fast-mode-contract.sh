#!/usr/bin/env bash
# Description: Contract test: benchmark and analysis fast/full modes are truthful.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

case "${1:-}" in
  --help|-h)
    echo "Usage: $(basename "$0")"
    echo "Validate benchmark and analysis fast/full mode contracts."
    exit 0
    ;;
esac

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-benchmark-fast-mode.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  echo "[FAIL] benchmark fast-mode contract: $*" >&2
  exit 1
}

run_dry() {
  local name="$1"
  local script="$2"
  local mode="$3"
  local output_dir="$TMP_ROOT/${name}-${mode} path;literal"
  shift 3
  if ! bash "$script" "$@" "--${mode}" --dry-run --output-dir "$output_dir" \
      >"$TMP_ROOT/${name}-${mode}.log" 2>&1; then
    fail_fixture "$name $mode dry-run failed; see $TMP_ROOT/${name}-${mode}.log"
  fi
  printf '%s\n' "$output_dir"
}

assert_mode_metadata() {
  local artifact="$1"
  local expected_mode="$2"
  local expected_cells="$3"
  python3 - "$artifact" "$expected_mode" "$expected_cells" <<'PY'
import json
import sys

path, expected_mode, expected_cells = sys.argv[1:]
document = json.loads(open(path, encoding="utf-8").read())
metadata = next(item for item in document["items"] if item.get("cell") == "meta")
meta = metadata["meta"]
expected = expected_cells.split(",") if expected_cells else []
if meta["mode"] != expected_mode:
    raise SystemExit(f"{path}: expected mode {expected_mode!r}, got {meta['mode']!r}")
if meta["selected_cells"] != expected:
    raise SystemExit(
        f"{path}: expected cells {expected!r}, got {meta['selected_cells']!r}"
    )
if meta["cell_count"] != len(expected):
    raise SystemExit(f"{path}: metadata cell_count does not match selected_cells")
if "N/A" in open(path, encoding="utf-8").read():
    raise SystemExit(f"{path}: mode artifact contains N/A")
PY
}

assert_orchestrator_metadata() {
  local artifact="$1"
  local expected_mode="$2"
  local expected_suites="$3"
  local expected_child_flag="$4"
  python3 - "$artifact" "$expected_mode" "$expected_suites" "$expected_child_flag" <<'PY'
import json
import sys

path, expected_mode, expected_suites, expected_child_flag = sys.argv[1:]
document = json.loads(open(path, encoding="utf-8").read())
metadata = next(item for item in document["items"] if item.get("cell") == "meta")
meta = metadata["meta"]
expected = expected_suites.split(",")
if meta["mode"] != expected_mode:
    raise SystemExit(f"{path}: expected mode {expected_mode!r}, got {meta['mode']!r}")
if meta["selected_suites"] != expected:
    raise SystemExit(
        f"{path}: expected suites {expected!r}, got {meta['selected_suites']!r}"
    )
if meta["suite_count"] != len(expected):
    raise SystemExit(f"{path}: metadata suite_count does not match selected_suites")

items = {item["name"]: item for item in document["items"] if "name" in item}
if set(items) != set(expected):
    raise SystemExit(f"{path}: child suite set does not match metadata")
for name, item in items.items():
    argv = item.get("argv") or []
    if expected_child_flag not in argv:
        raise SystemExit(f"{path}: child {name} does not receive {expected_child_flag}")
PY
}

case "$(uname -m)" in
  x86_64)
    CRYPTO_FULL_CELLS="crypto_all_native,crypto_all_sse2,crypto_all_avx2,morus_native,morus_sse2,aes_gcm_native,aes_gcm_aesni,aes_gcm_vaes,chacha20_poly1305_native"
    ;;
  aarch64|arm64)
    CRYPTO_FULL_CELLS="crypto_all_native,crypto_all_neon,morus_native,morus_neon,aes_gcm_native,aes_gcm_crypto,chacha20_poly1305_native"
    ;;
  *)
    CRYPTO_FULL_CELLS="crypto_all_native,morus_native,aes_gcm_native,chacha20_poly1305_native"
    ;;
esac

crypto_fast_dir="$(run_dry crypto scripts/benchmarks/suites/bench-crypto.sh fast)"
assert_mode_metadata "$crypto_fast_dir/results.json" fast \
  "crypto_all_native,morus_native,aes_gcm_native,chacha20_poly1305_native"
crypto_full_dir="$(run_dry crypto scripts/benchmarks/suites/bench-crypto.sh full)"
assert_mode_metadata "$crypto_full_dir/results.json" full "$CRYPTO_FULL_CELLS"

fec_fast_dir="$(run_dry fec scripts/benchmarks/suites/bench-fec.sh fast)"
assert_mode_metadata "$fec_fast_dir/results.json" fast fec_pipeline
fec_full_dir="$(run_dry fec scripts/benchmarks/suites/bench-fec.sh full)"
assert_mode_metadata "$fec_full_dir/results.json" full fec_matrix_mul,fec_pipeline

optimization_fast_dir="$(run_dry optimization scripts/benchmarks/suites/bench-optimization.sh fast)"
assert_mode_metadata "$optimization_fast_dir/results.json" fast sort_simd/1024_elems
optimization_full_dir="$(run_dry optimization scripts/benchmarks/suites/bench-optimization.sh full)"
assert_mode_metadata "$optimization_full_dir/results.json" full sort_simd,shuffle_simd

stealth_fast_dir="$(run_dry stealth scripts/benchmarks/suites/bench-stealth.sh fast)"
assert_mode_metadata "$stealth_fast_dir/results.json" fast padding_gen/pad_to_512B
stealth_full_dir="$(run_dry stealth scripts/benchmarks/suites/bench-stealth.sh full)"
assert_mode_metadata "$stealth_full_dir/results.json" full padding_gen

transport_fast_dir="$(run_dry transport scripts/benchmarks/suites/bench-transport.sh fast)"
assert_mode_metadata "$transport_fast_dir/results.json" fast varint
transport_full_dir="$(run_dry transport scripts/benchmarks/suites/bench-transport.sh full)"
assert_mode_metadata "$transport_full_dir/results.json" full varint,packet_number

coverage_fast_dir="$(run_dry coverage scripts/tests/analysis/analysis-coverage-summary.sh fast)"
assert_mode_metadata "$coverage_fast_dir/results.json" fast static-function-test-inventory
if command -v cargo-llvm-cov >/dev/null 2>&1; then
  coverage_full_cell="cargo-llvm-cov-summary"
else
  coverage_full_cell="cargo-test-function-inventory"
fi
coverage_full_dir="$(run_dry coverage scripts/tests/analysis/analysis-coverage-summary.sh full)"
assert_mode_metadata "$coverage_full_dir/results.json" full "$coverage_full_cell"

orchestrator_fast_dir="$(mktemp -d "$TMP_ROOT/orchestrator-fast.XXXXXX")"
bash scripts/benchmarks/suites/bench-orchestrator.sh \
  --fast --dry-run --suite transport,stealth --output-dir "$orchestrator_fast_dir" \
  >"$TMP_ROOT/orchestrator-fast.log" 2>&1
assert_orchestrator_metadata "$orchestrator_fast_dir/manifest.json" fast transport,stealth --fast

orchestrator_full_dir="$(mktemp -d "$TMP_ROOT/orchestrator-full.XXXXXX")"
bash scripts/benchmarks/suites/bench-orchestrator.sh \
  --full --dry-run --suite crypto,fec,optimization,transport,stealth \
  --output-dir "$orchestrator_full_dir" >"$TMP_ROOT/orchestrator-full.log" 2>&1
assert_orchestrator_metadata "$orchestrator_full_dir/manifest.json" full \
  crypto,fec,optimization,transport,stealth --full

echo "[PASS] benchmark and analysis fast/full mode contract"
