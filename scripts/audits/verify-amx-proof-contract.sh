#!/usr/bin/env bash
# Description: Verify the repository-owned AMX build and runtime proof contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
cd "$PROJECT_ROOT"

FAILURES=0

check_literal() {
  local label="$1"
  local value="$2"
  shift 2
  if rg -n --no-messages -F -- "$value" "$@" >/dev/null; then
    printf 'PASS: %s\n' "$label"
  else
    printf 'FAIL: %s\n' "$label"
    FAILURES=$((FAILURES + 1))
  fi
}

check_absent() {
  local label="$1"
  local value="$2"
  shift 2
  if rg -n --no-messages -F -- "$value" "$@" >/dev/null; then
    printf 'FAIL: %s\n' "$label"
    FAILURES=$((FAILURES + 1))
  else
    printf 'PASS: %s\n' "$label"
  fi
}

check_literal "Cargo registers the AMX proof target" \
  'name = "rt-amx-proof"' Cargo.toml
check_literal "Cargo points the proof target at its repository-owned source" \
  'path = "scripts/tests/rust/rt-amx-proof.rs"' Cargo.toml
check_literal "Cargo requires rust-tests for the AMX proof target" \
  'required-features = ["rust-tests"]' Cargo.toml

check_literal "The integration proof emits a structured result" \
  'AMX_PROOF_RESULT=' scripts/tests/rust/rt-amx-proof.rs
check_literal "The integration proof distinguishes availability states" \
  '"AVAILABLE"' scripts/tests/rust/rt-amx-proof.rs
check_literal "The integration proof reports unavailable states" \
  '"UNAVAILABLE"' scripts/tests/rust/rt-amx-proof.rs
check_literal "The proof requires exactly AMX-TILE and AMX-INT8" \
  '"required_target_features": ["amx-tile", "amx-int8"]' scripts/tests/rust/rt-amx-proof.rs
check_literal "The proof does not require AMX-BF16" \
  '"bf16_required": false' scripts/tests/rust/rt-amx-proof.rs
check_absent "The integration proof has no silent skip path" \
  'skipping' scripts/tests/rust/rt-amx-proof.rs

check_literal "The AMX module requires both target features" \
  'target_feature = "amx-tile", target_feature = "amx-int8"' src/simd/mod.rs
check_literal "The AMX backend remains fail-closed until verified" \
  'pub(crate) const VERIFIED_BACKEND: bool = false;' src/simd/amx.rs
check_literal "The capability surface retains backend proof state" \
  'pub verified_backend: bool,' src/optimize/parts/cpu_dispatch.rs
check_literal "Linux x86 records OS tile-state permission" \
  'libc::SYS_arch_prctl' src/optimize/parts/cpu_dispatch.rs
check_literal "Product eligibility requires backend proof" \
  'let product_dispatch_eligible = signals.verified_backend' src/optimize/parts/cpu_dispatch.rs
check_absent "The capability detector has no external cpuid process" \
  'Command::new("cpuid")' src/optimize/parts/cpu_dispatch.rs

check_literal "Wiedemann rejects non-square systems" \
  '|| m != n' src/fec/parts/decoders.rs
check_literal "Wiedemann validates RHS length" \
  '|| rhs.len() != m' src/fec/parts/decoders.rs
check_literal "Wiedemann validates every matrix row" \
  'matrix.iter().any(|row| row.len() != n)' src/fec/parts/decoders.rs
check_literal "The FEC proof covers concurrent scalar execution" \
  'fn test_wiedemann_scalar_solver_is_concurrent_and_amx_free' src/fec/tests.rs
check_literal "The FEC proof covers malformed dimensions" \
  'fn test_wiedemann_rejects_invalid_dimensions' src/fec/tests.rs
check_literal "The FEC proof covers resettable scratch storage" \
  'fn test_wiedemann_scratch_storage_is_dimension_bounded_and_resettable' src/fec/tests.rs

check_literal "The shell lane enables the exact AMX target features" \
  'AMX_RUSTFLAGS="-Ctarget-feature=+amx-tile,+amx-int8"' scripts/tests/suites/test-amx-proof.sh
check_literal "The shell lane has an explicit unavailable exit state" \
  'AMX_PROOF_STATUS=$OVERALL_STATUS' scripts/tests/suites/test-amx-proof.sh
check_literal "The shell lane emits rc 2 for unavailable proof" \
  'exit 2' scripts/tests/suites/test-amx-proof.sh
check_absent "The shell lane does not enable unrelated AMX-BF16" \
  'amx-bf16' scripts/tests/suites/test-amx-proof.sh scripts/tests/rust/rt-amx-proof.rs
check_literal "The full suite invokes the AMX proof lane" \
  'test-amx-proof.sh' scripts/tests/utils/util-run-full-suite.sh
check_literal "The comprehensive audit invokes the AMX contract checker" \
  'verify-amx-proof-contract.sh' scripts/tests/audits/audit-all-comprehensive.sh
check_literal "The runtime guardrails invoke the AMX contract checker" \
  'verify-amx-proof-contract.sh' scripts/tests/audits/audit-runtime-guardrails.sh
check_literal "CI invokes the AMX proof lane" \
  'scripts/tests/suites/test-amx-proof.sh' .github/workflows/ci.yml
check_literal "CI clippy contract checks the AMX proof wiring" \
  'verify-amx-proof-contract.sh' .github/workflows/clippy-matrix.yml

check_absent "Removed AMX tests do not reintroduce silent skips" \
  'AMX runtime support unavailable; skipping' src scripts/tests/rust scripts/tests/suites
check_absent "No proof lane treats BF16 as the eligibility requirement" \
  'amx_bf16' scripts/tests/rust/rt-amx-proof.rs scripts/tests/suites/test-amx-proof.sh

if [[ "$FAILURES" -eq 0 ]]; then
  printf '%s\n' 'AMX_PROOF_CONTRACT=PASS'
  exit 0
fi

printf 'AMX_PROOF_CONTRACT=FAIL failures=%s\n' "$FAILURES"
exit 1
