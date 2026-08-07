#!/usr/bin/env bash
# Description: Runtime guardrails for fastpath/runtime contract drift.
# shellcheck source=scripts/tests/lib/lib-common.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TS="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TS}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "audit_runtime_guardrails"

critical=0
warnings=0

pass() {
  info "$1"
}

fail_critical() {
  error "$1"
  critical=$((critical + 1))
}

warn_guardrail() {
  warn "$1"
  warnings=$((warnings + 1))
}

append_item() {
  local name="$1"
  local status="$2"
  local details="$3"
  qf_json_append_object "$JSON" "name=$name" "status=$status" "details=$details"
}

echo "==============================================================="
echo "  Runtime Guardrails Audit"
echo "==============================================================="

# 1) Public xdp fastpath token and alias helpers must be gone.
PUBLIC_XDP_TOKEN_REFS=$(rg -n --no-messages "QUICFUSCATE_FASTPATH=xdp|xdp.*compatibility alias|compatibility-only.*xdp|xdp.*maps to.*udp/io_uring|xdp-smoke|request_xdp_compat|enable_xdp_compat|FastpathMode::Xdp|xdp_compat_alias_log_message|normalize_request_xdp_compat" README.md docs/DOCUMENTATION.md src/interface.rs src/main.rs src/main_parts src/optimize src/implementations/client/io_driver.rs src/implementations/server || true)
if [[ -z "$PUBLIC_XDP_TOKEN_REFS" ]]; then
  pass "Public xdp fastpath token is fully removed"
  append_item "xdp_public_token_removed" "ok" "no public xdp fastpath token or alias helpers remain"
else
  fail_critical "Public xdp fastpath token or alias helpers remain"
  append_item "xdp_public_token_removed" "fail" "$PUBLIC_XDP_TOKEN_REFS"
fi

REMOVED_AF_XDP_REFS=$(rg -n --no-messages "internal_af_xdp_experimental|run_xdp_experimental_socket_probe|SockaddrXdp|XdpSocket" Cargo.toml README.md docs/DOCUMENTATION.md docs/MAP.md src/transport.rs src/transport/xdp.rs scripts/tests/rust || true)
if [[ -z "$REMOVED_AF_XDP_REFS" ]]; then
  pass "Retained AF_XDP implementation and feature claims are removed"
  append_item "xdp_internal_surface_removed" "ok" "no AF_XDP implementation, feature, probe, or runtime claim remains"
else
  fail_critical "Retained AF_XDP implementation or feature claims remain"
  append_item "xdp_internal_surface_removed" "fail" "$REMOVED_AF_XDP_REFS"
fi

ACCELERATE_PUBLIC_DOC_REFS=$(rg -n --no-messages "use quicfuscate::accelerate::(brain|iter|sort|string|transport_io)" README.md docs/DOCUMENTATION.md || true)
if [[ -z "$ACCELERATE_PUBLIC_DOC_REFS" ]]; then
  pass "README/docs do not present narrowed accelerate::* parity helpers as broad public imports"
  append_item "accelerate_docs_surface_narrowing" "ok" "no broad accelerate::* example imports remain in product docs"
else
  fail_critical "README/docs still present narrowed accelerate::* parity helpers as broad public imports"
  append_item "accelerate_docs_surface_narrowing" "fail" "$ACCELERATE_PUBLIC_DOC_REFS"
fi

DEFAULT_INTERNAL_FEATURE_REFS=$(python3 - <<'PY'
import re
from pathlib import Path
text = Path("Cargo.toml").read_text()
m = re.search(r'^default\s*=\s*\[(.*?)\]', text, re.M | re.S)
if not m:
    print("missing default feature list")
else:
    items = [x.strip().strip('"') for x in m.group(1).split(",") if x.strip()]
    internal = [x for x in items if x.startswith("internal_")]
    if internal:
        print(",".join(internal))
PY
)
if [[ -z "$DEFAULT_INTERNAL_FEATURE_REFS" ]]; then
  pass "Default Cargo feature set does not include internal-only feature gates"
  append_item "default_feature_internal_gates" "ok" "no internal_* features present in default feature set"
else
  fail_critical "Default Cargo feature set includes internal-only feature gates"
  append_item "default_feature_internal_gates" "fail" "$DEFAULT_INTERNAL_FEATURE_REFS"
fi

FEATURE_SURFACE_DOC_REFS=$(rg -n --no-messages "Product/default runtime:|Internal-only:|Backend/build knobs retained for dispatch or specialized integration:" docs/DOCUMENTATION.md || true)
if [[ -n "$FEATURE_SURFACE_DOC_REFS" ]]; then
  pass "Documentation keeps an explicit Cargo feature surface classification"
  append_item "feature_surface_doc_matrix" "ok" "Cargo feature categories documented"
else
  fail_critical "Documentation lost the explicit Cargo feature surface classification"
  append_item "feature_surface_doc_matrix" "fail" "feature classification headings missing"
fi

LAYER_MODEL_REFS=$(rg -n --no-messages "Runtime Layer Model|Runtime Complexity Layer Model|canonical runtime/product path|adaptive policy/control|platform acceleration|compat/test/experimental" README.md docs/DOCUMENTATION.md || true)
if [[ -n "$LAYER_MODEL_REFS" ]] \
  && rg -n --no-messages "Runtime Layer Model" README.md >/dev/null \
  && rg -n --no-messages "Runtime Complexity Layer Model" docs/DOCUMENTATION.md >/dev/null; then
  pass "Canonical docs keep the explicit four-layer runtime complexity model"
  append_item "runtime_layer_model_docs" "ok" "README/docs preserve the explicit four-layer model"
else
  fail_critical "Canonical docs lost the explicit four-layer runtime complexity model"
  append_item "runtime_layer_model_docs" "fail" "missing explicit four-layer model in README/docs"
fi

REVIEW_MAP_REFS=$(rg -n --no-messages "Security Review Boundary Map|Security Review Fast Path|Reviewer Checklist" README.md docs/DOCUMENTATION.md || true)
if [[ -n "$REVIEW_MAP_REFS" ]] \
  && rg -n --no-messages "Security Review Boundary Map" docs/DOCUMENTATION.md >/dev/null \
  && rg -n --no-messages "Security Review Fast Path" README.md >/dev/null; then
  pass "Canonical docs keep the explicit security review boundary map"
  append_item "security_review_boundary_map" "ok" "README/docs preserve the review fast path and boundary map"
else
  fail_critical "Canonical docs lost the explicit security review boundary map"
  append_item "security_review_boundary_map" "fail" "missing review fast path or boundary map in README/docs"
fi

AUDIT_PATH_REFS=$(rg -n --no-messages "Suggested skeptical review order|Shortest Audit Path|Runtime layer map|Retained backend evidence|Runtime/FEC evidence" README.md docs/DOCUMENTATION.md || true)
if [[ -n "$AUDIT_PATH_REFS" ]] \
  && rg -n --no-messages "Suggested skeptical review order" README.md >/dev/null \
  && rg -n --no-messages "Shortest Audit Path" docs/DOCUMENTATION.md >/dev/null; then
  pass "Canonical docs keep the shortest reviewer audit path explicit"
  append_item "reviewer_audit_fast_path" "ok" "README/docs preserve the ordered shortest audit path"
else
  fail_critical "Canonical docs lost the explicit shortest reviewer audit path"
  append_item "reviewer_audit_fast_path" "fail" "missing ordered reviewer audit path in README/docs"
fi

REVIEWER_TRUTH_REFS=$(rg -n --no-messages 'Reviewer Truth Snapshot|Reviewer Trust Snapshot|AI-assisted development is part of the repository workflow|MSG_ZEROCOPY is not part of the final runtime story|busy-poll socket tuning is not part of the final runtime story|repository is not reducible to `quinn-udp` plus trivial glue' README.md docs/DOCUMENTATION.md || true)
if [[ -n "$REVIEWER_TRUTH_REFS" ]] \
  && rg -n --no-messages "Reviewer Truth Snapshot" README.md >/dev/null \
  && rg -n --no-messages "Reviewer Trust Snapshot" docs/DOCUMENTATION.md >/dev/null \
  && rg -n --no-messages 'MSG_ZEROCOPY.*final runtime story' README.md docs/DOCUMENTATION.md >/dev/null \
  && rg -n --no-messages "busy-poll socket tuning is not part of the final runtime story" README.md docs/DOCUMENTATION.md >/dev/null; then
  pass "Canonical docs keep the consolidated reviewer truth snapshot"
  append_item "reviewer_truth_snapshot" "ok" "README/docs preserve the consolidated reviewer-trust statement"
else
  fail_critical "Canonical docs lost the consolidated reviewer truth snapshot"
  append_item "reviewer_truth_snapshot" "fail" "missing consolidated reviewer-trust statement in README/docs"
fi

QUALITY_EVIDENCE_REFS=$(rg -n --no-messages "Quality Evidence Snapshot|Consolidated Quality Evidence Bundle|Evidence Limits|test-runtime-soak-chaos.sh|test-fec-auto-controller-proof.sh|bench-retained-crypto-backends.sh" README.md docs/DOCUMENTATION.md || true)
if [[ -n "$QUALITY_EVIDENCE_REFS" ]] \
  && rg -n --no-messages "Quality Evidence Snapshot" README.md >/dev/null \
  && rg -n --no-messages "Consolidated Quality Evidence Bundle" docs/DOCUMENTATION.md >/dev/null \
  && rg -n --no-messages "Evidence Limits" docs/DOCUMENTATION.md >/dev/null; then
  pass "Canonical docs keep the consolidated quality evidence bundle explicit"
  append_item "quality_evidence_bundle" "ok" "README/docs preserve the compact evidence bundle and explicit limits"
else
  fail_critical "Canonical docs lost the consolidated quality evidence bundle"
  append_item "quality_evidence_bundle" "fail" "missing compact evidence bundle or explicit evidence limits in README/docs"
fi

QUINN_OVERLAP_REFS=$(rg -n --no-messages "Transport Overlap and Divergence vs quinn-udp|quinn_udp|UdpSocketState|Reviewer-facing conclusion" README.md docs/DOCUMENTATION.md || true)
if [[ -n "$QUINN_OVERLAP_REFS" ]] \
  && rg -n --no-messages "Transport Overlap and Divergence vs quinn-udp" docs/DOCUMENTATION.md >/dev/null \
  && rg -n --no-messages "Transport overlap/divergence note" README.md >/dev/null; then
  pass "Canonical docs keep the explicit quinn-udp overlap/divergence statement"
  append_item "quinn_udp_overlap_statement" "ok" "README/docs preserve the overlap/divergence audit entrypoint"
else
  fail_critical "Canonical docs lost the explicit quinn-udp overlap/divergence statement"
  append_item "quinn_udp_overlap_statement" "fail" "missing overlap/divergence entrypoint in README/docs"
fi

AEAD_POSTURE_REFS=$(rg -n --no-messages 'AEGIS-128L/X|Canonical data-plane suites include `Aegis128L`, `Aegis128X4`, and `Aegis128X8`|Aegis128X4 => "aegis-128x4"|Aegis128X8 => "aegis-128x8"' README.md docs/DOCUMENTATION.md || true)
if [[ -z "$AEAD_POSTURE_REFS" ]]; then
  pass "README/docs keep the forked AEAD posture narrowed to Aegis128L family plus Morus"
  append_item "aead_posture_narrowing" "ok" "no broad AEGIS-128L/X or X4/X8-as-suite wording remains in product docs"
else
  fail_critical "README/docs still present the forked AEAD posture as a broader suite zoo"
  append_item "aead_posture_narrowing" "fail" "$AEAD_POSTURE_REFS"
fi

AEAD_OVERRIDE_SURFACE_REFS=$(rg -n --no-messages 'DATA_AEAD_OVERRIDE_AEGIS_X4|DATA_AEAD_OVERRIDE_AEGIS_X8' src/crypto/ || true)
if [[ -z "$AEAD_OVERRIDE_SURFACE_REFS" ]]; then
  pass "Data-plane AEAD override surface stays narrowed to auto, Aegis128L family, and Morus"
  append_item "aead_override_surface_narrowing" "ok" "no X4/X8-specific data-plane override modes remain"
else
  fail_critical "Data-plane AEAD override surface still carries X4/X8-specific modes"
  append_item "aead_override_surface_narrowing" "fail" "$AEAD_OVERRIDE_SURFACE_REFS"
fi

UNSAFE_VISIBILITY_REFS=$(rg -n --no-messages '^pub unsafe fn (prefetch|encode_varint_neon|encode_varint_sve2|decode_varint_neon|decode_varint_sve2|canonical_ack_blocks_avx2|canonical_ack_blocks_avx512)\b|^pub enum PrefetchHint\b|^pub unsafe fn (xor_blocks_sve2|xor_blocks_neon|memcpy_sve2|memcpy_neon|crc32_arm|popcnt_neon|popcnt_sve2|validate_header_sve2|validate_header_neon|gf_mul_sve2|gf_mul_neon_pmull|gf_mul_neon|aes_encrypt_neon|ghash_pmull|sha256_hw|pack_bits_sve2|pack_bits_neon|unpack_bits_sve2|unpack_bits_neon|reed_solomon_encode_neon|histogram_sve2|histogram_neon|qpack_encode_neon|qpack_decode_neon|qpack_encode_sve2|qpack_decode_sve2|find_pattern_sve2|find_pattern_neon|dot_product_neon_dp|dot_product_neon|matmul_apple_amx)\b' src/optimize src/simd src/simd/arm_varint.rs src/simd/x86_ack.rs || true)
if [[ -z "$UNSAFE_VISIBILITY_REFS" ]]; then
  pass "Unsafe SIMD/prefetch helpers remain internalized behind runtime-owned facades"
  append_item "unsafe_surface_internalization" "ok" "no broad public visibility on narrowed unsafe helper set"
else
  fail_critical "Unsafe SIMD/prefetch helpers regained broad public visibility"
  append_item "unsafe_surface_internalization" "fail" "$UNSAFE_VISIBILITY_REFS"
fi

SIMD_X86_UNSAFE_VISIBILITY_REFS=$(rg -n --no-messages '^pub unsafe fn (find_pattern_vbmi2|dot_product_avx512|dot_product_fma|varint_decode_sse2_prefast|sha256_avx2|sha256_vnni|xor_blocks_avx512|xor_blocks_avx2|memcpy_avx512|memcpy_avx2|memcpy_sse42|crc32_sse42|popcnt_hw|gf_mul_avx512_gfni|gf_mul_avx2|find_pattern_sse42_short|aes_encrypt_vaes|aes_encrypt_aesni|ghash_vpclmulqdq|ghash_pclmulqdq|sha256_hw|histogram_avx512|qpack_encode_avx2|histogram_avx2|decode_varint_bmi2|decode_varint_avx2|find_pattern_avx2|amx_init|amx_release|amx_matmul_i8|matmul_gf256_amx|berlekamp_massey_gfni|berlekamp_massey_avx2|matmul_gf256_gfni|matmul_gf256_avx2|encode_varint_sse2|encode_varint_avx2|encode_varint_avx512|varint_encode_bmi2|varint_decode_bmi2|xor_multi_key_avx512|xor_multi_key_avx2|validate_header_avx2|validate_header_sse2|pack_bits_bmi2|unpack_bits_bmi2|string_compare_avx2|string_compare_sse42|popcnt_avx512|batch_crc32_pclmul|reed_solomon_encode_gfni|reed_solomon_encode_avx2|reed_solomon_decode_gfni|reed_solomon_decode_avx2|qpack_encode_ssse3|qpack_decode_avx2|qpack_decode_ssse3)\b' src/simd src/simd/x86_header.rs || true)
if [[ -z "$SIMD_X86_UNSAFE_VISIBILITY_REFS" ]]; then
  pass "x86 SIMD backend helpers remain internal to simd selectors and tests"
  append_item "simd_x86_backend_internalization" "ok" "x86 SIMD backend helpers no longer expose broad public unsafe entrypoints"
else
  fail_critical "x86 SIMD backend helpers regained broad public unsafe visibility"
  append_item "simd_x86_backend_internalization" "fail" "$SIMD_X86_UNSAFE_VISIBILITY_REFS"
fi

# 1b) Every unsafe SIMD declaration must have a local Safety contract. Keep
#     this inventory source-driven so private, pub(super), and pub(crate)
#     helpers cannot disappear behind a visibility-specific regex.
SIMD_SAFETY_CONTRACT_LOG="$OUTPUT_DIR/simd-safety-contracts.log"
set +e
SIMD_SAFETY_CONTRACT_RESULT=$(python3 - <<'PY'
from pathlib import Path
import re
import sys

roots = (Path("src/simd"), Path("src/optimize/simd"))
declaration = re.compile(
    r"^\s*(?:(?:pub(?:\s*\([^)]*\))?|async)\s+)*"
    r"unsafe\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
target_feature = re.compile(r'enable\s*=\s*"([^"]+)"')
all_functions = []
target_feature_functions = 0
missing_contracts = []
feature_mismatches = []

def normalized(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())

for root in roots:
    for path in sorted(root.rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = declaration.match(line)
            if match is None:
                continue

            docs = []
            attributes = []
            cursor = index - 1
            while cursor >= 0:
                stripped = lines[cursor].strip()
                if stripped.startswith("///"):
                    docs.append(stripped)
                    cursor -= 1
                    continue
                if stripped.startswith("#["):
                    attributes.append(stripped)
                    cursor -= 1
                    continue
                break

            location = f"{path}:{index + 1}:{match.group(1)}"
            all_functions.append(location)
            safety_text = " ".join(reversed(docs))
            if "# Safety" not in safety_text:
                missing_contracts.append(location)

            features = []
            for attribute in attributes:
                if not attribute.startswith("#[target_feature"):
                    continue
                target_feature_functions += 1
                for value in target_feature.findall(attribute):
                    features.extend(feature.strip() for feature in value.split(","))
            normalized_safety = normalized(safety_text)
            missing_features = [
                feature
                for feature in features
                if feature and normalized(feature) not in normalized_safety
            ]
            if missing_features:
                feature_mismatches.append(
                    f"{location}: missing {','.join(missing_features)} in # Safety"
                )

print(
    f"unsafe_functions={len(all_functions)} "
    f"unsafe_target_feature_functions={target_feature_functions}"
)
if missing_contracts:
    print("missing_safety_contracts:")
    print("\n".join(missing_contracts))
if feature_mismatches:
    print("target_feature_contract_mismatches:")
    print("\n".join(feature_mismatches))
if missing_contracts or feature_mismatches or not all_functions:
    sys.exit(1)
PY
)
SIMD_SAFETY_CONTRACT_RC=$?
set -e
printf '%s\n' "$SIMD_SAFETY_CONTRACT_RESULT" >"$SIMD_SAFETY_CONTRACT_LOG"
if [[ "$SIMD_SAFETY_CONTRACT_RC" -eq 0 ]] \
  && ! rg -n --no-messages '#!\[allow\(clippy::missing_safety_doc\)\]' src/simd src/optimize/simd >/dev/null; then
  pass "SIMD unsafe inventory has local Safety contracts and exact declared ISA wording"
  append_item "simd_safety_contract_inventory" "ok" "$SIMD_SAFETY_CONTRACT_RESULT; blanket missing_safety_doc suppression absent"
else
  fail_critical "SIMD unsafe Safety-contract inventory or blanket lint guardrail failed"
  append_item "simd_safety_contract_inventory" "fail" "artifact=$SIMD_SAFETY_CONTRACT_LOG rc=$SIMD_SAFETY_CONTRACT_RC"
fi

# 1c) ISA-gated tests must account for unsupported hardware explicitly. A
#     passing Rust test that silently returns is not evidence for that lane.
SIMD_SKIP_TEST_LOG="$OUTPUT_DIR/simd-skip-accounting.log"
set +e
SIMD_SKIP_TEST_RESULT=$(python3 - <<'PY'
from pathlib import Path

files = [
    Path("src/simd/tests_arm.rs"),
    Path("src/simd/x86_extended.rs"),
    Path("scripts/tests/rust/rt-ack-merge-parity.rs"),
    Path("scripts/tests/rust/rt-header-validate-parity.rs"),
    Path("scripts/tests/rust/rt-simd-selfcheck.rs"),
    Path("scripts/tests/rust/rt-chacha-x16-parity.rs"),
    Path("scripts/tests/rust/rt-chacha-x4-parity.rs"),
    Path("scripts/tests/rust/rt-ghash-sse-parity.rs"),
    Path("scripts/tests/rust/rt-xor-sse2-parity.rs"),
]
failures = []
checked = 0
for path in files:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = 0
    if path == Path("src/simd/x86_extended.rs"):
        start = next(
            (index for index, line in enumerate(lines) if line.strip() == "mod tests {"),
            len(lines),
        )
    for index, line in enumerate(lines[start:], start=start):
        if line.strip() != "return;":
            continue
        context = "\n".join(lines[max(start, index - 12):index + 1])
        if "is_x86_feature_detected" not in context and "is_aarch64_feature_detected" not in context:
            continue
        checked += 1
        if "SIMD_SKIP" not in context and "report_simd_skip" not in context:
            failures.append(f"{path}:{index + 1}: return without SIMD_SKIP accounting")

    if "is_x86_feature_detected" in "\n".join(lines) or "is_aarch64_feature_detected" in "\n".join(lines):
        if "SIMD_SKIP" not in "\n".join(lines):
            failures.append(f"{path}: ISA detection has no SIMD_SKIP marker")

print(f"files={len(files)} unsupported_returns_checked={checked}")
if failures:
    print("failures:")
    print("\n".join(failures))
    raise SystemExit(1)
PY
)
SIMD_SKIP_TEST_RC=$?
set -e
printf '%s\n' "$SIMD_SKIP_TEST_RESULT" >"$SIMD_SKIP_TEST_LOG"
if [[ "$SIMD_SKIP_TEST_RC" -eq 0 ]]; then
  pass "ISA-gated SIMD tests report explicit SIMD_SKIP accounting for unsupported lanes"
  append_item "simd_skip_accounting" "ok" "$SIMD_SKIP_TEST_RESULT"
else
  fail_critical "ISA-gated SIMD tests contain silent unsupported-lane returns"
  append_item "simd_skip_accounting" "fail" "artifact=$SIMD_SKIP_TEST_LOG rc=$SIMD_SKIP_TEST_RC"
fi

AMX_EXTERNAL_DETECTOR_REFS=$(rg -n --no-messages 'Command::new\("cpuid"\)|\bcpuid\b' src/optimize/parts/cpu_dispatch.rs || true)
if [[ -z "$AMX_EXTERNAL_DETECTOR_REFS" ]]; then
  pass "AMX capability detection stays in-process and has no cpuid helper dependency"
  append_item "amx_detector_process_free" "ok" "cpu_dispatch uses in-process AMX feature detection"
else
  fail_critical "AMX capability detection still depends on the cpuid helper"
  append_item "amx_detector_process_free" "fail" "$AMX_EXTERNAL_DETECTOR_REFS"
fi

AMX_PROOF_CONTRACT_LOG="$OUTPUT_DIR/amx-proof-contract.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-amx-proof-contract.sh" >"$AMX_PROOF_CONTRACT_LOG" 2>&1
AMX_PROOF_CONTRACT_RC=$?
set -e
if [[ "$AMX_PROOF_CONTRACT_RC" -eq 0 ]]; then
  pass "AMX build/runtime proof contract is wired and fail-closed"
  append_item "amx_proof_contract" "ok" "artifact=$AMX_PROOF_CONTRACT_LOG"
else
  fail_critical "AMX build/runtime proof contract is incomplete"
  append_item "amx_proof_contract" "fail" "artifact=$AMX_PROOF_CONTRACT_LOG rc=$AMX_PROOF_CONTRACT_RC"
fi

# 2) Public fastpath mode space must be narrowed to auto and off.
if rg -n --no-messages 'QUICFUSCATE_FASTPATH.*auto\\|off|QUICFUSCATE_FASTPATH.*off\\|auto|FastpathMode::Auto|FastpathMode::Off' README.md docs/DOCUMENTATION.md src/interface.rs >/dev/null \
  && ! rg -n --no-messages 'FastpathMode::Uring|QUICFUSCATE_FASTPATH.*uring' README.md docs/DOCUMENTATION.md src/interface.rs >/dev/null; then
  pass "Public fastpath mode space is narrowed to auto and off"
  append_item "fastpath_mode_space" "ok" "canonical fastpath mode space narrowed"
else
  fail_critical "Public fastpath mode space is not clearly narrowed to auto and off"
  append_item "fastpath_mode_space" "fail" "missing narrowed fastpath mode wording"
fi

# 3) udpfast batch send must either use per-packet destination addresses directly
#    or delegate to the shared optimize::udp batch path that performs per-packet conversion.
if rg -n --no-messages "socket2::SockAddr::from\\(packet\\.1\\)" src/transport/udpfast.rs >/dev/null \
  && ! rg -n --no-messages "SockAddr::from\\(packets\\[0\\]\\.1\\)" src/transport/udpfast.rs >/dev/null; then
  pass "udpfast uses per-packet destination addressing in batch send"
  append_item "udpfast_per_packet_addr" "ok" "per-packet address conversion present in udpfast"
elif rg -n --no-messages "send_batch\\(&self\\.socket, batch_packets\\)" src/transport/udpfast.rs >/dev/null \
  && rg -n --no-messages "SocketAddr::V4\\(v4\\)|SocketAddr::V6\\(v6\\)" src/optimize/udp.rs >/dev/null; then
  pass "udpfast delegates batch destination handling to shared optimize::udp path"
  append_item "udpfast_per_packet_addr" "ok" "udpfast delegates to shared per-packet address conversion"
else
  fail_critical "udpfast batch send appears to use shared/first destination address"
  append_item "udpfast_per_packet_addr" "fail" "found shared destination usage pattern"
fi

# 3b) Retained MSG_ZEROCOPY and busy-poll runtime machinery must stay removed.
ZEROCOPY_RUNTIME_REFS=$(rg -n --no-messages "MSG_ZEROCOPY|SO_ZEROCOPY|should_use_msg_zerocopy|msg_zerocopy_requested|should_retry_without_zerocopy|enable_specialized_zerocopy|drain_zerocopy|zerocopy_drain_batch" src/optimize/udp.rs src/transport/udpfast.rs src/transport/xdp.rs src/transport/connection src/transport.rs || true)
if [[ -z "$ZEROCOPY_RUNTIME_REFS" ]]; then
  pass "Retained MSG_ZEROCOPY runtime machinery stays removed"
  append_item "zerocopy_runtime_surface_removed" "ok" "no retained MSG_ZEROCOPY runtime helpers or branches remain"
else
  fail_critical "Retained MSG_ZEROCOPY runtime machinery is still present"
  append_item "zerocopy_runtime_surface_removed" "fail" "$ZEROCOPY_RUNTIME_REFS"
fi

XDP_LOCAL_URING_REFS=$(rg -n --no-messages "pub mod uring_udp|struct UringUdp|enable_uring\\(|try_enable_uring_fastpath|enable_uring_or_udp_fallback" src/transport/xdp.rs || true)
if [[ -z "$XDP_LOCAL_URING_REFS" ]]; then
  pass "xdp compatibility shim does not carry a second private io_uring runtime"
  append_item "xdp_local_uring_removed" "ok" "xdp compatibility shim relies on narrowed UDP fastpath coverage only"
else
  fail_critical "xdp compatibility shim still carries a second private io_uring runtime"
  append_item "xdp_local_uring_removed" "fail" "$XDP_LOCAL_URING_REFS"
fi

BUSYPOLL_REFS=$(rg -n --no-messages "SO_BUSY_POLL|QUICFUSCATE_BUSY_POLL|BusyPollSocket" src docs/DOCUMENTATION.md || true)
if [[ -z "$BUSYPOLL_REFS" ]]; then
  pass "Busy-poll socket tuning surface stays removed"
  append_item "busypoll_surface_removed" "ok" "no SO_BUSY_POLL or busy-poll helper surface remains"
else
  fail_critical "Busy-poll socket tuning surface is still present"
  append_item "busypoll_surface_removed" "fail" "$BUSYPOLL_REFS"
fi

# 4) IPv4 sockaddr conversion must not byte-swap after from_ne_bytes(octets).
if rg -n --no-messages "from_ne_bytes\\(v4\\.ip\\(\\)\\.octets\\(\\)\\)\\.to_be\\(\\)" src/transport src/optimize >/dev/null; then
  fail_critical "Found IPv4 sockaddr conversion pattern with extra to_be() byte swap"
  append_item "ipv4_sockaddr_endian_pattern" "fail" "from_ne_bytes(...).to_be() detected"
else
  pass "No IPv4 sockaddr double-swap pattern in transport/optimize paths"
  append_item "ipv4_sockaddr_endian_pattern" "ok" "no from_ne_bytes(...).to_be() pattern found"
fi

# 4b) Shared UDP FFI metadata validators and malformed-result regressions must
# stay present and must be executed by the transport suite.
if rg -n --no-messages '^pub\(crate\) fn checked_syscall_count\(' src/optimize/udp.rs >/dev/null \
  && rg -n --no-messages '^pub\(crate\) fn checked_received_len\(' src/optimize/udp.rs >/dev/null \
  && rg -n --no-messages '^fn checked_sent_len\(' src/optimize/udp.rs >/dev/null \
  && rg -F -- 'fn test_udp_syscall_metadata_rejects_malformed_results()' src/optimize/udp.rs >/dev/null \
  && rg -F -- 'checked_syscall_count(3, 2)' src/optimize/udp.rs >/dev/null \
  && rg -F -- 'checked_received_len(9, 8, 4)' src/optimize/udp.rs >/dev/null \
  && rg -F -- 'checked_sent_len(7, 8, 2)' src/optimize/udp.rs >/dev/null \
  && rg -F -- 'run_verified_library_target udp-syscall-metadata' scripts/tests/suites/test-transport.sh >/dev/null; then
  pass "UDP syscall count, receive length, partial-send, batch, datagram, and address metadata guards have a wired malformed-result regression"
  append_item "udp_malformed_metadata_regressions" "ok" "shared validators, malformed fixtures, and transport-suite execution wiring are present"
else
  fail_critical "UDP malformed syscall/result regression or transport-suite execution contract is missing"
  append_item "udp_malformed_metadata_regressions" "fail" "missing shared validator, malformed fixture, or executed suite target"
fi

# 4c) Linux caller-fd failures must be exercised against the real batch path;
# non-Linux hosts must record the platform boundary instead of compiling it out.
if rg -F -- 'fn test_linux_batch_send_rejects_invalid_caller_fd()' src/transport/batch.rs >/dev/null \
  && rg -F -- 'Some(libc::EBADF)' src/transport/batch.rs >/dev/null \
  && rg -F -- 'batch-invalid-caller-fd' scripts/tests/suites/test-transport.sh >/dev/null \
  && rg -F -- 'host_os_not_linux' scripts/tests/suites/test-transport.sh >/dev/null; then
  pass "Linux batch caller-fd failure coverage is real and non-Linux execution is explicitly bounded"
  append_item "batch_invalid_caller_fd_regression" "ok" "Linux EBADF regression plus explicit non-Linux platform boundary present"
else
  fail_critical "Linux batch caller-fd failure coverage or its platform boundary is missing"
  append_item "batch_invalid_caller_fd_regression" "fail" "missing EBADF fixture, suite invocation, or non-Linux skip"
fi

# 4d) Transport frame malformed-input coverage must be represented in the
# executed integration target, including the cumulative batch boundary.
if rg -F -- 'fn malformed_ack_ranges_are_rejected_before_serialization()' \
    scripts/tests/rust/rt-transport-frames-roundtrip.rs >/dev/null \
  && rg -F -- 'fn malformed_connection_ids_are_rejected_before_serialization()' \
    scripts/tests/rust/rt-transport-frames-roundtrip.rs >/dev/null \
  && rg -F -- 'fn arm_stream_cursor_bounds_are_rejected()' \
    scripts/tests/rust/rt-transport-frames-roundtrip.rs >/dev/null \
  && rg -F -- 'fn batch_encoding_rejects_cumulative_capacity_overflow()' \
    scripts/tests/rust/rt-transport-frames-roundtrip.rs >/dev/null \
  && rg -F -- 'run_arm_transport_target rt-transport-frames-roundtrip arm_stream_cursor_bounds_are_rejected rust-tests' \
    scripts/tests/suites/test-transport.sh >/dev/null; then
  pass "Transport integration target covers malformed ACK/CID, ARM cursor, and cumulative batch boundaries"
  append_item "transport_frame_malformed_regressions" "ok" "malformed frame tests and the ARM platform runner are present"
else
  fail_critical "Transport frame malformed-input regression or ARM platform runner is missing"
  append_item "transport_frame_malformed_regressions" "fail" "missing malformed frame target or explicit ARM execution boundary"
fi

# 4e) The x86 packet-number lane must compile the real AVX2 target-feature
# body, compare against scalar big-endian bytes, and use a host skip boundary.
if rg -F -- '#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]' \
    scripts/tests/rust/rt-transport-packet-headers.rs >/dev/null \
  && rg -F -- 'fn native_avx2_packet_number_encoding_matches_scalar_unaligned()' \
    scripts/tests/rust/rt-transport-packet-headers.rs >/dev/null \
  && rg -F -- 'scalar_encode_packet_number' scripts/tests/rust/rt-transport-packet-headers.rs >/dev/null \
  && rg -F -- '-C target-feature=+avx2' scripts/tests/suites/test-transport.sh >/dev/null \
  && rg -F -- 'host_cpu_has_no_avx2' scripts/tests/suites/test-transport.sh >/dev/null \
  && rg -F -- 'run_native_avx2_target rt-transport-packet-headers native_avx2_packet_number_encoding_matches_scalar_unaligned rust-tests' \
    scripts/tests/suites/test-transport.sh >/dev/null \
  && rg -F -- 'run_verified_target rt-packet-number-parity packet_number_decode_matches_scalar_reference rust-tests' \
    scripts/tests/suites/test-transport.sh >/dev/null; then
  pass "Packet-number scalar parity, unaligned output, compile-time AVX2 execution, and explicit host skips are wired"
  append_item "transport_packet_number_native_regression" "ok" "scalar parity target plus explicit AVX2 target-feature runner present"
else
  fail_critical "Packet-number native AVX2 parity or its fail-closed host boundary is missing"
  append_item "transport_packet_number_native_regression" "fail" "missing scalar parity, target-feature compile, suite runner, or skip contract"
fi

# 4f) Interface BMI2 dispatch must keep profile selection and the parser's
# runtime feature intersection explicit. Hardware-specific execution is a
# platform lane; unsupported hosts must be recorded rather than silently green.
if rg -F -- 'fn bmi2_parser_is_allowed(profile: CpuProfile, features: &CpuFeatures)' \
    src/interface.rs >/dev/null \
  && rg -F -- 'if bmi2_parser_is_allowed(detector.profile(), features)' \
    src/interface.rs >/dev/null \
  && rg -F -- 'Self::profile_from_features(features_full)' \
    src/optimize/parts/cpu_dispatch.rs >/dev/null \
  && rg -F -- 'fn x86_profile_selection_keeps_bmi2_explicit()' \
    src/optimize/parts/cpu_dispatch.rs >/dev/null \
  && rg -F -- 'fn bmi2_dispatch_requires_profile_and_runtime_feature_intersection()' \
    src/interface.rs >/dev/null \
  && rg -F -- 'SIMD_SKIP test=bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported required=bmi2' \
    src/interface.rs >/dev/null \
  && rg -F -- 'run_verified_library_target "interface-unaligned-write"' \
    scripts/tests/suites/test-core.sh >/dev/null \
  && rg -F -- 'run_verified_library_target "interface-bmi2-dispatch"' \
    scripts/tests/suites/test-core.sh >/dev/null \
  && rg -F -- 'run_verified_library_target "cpu-profile-bmi2-intersection"' \
    scripts/tests/suites/test-core.sh >/dev/null \
  && rg -F -- 'host_cpu_has_no_bmi2' scripts/tests/suites/test-core.sh >/dev/null; then
  pass "Interface BMI2 dispatch proves profile selection, runtime feature intersection, unaligned input, and native host skips"
  append_item "interface_bmi2_dispatch_regression" "ok" "cached profile, exact BMI2 gate, synthetic profile cases, unaligned coverage, and explicit native skip wiring present"
else
  fail_critical "Interface BMI2 dispatch proof or its fail-closed platform runner is missing"
  append_item "interface_bmi2_dispatch_regression" "fail" "missing profile intersection, test coverage, SIMD skip, or core-suite wiring"
fi

# 4g) The public interface schema must match the runtime that is actually
#     shipped. Removed XDP fields stay absent from serialization, while legacy
#     interface type values fail closed during validation.
if ! rg -F -- 'pub xdp_mode:' src/engine/config.rs >/dev/null \
  && ! rg -F -- 'pub xdp_flags:' src/engine/config.rs >/dev/null \
  && ! rg -F -- 'pub enum XdpMode' src/engine/config.rs >/dev/null \
  && rg -F -- 'AF_XDP was removed; use' \
    src/engine/config.rs >/dev/null \
  && rg -F -- 'fn interface_validation_rejects_legacy_non_tun_types()' \
    src/engine/config.rs >/dev/null \
  && rg -F -- 'fn interface_schema_removes_xdp_fields_and_rejects_legacy_input()' \
    src/engine/config.rs >/dev/null \
  && ! rg -n --no-messages 'xdp_mode|xdp_flags' config/quicfuscate.toml \
    config/server-linux.default.toml >/dev/null \
  && rg -F -- '# The current runtime supports only the layer-3 TUN interface.' \
    config/quicfuscate.toml >/dev/null \
  && rg -F -- '# type = "tun"                 # The current runtime supports only "tun".' \
    config/server-linux.default.toml >/dev/null; then
  pass "Interface configuration surface matches the TUN-only runtime and rejects stale XDP input"
  append_item "xdp_config_surface_truth" "ok" "removed XDP fields, fail-closed legacy types, schema tests, and canonical templates are aligned"
else
  fail_critical "Interface configuration surface still advertises or accepts stale XDP configuration"
  append_item "xdp_config_surface_truth" "fail" "removed-field, validation, test, or template contract is incomplete"
fi

# 5) Guardrail warning: broad dead_code suppression in production/runtime-critical modules.
DEADCODE_SUPPRESSIONS="$(rg -n --no-messages '^#!\[allow\(dead_code\)\]' src/optimize src/transport src/fec src/simd || true)"
if [[ -n "$DEADCODE_SUPPRESSIONS" ]]; then
  warn_guardrail "Broad #![allow(dead_code)] found in production/runtime-critical modules"
  echo "$DEADCODE_SUPPRESSIONS"
  append_item "dead_code_suppression" "warn" "broad module-level dead_code suppression present"
else
  pass "No broad module-level dead_code suppression in optimize/transport/fec/simd"
  append_item "dead_code_suppression" "ok" "no broad suppression found"
fi

FEC_INTERNAL_DEADCODE_SUPPRESSIONS="$(rg -n --no-messages '#\[allow\(dead_code\)\]' src/fec/internal.rs || true)"
if [[ -n "$FEC_INTERNAL_DEADCODE_SUPPRESSIONS" ]]; then
  fail_critical "FEC internal implementation regained item-level dead_code suppression"
  append_item "fec_internal_dead_code_suppression" "fail" "$FEC_INTERNAL_DEADCODE_SUPPRESSIONS"
else
  pass "FEC internal implementation has no dead_code suppression"
  append_item "fec_internal_dead_code_suppression" "ok" "test-only constructors use explicit cfg(test) ownership"
fi

FEC_RECOVERY_INTEGRITY_REGRESSIONS="$(rg -n --no-messages 'norm_base|base_id\.wrapping_add\(j as u64\)|return self\.try_eliminate_wiedemann\(\)' src/fec || true)"
if [[ -n "$FEC_RECOVERY_INTEGRITY_REGRESSIONS" ]]; then
  fail_critical "FEC decoder regained ambiguous anchors, forward GF4 mapping, or unvalidated auto-Wiedemann recovery"
  append_item "fec_recovery_integrity" "fail" "$FEC_RECOVERY_INTEGRITY_REGRESSIONS"
elif rg -n --no-messages 'valid\.then_some\(solution\)' src/fec >/dev/null \
  && rg -n --no-messages 'test_fec_e2e_default_interleave_recovers_1000_packets_at_5pct_random_loss' src/fec/e2e_tests.rs >/dev/null \
  && rg -n --no-messages 'test_fec_e2e_default_interleave_recovers_four_consecutive_losses_per_sixteen' src/fec/e2e_tests.rs >/dev/null; then
  pass "FEC recovery keeps exact anchors, validated solver output, and deterministic interleaved integrity gates"
  append_item "fec_recovery_integrity" "ok" "exact anchors, solver validation, and 1000-packet random/burst gates are present"
else
  fail_critical "FEC recovery integrity contract is incomplete"
  append_item "fec_recovery_integrity" "fail" "solver validation or deterministic interleaved recovery gates missing"
fi

FEC_WRONG_FIELD_GFNI_CALLS="$(rg -n --no-messages '_mm512_gf2p8mul_epi8\(' src/fec/gf_tables.rs src/fec || true)"
if [[ -z "$FEC_WRONG_FIELD_GFNI_CALLS" ]] \
  && rg -n --no-messages 'IRREDUCIBLE_POLY: u16 = 0x11D' src/fec/gf_tables.rs >/dev/null; then
  pass "FEC GF8 kernels preserve the canonical 0x11D wire field"
  append_item "fec_gf8_polynomial" "ok" "no raw Intel GFNI 0x11B multiply remains in canonical FEC kernels"
else
  fail_critical "FEC GF8 polynomial contract is missing or raw Intel GFNI multiplication returned"
  append_item "fec_gf8_polynomial" "fail" "${FEC_WRONG_FIELD_GFNI_CALLS:-canonical 0x11D polynomial declaration missing}"
fi

BROKEN_U32_SORT_BACKENDS="$(rg -n --no-messages 'sort_u32_(avx512|avx2|neon)|sort_small_avx(512|2)|partition_avx512' src/optimize/sort.rs || true)"
if [[ -z "$BROKEN_U32_SORT_BACKENDS" ]] \
  && rg -n --no-messages 'pub fn sort_u32\(data: &mut \[u32\]\).*' src/optimize/sort.rs >/dev/null \
  && rg -n --no-messages 'data\.sort_unstable\(\)' src/optimize/sort.rs >/dev/null \
  && rg -n --no-messages 'berlekamp_massey_boundary_lengths_match_scalar' src/simd >/dev/null; then
  pass "Windows SIMD parity paths reject the corrupt u32 sorters and cover Berlekamp boundaries"
  append_item "windows_simd_parity" "ok" "canonical u32 sort and Berlekamp boundary parity gate are present"
else
  fail_critical "Windows SIMD parity contract regressed"
  append_item "windows_simd_parity" "fail" "${BROKEN_U32_SORT_BACKENDS:-canonical sort or Berlekamp boundary gate missing}"
fi

TLS_COVER_REINSTALL_REGRESSIONS="$(rg -n --no-messages 'TODO-269|install_tls_cover_chacha|install_tls_cover_aes_gcm|tls_cover_(write|read)_seq\.wrapping_add' src scripts/tests/rust || true)"
if [[ -n "$TLS_COVER_REINSTALL_REGRESSIONS" ]]; then
  fail_critical "TLS Cover retained an unsafe or parallel cipher reinstallation path"
  append_item "tls_cover_reinstallation_safety" "fail" "$TLS_COVER_REINSTALL_REGRESSIONS"
elif rg -n --no-messages 'pub fn install_tls_cover_cipher\(' src/transport/packet.rs >/dev/null \
  && rg -n --no-messages 'retired_tls_cover_identities' src/transport/packet.rs >/dev/null \
  && rg -n --no-messages 'checked_add\(1\).*AeadLimitReached' src/transport/packet.rs >/dev/null \
  && rg -n --no-messages 'crate::rng::fill_secure\(&mut entropy\)' src/stealth >/dev/null; then
  pass "TLS Cover uses one fresh-entropy, no-reuse cipher installation contract"
  append_item "tls_cover_reinstallation_safety" "ok" "typed install, retired-key rejection, checked counters, and per-provider entropy are present"
else
  fail_critical "TLS Cover cipher installation safety contract is incomplete"
  append_item "tls_cover_reinstallation_safety" "fail" "typed install, retired-key rejection, checked counters, or fresh entropy missing"
fi

TUN_E2E_GLOBAL_PROCESS_REAPER="$(rg -n --no-messages 'pkill.*quicfuscate|killall.*quicfuscate' scripts/tests/tun-e2e-netns.sh || true)"
if [[ -n "$TUN_E2E_GLOBAL_PROCESS_REAPER" ]]; then
  fail_critical "Base TUN E2E harness retained a global QuicFuscate process reaper"
  append_item "tun_e2e_owned_process_cleanup" "fail" "$TUN_E2E_GLOBAL_PROCESS_REAPER"
elif rg -n --no-messages '^[[:space:]]*SERVER_PID=\$![[:space:]]*$' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages '^[[:space:]]*CLIENT_PID=\$![[:space:]]*$' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages 'stop_owned_process "\$CLIENT_PID"' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages 'stop_owned_process "\$SERVER_PID"' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages '^trap cleanup_on_exit EXIT$' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages 'pgrep -x quicfuscate' scripts/tests/tun-e2e-netns.sh >/dev/null \
  && rg -n --no-messages 'NAMESPACES_CREATED' scripts/tests/tun-e2e-netns.sh >/dev/null; then
  pass "Base TUN E2E harness owns exact child PIDs and refuses broad process cleanup"
  append_item "tun_e2e_owned_process_cleanup" "ok" "exact child PID cleanup, exit trap, and pre-existing runtime refusal are present"
else
  fail_critical "Base TUN E2E harness process-ownership contract is incomplete"
  append_item "tun_e2e_owned_process_cleanup" "fail" "child PID capture, scoped cleanup, exit trap, or pre-existing runtime refusal missing"
fi

TUN_PROVISIONING_NEGATIVE_HARNESS="scripts/tests/tun-provisioning-negative-netns.sh"
if [[ -x "$TUN_PROVISIONING_NEGATIVE_HARNESS" ]] \
  && rg -F -- 'expect_failure "overlong-name"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'expect_failure "duplicate-name"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'expect_failure "permission-denied"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'expect_failure "conflicting-address"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'expect_failure "routing-failure"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'expect_failure "routing-retry"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'missing-interface' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'assert_interface_absent' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && rg -F -- 'ip netns add "$NAMESPACE"' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null \
  && ! rg -n --no-messages 'pkill|killall' "$TUN_PROVISIONING_NEGATIVE_HARNESS" >/dev/null; then
  pass "Linux TUN provisioning has a process-real negative, retry, rollback, and zero-residue namespace harness"
  append_item "tun_provisioning_negative_namespace_proof" "ok" "overlong names, duplicate state, permission denial, conflicting address, missing interface, retry, and exact residue checks are present"
else
  fail_critical "Linux TUN provisioning negative namespace proof is missing or incomplete"
  append_item "tun_provisioning_negative_namespace_proof" "fail" "missing executable harness, required negative cases, exact residue checks, namespace setup, or safe process ownership"
fi

SPECIALIZED_TUN_E2E_HARNESSES=(
  scripts/tests/tun-e2e-fec-netns.sh
  scripts/tests/tun-e2e-fec-burst-netns.sh
  scripts/tests/tun-e2e-fec-transition-netns.sh
  scripts/tests/tun-e2e-fec-netem-adversity.sh
)
SPECIALIZED_TUN_E2E_GLOBAL_REAPERS="$(
  rg -n --no-messages 'pkill.*quicfuscate|killall.*quicfuscate' \
    "${SPECIALIZED_TUN_E2E_HARNESSES[@]}" || true
)"
SPECIALIZED_TUN_E2E_SHARED_RUNTIME_REFS="$(
  rg -n --no-messages \
    '/tmp/(ns-srv\.log|ns-cli\.log|qf-admin\.sock|iperf-srv\.log|leaf-ext\.cnf|s\.csr|leaf\.crt)|config/local/server\.(crt|key)' \
    "${SPECIALIZED_TUN_E2E_HARNESSES[@]}" || true
)"
SPECIALIZED_TUN_E2E_INCOMPLETE=()
for harness in "${SPECIALIZED_TUN_E2E_HARNESSES[@]}"; do
  SPECIALIZED_SERVER_PID_CAPTURES="$(rg -c --no-messages '^[[:space:]]*SERVER_PID=\$!$' "$harness" || true)"
  SPECIALIZED_CLIENT_PID_CAPTURES="$(rg -c --no-messages '^[[:space:]]*CLIENT_PID=\$!$' "$harness" || true)"
  if [[ "${SPECIALIZED_SERVER_PID_CAPTURES:-0}" -lt 2 ]] \
    || [[ "${SPECIALIZED_CLIENT_PID_CAPTURES:-0}" -lt 2 ]] \
    || ! rg -n --no-messages 'stop_owned_process "\$CLIENT_PID"' "$harness" >/dev/null \
    || ! rg -n --no-messages 'stop_owned_process "\$SERVER_PID"' "$harness" >/dev/null \
    || ! rg -n --no-messages '^trap cleanup_on_exit EXIT$' "$harness" >/dev/null \
    || ! rg -n --no-messages "^trap 'exit 143' TERM$" "$harness" >/dev/null \
    || ! rg -n --no-messages "^trap 'exit 130' INT$" "$harness" >/dev/null \
    || ! rg -n --no-messages 'pgrep -x quicfuscate' "$harness" >/dev/null \
    || ! rg -n --no-messages 'SERVER_NAMESPACE_CREATED|CLIENT_NAMESPACE_CREATED|VETH_CREATED|QDISC_CREATED' "$harness" >/dev/null \
    || ! rg -n --no-messages 'ip netns exec ns-srv ip route add default dev veth-srv' "$harness" >/dev/null \
    || ! rg -n --no-messages 'mktemp -d /tmp/quicfuscate-' "$harness" >/dev/null \
    || ! rg -n --no-messages -- '--qkey-store "\$QKEY_STORE"' "$harness" >/dev/null \
    || ! rg -n --no-messages 'preserve_failure_if_requested' "$harness" >/dev/null \
    || ! rg -n --no-messages 'QF_E2E_OWNERSHIP_SELF_TEST' "$harness" >/dev/null; then
    SPECIALIZED_TUN_E2E_INCOMPLETE+=("$harness")
  fi
done

if [[ -n "$SPECIALIZED_TUN_E2E_GLOBAL_REAPERS" ]]; then
  fail_critical "Specialized TUN/FEC E2E harnesses retained a global QuicFuscate process reaper"
  append_item "specialized_tun_e2e_owned_cleanup" "fail" "$SPECIALIZED_TUN_E2E_GLOBAL_REAPERS"
elif [[ -n "$SPECIALIZED_TUN_E2E_SHARED_RUNTIME_REFS" ]]; then
  fail_critical "Specialized TUN/FEC E2E harnesses retained shared mutable runtime paths"
  append_item "specialized_tun_e2e_owned_cleanup" "fail" "$SPECIALIZED_TUN_E2E_SHARED_RUNTIME_REFS"
elif [[ "${#SPECIALIZED_TUN_E2E_INCOMPLETE[@]}" -gt 0 ]]; then
  fail_critical "Specialized TUN/FEC E2E ownership contract is incomplete"
  append_item "specialized_tun_e2e_owned_cleanup" "fail" "incomplete harnesses: ${SPECIALIZED_TUN_E2E_INCOMPLETE[*]}"
elif [[ "$(rg -c --no-messages '^[[:space:]]*IPERF_SERVER_PID=\$!$' \
    scripts/tests/tun-e2e-fec-netns.sh || true)" -lt 2 ]] \
  || ! rg -n --no-messages 'stop_owned_process "\$IPERF_SERVER_PID"' \
    scripts/tests/tun-e2e-fec-netns.sh >/dev/null; then
  fail_critical "Specialized FEC netns harness does not own its iperf3 server PID"
  append_item "specialized_tun_e2e_owned_cleanup" "fail" "iperf3 server PID ownership missing"
elif ! rg -F -- 'QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate' \
    scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || ! rg -F -- 'QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate' \
    scripts/tests/tun-e2e-fec-burst-netns.sh >/dev/null \
  || ! rg -F -- 'QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate' \
    scripts/tests/tun-e2e-fec-transition-netns.sh >/dev/null \
  || ! rg -F -- 'QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate' \
    scripts/tests/tun-e2e-fec-netem-adversity.sh >/dev/null \
  || ! rg -F -- '-J > "$iperf_json"' scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || ! rg -F -- 'receiver=data["end"]["sum_received"]' \
    scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || ! rg -F -- 'all(item["bytes"] > 0 and item["bits_per_second"] > 0 for item in intervals)' \
    scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || rg -F -- 'iperf_output=$(ip netns exec' scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || rg -F -- 'SKIP:' scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || rg -F -- '[ "$retransmits" = "0" ]' scripts/tests/tun-e2e-fec-netns.sh >/dev/null \
  || rg -Fi -- 'interleaving should handle burst patterns better than block codes' \
    scripts/tests/tun-e2e-fec-burst-netns.sh >/dev/null \
  || rg -F -- 'Phase 1: 0% loss for 5s' scripts/tests/tun-e2e-fec-transition-netns.sh >/dev/null \
  || rg -Fi -- 'tunnel loss should be <20% (fec helps)' \
    scripts/tests/tun-e2e-fec-netem-adversity.sh >/dev/null \
  || rg -Fi -- 'recovery after de-escalation' \
    scripts/tests/tun-e2e-fec-netem-adversity.sh >/dev/null \
  || rg -F -- 'SKIP=' scripts/tests/tun-e2e-fec-netem-adversity.sh >/dev/null; then
  fail_critical "Specialized FEC netns throughput gate can silently accept sender-only or skipped results, or require a flakey retransmit count"
  append_item "specialized_tun_e2e_receiver_throughput" "fail" "receiver JSON proof, required-tool failure, exact-artifact override, or stable acceptance missing"
else
  pass "Specialized TUN/FEC E2E harnesses own exact processes, namespaces, qdiscs, and runtime artifacts"
  append_item "specialized_tun_e2e_owned_cleanup" "ok" "four harnesses use exact child ownership, isolated runtime paths, owned server routes, and fail-closed resource preflights"
  append_item "specialized_tun_e2e_receiver_throughput" "ok" "uniform FEC iperf3 uses bounded JSON output and positive receiver interval proof"
fi

UNIFORM_FEC_CONTRACT_HARNESS="scripts/tests/tun-e2e-fec-netns.sh"
BURST_FEC_CONTRACT_HARNESS="scripts/tests/tun-e2e-fec-burst-netns.sh"
TRANSITION_FEC_CONTRACT_HARNESS="scripts/tests/tun-e2e-fec-transition-netns.sh"
ADVERSITY_FEC_CONTRACT_HARNESS="scripts/tests/tun-e2e-fec-netem-adversity.sh"
FEC_LOSS_STABILITY_HARNESS="scripts/tests/tun-e2e-fec-loss-stability.sh"
if rg -F -- 'UNIFORM_PING_SCENARIOS=(' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'UNIFORM_IPERF_SCENARIOS=(0 10)' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'refusing to overwrite existing artifact path' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'binary_sha256=' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'results.tsv' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RUNTIME_FAILURE_PATTERN=' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'run_loss_level "$loss" "$max_loss"' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && ! rg -F -- 'case "$loss_pct" in' "$UNIFORM_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'BURST_SCENARIOS=(' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'refusing to overwrite existing artifact path' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'binary_sha256=' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'results.tsv' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RUNTIME_FAILURE_PATTERN=' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'run_burst_scenario "$loss_pct" "$correlation" "$label burst" "$median_limit" "$sample_limit"' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && ! rg -F -- 'run_burst_scenario 10 25' "$BURST_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'TRANSITION_SCENARIOS=(' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'if [ "$profile_name" = "$LOSS_PROFILE" ]; then' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'loss1=$(ping_phase "$CLEAN_PING_COUNT" "1")' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'loss2=$(ping_phase "$LOSS_PHASE_PING_COUNT" "2")' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'loss3=$(ping_phase "$RECOVERY_PING_COUNT" "3")' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'quicfuscate_fec_wire_overhead_sent_ppm' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'quicfuscate_fec_recovered_packets_total' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RECOVERY_DURATION_MS=$((recovery_finished_ms - recovery_started_ms))' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'MAX_RECOVERY_DURATION_MS' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'runtime_failure_count=' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && ! rg -F -- 'case "$LOSS_PROFILE" in' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && ! rg -F -- 'ping_phase 50 "1"' "$TRANSITION_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'LOSS_SCENARIOS=(' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'JITTER_SCENARIOS=(' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'BANDWIDTH_SCENARIOS=(' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RTT_SCENARIOS=(' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'COMBINED_SCENARIO=' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RECOVERY_SCENARIO=' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'for scenario in "${LOSS_SCENARIOS[@]}"; do' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'for scenario in "${JITTER_SCENARIOS[@]}"; do' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'for scenario in "${BANDWIDTH_SCENARIOS[@]}"; do' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'for scenario in "${RTT_SCENARIOS[@]}"; do' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_ARTIFACT_DIR' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- '"$B" --telemetry server' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- '"$B" --telemetry client' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'capture_telemetry "loss-${loss}"' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'capture_telemetry "recovery-lossy"' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'record_loss_result "loss-${loss}"' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- "printf 'result=%s\\n'" "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'preserve_telemetry_evidence' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'runtime_failure_count=' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'RUNTIME_FAILURE_PATTERN=' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'ADVERSITY_PING_COUNT="${QF_ADVERSITY_PING_COUNT:-50}"' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null \
  && rg -F -- 'LOSS_PING_COUNT=200' "$FEC_LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_ADVERSITY_PING_COUNT="$LOSS_PING_COUNT"' "$FEC_LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'grep -Fx "ping_count=$LOSS_PING_COUNT" "$manifest"' "$FEC_LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'grep -Fx "runtime_failure_count=0" "$manifest"' "$FEC_LOSS_STABILITY_HARNESS" >/dev/null \
  && ! rg -F -- 'for loss in 0 1 5 10 25 50; do' "$ADVERSITY_FEC_CONTRACT_HARNESS" >/dev/null; then
  pass "Specialized FEC acceptance executes printed contracts and captures loss/recovery controller evidence"
  append_item "fec_specialized_single_source_contract" "ok" "scenario inputs and bounds flow from contract arrays into execution; adversity captures FEC controller telemetry"
else
  fail_critical "Specialized FEC acceptance drifted from its scenario contract or lost FEC controller evidence"
  append_item "fec_specialized_single_source_contract" "fail" "missing scenario contract arrays, contract-driven execution, telemetry evidence, or stale duplicated threshold branch"
fi

SPECIALIZED_TUN_E2E_REGRESSION="scripts/tests/test-specialized-tun-e2e-ownership.sh"
if rg -n --no-messages 'quicfuscate-sentinel' "$SPECIALIZED_TUN_E2E_REGRESSION" >/dev/null \
  && rg -n --no-messages 'QF_E2E_OWNERSHIP_SELF_TEST_MODE' "$SPECIALIZED_TUN_E2E_REGRESSION" >/dev/null \
  && rg -n --no-messages 'unowned namespace' "$SPECIALIZED_TUN_E2E_REGRESSION" >/dev/null \
  && rg -n --no-messages 'unowned link' "$SPECIALIZED_TUN_E2E_REGRESSION" >/dev/null \
  && ! rg -n --no-messages 'pkill|killall' "$SPECIALIZED_TUN_E2E_REGRESSION" >/dev/null; then
  pass "Specialized TUN/FEC ownership regression covers unrelated process, namespace, link, exit, signal, and keep-on-failure paths"
  append_item "specialized_tun_e2e_ownership_regression" "ok" "failable lifecycle and unrelated-resource survival regression is present"
else
  fail_critical "Specialized TUN/FEC ownership regression is missing or unsafe"
  append_item "specialized_tun_e2e_ownership_regression" "fail" "sentinel, lifecycle mode, namespace/link refusal, or exact cleanup coverage missing"
fi

LOSS_STABILITY_HARNESS="scripts/tests/tun-e2e-fec-loss-stability.sh"
if rg -F -- 'LOSS_TRIALS=3' "$LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_ADVERSITY_SUITE=loss' "$LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'summary.tsv' "$LOSS_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'missing, duplicate, incomplete, or out-of-contract results' "$LOSS_STABILITY_HARNESS" >/dev/null; then
  pass "Repeated FEC loss stability harness requires three raw-evidence trials and a fail-closed aggregate"
  append_item "fec_loss_stability_aggregate" "ok" "three loss trials, child evidence, and TSV aggregation are required"
else
  fail_critical "Repeated FEC loss stability harness is missing its fail-closed aggregate contract"
  append_item "fec_loss_stability_aggregate" "fail" "missing trial count, loss selector, raw aggregate, or failure check"
fi

CUBIC_FEC_CONTROL_HARNESS="scripts/tests/tun-e2e-cubic-netns.sh"
RUNTIME_PERFORMANCE_SAMPLER="scripts/tests/utils/runtime-performance-sampler.py"
if rg -F -- 'LOSS_TRIALS=3' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'for fec_mode in auto off; do' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'run_loss_comparison "$fec_mode"' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'loss-summary-$fec_mode.json' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'fec-comparison-summary.json' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'auto_minus_off_retained_percentage_points' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'prepare_certificate' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'CA_KEY="${QF_E2E_CA_KEY:-$PROJECT_ROOT/config/local/ca.key}"' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'start_performance_sampler "$fec_mode-$phase"' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'validate_performance_phase "$fec_mode" "$phase"' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'capture_latency "$fec_mode-$phase"' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'prove_runtime_logs_clean' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'refusing to overwrite existing artifact path' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'preflight_owned_resources' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'return 0' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'panic|Crypto error: crypto failure|AEAD limit reached|Key update error|heartbeat timeout|InternalError|TUN packet send failed' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null \
  && rg -F -- 'cpu_one_core_percent' "$RUNTIME_PERFORMANCE_SAMPLER" >/dev/null \
  && rg -F -- 'peak_pending_packets' "$RUNTIME_PERFORMANCE_SAMPLER" >/dev/null \
  && rg -F -- 'allocation_deltas' "$RUNTIME_PERFORMANCE_SAMPLER" >/dev/null \
  && rg -F -- 'rate_limited_delta' "$RUNTIME_PERFORMANCE_SAMPLER" >/dev/null \
  && ! rg -F -- 'config/local/server.crt' "$CUBIC_FEC_CONTROL_HARNESS" >/dev/null; then
  pass "CUBIC loss proof keeps matched controls plus fail-closed runtime performance evidence"
  append_item "cubic_fec_control_comparison" "ok" "three clean/loss trials per policy, isolated fixture, comparison, latency, CPU, allocation, queue, RSS, and rate-limit evidence are required"
else
  fail_critical "CUBIC loss proof lost its matched control or runtime performance contract"
  append_item "cubic_fec_control_comparison" "fail" "missing repetition, policy control, isolated fixture, comparison, latency, CPU, allocation, queue, RSS, or rate-limit evidence"
fi

MULTI_CLIENT_DUAL_STACK_HARNESS="scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh"
TCP_THROUGHPUT_PROBE="scripts/tests/utils/tcp-throughput-probe.py"
EGRESS_SUMMARIZER="scripts/tests/utils/summarize-external-egress.py"
BOUNDARY_SUMMARIZER="scripts/tests/utils/summarize-throughput-boundaries.py"
UDP_SOCKET_EVIDENCE="scripts/tests/utils/udp-socket-evidence.py"
if rg -F -- 'for host_veth in "${HOST_VETH[@]}"; do' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'ip link del "$host_veth" 2>/dev/null' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'THROUGHPUT_PROBE="$SCRIPT_DIR/utils/tcp-throughput-probe.py"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'python3 "$THROUGHPUT_PROBE" server' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'python3 "$THROUGHPUT_PROBE" client' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '--rate-bps "$THROUGHPUT_RATE_BPS"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'IPv6 throughput evidence exceeded the bounded trial duration in phase $phase' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'assert_metric_zero "throughput-$phase" quicfuscate_rate_limited_total' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'prove_runtime_logs_clean' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'fetch_metrics throughput-failure || true' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && ! rg -F -- 'iperf3' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'sender/receiver byte mismatch' "$TCP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'sender/receiver SHA-256 mismatch' "$TCP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'receiver_bits_per_second' "$TCP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'started_at_unix_ns' "$TCP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'finished_at_unix_ns' "$TCP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'EGRESS_SUMMARIZER="$SCRIPT_DIR/utils/summarize-external-egress.py"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'server-ingress-$phase.log' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '--server-capture "$ARTIFACT_DIR/server-ingress-$phase.log"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '--trial "$ARTIFACT_DIR/tcp6-client-$phase-1.json"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'SERVER_INGRESS_LABEL = "server UDP ingress"' "$EGRESS_SUMMARIZER" >/dev/null \
  && rg -F -- 'retained fewer than two {label} packets' "$EGRESS_SUMMARIZER" >/dev/null \
  && rg -F -- 'BOUNDARY_SUMMARIZER="$SCRIPT_DIR/utils/summarize-throughput-boundaries.py"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'server-return-$phase.log' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'client-ingress-$phase.log' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'throughput-window-$phase-$trial.json' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'summarize_throughput_boundaries "$phase"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '("server UDP return", "server_return_capture")' "$BOUNDARY_SUMMARIZER" >/dev/null \
  && rg -F -- '("client-1 UDP ingress", "client_ingress_capture")' "$BOUNDARY_SUMMARIZER" >/dev/null \
  && rg -F -- 'External throughput trial {window.trial} client exit status' "$BOUNDARY_SUMMARIZER" >/dev/null \
  && rg -F -- 'parser.add_argument("--self-test", action="store_true")' "$BOUNDARY_SUMMARIZER" >/dev/null \
  && rg -F -- 'UDP_SOCKET_EVIDENCE="$SCRIPT_DIR/utils/udp-socket-evidence.py"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'server-udp-$phase-$trial-before.json' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'client-udp-$phase-$trial-before.json' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'CLIENT_RECV_DIAGNOSTICS="${QF_E2E_CLIENT_RECV_DIAGNOSTICS:-1}"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS="$CLIENT_RECV_DIAGNOSTICS"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'capture_client_receive_diagnostics "$phase" "$trial"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'capture_client_persistent_congestion "$phase" "$trial"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'capture_client_persistent_congestion "black-hole" 1 "$client_log"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'start_client_egress_capture black-hole' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'record_throughput_trial_window "black-hole" 1' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'summarize_throughput_boundaries black-hole' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'Client receive diagnostics at heartbeat:' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '[[ ! -e "$output" ]] || fail "refusing to replace client receive diagnostics: $output"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'persistent congestion established;' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'refusing to replace client persistent-congestion evidence' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'CLIENT_RECV_DIAGNOSTICS must be 0 or 1' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'FEC_MODE="${QF_E2E_FEC_MODE:-auto}"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_FEC_MODE must be auto or off' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'printf '"'"'\n[fec]\nmode = "%s"\n'"'"' "$FEC_MODE"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'CLIENT_RECV_DIAGNOSTICS_ENV: &str = "QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS"' src/main.rs src/main_parts >/dev/null \
  && rg -F -- 'Client receive diagnostics at heartbeat:' src/main.rs src/main_parts >/dev/null \
  && rg -F -- 'last_activity_marker' src/main.rs src/main_parts src/transport/connection >/dev/null \
  && rg -F -- 'terminal_packet_threshold={}' src/transport/connection >/dev/null \
  && rg -F -- 'ack_delay_us={}' src/transport/connection >/dev/null \
  && rg -F -- 'ack_time_threshold_losses={}' src/transport/connection >/dev/null \
  && rg -F -- 'smoothed_rtt_us={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_min_packet_size={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_control_packets={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_stream_packets={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_stream_fresh_packets={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_stream_retransmission_packets={}' src/transport/connection >/dev/null \
  && rg -F -- 'run_datagram_packets={}' src/transport/connection >/dev/null \
  && rg -F -- 'server UDP socket dropped datagrams during IPv6 throughput trial' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'client UDP socket dropped datagrams during IPv6 throughput trial' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'selector = f"on port {port}"' "$UDP_SOCKET_EVIDENCE" >/dev/null \
  && rg -F -- '--remote-port' "$UDP_SOCKET_EVIDENCE" >/dev/null \
  && rg -F -- 'remote_port' "$UDP_SOCKET_EVIDENCE" >/dev/null \
  && rg -F -- 'UDP socket dropped {drop_delta} datagrams during the trial' "$UDP_SOCKET_EVIDENCE" >/dev/null; then
  pass "Multi-client dual-stack proof keeps receiver-verified forward and reverse boundary evidence, including black-hole recovery, plus client/server UDP socket-drop evidence"
  append_item "multi_client_dual_stack_tcp_throughput" "ok" "receiver bytes, SHA-256, persisted failure windows including black-hole recovery, four host-veth boundaries, client/server socket-drop deltas, and partial-run host-veth cleanup are fail-closed"
else
  fail_critical "Multi-client dual-stack proof lost receiver-verified forward/reverse boundary, black-hole, or client/server UDP socket-drop evidence"
  append_item "multi_client_dual_stack_tcp_throughput" "fail" "missing receiver byte/hash/window gate, external forward/reverse capture including black-hole recovery, client/server UDP socket-drop proof, direct probe use, no-iperf contract, or host-veth cleanup"
fi

PER_CLIENT_BANDWIDTH_HARNESS="scripts/tests/tun-e2e-bandwidth-netns.sh"
UDP_THROUGHPUT_PROBE="scripts/tests/utils/udp-throughput-probe.py"
BANDWIDTH_RELEASE_SIDE_EFFECTS="$(rg -n --no-messages 'debug_assert!\([^;]*\.(record|check|update|insert|remove)\(' src/implementations/server/bandwidth.rs || true)"
if [[ -z "$BANDWIDTH_RELEASE_SIDE_EFFECTS" ]]; then
  pass "Per-client bandwidth accounting remains active in release builds"
  append_item "per_client_bandwidth_release_accounting" "ok" "quota and limiter state changes execute outside debug-only assertions"
else
  fail_critical "Per-client bandwidth accounting contains debug-only side effects"
  append_item "per_client_bandwidth_release_accounting" "fail" "$BANDWIDTH_RELEASE_SIDE_EFFECTS"
fi

if rg -F -- 'UDP_PROBE="$SCRIPT_DIR/utils/udp-throughput-probe.py"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'sha256sum "$BINARY"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'cc_algorithm = "reno"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'preflight_topology' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'TOPOLOGY_OWNED=1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'refusing to replace artifact directory' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- '--header "Origin: http://127.0.0.1:$ADMIN_PORT"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- '--header "X-CSRF-Token: $CSRF_TOKEN"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- '--header "X-CSRF-Nonce: todo529-$ADMIN_REQUEST_INDEX"' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'set_policies 0 0 0 0 1 1 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'set_policies 1250000 125000 0 0 1 1 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'set_policies 1250000 2500000 0 0 1 1 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'run_sequential_downlink_matrix burst 1.5 40000000' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'set_policies 0 0 2400000 0 1 1 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'capture_bandwidth_stats quota-after 0 0 2400000 0 1 1 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'set_policies 0 0 0 0 1 2 1' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'SERVER_DOWNLINK_RATE_BYTES_PER_SECOND=2000000' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'SERVER_DOWNLINK_BURST_BYTES=24000' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'downlink-scheduler-policy.env' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_VERBOSE' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'runtime-log-mode.env' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && ! rg -F -- '-v >"$ARTIFACT_DIR/' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'QUICFUSCATE_SERVER_DOWNLINK_RATE_BYTES_PER_SECOND' src/implementations/server/parts/config.rs config/server-linux.default.toml "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'reserve_capacity(entry.packet.len())' src/implementations/server/parts/tun_path.rs >/dev/null \
  && rg -F -- 'daily_quota_exceeded' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'assert_matrix weighted-1-2-1 weighted' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'prove_runtime_clean' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'prove_topology_absent' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && ! rg -F -- 'iperf3' "$PER_CLIENT_BANDWIDTH_HARNESS" >/dev/null \
  && rg -F -- 'refusing to replace existing result' "$UDP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'duplicate_packets' "$UDP_THROUGHPUT_PROBE" >/dev/null \
  && rg -F -- 'payload_bits_per_second' "$UDP_THROUGHPUT_PROBE" >/dev/null; then
  pass "Per-client bandwidth proof keeps exact-artifact authenticated three-client rate, burst, quota, and weighted-fairness evidence"
  append_item "per_client_bandwidth_three_client_matrix" "ok" "unlimited, exact 10-Mbit, burst, quota, equal-weight, 1:2:1, CSRF-authenticated mutation, binary identity, and cleanup gates are required"
else
  fail_critical "Per-client bandwidth proof lost its authenticated three-client evidence contract"
  append_item "per_client_bandwidth_three_client_matrix" "fail" "missing exact policy matrix, receiver evidence, authenticated admin mutation, binary identity, fail-closed artifact ownership, or cleanup"
fi

DUAL_STACK_STABILITY_HARNESS="scripts/tests/tun-e2e-multi-client-dual-stack-stability.sh"
DUAL_STACK_STABILITY_AGGREGATOR="scripts/tests/utils/aggregate-dual-stack-stability.py"
if rg -F -- 'STABILITY_TRIALS=3' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_EXTERNAL_EGRESS_CAPTURE=1' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_DEFER_PMTU_GAIN_GATE=1' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_ARTIFACT_DIR="$trial_dir"' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'FEC_MODE="${QF_E2E_FEC_MODE:-auto}"' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'QF_E2E_FEC_MODE must be auto or off' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'printf '"'"'fec_mode=%s\n'"'"' "$FEC_MODE"' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'summary.tsv' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'dual-stack stability aggregate has' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'median receiver-verified PMTU throughput gain is below 15 percent' "$DUAL_STACK_STABILITY_AGGREGATOR" >/dev/null \
  && rg -F -- 'every stability trial must retain a positive PMTU gain' "$DUAL_STACK_STABILITY_AGGREGATOR" >/dev/null \
  && rg -F -- '--finalize' "$DUAL_STACK_STABILITY_HARNESS" >/dev/null \
  && rg -F -- 'child artifact binary SHA-256 differs from the stability artifact' "$DUAL_STACK_STABILITY_AGGREGATOR" >/dev/null \
  && rg -F -- 'External server UDP ingress packets' "$DUAL_STACK_STABILITY_AGGREGATOR" >/dev/null \
  && rg -F -- 'egress summary has malformed trial evidence' "$DUAL_STACK_STABILITY_AGGREGATOR" >/dev/null; then
  pass "Repeated dual-stack stability harness requires identical-artifact receiver, black-hole, per-trial client/server evidence, and a positive three-run median PMTU gate"
  append_item "dual_stack_stability_aggregate" "ok" "three capture-enabled complete child proofs, exact binary identity, positive per-child gain, median gain of at least 15 percent, and per-trial client/server evidence are required"
else
  fail_critical "Repeated dual-stack stability harness is missing its fail-closed evidence contract"
  append_item "dual_stack_stability_aggregate" "fail" "missing fixed trial count, forced capture, exact child artifact, aggregate, binary identity, receiver, black-hole, or client/server validation"
fi

if rg -F -- '--tun-mtu "$tun_mtu_ceiling"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- '--tun-mtu "$client_tun_mtu_ceiling"' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'start_phase default 0 1280 1280' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'start_phase opt-in 1 1472 1500 1000 2000' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'DPLPMTUD confirmed path MTU: 1280B -> 1472B' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'DPLPMTUD black hole detected: path MTU 1472B -> 1280B' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && ! rg -F -- 'ip link set "$TUN_NAME" mtu 1280 up' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null \
  && rg -F -- 'assert gain >= 0.15, gain' "$MULTI_CLIENT_DUAL_STACK_HARNESS" >/dev/null; then
  pass "Multi-client PMTU comparison keeps IPv4 Ethernet MTU separate from QUIC UDP payload and retains the 15% gate"
  append_item "multi_client_dual_stack_pmtu_ceiling" "ok" "default uses 1280-byte UDP payload, opt-in uses 1472 for a 1500-byte IPv4 path, and routes preserve dynamic client TUN MTU"
else
  fail_critical "Multi-client PMTU comparison no longer models the IPv4 L3 to QUIC UDP-payload boundary or retained 15% gate"
  append_item "multi_client_dual_stack_pmtu_ceiling" "fail" "missing phase-specific TUN ceiling, 1472-byte UDP payload limit, route preservation, or 15% comparison threshold"
fi

# 6) Guardrail warning: shadow runtime modules with no non-test call sites.
BATCH_RUNTIME_REFS=$(rg -n --no-messages "BatchProcessor" src | rg -v "src/transport/batch.rs|src/transport.rs" || true)
if [[ -z "$BATCH_RUNTIME_REFS" ]]; then
  pass "BatchProcessor has no runtime call sites and is treated as compatibility/test-only"
  append_item "batchprocessor_runtime_reachability" "ok" "no runtime references found (compat/test-only surface)"
else
  pass "BatchProcessor has runtime references"
  append_item "batchprocessor_runtime_reachability" "ok" "runtime references found"
fi

BATCH_MODULE_DECLS=$(rg -n --no-messages '^pub mod batch;$' src/transport.rs || true)
if [[ -z "$BATCH_MODULE_DECLS" ]]; then
  fail_critical "transport::batch module declaration missing expected explicit rust-tests/test gate"
  append_item "batchprocessor_module_gate" "fail" "no transport::batch declaration found"
elif rg -n --no-messages 'Explicit rust parity/test-only surface|cfg\(any\(test, feature = "rust-tests"\)\)' src/transport.rs >/dev/null; then
  pass "transport::batch remains explicitly gated as rust parity/test-only surface"
  append_item "batchprocessor_module_gate" "ok" "transport::batch remains test/rust-tests gated"
else
  fail_critical "transport::batch no longer advertises explicit rust parity/test-only gating"
  append_item "batchprocessor_module_gate" "fail" "$BATCH_MODULE_DECLS"
fi

FASTPATH_RUNTIME_REFS=$(rg -n --no-messages "FastPathTransport" src | rg -v "src/transport/xdp.rs|src/main.rs src/main_parts" || true)
if [[ -z "$FASTPATH_RUNTIME_REFS" ]]; then
  pass "FastPathTransport has no runtime call sites outside xdp/main and is treated as compatibility/test-only"
  append_item "fastpathtransport_runtime_reachability" "ok" "no runtime references found (compat/test-only surface)"
else
  pass "FastPathTransport has runtime references"
  append_item "fastpathtransport_runtime_reachability" "ok" "runtime references found"
fi

FASTPATH_PUBLIC_DECLS=$(rg -n --no-messages "pub struct FastPathTransport|pub\\(crate\\) struct FastPathTransport|pub\\(super\\) struct FastPathTransport" src/transport/xdp.rs || true)
if [[ -z "$FASTPATH_PUBLIC_DECLS" ]]; then
  pass "FastPathTransport does not expose a public or crate-visible type surface"
  append_item "fastpathtransport_visibility" "ok" "FastPathTransport declaration remains private"
else
  fail_critical "FastPathTransport regained a public or crate-visible type surface"
  append_item "fastpathtransport_visibility" "fail" "$FASTPATH_PUBLIC_DECLS"
fi

FASTPATH_GSO_GRO_REFS=$(rg -n --no-messages "\\bsend_with_gso\\b|\\brecv_with_gro\\b" src/transport/xdp.rs docs/DOCUMENTATION.md README.md || true)
if [[ -z "$FASTPATH_GSO_GRO_REFS" ]]; then
  pass "Compat fastpath surface no longer overclaims GSO/GRO semantics"
  append_item "fastpathtransport_gso_gro_semantics" "ok" "no send_with_gso/recv_with_gro contract naming remains"
else
  fail_critical "Compat fastpath surface still overclaims GSO/GRO semantics"
  append_item "fastpathtransport_gso_gro_semantics" "fail" "$FASTPATH_GSO_GRO_REFS"
fi

UDPFAST_PUBLIC_BUFFER_REFS=$(rg -n --no-messages "^pub struct AlignedBuffer" src/transport/udpfast.rs || true)
if [[ -z "$UDPFAST_PUBLIC_BUFFER_REFS" ]]; then
  pass "udpfast aligned buffer does not expose a broad public surface"
  append_item "udpfast_internal_buffer_visibility" "ok" "AlignedBuffer remains internal or crate-internal"
else
  fail_critical "udpfast internal aligned buffer regained broad visibility"
  append_item "udpfast_internal_buffer_visibility" "fail" "$UDPFAST_PUBLIC_BUFFER_REFS"
fi

UDPFAST_PUBLIC_SINGLE_REFS=$(rg -n --no-messages "^\\s*pub fn send_single\\(|^\\s*pub\\(crate\\) fn send_single\\(|^\\s*pub fn recv_single\\(|^\\s*pub\\(crate\\) fn recv_single\\(" src/transport/udpfast.rs || true)
if [[ -z "$UDPFAST_PUBLIC_SINGLE_REFS" ]]; then
  pass "udpfast single-packet helpers remain internal implementation detail"
  append_item "udpfast_single_helper_visibility" "ok" "send_single/recv_single remain internal"
else
  fail_critical "udpfast single-packet helpers regained visible surface"
  append_item "udpfast_single_helper_visibility" "fail" "$UDPFAST_PUBLIC_SINGLE_REFS"
fi

XDP_NAMESPACE_REFS=$(rg -n --no-messages "transport::xdp::" src scripts/tests/rust || true)
if [[ -z "$XDP_NAMESPACE_REFS" ]]; then
  pass "transport::xdp is not used as a parallel public namespace"
  append_item "transport_xdp_namespace_reachability" "ok" "no direct transport::xdp namespace references found"
else
  warn_guardrail "transport::xdp direct namespace references remain"
  append_item "transport_xdp_namespace_reachability" "warn" "$XDP_NAMESPACE_REFS"
fi

XDP_EXPERIMENTAL_OWNER_REFS=$(rg -n --no-messages "xdp::linux::XdpSocket" src scripts/tests/rust | rg -v "^src/transport.rs:" || true)
if [[ -z "$XDP_EXPERIMENTAL_OWNER_REFS" ]]; then
  pass "experimental AF_XDP constructor surface is removed"
  append_item "xdp_experimental_owner_reachability" "ok" "no xdp::linux::XdpSocket constructor surface remains"
else
  fail_critical "removed AF_XDP constructor surface still has direct references"
  append_item "xdp_experimental_owner_reachability" "fail" "$XDP_EXPERIMENTAL_OWNER_REFS"
fi

OPTIMIZE_XDP_SOCKET_REFS=$(rg -n --no-messages "optimize::xdp_socket|create_xdp_socket\\(" src scripts/tests/rust || true)
if [[ -z "$OPTIMIZE_XDP_SOCKET_REFS" ]]; then
  pass "optimize-side XDP socket shell is absent from active references"
  append_item "optimize_xdp_socket_reachability" "ok" "no optimize::xdp_socket or create_xdp_socket references found"
else
  warn_guardrail "optimize-side XDP socket shell references remain"
  append_item "optimize_xdp_socket_reachability" "warn" "$OPTIMIZE_XDP_SOCKET_REFS"
fi

ZEROCOPY_SHADOW_REFS=$(rg -n --no-messages "pub mod zerocopy|optimize::zerocopy|struct ZeroCopySocket" src/optimize src/optimize/udp.rs docs/DOCUMENTATION.md || true)
if [[ -z "$ZEROCOPY_SHADOW_REFS" ]]; then
  pass "optimize-side zerocopy shadow surface remains absent"
  append_item "optimize_zerocopy_shadow_surface" "ok" "no optimize::zerocopy shim or orphan ZeroCopySocket remains"
else
  fail_critical "optimize-side zerocopy shadow surface reappeared"
  append_item "optimize_zerocopy_shadow_surface" "fail" "$ZEROCOPY_SHADOW_REFS"
fi

OPTIMIZATION_MANAGER_XDP_STATE_REFS=$(rg -n --no-messages "XDP_RUNTIME_WIRING_ENABLED|is_xdp_compat_available\\(|is_xdp_compat_enabled\\(" src/optimize src/main.rs src/main_parts docs/DOCUMENTATION.md || true)
if [[ -z "$OPTIMIZATION_MANAGER_XDP_STATE_REFS" ]]; then
  pass "OptimizationManager does not carry dead XDP runtime state helpers"
  append_item "optimizationmanager_xdp_runtime_state" "ok" "no dead XDP runtime state helpers found"
else
  fail_critical "OptimizationManager still exposes dead XDP runtime state helpers"
  append_item "optimizationmanager_xdp_runtime_state" "fail" "$OPTIMIZATION_MANAGER_XDP_STATE_REFS"
fi

CORE_XDP_REFS=$(rg -n --no-messages "xdp|FastPathTransport|request_xdp_compat|QUICFUSCATE_FASTPATH" src/core.rs src/core_parts src/transport/connection || true)
if [[ -z "$CORE_XDP_REFS" ]]; then
  pass "active core transport/runtime path has no XDP compatibility branches"
  append_item "core_xdp_runtime_reachability" "ok" "no XDP compatibility references found in src/core.rs src/core_parts or src/transport/connection"
else
  warn_guardrail "active core transport/runtime path still references XDP compatibility surface"
  append_item "core_xdp_runtime_reachability" "warn" "$CORE_XDP_REFS"
fi

# 7) Guardrail warning: ServerRuntime packet limiter hooks with no external call sites.
SERVER_RUNTIME_RATE_DEFS=$(rg -n --no-messages "pub fn (check_packet_rate|record_packet)\\(" src/implementations/server || true)
if [[ -z "$SERVER_RUNTIME_RATE_DEFS" ]]; then
  pass "ServerRuntime packet limiter hook surface is not present"
  append_item "serverruntime_rate_limiter_reachability" "ok" "no duplicate ServerRuntime limiter hooks present"
else
  SERVER_RUNTIME_RATE_REFS=$(rg -n --no-messages "check_packet_rate\\(|record_packet\\(" src | rg -v "src/implementations/server" || true)
  if [[ -z "$SERVER_RUNTIME_RATE_REFS" ]]; then
    warn_guardrail "ServerRuntime packet limiter hooks have no external call sites"
    append_item "serverruntime_rate_limiter_reachability" "warn" "no external references to check_packet_rate/record_packet"
  else
    pass "ServerRuntime packet limiter hooks have external call sites"
    append_item "serverruntime_rate_limiter_reachability" "ok" "external references found"
  fi
fi

# 8) Broad batch-send MSG_ZEROCOPY path must stay removed.
if rg -n --no-messages "send_batch_maybe_zerocopy\\(" src/optimize/udp.rs src/transport/udpfast.rs >/dev/null; then
  fail_critical "Broad batch-send MSG_ZEROCOPY path reappeared"
  append_item "zerocopy_batch_path_removed" "fail" "send_batch_maybe_zerocopy still present"
else
  pass "Broad batch-send MSG_ZEROCOPY path stays removed"
  append_item "zerocopy_batch_path_removed" "ok" "no send_batch_maybe_zerocopy helper remains"
fi

# 9) Security-sensitive RNG call sites must use centralized fail-closed entropy API.
RNG_POLICY_FILES=(
  src/transport/pn.rs
  src/transport/recovery.rs
  src/main.rs src/main_parts
  src/implementations/server/admin.rs
  src/implementations/server/admin_http.rs
  src/implementations/server/admin_http_parts
)
if rg -n --no-messages "OsRng\\.fill_bytes|getrandom::getrandom|rand::thread_rng\\(\\)\\.fill_bytes|rand::random\\(" "${RNG_POLICY_FILES[@]}" >/dev/null; then
  fail_critical "Direct RNG fill usage detected in security-sensitive modules (expected centralized rng API)"
  append_item "rng_policy_security_modules" "fail" "found direct RNG fill usage in security-sensitive modules"
else
  RNG_HELPER_REFS="$(rg -n --no-messages "fill_secure_or_abort\\(" "${RNG_POLICY_FILES[@]}" | wc -l | tr -d ' ')"
  if [[ "${RNG_HELPER_REFS}" -lt 4 ]]; then
    fail_critical "Central secure RNG API is not sufficiently wired in security-sensitive modules"
    append_item "rng_policy_security_modules" "fail" "insufficient fill_secure_or_abort references"
  else
    pass "Security-sensitive modules use centralized secure RNG API"
    append_item "rng_policy_security_modules" "ok" "centralized secure RNG API is wired"
  fi
fi

# 10) Security-sensitive modules must not import optimize::random acceleration helpers directly.
if rg -n --no-messages "(crate::)?optimize::random|accelerate::random" "${RNG_POLICY_FILES[@]}" >/dev/null; then
  fail_critical "Security-sensitive modules reference optimize/accelerate random helpers directly"
  append_item "rng_policy_no_optimize_random_in_security_modules" "fail" "optimize/accelerate random referenced in security-sensitive modules"
else
  pass "Security-sensitive modules do not reference optimize/accelerate random helpers"
  append_item "rng_policy_no_optimize_random_in_security_modules" "ok" "no optimize/accelerate random references in security-sensitive modules"
fi

if rg -F -- 'pub const DEFAULT_PER_SOURCE_RATE_LIMIT_PPS: u64 = 10_000;' \
    src/implementations/server/limits.rs >/dev/null \
  && rg -F -- 'max_pps: DEFAULT_PER_SOURCE_RATE_LIMIT_PPS' \
    src/implementations/server/limits.rs >/dev/null \
  && rg -F -- 'default: `10000`' docs/DOCUMENTATION.md >/dev/null; then
  pass "Per-source server rate limit preserves documented tunnel-throughput headroom"
  append_item "server_rate_limit_tunnel_headroom" "ok" "runtime, tests, docs, and native throughput gate retain the 10000 PPS default"
else
  fail_critical "Per-source server rate limit can regress below the documented tunnel-throughput default"
  append_item "server_rate_limit_tunnel_headroom" "fail" "missing 10000 PPS runtime default or documentation contract"
fi

# 11) optimize::random must not expose misleading secure-entropy naming.
FORBIDDEN_RNG_ALIAS_REFS="$(rg -n --no-messages '^pub fn random_bytes_secure\b|optimize::random::random_bytes_secure|accelerate::random::random_bytes_secure' src scripts/tests/rust docs/DOCUMENTATION.md || true)"
if [[ -n "$FORBIDDEN_RNG_ALIAS_REFS" ]]; then
  fail_critical "Misleading optimize-side secure RNG alias detected"
  append_item "rng_policy_no_misleading_secure_alias" "fail" "$FORBIDDEN_RNG_ALIAS_REFS"
else
  pass "No misleading optimize-side secure RNG alias remains"
  append_item "rng_policy_no_misleading_secure_alias" "ok" "no optimize-side secure RNG alias detected"
fi

# 11b) Docs must not describe accelerate::random as a canonical security API.
if rg -n --no-messages 'accelerate::random.*(secure|security|cryptographic)|cryptographic security.*accelerate::random' docs/DOCUMENTATION.md >/dev/null; then
  fail_critical "Documentation overclaims accelerate::random security posture"
  append_item "rng_docs_truth_alignment" "fail" "accelerate::random described as secure/canonical security API"
else
  pass "Documentation keeps accelerate::random on the non-security/test-only side"
  append_item "rng_docs_truth_alignment" "ok" "accelerate::random docs remain non-security/test-only"
fi

# 11c) The retained AArch64 optimize-random helper path must stay explicitly covered as rust-tests/test-only contract.
if rg -n --no-messages '^#!\[cfg\(target_arch = "aarch64"\)\]$' scripts/tests/rust/rt-random-aes-ctr.rs >/dev/null \
  && rg -n --no-messages '^#!\[cfg\(feature = "rust-tests"\)\]$' scripts/tests/rust/rt-random-aes-ctr.rs >/dev/null \
  && rg -n --no-messages 'random::random_array_u32\(&mut words\)|random::random_u64\(\)' scripts/tests/rust/rt-random-aes-ctr.rs >/dev/null; then
  pass "AArch64 optimize-random contract remains covered by explicit rust-tests gate"
  append_item "rng_aarch64_contract_test_surface" "ok" "rt-random-aes-ctr keeps explicit aarch64 rust-tests coverage"
else
  fail_critical "AArch64 optimize-random contract lost explicit rust-tests coverage"
  append_item "rng_aarch64_contract_test_surface" "fail" "rt-random-aes-ctr coverage missing or incomplete"
fi

# 11d) QKey bearers must stay out of the pre-handshake QUIC transport-parameter surface.
QKEY_TRANSPORT_PARAMETER_REFS=$(rg -n --no-messages 'QKEY_AUTH_TP_ID|inject_qkey_auth_into_tp|extract_qkey_auth_from_tp|set_qkey_auth_token|peer_qkey_auth_token|evaluate_qkey_transport_token|QKey auth transport parameter' src || true)
if [[ -z "$QKEY_TRANSPORT_PARAMETER_REFS" ]]; then
  pass "QKey bearer transport-parameter channel stays removed"
  append_item "qkey_transport_parameter_channel_removed" "ok" "no QKey bearer transport-parameter producer, parser, accessor, or server branch remains"
else
  fail_critical "QKey bearer transport-parameter channel reappeared"
  append_item "qkey_transport_parameter_channel_removed" "fail" "$QKEY_TRANSPORT_PARAMETER_REFS"
fi

QKEY_CONFIDENTIALITY_OVERCLAIMS=$(rg -n --no-messages 'QKey.*(transport parameters|transport-parameter).*(EncryptedExtensions|invisible to DPI)|QKey-in-Encrypted-Extension' src docs/DOCUMENTATION.md docs/MAP.md || true)
if [[ -z "$QKEY_CONFIDENTIALITY_OVERCLAIMS" ]]; then
  pass "QKey authentication documentation matches the encrypted HTTP/3 runtime path"
  append_item "qkey_auth_documentation_truth" "ok" "no false QKey transport-parameter confidentiality claim remains"
else
  fail_critical "QKey authentication documentation still overclaims transport-parameter confidentiality"
  append_item "qkey_auth_documentation_truth" "fail" "$QKEY_CONFIDENTIALITY_OVERCLAIMS"
fi

QKEY_REGISTRY_FAIL_OPEN_REFS=$(rg -n --no-messages 'writing plaintext|decryption failed.*plaintext|failed ciphertext.*plaintext|decrypt.*fallback.*plaintext' src/implementations/server/qkey_registry.rs src/implementations/server/qkey_registry_storage.rs || true)
if [[ -z "$QKEY_REGISTRY_FAIL_OPEN_REFS" ]] \
  && rg -F -- 'pub fn open(' src/implementations/server/qkey_registry.rs >/dev/null \
  && rg -F -- ') -> Result<Self, QKeyRegistryError>' src/implementations/server/qkey_registry.rs >/dev/null \
  && rg -F -- 'map_err(std::io::Error::other)?' src/implementations/server/parts/runtime_impl.rs >/dev/null \
  && rg -F -- 'QUICFUSCATE_QKEY_ENC_KEY_FILE' src/implementations/server/qkey_registry_storage.rs scripts/install/install-server-linux.sh docs/DOCUMENTATION.md >/dev/null \
  && rg -F -- 'QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY_FILE' src/implementations/server/qkey_registry_storage.rs docs/DOCUMENTATION.md >/dev/null; then
  pass "QKey registry encryption remains versioned, key-file capable, and fail closed at startup"
  append_item "qkey_registry_fail_closed_encryption" "ok" "startup propagation, production key-file source, rotation source, and no plaintext fallback remain present"
else
  fail_critical "QKey registry fail-closed encryption contract is incomplete"
  append_item "qkey_registry_fail_closed_encryption" "fail" "${QKEY_REGISTRY_FAIL_OPEN_REFS:-missing startup propagation, key-file source, rotation source, installer default, or documentation}"
fi

QKEY_AUTH_POLICY_ORDER_ERRORS="$(python3 - <<'PY'
from pathlib import Path

checks = [
    (
        Path("src/implementations/server/parts/live_state.rs"),
        "let admission =",
        "parse_live_server_initial_auth(",
        "QKey admission no longer precedes registry lookup",
    ),
    (
        Path("src/main_parts/late_tests_and_mlock.rs"),
        "server_config_from_listen_addr(",
        "init_audit_log_with_options(",
        "auth configuration no longer validates before audit resource creation",
    ),
]
errors = []
for path, first, second, message in checks:
    text = path.read_text(encoding="utf-8")
    first_index = text.find(first)
    second_index = text.find(second)
    if first_index < 0 or second_index < 0 or first_index >= second_index:
        errors.append(message)
print("; ".join(errors))
PY
)"
QKEY_AUTH_POLICY_HARNESS="scripts/tests/suites/test-qkey-auth-policy.sh"
if [[ -z "$QKEY_AUTH_POLICY_ORDER_ERRORS" ]] \
  && rg -F -- 'pub struct AuthPolicyConfig {' src/implementations/server/limits.rs >/dev/null \
  && rg -F -- 'max_tracked_ips: 65_536' src/implementations/server/limits.rs >/dev/null \
  && rg -F -- 'max_pending_attempts_per_ip: 4' src/implementations/server/limits.rs >/dev/null \
  && rg -F -- 'QUICFUSCATE_AUTH_BACKOFF_AFTER_FAILURES' src/implementations/server/parts/config.rs config/server-linux.default.toml docs/DOCUMENTATION.md >/dev/null \
  && rg -F -- 'AuthRateLimiter::new(' src/implementations/server/parts/live_state.rs >/dev/null \
  && [[ "$(rg -c --no-messages 'qkey_auth_denied' src/implementations/server/parts/live_auth.rs || true)" -ge 3 ]] \
  && rg -F -- 'quicfuscate_auth_backoff_rejected_total' src/implementations/server/metrics.rs docs/DOCUMENTATION.md >/dev/null \
  && rg -F -- 'quicfuscate_auth_blocked_rejected_total' src/implementations/server/metrics.rs docs/DOCUMENTATION.md >/dev/null \
  && rg -F -- 'assert_metric_exact quicfuscate_auth_attempts_total 100' "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- 'assert_metric_exact quicfuscate_auth_failed_total 4' "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- 'assert_metric_exact quicfuscate_auth_blocked_rejected_total 94' "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- 'run_valid_probe secondary "$SECONDARY_LOCAL"' "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- 'flood_server_rss_growth_kib=' "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- '--initial-only' src/bin/qf-e2e-client.rs "$QKEY_AUTH_POLICY_HARNESS" >/dev/null \
  && rg -F -- 'conn.conn.is_closed()' src/bin/qf-e2e-client.rs >/dev/null \
  && rg -F -- '--ca-file' src/bin/qf-e2e-client.rs "$QKEY_AUTH_POLICY_HARNESS" >/dev/null; then
  pass "QKey auth abuse policy remains bounded, pre-lookup, non-oracular, observable, and process-proved"
  append_item "qkey_auth_policy_lifecycle" "ok" "validated startup ordering, bounded state, generic wire denial, exact metrics, two-IP lifecycle, and 100-attempt resource proof remain present"
else
  fail_critical "QKey auth abuse-policy lifecycle contract is incomplete"
  append_item "qkey_auth_policy_lifecycle" "fail" "${QKEY_AUTH_POLICY_ORDER_ERRORS:-missing bounded config, startup order, generic denial, metrics/docs, client terminal detection, CA verification, or exact process harness}"
fi

# 12) Detect acceleration exports with no runtime references outside their defining module.
DEAD_ACCEL_EXPORTS=(
)
dead_candidates=()
for entry in "${DEAD_ACCEL_EXPORTS[@]}"; do
  file="${entry%%:*}"
  symbol="${entry##*:}"
  refs="$(rg -n --no-messages "\\b${symbol}\\b" src | rg -v "^${file}:" || true)"
  if [[ -z "${refs}" ]]; then
    dead_candidates+=("${symbol}")
  fi
done
if [[ "${#dead_candidates[@]}" -gt 0 ]]; then
  warn_guardrail "Acceleration exports with zero runtime references detected: ${dead_candidates[*]}"
  append_item "dead_accel_exports_runtime_reachability" "warn" "zero-runtime-reference exports: ${dead_candidates[*]}"
else
  pass "No zero-runtime-reference acceleration exports in monitored candidate set"
  append_item "dead_accel_exports_runtime_reachability" "ok" "monitored acceleration exports have runtime references"
fi

# 13) Optimize microprimitives in memory/string must either be runtime-owned or explicitly test/rust-tests gated.
if ! rg -n --no-messages "crate::accelerate::string::string_contains\\(" src/stealth/ >/dev/null; then
  fail_critical "optimize::string::string_contains lost its runtime owner in stealth path"
  append_item "optimize_microprimitives_runtime_owner" "fail" "string_contains runtime owner missing"
elif ! rg -n --no-messages '^pub fn base64_encode' src/optimize/string.rs >/dev/null \
  || ! rg -n --no-messages '^pub fn base64_decode' src/optimize/string.rs >/dev/null \
  || ! rg -n --no-messages '#\[cfg\(any\(test, feature = "rust-tests"\)\)\][[:space:]]*\npub fn base64_encode' -U src/optimize/string.rs >/dev/null \
  || ! rg -n --no-messages '#\[cfg\(any\(test, feature = "rust-tests"\)\)\][[:space:]]*\npub fn base64_decode' -U src/optimize/string.rs >/dev/null; then
  fail_critical "base64 microprimitives are no longer explicitly test/rust-tests gated"
  append_item "optimize_microprimitives_runtime_owner" "fail" "base64 helper gating missing"
elif ! rg -n --no-messages '^pub fn transpose_matrix' src/optimize/memory.rs >/dev/null \
  || ! rg -n --no-messages '^pub struct LockFreeRingBuffer' src/optimize/memory.rs >/dev/null \
  || ! rg -n --no-messages '#\[cfg\(any\(test, feature = "rust-tests"\)\)\][[:space:]]*\npub fn transpose_matrix' -U src/optimize/memory.rs >/dev/null \
  || ! rg -n --no-messages '#\[cfg\(any\(test, feature = "rust-tests"\)\)\][[:space:]]*\npub struct LockFreeRingBuffer' -U src/optimize/memory.rs >/dev/null; then
  fail_critical "memory microprimitives are no longer explicitly test/rust-tests gated"
  append_item "optimize_microprimitives_runtime_owner" "fail" "memory helper gating missing"
else
  pass "Optimize microprimitives in memory/string have explicit runtime or rust-tests owners"
  append_item "optimize_microprimitives_runtime_owner" "ok" "memory/string microprimitives have explicit owners"
fi

# 13) Removed orphan optimize exports must not reappear as broad public surface.
FORBIDDEN_OPTIMIZE_EXPORTS="$(rg -n --no-messages \
  '^pub fn (validate_utf8|parse_u64|mix_entropy|generate_http_headers|shape_traffic_pattern)\b' \
  src/optimize/string.rs src/optimize/stealth.rs || true)"
if [[ -n "$FORBIDDEN_OPTIMIZE_EXPORTS" ]]; then
  fail_critical "Removed orphan optimize exports reappeared as public surface"
  append_item "forbidden_optimize_exports" "fail" "$FORBIDDEN_OPTIMIZE_EXPORTS"
else
  pass "Removed orphan optimize exports remain absent from public surface"
  append_item "forbidden_optimize_exports" "ok" "no removed orphan optimize exports reintroduced"
fi

# 14) Server observability contract must keep accepted-connection ownership explicit.
CLIENT_CONNECTED_BODY="$(awk '
  /pub fn client_connected\(/ { in_fn=1 }
  in_fn { print }
  in_fn && /^    }$/ { exit }
' src/instrumentation.rs)"
if [[ "$CLIENT_CONNECTED_BODY" == *"connections_accepted"* ]]; then
  fail_critical "Global server client_connected() still implies accepted-connection counting"
  append_item "server_observability_client_connected_accept_split" "fail" "client_connected still mutates connections_accepted"
else
  pass "Global server client lifecycle is split from accepted-connection counting"
  append_item "server_observability_client_connected_accept_split" "ok" "client_connected does not mutate connections_accepted"
fi

if rg -n --no-messages "pub fn record_connection_accepted\\(" src/implementations/server/metrics.rs >/dev/null \
  && rg -n --no-messages "quicfuscate_connections_accepted" src/implementations/server/metrics.rs src/implementations/server docs/DOCUMENTATION.md >/dev/null; then
  pass "Standalone server accepted-connection metrics surface remains explicit and documented"
  append_item "server_observability_connections_accepted_surface" "ok" "producer/export/docs for connections_accepted present"
else
  fail_critical "Standalone server accepted-connection metrics surface is incomplete"
  append_item "server_observability_connections_accepted_surface" "fail" "missing producer or export/docs for connections_accepted"
fi

# 15) Top-level truth surfaces must keep fork/compat-only posture explicit.
if rg -n --no-messages "not a drop-in upstream QUIC implementation" src/lib.rs README.md docs/DOCUMENTATION.md >/dev/null; then
  pass "Top-level truth surfaces keep fork/non-upstream posture explicit"
  append_item "feature_claims_fork_posture" "ok" "fork/non-upstream wording present in top-level truth surfaces"
else
  fail_critical "Top-level truth surfaces are missing explicit fork/non-upstream posture wording"
  append_item "feature_claims_fork_posture" "fail" "missing fork/non-upstream wording in src/lib.rs/README.md/docs"
fi

if rg -n --no-messages "production-ready server implementation" src/implementations/server >/dev/null; then
  fail_critical "Server module header still overclaims a production-ready implementation surface"
  append_item "feature_claims_server_header_truth" "fail" "production-ready wording present in server module header"
else
  pass "Server module header avoids production-ready overclaim wording"
  append_item "feature_claims_server_header_truth" "ok" "server module header is truth-aligned"
fi

if rg -n --no-messages "full QUIC connection lifecycle" src/core.rs src/core_parts >/dev/null; then
  fail_critical "Core module header still overclaims a full QUIC lifecycle"
  append_item "feature_claims_core_header_truth" "fail" "full QUIC lifecycle wording present in core header"
else
  pass "Core module header avoids upstream/full-QUIC overclaim wording"
  append_item "feature_claims_core_header_truth" "ok" "core header is truth-aligned"
fi

if rg -n --no-messages "standard QUIC server" src/reality.rs >/dev/null; then
  fail_critical "Reality fallback comment still overclaims standard-QUIC proof semantics"
  append_item "feature_claims_reality_comment_truth" "fail" "standard QUIC server wording present in reality comment"
else
  pass "Reality fallback comment avoids standard-QUIC proof overclaim wording"
  append_item "feature_claims_reality_comment_truth" "ok" "reality comment is truth-aligned"
fi

if rg -n --no-messages "release-ready for source-first distribution|feature-complete pre-production surface" README.md >/dev/null; then
  fail_critical "README still overclaims surface maturity"
  append_item "feature_claims_surface_maturity_truth" "fail" "release-ready or feature-complete pre-production wording present"
else
  pass "README surface-maturity wording avoids release/product-complete overclaim"
  append_item "feature_claims_surface_maturity_truth" "ok" "surface maturity wording is truth-aligned"
fi

if rg -n --no-messages "release-ready local builds" README.md >/dev/null; then
  fail_critical "README still overclaims local build readiness"
  append_item "feature_claims_build_readiness_truth" "fail" "release-ready local builds wording present"
else
  pass "README build wording avoids release-ready overclaim"
  append_item "feature_claims_build_readiness_truth" "ok" "README build wording is truth-aligned"
fi

if rg -n --no-messages "^QuicFuscate supports multiple congestion control algorithms:" docs/DOCUMENTATION.md >/dev/null; then
  fail_critical "Documentation still presents congestion-control surface as an unqualified broad support claim"
  append_item "feature_claims_cc_surface_truth" "fail" "broad congestion-control support wording present"
else
  pass "Documentation qualifies the retained congestion-control surface"
  append_item "feature_claims_cc_surface_truth" "ok" "congestion-control wording is truth-aligned"
fi

if rg -n --no-messages "custom 1-RTT data-plane AEAD posture.*full-fork assumption.*TLS cipher-suite|custom 1-RTT data-plane AEAD posture.*full-fork assumption.*upstream interoperability claim" docs/DOCUMENTATION.md >/dev/null; then
  pass "Documentation keeps forked data-plane AEAD separate from TLS/upstream claims"
  append_item "feature_claims_aead_tls_boundary_truth" "ok" "forked AEAD vs TLS/upstream boundary wording present"
else
  fail_critical "Documentation is missing explicit forked AEAD vs TLS/upstream boundary wording"
  append_item "feature_claims_aead_tls_boundary_truth" "fail" "missing explicit AEAD/TLS boundary wording"
fi

if rg -n --no-messages "forked data-plane AEAD contract.*full-fork assumption|full-fork assumption.*forked data-plane AEAD contract" src/transport/packet.rs >/dev/null \
  && rg -n --no-messages "fork-specific data-plane decision, not a TLS cipher-suite decision.*full-fork assumption|full-fork assumption.*fork-specific data-plane decision, not a TLS cipher-suite decision" src/crypto/ >/dev/null; then
  pass "Runtime-adjacent AEAD comments keep forked data-plane posture explicit"
  append_item "feature_claims_runtime_aead_comment_truth" "ok" "fork-specific AEAD wording present in packet/crypto comments"
else
  fail_critical "Runtime-adjacent AEAD comments are missing explicit forked posture wording"
  append_item "feature_claims_runtime_aead_comment_truth" "fail" "missing fork-specific AEAD wording in packet/crypto comments"
fi

qf_json_append_object "$JSON" "critical=int:$critical" "warnings=int:$warnings"
json_end "$JSON"

echo
echo "Critical: $critical"
echo "Warnings: $warnings"
echo "Log: $LOG_FILE"

if [[ "$critical" -gt 0 ]]; then
  exit 1
fi
exit 0
