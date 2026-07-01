---
id: TODO-493
title: Runtime guardrail contract drift hardening
severity: HIGH
phase: "R"
priority: P0
status: DONE
created: 2026-07-01
depends_on: [TODO-389, TODO-492]
---

# TODO-493: Runtime guardrail contract drift hardening

## Context

The runtime guardrail audit caught drift between code, reviewer-facing docs, and
the intended production contract. The critical gaps were:

- reviewer truth snapshot wording was missing from top-level docs
- quinn-udp overlap/divergence was not stated explicitly
- data-plane AEAD config still exposed internal X4/X8 backend override labels
- memory microprimitives were still bench-gated rather than test/rust-tests only
- runtime-adjacent AEAD comments did not state the explicit full-fork assumption

## Desired Outcome

- Keep reviewer-facing truth surfaces precise and auditable.
- Keep product-level AEAD config narrowed to `auto`, `aegis-128l`, and `morus`.
- Keep AEGIS X4/X8 as internal planner-owned backends with direct internal test
  coverage, not runtime config choices.
- Keep memory microprimitives as rust-tests parity surfaces only.
- Preserve benchmark coverage only for runtime-owned optimization paths.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added reviewer truth snapshot lines to `README.md` and
  `docs/DOCUMENTATION.md`, including AI-assisted workflow truth,
  non-MSG_ZEROCOPY runtime posture, non-busy-poll posture, and the statement
  that the repository is not reducible to `quinn-udp` plus trivial glue.
- Added `Transport Overlap and Divergence vs quinn-udp` to the canonical docs.
- Removed public/runtime `DATA_AEAD_OVERRIDE_AEGIS_X4` and
  `DATA_AEAD_OVERRIDE_AEGIS_X8` modes from `src/crypto/mod.rs`.
- Rejected `aegis-128x4`, `aegis128x4`, `aegis-128x8`, and `aegis128x8` in
  `CryptoConfig::validate()`.
- Preserved X4/X8 backend coverage by testing direct internal
  `CryptoAeadPlan::Aegis128X4` and `CryptoAeadPlan::Aegis128X8` construction.
- Restricted `optimize::memory` and its retained microprimitives to
  `cfg(any(test, feature = "rust-tests"))`.
- Removed `memory_transpose` from `ci_regression` and
  `bench-optimization.sh`, leaving that bench suite focused on runtime-owned
  SIMD sort/shuffle paths.
- Updated 0-RTT/1-RTT AEAD comments in `src/transport/packet.rs` to state the
  forked data-plane AEAD contract under the explicit full-fork assumption.
- Corrected TODO-389 and TODO-79 docs so historical X4/X8 alias claims no
  longer contradict the current contract.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests data_aead` pass.
- Local: `cargo test --lib --features rust-tests test_crypto_force_aead_rejects_internal_width_backends` pass.
- Local: `cargo bench --bench ci_regression --features benches --no-run` pass.
- Local: `cargo clippy --workspace --all-targets -- -D warnings` pass.
- Local: `cargo test --lib --features rust-tests` pass, `1635 passed`.
- Local: `bash scripts/tests/audits/audit-runtime-guardrails.sh --output-dir scripts/out/audits/local-runtime-guardrails-final` pass, `Critical: 0`, one known warning for `src/optimize/x86_sse2.rs`.
- Broderick: `bash scripts/tests/audits/audit-runtime-guardrails.sh --output-dir scripts/out/audits/codex-runtime-guardrails-final` pass, `Critical: 0`, same known warning.
- Broderick: `bash scripts/tests/suites/test-stealth.sh --fast --output-dir scripts/out/tests/codex-stealth-fast-final` pass.
- Broderick: `bash scripts/tests/suites/test-fec-all.sh --mode fast --output-dir scripts/out/tests/codex-fec-fast-final` pass.

## Notes

This task intentionally narrows public/runtime surfaces rather than deleting
internal capability. Internal X4/X8 AEGIS backends remain available to the
planner and tests; operators configure product AEAD families only.
