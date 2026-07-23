---
id: TODO-362
title: "Audit 8 #[allow(dead_code)] markers in fec/internal.rs"
severity: "HIGH"
phase: S
priority: P0
status: OPEN
created: 2026-03-27
backfilled: 2026-07-23
depends_on: []
---

# TODO-362: Audit 8 #[allow(dead_code)] markers in fec/internal.rs


## Problem
`src/fec/internal.rs` has 8 separate `#[allow(dead_code)]` markers at lines:
24, 254, 415, 469, 661, 818, 910, 1037.

These suppress warnings for functions/structs that are defined but never called.
This includes `AdaptiveEncoder::new()` and multiple internal helpers. Either:
- The code IS used via the public fec/mod.rs surface (remove allow markers)
- The code is truly dead and should be deleted
- The code is planned-but-unfinished (document and keep)

## Fix Plan
1. For each #[allow(dead_code)] marker, identify the annotated item
2. Grep the entire codebase for callers
3. If called: remove the allow marker (it is not dead code)
4. If not called: determine if it is planned/useful or truly dead
5. Delete truly dead code, keep planned code with TODO annotation

## Files to Modify
- src/fec/internal.rs
- Potentially src/fec/mod.rs if dead code references are removed

## Acceptance

- Classify every `#[allow(dead_code)]` in `src/fec/internal.rs` by exact production, feature-gated, test-only, or genuinely dead callers.
- Remove genuinely dead code and unjustified suppressions without deleting planned production behavior or weakening tests.
- Give retained compatibility/test-only items explicit narrow ownership and runtime guardrail coverage.
- Pass full local Rust gates, native CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Ownership gate: every original suppression has a recorded caller classification and every retained suppression is narrower than module-wide scope with a failable guardrail.
- Source gate: no production behavior or test strength is removed, no unclassified FEC suppression remains, and the exact touched source diff matches the recorded classification.
- Evidence gate: the already-green local format, Clippy, test, and runtime-guardrail results remain reproducible; required native CI completes for the exact reviewed commit.
- Artifact and truth gate: the exact release artifact is linked to that commit by SHA-256, protected UI paths have no diff, and documentation/MAP/TODO truth contains the commands and results before closure.

## Sub-Tasks

- [x] Read every annotated item and all direct callers.
- [x] Classify runtime and feature ownership before editing.
- [x] Apply minimal removals or narrow justifications.
- [~] Run full local and native evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Reopened by the exhaustive acceptance reconciliation because eight current suppressions remained without a completed dead-code audit.
- Exact disposition: `AdaptiveEncoder::new`, `AdaptiveDecoder::new`, and `InterleavedEncoder::new` had no callers and were removed. `EncoderVariant::new`, `DecoderVariant::new`, `LazyDecoder::new`, `InterleavedDecoder::new`, and `ModeManager::with_switch_threshold` are called only by the in-module `#[cfg(test)]` suite and now carry that explicit ownership instead of warning suppression. Production continues to use the corresponding explicit-policy constructors.
- The first all-target Clippy replay exposed `DecoderVariant::new_with_policy` and `LazyDecoder::new_with_policy` as two more unit-test-only intermediates after their callers were narrowed. Exact caller search found only the internal test module, so both now carry the same explicit `#[cfg(test)]` ownership; production already calls `new_with_depth` directly.
- The runtime guardrail audit now fails critically if any item-level `#[allow(dead_code)]` returns to `src/fec/internal.rs`. No runtime behavior, public contract, protected UI, or architecture wiring changed, so `docs/DOCUMENTATION.md` and `docs/MAP.md` require no semantic update for this removal.
- Local evidence: `cargo fmt --all -- --check` passes; workspace all-target Clippy with `rust-tests` and warnings denied passes; workspace all-target tests with `rust-tests` pass with 1,684 library tests and zero failures; runtime guardrails pass with zero critical findings and zero warnings; TODO consistency and `git diff --check` pass. Native CI remains the open closure gate.

## Deviations

None.
