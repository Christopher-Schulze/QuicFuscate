# TODO 71: `BatchProcessor` Shadow Surface Resolution

## Scope
- `src/transport.rs`
- `src/transport/batch.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- `BatchProcessor` remains publicly exposed.
  - Evidence: `src/transport.rs:22`
- It is no longer the canonical runtime owner.
  - Evidence: `src/transport/batch.rs:26`, `:112`

## Objectives
- Resolve `BatchProcessor` as canonical, compat-only, or retired.

## Work Breakdown
- [x] Reclassify `BatchProcessor` ownership.
- [x] Adjust re-exports and docs to reflect that classification.
- [x] Add guardrails for future shadow-surface reappearance.

## Acceptance Criteria
- [x] `BatchProcessor` does not remain a misleading top-level public alternative path.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-06: Extracted the only remaining production helper (`init_socket_acceleration`) out of `src/transport/batch.rs` into hidden `src/transport.rs` runtime surface. `BatchProcessor` is now fully confined to `cfg(any(test, feature = "rust-tests"))`, making `transport::batch` a genuine test/compat module instead of a mixed runtime shadow surface.
- 2026-03-08: Re-verified the external rust parity test at `scripts/tests/rust/rt-transport-batch-processor.rs`; this is now the only intentional non-local import path for `quicfuscate::transport::batch::BatchProcessor`.
- 2026-03-08: Tightened the contract comments:
  - `src/transport.rs` now labels `transport::batch` as an explicit rust parity/test-only surface
  - `src/transport/batch.rs` now states directly that the module is not part of the normal runtime transport surface
- 2026-03-08: Added an audit guardrail that fails if `transport::batch` loses its explicit rust-tests/test gating contract.
