# TODO 90: Linux Send-Path Collapse Around io_uring

## Scope
- `src/optimize/udp.rs`
- `src/transport/uring.rs`
- `src/transport/udpfast.rs`
- Linux transport validation and guardrails
- canonical transport documentation

## Problem Statement
- The Linux send path still reads like three overlapping runtime stories:
  - plain UDP batching in `src/optimize/udp.rs`
  - `io_uring` in `src/transport/uring.rs`
  - `MSG_ZEROCOPY` in both `src/optimize/udp.rs` and `src/transport/udpfast.rs`
- Completion and fallback accounting were already centralized earlier, but the actual send-path ownership is still too broad.
- This is the strongest remaining transport criticism from an external review perspective because it still looks like multiple competing "fast path" truths live at once.

## Desired End State
- Canonical Linux send-path policy becomes:
  - `io_uring` first when available and profitable
  - normal UDP batching as the default fallback
  - `MSG_ZEROCOPY` retained only as a specialized Linux path with strict gating
- All retry, completion, and fallback semantics remain centralized.
- `udpfast` stops carrying broad per-path send heuristics that duplicate transport-owner policy.

## Current Truth Snapshot
- `src/transport/uring.rs` now owns the canonical Linux high-end send and completion story:
  - `try_send_to(...)`
  - zerocopy inbox notification/drain
  - errqueue mirroring
- `src/optimize/udp.rs` now owns plain Linux UDP batching and shared zerocopy gating logic:
  - `send_batch(...)`
  - `send_batch_connected(...)`
  - `should_retry_without_zerocopy(...)`
  - `should_use_msg_zerocopy(...)`
  - explicit opt-in parsing for `QUICFUSCATE_ENABLE_MSG_ZEROCOPY`
- `src/transport/uring.rs` no longer sets `MSG_ZEROCOPY` directly on its own send path.
- Broad Linux batch-send zerocopy is gone:
  - `send_batch_maybe_zerocopy(...)` was removed
  - Linux `sendmmsg` batching now runs as plain batching with centralized unsupported-error classification
- `src/transport/udpfast.rs` now keeps only the specialized retained Linux zerocopy branch:
  - `specialized_zerocopy_enabled`
  - `enable_specialized_zerocopy(...)`
  - `send_gso(...)` with explicit `MSG_ZEROCOPY` gating for the specialized path
- The productive send ladder is now singular enough to defend:
  - `io_uring` first where available
  - shared UDP batching fallback
  - `MSG_ZEROCOPY` only as explicit specialized path

## Target Architecture

### Primary Send Ladder
- One explicit send-path owner should choose:
  - `io_uring` if kernel support and runtime setup justify it
  - otherwise batched UDP
  - `MSG_ZEROCOPY` only behind an explicit specialized branch

### Ownership Split
- `src/transport/uring.rs`
  - Linux high-end async send owner
  - zerocopy completion/errqueue owner
- `src/optimize/udp.rs`
  - plain UDP batching owner
  - Linux zerocopy fallback/error classification owner
- `src/transport/udpfast.rs`
  - transport harness/runtime integration
  - not its own broad send-policy engine

### MSG_ZEROCOPY Policy
- Retain only when all of these are true:
  - Linux-only
  - large enough sends
  - no better already-selected `io_uring` path
  - explicit policy gate still says yes
- Do not let `MSG_ZEROCOPY` remain a general-purpose runtime acceleration story.

## Non-Negotiables
- Keep Linux throughput capability.
- Keep centralized completion accounting.
- Keep fallback correctness.
- Do not weaken normal UDP fallback behavior.
- Do not create another parallel transport abstraction to solve this.

## Work Breakdown
- [x] Re-audit the exact ownership split among `optimize::udp`, `transport::uring`, and `udpfast`.
- [x] Collapse productive send-path selection onto one explicit ladder.
- [x] Narrow `MSG_ZEROCOPY` usage and remove duplicate local policy logic.
- [x] Keep completion and retry semantics centralized and regression-tested.
- [x] Update docs/guardrails to describe the final Linux send story honestly.

## Detailed Execution Plan

### Phase 1: Send-Path Owner Selection
- Decide the canonical productive ladder.
- Most likely:
  - `try_send_to(...)` / `io_uring` as first Linux acceleration path
  - `send_batch(...)` / normal UDP batching as fallback
  - `MSG_ZEROCOPY` only for explicitly justified large-send cases

### Phase 2: Policy Collapse
- Remove duplicated path-choice logic from `udpfast`.
- Keep zerocopy eligibility checks and errno classification in one place.
- Ensure `udpfast` consumes transport-owner decisions instead of rebuilding them.

### Phase 3: Completion/Fallback Confirmation
- Confirm that:
  - errqueue drain
  - zerocopy inbox drain
  - retry-without-zerocopy classification
  still route through single-owner helpers.

### Phase 4: Regression Hardening
- Add or tighten tests for:
  - `io_uring` preferred path
  - normal UDP fallback
  - `MSG_ZEROCOPY` not used when policy/hardware/size do not justify it
- Update guardrails and docs.

## Acceptance Criteria
- [x] There is one explicit productive Linux send-path ladder.
- [x] `udpfast` no longer carries duplicate high-level send-policy logic.
- [x] `MSG_ZEROCOPY` is no longer a broad default acceleration story.
- [x] Completion/retry semantics stay centralized and validated.
- [x] Docs and guardrails describe the same transport truth.

## Validation Matrix
- `cargo check`
- focused transport rust-tests for `udpfast` / `uring` / batch send behavior
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- The goal is not to delete Linux performance work.
- The goal is to make the send-path hierarchy singular, explainable, and defensible.

## Closure Notes
- `io_uring` send no longer carries direct `MSG_ZEROCOPY` policy.
- Linux batch send no longer has a broad zerocopy branch.
- `QUICFUSCATE_ENABLE_MSG_ZEROCOPY` now defaults to off unless explicitly opted in.
- Retained `MSG_ZEROCOPY` use is specialized to explicit Linux branches that still justify it, rather than being part of the normal productive send ladder.
