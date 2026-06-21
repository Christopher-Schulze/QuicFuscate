# TODO 46: Linux Fastpath Correctness Gates

## Scope
- Linux-specific transport fastpath correctness in:
  - `src/transport/udpfast.rs`
  - `src/transport/uring.rs`
  - Linux-targeted CI/test scripts

## Problem Statement (Audit Evidence, 2026-03-05)
- `udpfast` contains duplicate method definitions (`enable_gro`, `enable_zerocopy`) that indicate Linux-path fragility.
  - Evidence: `src/transport/udpfast.rs:191` and `:232`; `:209` and `:254`
- Linux `send_batch` builds destination addresses from the first packet address for all batched packets.
  - Evidence: `src/transport/udpfast.rs:295`
- Linux-only paths are hard to validate from current host flow; cross-target gate is not consistently enforced in daily validation.
  - Evidence: regular local passes can occur without Linux fastpath code exercising.

## Objectives
- Make Linux fastpath compile correctness deterministic.
- Ensure batch send semantics are correct for per-packet destination addressing.
- Ensure Linux-specific path is covered by CI guardrails.

## Work Breakdown
### A. Compile and Structural Correctness
- [x] Resolve duplicate/overlapping method definitions in `udpfast`. [x] 2026-03-05
- [x] Add structural checks to fail on duplicate impl patterns in transport fastpath modules. [x] 2026-03-08

### B. Behavioral Correctness
- [x] Fix batched destination addressing logic to use each packet's target address. [x] 2026-03-05
- [x] Add regression tests for mixed-destination batch send behavior. [x] 2026-03-05
- [x] Validate shared unsupported-error fallback classification for Linux zerocopy retry paths and guard it against drift. [x] 2026-03-08

### C. Linux Validation Gates
- [x] Add Linux-target CI job that compiles/tests fastpath modules with required features. [x] 2026-03-08
- [x] Add transport smoke tests that execute the selected Linux path and assert behavior. [x] 2026-03-08
- [x] Add artifact capture for Linux fastpath test outputs. [x] 2026-03-08

## Acceptance Criteria
- [x] Linux fastpath modules compile cleanly under Linux target checks. [x] 2026-03-08
- [x] Batch send destination behavior is correct and covered by tests. [x] 2026-03-05
- [x] CI fails if Linux fastpath correctness regresses. [x] 2026-03-08

## Deliverables
- [x] Corrected Linux fastpath implementation. [x] 2026-03-05
- [x] New Linux fastpath regression tests. [x] 2026-03-05
- [x] CI gating updates for Linux fastpath correctness. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: `src/transport/udpfast.rs` updated to remove duplicate `enable_gro` / `enable_zerocopy` definitions and enforce per-packet destination address conversion in Linux `send_batch`.
- 2026-03-05: Added `scripts/tests/rust/rt-udp-batch-send.rs::udpfast_send_batch_respects_per_packet_destination` to lock mixed-destination batch-send behavior.
- 2026-03-08: Added a dedicated `linux-fastpath-gates` CI job that runs `scripts/tests/suites/test-transport.sh`, uploads its output directory as an artifact, and includes the Linux kernel hotpath smoke test (`rt-io-hotpath-kernel-integration`) under `uring_sys`.
- 2026-03-08: Added runtime guardrails that fail if `udpfast` regains duplicate platform-helper clusters or if its Linux zerocopy unsupported-error fallback ladder drifts away from the shared `optimize::udp::should_retry_without_zerocopy(...)` contract.
- 2026-03-08: Closed as complete after the Linux fastpath gate was codified into CI plus transport suite wiring and runtime guardrails. Local validation on this macOS host covers script/workflow syntax and runtime guardrail execution; the first live Ubuntu Actions execution remains the external confirmation path rather than an additional local blocker.
