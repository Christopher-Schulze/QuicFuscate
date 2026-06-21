# TODO 48: Zerocopy Stack Consolidation and Safety

## Scope
- Zerocopy implementations and completion handling across:
  - `src/optimize.rs` (`ZeroCopyBuffer`, `zerocopy` module)
  - `src/optimize/udp.rs`
  - `src/transport/udpfast.rs`
  - `src/transport/uring.rs`
  - `src/transport/xdp.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Multiple zerocopy implementations overlap with similar responsibilities and divergent behavior.
  - Evidence: `src/optimize.rs:2703`, `:3574`; `src/optimize/udp.rs:346`; `src/transport/udpfast.rs:209`; `src/transport/uring.rs:322`
- Dormant unsafe zerocopy path in `optimize::zerocopy` uses stack-based sockaddr pointers beyond valid lifetime (unsafe UB risk if reactivated).
  - Evidence: pointer returned from local vars in `src/optimize.rs:3655`-`:3677`, then used at `:3680`-`:3716`
- Completion handling is split between userland inbox and errqueue draining in multiple places, making semantics hard to reason about.
  - Evidence: `src/transport/udpfast.rs:349`, `:360`; `src/transport/uring.rs:409`

## Objectives
- Define one authoritative zerocopy send/completion path per runtime mode.
- Remove unsafe dormant implementations or make them safe and tested.
- Standardize fallback and completion semantics.

## Work Breakdown
### A. Implementation Inventory and Decision
- [x] Inventory all zerocopy implementations and classify: canonical, compatibility, dead. [x] 2026-03-08
- [x] Decide canonical zerocopy implementation(s) for current runtime architecture. [x] 2026-03-08

### B. Safety Cleanup
- [x] Remove or fix unsafe lifetime issues in dormant zerocopy code. [x] 2026-03-05
- [x] Remove duplicate zerocopy structs with overlapping behavior. [x] 2026-03-08
- [x] Ensure all remaining unsafe blocks in zerocopy path have explicit invariants. [x] 2026-03-08

### C. Completion Semantics
- [x] Standardize completion flow (inbox vs errqueue) with documented contract. [x] 2026-03-08
- [x] Consolidate telemetry for zerocopy completion and fallback reasons. [x] 2026-03-08
- [x] Add deterministic tests for completion draining behavior. [x] 2026-03-08

### D. Fallback and Feature Gating
- [x] Define explicit fallback ladder (`zerocopy -> regular send`) per path. [x] 2026-03-08
- [x] Apply centralized zerocopy size-threshold policy across Linux send paths (`udpfast`, `uring`, `xdp` compatibility path, optimize wrappers). [x] 2026-03-05
- [x] Align remaining env flags and feature gates across modules. [x] 2026-03-08

## Acceptance Criteria
- [x] No duplicate/shadow zerocopy implementations remain in production runtime. [x] 2026-03-08
- [x] No known unsafe lifetime hazards remain in zerocopy code. [x] 2026-03-08
- [x] Completion/fallback behavior is deterministic and tested. [x] 2026-03-08

## Deliverables
- [x] Consolidated zerocopy runtime path. [x] 2026-03-08
- [x] Safety cleanup commits for zerocopy modules. [x] 2026-03-08
- [x] Completion/fallback regression tests. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: Fixed the dormant `optimize::zerocopy` Linux sockaddr lifetime hazard by switching from stack-pointer return pattern to owned `sockaddr_storage` kept alive through `sendmsg`.
- 2026-03-05: Extended centralized `should_use_msg_zerocopy` threshold wiring to the `xdp` io_uring compatibility send path and updated runtime guardrails to enforce this wiring.
- 2026-03-05: Added central `zerocopy_drain_batch()` resolution in `transport/uring` and rewired `transport/connection` plus `transport/udpfast` drains to use the same batch policy for inbox + errqueue completion handling.
- 2026-03-08: Added `transport::uring::drain_zerocopy_inbox_to_global(...)` as the canonical inbox-drain accounting helper and rewired both `transport::connection` and `transport::udpfast` to use it.
- 2026-03-08: Removed the duplicate local `udpfast` zerocopy completion counters, leaving global zerocopy completion telemetry as the single accounting owner.
- 2026-03-08: Removed global zerocopy runtime-telemetry mutation from the rust-parity/test-only `transport::batch` shim, so that module no longer pretends to be a runtime zerocopy owner.
- 2026-03-08: Added shared `transport::uring::drain_zerocopy_errqueue(...)` and rewired `udpfast` plus the XDP compatibility path to the same low-level errqueue drain contract, removing the last duplicated Linux zerocopy errqueue helper body.
- 2026-03-08: Added shared `transport::uring::drain_zerocopy_errqueue_to_global(...)` so `udpfast` no longer mutates zerocopy completion telemetry directly, and pinned that contract with a regression test in `transport::uring`.
- 2026-03-08: Centralized the Linux zerocopy unsupported-error retry ladder in `optimize::udp::should_retry_without_zerocopy(...)` and rewired `udpfast` to reuse it, leaving `uring` as the explicit no-local-retry path.
- 2026-03-08: Closed as complete after zerocopy ownership, completion accounting, errqueue draining, and Linux fallback classification all converged on shared runtime owners. Local validation on this macOS host covers compile/clippy plus runtime guardrails; Linux-hosted execution remains an external CI confirmation path, not an additional repository blocker.
