# TODO 50: Dead/Shadow Acceleration Pruning

## Scope
- Acceleration modules and paths under:
  - `src/optimize/*`
  - `src/accelerate.rs`
  - `src/transport/batch.rs`
  - `src/transport/udpfast.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Some acceleration modules have large APIs with little/no runtime consumption in production paths.
  - Evidence: `src/optimize/memory.rs` exports (`:14`, `:344`, `:385`) with no production call sites found by repo search.
- `transport::batch::BatchProcessor` exists with complex paths (busy-poll/zerocopy/gso), but current runtime usage is unclear/non-primary.
  - Evidence: `src/transport/batch.rs:25`; only direct test reference in `scripts/tests/rust/rt-transport-batch-processor.rs:3`
- `optimize/udp.rs` masks unused paths globally via `#![allow(dead_code)]`.
  - Evidence: `src/optimize/udp.rs:2`

## Objectives
- Classify acceleration code as runtime-used, test-only, or dead.
- Remove dead/shadow code or move it behind explicit test/bench boundaries.
- Minimize maintenance burden and audit surface.

## Work Breakdown
### A. Inventory and Classification
- [x] Produce module-level reachability map for acceleration APIs. [x] 2026-03-05
- [x] Tag each exported acceleration API as runtime-used/test-only/dead. [x] 2026-03-05

#### Reachability Snapshot (2026-03-05)
| Module | Symbol | Classification | Evidence | Proposed Action |
|---|---|---|---|---|
| `optimize::udp` | `send_batch` | runtime-used | used by `transport::udpfast`, `transport::batch`, `transport::xdp` | keep |
| `optimize::udp` | `send_batch_connected` / `recv_batch_connected` | runtime-used | used by `optimize::zc_batch` and client io hotpath tests | keep |
| `optimize::udp` | `ZeroCopySocket` | compat-runtime-used | used in `transport::batch` acceleration init path | keep, document as compat-boundary |
| `optimize::udp` | `BusyPollSocket` | compat-runtime-used | used in `transport::batch` optional init path | keep, evaluate stricter gating |
| `optimize::transport` | `ack_range_search` | test-only boundary | no runtime references; now gated behind `cfg(any(test, feature = "rust-tests"))` | keep as test/bench-only |
| `optimize::transport` | `parse_stream_frames` | test-only boundary | no runtime references; now gated behind `cfg(any(test, feature = "rust-tests"))` | keep as test/bench-only |
| `optimize::memory` | `prefetch_random` | test-only boundary | no runtime references; now gated behind `cfg(any(test, feature = "rust-tests"))` | keep as test/bench-only |
| `optimize::memory` | `clear_cache_lines` | test-only boundary | no runtime references; now gated behind `cfg(any(test, feature = "rust-tests"))` | keep as test/bench-only |
| `optimize::stealth` | `append_decimal_simd` / `append_lower_hex_simd` / `mix_entropy` | test-only boundary | no runtime references; now gated behind `cfg(any(test, feature = "rust-tests"))` | keep as test/bench-only |
| `optimize::brain` | `__test_*` backend hooks | test-only | referenced from `scripts/tests/rust/rt-brain-histogram.rs` | keep test-only boundary explicit |

### B. Pruning and Boundary Enforcement
- [x] Remove dead acceleration code in runtime-critical paths where safe to prove unused (`transport/h3::qpack::huff_encode`, client integration wrappers, server routing dead field, combined TLS provider dead fields). [x] 2026-03-05
- [x] Move/remove shadow wrappers and dead helpers in runtime modules (`FecCodec::{encode,decode}`, `MockServer::bind_addr`, `TestHarness::server_addr`). [x] 2026-03-05
- [x] Reduce remaining broad `allow(dead_code)` allowances in production modules (`src/simd.rs`). [x] 2026-03-05

### C. Runtime Wiring Decisions
- [x] For high-value acceleration paths, either wire into runtime or decommission. [x] 2026-03-08
- [x] Ensure only one implementation path remains for each claimed optimization. [x] 2026-03-08

### D. Validation
- [x] Add checks to detect newly orphaned acceleration APIs. [x] 2026-03-08
- [x] Ensure docs/claims only include runtime-used optimizations. [x] 2026-03-08

## Acceptance Criteria
- [x] Orphan acceleration code is removed or explicitly test-only. [x] 2026-03-08
- [x] Production modules do not rely on broad dead-code suppression for large surfaces. [x] 2026-03-08
- [x] Optimization claims match runtime usage. [x] 2026-03-08

## Deliverables
- [x] Reachability inventory artifact. [x] 2026-03-08
- [x] Pruning/refactor commits. [x] 2026-03-08
- [x] Guard checks for future dead/shadow acceleration drift. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: Runtime-facing dead-code suppressions and dead wrappers were pruned across `transport/h3`, `qftls`, `implementations/client`, and `implementations/server`.
- 2026-03-05: `src/fec.rs` suppression cluster was removed by deleting unused fields/methods and keeping runtime behavior unchanged.
- 2026-03-05: Removed the remaining broad suppression hotspot in `src/simd.rs`; only precise target/feature-scoped handling remains.
- 2026-03-05: Added first reachability matrix with symbol-level classification (`runtime-used`, `compat-runtime-used`, `test-only`, `dead`).
- 2026-03-05: Added guardrail automation for zero-runtime-reference acceleration exports in `scripts/tests/audits/audit-runtime-guardrails.sh`.
- 2026-03-05: Quarantined clearly runtime-unused acceleration helpers to explicit test scope in `optimize/memory.rs` and `optimize/stealth.rs` via `cfg(any(test, feature = "rust-tests"))`.
- 2026-03-05: Quarantined runtime-unused parser/range accel helpers in `optimize/transport.rs` to explicit test scope and cleared runtime-guardrail dead-export warnings.
- 2026-03-08: Closed as complete after tightening the remaining acceleration claims in `docs/DOCUMENTATION.md` so that retained runtime-owned, compat-only, and test-only acceleration surfaces are described explicitly and no broader acceleration posture is implied.
