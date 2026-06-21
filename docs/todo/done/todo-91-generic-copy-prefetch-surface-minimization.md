# TODO 91: Generic Copy/Prefetch Surface Minimization

## Scope
- `src/optimize.rs`
- `src/optimize/memory.rs`
- copy/prefetch usage in runtime hot paths
- optimize documentation and guardrails

## Problem Statement
- The repo still carries broad generic helpers like:
  - `memcpy_fast(...)`
  - `prefetch_read(...)`
  - raw `prefetch(...)`
- These are active, not dead.
- Generic copy/prefetch magic is hard to justify unless it is tightly tied to a known workload and clearly owned by a real hot path.

## Desired End State
- No broad "faster memcpy/prefetch in general" surface remains.
- Retained acceleration is one of:
  - removed because it is generic and weakly justified
  - localized to a named workload-specific helper
  - kept only where it has a clear owner and hot-path rationale
- The code should read as workload-aware optimization, not blanket replacement of compiler/libc behavior.

## Current Truth Snapshot
- `src/optimize.rs` still exposes active generic helpers:
  - `SimdDispatch::memcpy_fast(...)`
  - `prefetch(...)`
  - `prefetch_impl(...)`
- The broad optimize-surface wrappers that previously made this look like a generic memcpy/prefetch layer are now materially smaller:
  - `SimdDispatch::prefetch_read(...)` is gone
  - `optimize::simd::core::prefetch_read(...)` is gone
  - `optimize::simd::memcpy_prefetch(...)` is gone
- `src/optimize/memory.rs` no longer uses `memcpy_fast(...)` inside `LockFreeRingBuffer`.
- `src/transport/h3.rs` no longer uses the removed generic `memcpy_prefetch(...)` wrapper.
- `src/optimize/stealth.rs` scalar ASCII assembly no longer routes through an optimize-surface memcpy wrapper.
- `src/crypto.rs` also still issues a number of prefetch calls in hot paths.
- This means the criticism is no longer about dead code. It is about retained active surface that needs tighter ownership.

## Target Architecture

### Keep / Localize / Remove Classification
- `Keep`
  - only if the helper is already narrowly tied to one hot path
- `Localize`
  - move from generic helper naming to workload-specific naming and scope
- `Remove`
  - anything generic with weak or unproven justification

### Preferred Naming
- Prefer:
  - `copy_ring_buffer_chunk(...)`
  - `prefetch_crypto_input(...)`
  - `prefetch_fec_decode_window(...)`
- Avoid:
  - `memcpy_fast(...)`
  - generic "do magic faster" helper names with no workload ownership

## Non-Negotiables
- Do not regress correctness.
- Do not remove a retained hot-path optimization blindly if it has a clear workload owner.
- Do not broaden unsafe or SIMD surface to solve this.
- Prefer simpler generic fallback when a custom helper does not clearly earn its existence.

## Work Breakdown
- [x] Inventory active generic copy/prefetch usage sites.
- [x] Decide keep/localize/remove for each.
- [x] Replace generic names/surfaces with workload-specific owners where justified.
- [x] Remove unjustified generic wrappers.
- [x] Revalidate ring-buffer and crypto hot paths after the surface collapse.

## Current Progress
- [x] Removed broad optimize-layer wrappers:
  - `SimdDispatch::prefetch_read(...)`
  - `optimize::simd::core::prefetch_read(...)`
  - `optimize::simd::memcpy_prefetch(...)`
- [x] `LockFreeRingBuffer` now uses direct slice copies instead of routing through a generic optimize-owned memcpy helper.
- [x] The raw H3 copy path now uses direct `copy_from_slice(...)` instead of the removed generic optimize wrapper.
- [x] The last optimize-surface `memcpy_fast` wrapper is gone; `src/optimize/stealth.rs` scalar fallback now copies directly.
- [x] `src/transport/udpfast.rs` now names its retained prefetches by workload owner:
  - `prefetch_outbound_payload(...)`
  - `prefetch_receive_buffer(...)`
- [x] `src/transport/uring.rs` now names its retained aarch64 prefetch helper by workload owner:
  - `prefetch_uring_send_input(...)`
- [x] `src/transport/xdp.rs` compat/test GSO-GRO helpers now name retained prefetches by workload owner:
  - `prefetch_next_segment_input(...)`
  - `prefetch_coalesced_packet_input(...)`
- [x] `src/crypto.rs` now names retained runtime prefetches by crypto owner intent:
  - `prefetch_aegis_state(...)`
  - `prefetch_morus_buffer(...)`
- [x] `src/transport/connection.rs` now names retained runtime prefetches by transport owner intent:
  - `prefetch_recv_packet_buffer(...)`
  - `prefetch_frame_parse_window(...)`
  - `prefetch_stream_send_input(...)`
  - `prefetch_outbound_datagram_input(...)`
- [x] `src/fec.rs` no longer re-exports a generic crate-wide `prefetch_data(...)` helper.
- [x] FEC now keeps its retained prefetches under explicit internal owners:
  - `prefetch_decode_window(...)` for the cross-module decode lookahead seam
  - `prefetch_fec_slice(...)` for local GF/FEC slice hot paths
  - `prefetch_gf_log_lookup(...)` for local lookup-table hot paths
- [x] Remaining active surface is now mostly low-level owner-local prefetch in:
  - `src/crypto.rs`
  - any residual low-level FEC machine-room helper naming that still reads broader than its actual owner
  with the transport machine-room paths and the old FEC cross-module generic seam already moved away from generic optimize naming.

## Detailed Execution Plan

### Phase 1: Usage Inventory
- Enumerate all remaining active callers of:
  - `memcpy_fast(...)`
  - `prefetch_read(...)`
  - low-level `prefetch(...)`

### Phase 2: Ring-Buffer and Memory Path
- Decide whether `LockFreeRingBuffer` should:
  - keep a local optimized copy helper
  - or drop back to simpler slice copy logic
- If retained, localize it as ring-buffer-specific machinery.

### Phase 3: Crypto Prefetch Path
- Classify retained prefetch sites in `src/crypto.rs`.
- Keep only those that clearly belong to concrete crypto hot paths.
- Prefer owner-local helpers over broad generic optimize-surface helpers.

### Phase 4: Surface Cleanup
- Reduce or remove broad optimize-level generic entry points.
- Update docs and guardrails so the final story is explicit.

## Acceptance Criteria
- [x] Broad generic copy/prefetch surface is materially smaller.
- [x] Retained helpers have explicit workload ownership across the transport machine room, current crypto hot paths, and the FEC decode seam.
- [x] No unjustified generic memcpy replacement story remains at broad optimize/runtime surface level.
- [x] Runtime hot paths still compile and validate cleanly for the touched transport/FEC paths.

## Validation Matrix
- `cargo check`
- focused rust-tests covering touched optimize/memory/crypto paths
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- This is a readability and justification cleanup, not an anti-performance crusade.
- The best optimization here is likely less generic magic and more local, measurable ownership.
