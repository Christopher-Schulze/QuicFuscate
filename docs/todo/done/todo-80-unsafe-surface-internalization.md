# TODO 80: Unsafe Surface Internalization

## Scope
- `src/lib.rs`
- `src/optimize/unsafe.rs`
- public re-exports of unsafe/SIMD primitives
- owner modules in FEC, compression, and transport hot paths

## Problem Statement
- Unsafe/SIMD internals currently read too much like a public product toolbox.
- This weakens architectural discipline and makes the codebase look broader and riskier than necessary.
- The goal is not to remove all unsafe fast paths, but to keep them only where they have a proven runtime owner and value.

## Objectives
- Make unsafe code internal-first.
- Keep SIMD/unsafe gains only behind narrow safe facades.
- Require benchmark and fallback rationale for every retained unsafe path.

## Core Rules
- No broad top-level public export of unsafe primitives unless they are genuinely canonical.
- Every retained unsafe path must have:
  - a clear runtime owner
  - a clear advantage
  - a clear fallback
- FEC, compression, and selected transport hot paths may keep unsafe backends if justified.

## Work Breakdown
- [x] Inventory all public unsafe exports and classify ownership. [x] 2026-03-06
- [x] Identify which unsafe facilities are actually used by canonical runtime paths. [x] 2026-03-06
- [x] Move remaining useful unsafe facilities behind safe owner-specific facades. [x] 2026-03-08
- [x] Remove or quarantine broad public unsafe exports with no clear owner. [x] 2026-03-06
- [x] Add benchmark evidence and fallback notes for retained unsafe paths. [x] 2026-03-08

## Progress Notes
- 2026-03-06: Confirmed that `UnsafeMemoryPool`, `UnsafePacket`, `UnsafeCompressor`, and the `optimize::unsafe_simd` re-export toolbox had no canonical runtime call sites outside their own definition surface.
- 2026-03-06: Removed top-level `lib.rs` re-exports for unsafe pool/packet types.
- 2026-03-06: Demoted `optimize::r#unsafe` to hidden crate-internal visibility and limited `optimize::unsafe_simd` to test or `rust-tests` compatibility coverage only.
- 2026-03-06: Updated documentation so the unsafe zstd backend is described as an internal backend, not a public product API.
- 2026-03-08: Demoted `optimize::PrefetchHint` and `optimize::prefetch(...)` to crate-internal visibility because they are only used by internal runtime owners (`crypto`, `fec`, `transport`, `simd`) and do not need broad product visibility.
- 2026-03-08: Demoted ARM SIMD helper functions in `src/simd.rs` from broad `pub unsafe` visibility to `pub(super)` so only the enclosing selector/facade and in-file regression tests can reach them.
- 2026-03-08: Demoted `src/simd/arm_varint.rs` and `src/simd/x86_ack.rs` unsafe helper entrypoints to `pub(crate)` because they are crate-only transport/SIMD machinery rather than product-facing APIs.
- 2026-03-08: Demoted the broad x86 backend helper cluster in `src/simd.rs` to `pub(super)` and the standalone AVX-512 header validator in `src/simd/x86_header.rs` to `pub(crate)`, because the callgraph shows only internal selector/runtime/test ownership.
- 2026-03-08: Removed the now-unused `optimize::unsafe_simd` re-export block entirely after verifying it had no remaining Rust parity or runtime consumers.
- 2026-03-08: Tightened `optimize::r#unsafe` itself to `cfg(all(test, feature = "unsafe_rust"))`, so the remaining unsafe pool/compressor machinery only compiles in its actual test context.
- 2026-03-08: Removed dead test-only leftovers from `src/optimize/unsafe.rs` (`UnsafePacket::as_mut_slice`, `UnsafeCompressor::{compress_streaming, compress_auto}`, `stream_min`) once their former re-export/test surface was gone.
- 2026-03-08: Added guardrails to fail if these narrowed unsafe helper surfaces regain broad public visibility.
- 2026-03-08: Demoted the remaining ARM SIMD helper cluster in `src/simd.rs` so only crate-owned selectors or the one retained crate-level string-search owner can reach it: Reed-Solomon, histogram, dot-product, and AMX shim helpers are now `pub(super)`, while retained cross-module QPACK and SVE2 pattern-search entrypoints are only `pub(crate)`.
- 2026-03-08: Retained unsafe runtime backends now have explicit owner/fallback stories instead of broad toolbox posture:
  - `SimdOps`/owner selectors remain the runtime dispatch point
  - scalar fallbacks remain the canonical correctness baseline
  - audit guardrails now also fail if the narrowed ARM helper set regains broad `pub unsafe` visibility

## Acceptance Criteria
- [x] Unsafe internals are no longer presented as a broad top-level public toolkit. [x] 2026-03-08
- [x] Canonical runtime users only see safe, narrow APIs. [x] 2026-03-08
- [x] Remaining unsafe code is clearly justified by owner, benefit, and fallback. [x] 2026-03-08

## Notes
- The goal is not “no unsafe”.
- The goal is “unsafe only where it materially wins and only behind disciplined ownership”.
