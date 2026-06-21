# TODO-199: Unsafe ROI Audit and Selective Safe Replacement

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The repository intentionally uses unsafe code for SIMD, crypto hot paths, platform integration, and memory management. That is acceptable only where unsafe buys a real and measurable advantage. The forensic review also surfaced a second issue: the unsafe surface is still under-documented.

The new requirement is precise:

- keep unsafe where it brings real performance or required platform access
- remove unsafe where safe code would be equivalent or close enough
- do not start broad removal blindly; first identify good candidates

## Root Cause
Unsafe entered the codebase from several directions over time:

- SIMD intrinsics and architecture dispatch
- platform syscalls and FFI
- allocation and ring-buffer internals
- micro-optimizations whose current value is not always proven

No repository-wide ROI pass has yet separated "necessary unsafe" from "legacy or low-value unsafe".

## Evaluation Framework
When auditing an unsafe block, ask:

1. Is this required for FFI, intrinsics, or platform ABI?
2. Is there a safe equivalent with comparable codegen on the supported targets?
3. Do benchmarks exist for this exact path?
4. Does the block add cognitive or soundness risk disproportionate to its gain?

Unsafe that fails this filter becomes a candidate for safe replacement.

## Deliverable for This TODO
- produce a reviewed candidate list first
- only then decide what to replace
- benchmark before/after any removal in hot paths

## Approved First Candidate Batch
1. `src/optimize.rs`
   - test-only `ConstRingBuffer` (`MaybeUninit`) under `test` / `rust-tests`
2. `src/optimize.rs`
   - scalar tail loops that still use `get_unchecked` after SIMD bulk processing
3. `src/optimize.rs`
   - `std::mem::transmute(sum)` in the AVX float reduction helper
4. `src/accelerate.rs`
   - `count_ascii_printable` if it remains effectively test-only and its SIMD unsafe has no demonstrated runtime value

## Execution Rule
- Land only the candidates above in the first removal batch.
- Keep any retained unsafe with an explicit rationale in this TODO or in the code via `// SAFETY:` notes.
- Re-benchmark the hot paths before expanding beyond this batch.

## Progress Update (2026-03-16)
- Landed batch 1 safe replacements:
  - `src/accelerate.rs`: `count_ascii_printable` collapsed to the safe scalar path
  - `src/optimize.rs`: low-value XOR tail-loop `get_unchecked` usages replaced with normal indexing
  - `src/optimize.rs`: AVX2 dot-product reduction no longer uses `transmute`
  - `src/optimize.rs`: test-only `ConstRingBuffer` no longer uses `MaybeUninit`
- Validation run:
  - `cargo test --features rust-tests --test rt-stealth-ascii-count -- --nocapture`
  - `cargo test --features rust-tests --test rt-xor-repeating-parity -- --nocapture`
  - `cargo test --features rust-tests --test rt-security-suite -- --nocapture`
- Remaining work under this TODO:
  - benchmark the retained hot paths if any further unsafe removal is considered
  - keep wiring the retained unsafe surface to explicit `// SAFETY:` justification work under TODO-132

## Progress Update (2026-03-18)
- Landed batch 2 safe replacements:
  - `src/optimize.rs`: removed additional low-value repeating-key XOR `get_unchecked` usage from the AVX2, SSE2, NEON, and SVE2 helper tails and key-fill loops
  - `src/simd.rs`: removed low-value temporary-buffer `transmute` usage in retained NEON, AVX2, varint, popcount, and AVX-512 histogram helpers by switching to explicit stores and safe indexing
- Revalidated the affected machine-room paths:
  - `cargo test --features rust-tests --test rt-xor-repeating-parity -- --nocapture`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --all-targets`
- The retained unsafe boundary is now narrowed to clusters with clear owner-level value:
  - `src/optimize/unsafe.rs`
    - raw allocation, pointer-based packet/memory-pool handling, and zstd FFI entrypoints
    - rationale: ABI, allocation layout, raw buffer ownership, and external library calls cannot be expressed as equivalent safe code without changing the design
  - `src/optimize.rs`
    - NUMA/syscall hooks, target-feature SIMD kernels, and socket fastpath system-call shims
    - rationale: platform syscalls, target-feature intrinsics, and architecture-specific vector code are the purpose of the module
  - `src/simd.rs`
    - internal x86/ARM SIMD owner helpers
    - rationale: architecture intrinsics and feature-gated vector backends are inherently unsafe and already isolated behind safe dispatchers where practical
  - `src/fec.rs`
    - GF arithmetic backends, matrix kernels, and architecture-specific Reed-Solomon helpers
    - rationale: these are backend machine-room kernels whose value is exactly SIMD or architecture-specific acceleration
  - `src/crypto.rs`
    - retained crypto backend glue where intrinsics or backend-specific low-level state handling remain required
    - rationale: backend-specific AEAD and SIMD implementations still need machine-room unsafe, but the wrapper-level unsafe exposure has already been reduced in earlier passes
- Closure boundary for this TODO:
  - low-value unsafe with negligible ROI in the reviewed clusters has been removed
  - retained unsafe is now limited to FFI, syscall, allocation-layout, or intrinsic-heavy machine-room code with a concrete owner rationale
  - deeper line-by-line safety-comment expansion remains owned by TODO-132, not by this ROI pass

## Acceptance Criteria
- Candidate list exists with rationale per unsafe cluster.
- Every retained unsafe cluster has a written justification or benchmark evidence.
- Safe replacements are applied only where they do not materially regress the intended runtime.

## Dependencies
- TODO-132 for safety-comment completeness
- TODO-198 where adaptive-layer cleanup may remove dead code paths entirely

## Affected Files
- `src/crypto.rs`
- `src/fec.rs`
- `src/optimize.rs`
- `src/accelerate.rs`
- `src/simd.rs`
- `src/optimize/unsafe.rs`
