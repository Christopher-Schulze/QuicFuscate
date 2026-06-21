# TODO-132: Missing SAFETY Comments on Unsafe Blocks

## Status
**PARTIAL** - ~25 SAFETY comments added across crypto.rs (10 blocks), optimize/unsafe.rs (10 blocks), simd.rs (5 blocks). Remaining ~275+ blocks still need annotation.

## Severity
**HIGH**

## Context
Over 300 unsafe blocks across the codebase lack `// SAFETY:` documentation explaining invariants, preconditions, and soundness justification. Key hotspots:

- `src/crypto.rs` - security-critical unsafe for crypto operations
- `src/optimize/unsafe.rs` - 1188 LOC, 44 unsafe blocks, performance-critical memory operations
- `src/simd.rs` - SIMD intrinsics with alignment and length preconditions
- `src/brain.rs` - 77 unsafe blocks for adaptive optimization
- `src/simd/x86_ack.rs` - x86 SSE/AVX intrinsics
- `src/simd/arm_varint.rs` - ARM NEON intrinsics

Without SAFETY comments, it is impossible for reviewers (or future contributors) to verify that unsafe usage is sound. This is a blocker for any security audit.

## Root Cause
Unsafe blocks were written for performance without documenting the invariants that make them sound. No lint or CI gate enforces `// SAFETY:` comments on unsafe blocks.

## Fix Plan
1. **Phase 1 - crypto.rs** (security critical, highest priority):
   - Audit every unsafe block
   - Document: what pointers are valid, what alignment is guaranteed, what lifetime constraints hold
   - Verify no UB paths exist
2. **Phase 2 - optimize/unsafe.rs** (44 blocks):
   - Document memory operation invariants (pointer validity, non-overlapping regions, alignment)
   - Document why raw pointer arithmetic is bounded
3. **Phase 3 - simd modules** (simd.rs, x86_ack.rs, arm_varint.rs, arm_stream.rs, x86_header.rs):
   - Document SIMD alignment requirements
   - Document input length preconditions for intrinsics
   - Document target_feature requirements
4. **Phase 4 - brain.rs** (77 blocks):
   - Document adaptive optimization invariants
   - Document why concurrent access patterns are sound
5. **Phase 5 - remaining files**:
   - Sweep all remaining unsafe blocks across the codebase
6. Add clippy lint `#![deny(clippy::undocumented_unsafe_blocks)]` to enforce going forward

## Acceptance Criteria
- Every `unsafe` block in the codebase has a `// SAFETY:` comment directly above it
- Comments explain: what invariants must hold, why they hold at this call site, what could go wrong
- `clippy::undocumented_unsafe_blocks` lint enabled in CI to prevent regression
- No new unsafe blocks can be added without SAFETY documentation

## Dependencies
- None (documentation-only change, no behavioral changes)

## Affected Files
- `src/crypto.rs`
- `src/optimize/unsafe.rs`
- `src/simd.rs`
- `src/simd/x86_ack.rs`
- `src/simd/x86_header.rs`
- `src/simd/arm_varint.rs`
- `src/simd/arm_stream.rs`
- `src/brain.rs`
- All other files containing `unsafe` blocks
