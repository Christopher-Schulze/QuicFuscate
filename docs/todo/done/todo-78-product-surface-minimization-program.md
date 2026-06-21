# TODO 78: Product Surface Minimization Program

## Scope
- `Cargo.toml`
- public module exports in `src/lib.rs`
- top-level product/config/docs surfaces that currently overstate internal feature breadth

## Problem Statement
- The project still exposes too many ISA, platform, and experiment knobs as if they were core product posture.
- This broad surface makes the fork look less disciplined than the canonical runtime really is.
- FEC and stealth should remain strong, but internal machinery should not read like a giant public product matrix.

## Objectives
- Reduce product-visible surface to canonical runtime truths.
- Preserve FEC and stealth capability while shrinking visible architecture clutter.
- Move internal math/ISA/experiment knobs behind internal policy or test-only boundaries.

## Planned Decisions
- Remove or hide low-value product-facing feature knobs:
  - `internal_af_xdp_experimental` (internal only)
  - `amx-int8` (remove from Cargo product surface)
  - `amx-tile` (remove from Cargo product surface)
  - `internal_avx10_preview` (internal only)
- Reclassify `wiedemann` as internal FEC decoder policy, not product posture.
- Keep FEC and stealth visible as capabilities, not as giant sub-feature explosion.

## Work Breakdown
- [x] Build a full feature inventory from `Cargo.toml` and classify each item as product, internal, test-only, compat-only, or removable. [x] 2026-03-08
- [x] Identify all docs and top-level exports that currently amplify the feature surface beyond the canonical runtime. [x] 2026-03-08
- [x] Collapse low-value ISA/experiment features out of product posture.
- [x] Narrow `accelerate::*` from broad product-facing re-export surface to internal runtime ownership plus explicit `rust-tests` parity visibility. [x] 2026-03-08
- [x] Pull README/DOCUMENTATION truth in line with the narrowed `accelerate::*` surface and internal AF_XDP feature naming. [x] 2026-03-08
- [x] Keep only meaningful product-level knobs that match real runtime contracts. [x] 2026-03-08
- [x] Add guardrails so new experiment/ISA knobs cannot silently become public posture again. [x] 2026-03-08

## Acceptance Criteria
- [x] Product-visible feature surface is much smaller and maps to real runtime contracts. [x] 2026-03-08
- [x] Internal math/ISA experimentation no longer reads like the main product identity. [x] 2026-03-08
- [x] FEC and stealth remain first-class capabilities without exposing unnecessary internals. [x] 2026-03-08

## Notes
- This program is about truthful surface reduction, not feature amputation for its own sake.
- Stealth and FEC remain broad in capability, but their internal sub-mechanics should be exposed selectively.
- March 6, 2026:
  - `amx-int8` and `amx-tile` were removed from the visible Cargo feature surface.
  - `af_xdp_experimental`, `avx10_preview`, and `wiedemann` were renamed to internal-only Cargo feature gates.
- March 8, 2026:
  - `accelerate::*` broad re-exports were reduced so normal product builds keep them crate-internal, while Rust parity/test builds retain the explicit compatibility surface.
  - README and canonical documentation were aligned so narrowed `accelerate::*` helpers no longer read like a broad product API, and stale `af_xdp_experimental` naming was removed from visible product truth.
  - Cargo feature posture is now classified explicitly in canonical documentation, and the runtime guardrail now checks that internal-only feature gates stay out of the default feature set and that the classification block remains present.
