# TODO 93: Final Runtime Complexity Layer Separation

## Scope
- canonical docs
- runtime surface classification across transport/stealth/fec/crypto/optimize
- guardrails and remaining visible config/helper boundaries

## Problem Statement
- The repo is now much cleaner, but its remaining retained complexity is still easier to defend if it is organized as explicit layers rather than as one large highly capable system.
- This is the final readability and defensibility pass after the harder owner reductions in TODO 90-92.

## Desired End State
- Every remaining visible capability belongs clearly to one of these layers:
  - canonical runtime/product path
  - adaptive policy/control
  - platform acceleration
  - compat/test/experimental
- No broad helper, hook, or config surface should span layers without one explicit owner.

## Current Truth Snapshot
- Large parts of the repo already lean this way.
- The remaining gap is final explicit classification and guardrail/documentation alignment after transport, optimize, and crypto cleanup.

## Target Layer Model

### Canonical Runtime/Product Path
- product-visible runtime behavior
- canonical transport/FEC/stealth/crypto paths

### Adaptive Policy/Control
- `brain`
- FEC auto-controller
- stealth policy/orchestration

### Platform Acceleration
- hardware detection
- SIMD
- Linux fastpath
- localized hot-path helpers

### Compat/Test/Experimental
- XDP compatibility
- MASQUE compatibility surface
- rust-tests-only helpers
- experimental internal-only switches

## Non-Negotiables
- No UI redesign.
- No product capability rollback.
- No fake simplification by deleting retained real capability.
- The final state must be easier to explain without being weaker.

## Work Breakdown
- [x] Reclassify remaining visible surfaces into the four-layer model.
- [x] Remove or narrow helpers/config knobs that cross layers without a single owner.
- [x] Tighten docs/guardrails to match the final layer map.
- [x] Close remaining reviewer-facing ambiguity after TODO 90-92 land.

## Detailed Execution Plan

### Phase 1: Layer Inventory
- Identify remaining visible layer-crossing helpers, types, or config surfaces.

### Phase 2: Boundary Tightening
- Narrow or relocate anything that still violates the four-layer owner model.

### Phase 3: Documentation and Guardrails
- Update the canonical docs to describe the final layer model.
- Add guardrails where a layer boundary is easy to regress.

### Phase 4: Final Reality Check
- Revalidate that the final repo reads as intentionally layered rather than merely feature-heavy.

## Acceptance Criteria
- [x] The four-layer model is visible in code/docs/guardrails.
- [x] Remaining broad helper/config surfaces each have one explicit layer owner.
- [x] External review of retained complexity is easier to defend technically.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- This is the final readability and architecture-shape pass, not a new feature program.

## Completion Summary
- The four-layer model is now explicit in canonical docs:
  - `README.md`
  - `docs/DOCUMENTATION.md`
- Runtime guardrails now fail if that explicit layer model disappears from the canonical docs.
- The final retained interpretation is now stable:
  - `canonical runtime/product path`
  - `adaptive policy/control`
  - `platform acceleration`
  - `compat/test/experimental`
- This closes the remaining reviewer-facing ambiguity after TODO 90-92 without deleting retained capability or inventing new surface.
