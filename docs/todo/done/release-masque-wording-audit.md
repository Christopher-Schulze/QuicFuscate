# Release Task: MASQUE Wording Precision Audit

## Scope
- Remove vague wording around MASQUE behavior and align docs with exact runtime conditions.

## Current Finding
- Completed on 2026-02-12:
  - Normalized terms in docs to separate:
    - enabled (manager can exist),
    - preferred (path selection policy),
    - active (flow established).
  - Updated wording in:
    - `docs/DOCUMENTATION.md` (escalation and MASQUE API helper notes),
    - `docs/MAP.md` (test/docs summary wording).
  - Removed ambiguous "available/configured" phrasing from MASQUE policy statements.

## Plan
1. Build a truth table from code paths:
   - Manager creation conditions.
   - Preference toggles during escalation.
   - Datagrams default/override behavior.
2. Audit and normalize wording in:
   - `README.md`
   - `docs/DOCUMENTATION.md`
   - `docs/MAP.md`
3. Standardize language:
   - "enabled" for config-gated capability,
   - "preferred" for policy choice,
   - "active" for established flow,
   - "available" only for runtime capability checks.

## Acceptance Criteria
- No contradictory MASQUE wording remains in top-level docs.
- Every behavior claim maps directly to code conditions.
- A short policy table documents enable/prefer/active transitions.

## Deliverables
- Updated docs sections with consistent terminology.
- Cross-reference to relevant runtime functions in `src/stealth.rs` and `src/core.rs`.

## Verification
- `rg -n "MASQUE.*available|available.*MASQUE|when MASQUE" docs/DOCUMENTATION.md docs/MAP.md README.md`
- Result now only reflects explicit API helper return semantics, not policy wording.
