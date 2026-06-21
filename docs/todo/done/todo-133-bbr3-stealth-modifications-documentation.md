# TODO-133: BBR3 Stealth Modifications Undocumented

## Status
**COMPLETED**

## Severity
**MEDIUM**

## Context
In `src/transport/recovery.rs:85-180`, the `Bbr3State` struct includes fields not present in standard BBR3:
- `stealth_mode: bool` - enables traffic-shaping evasion behaviors
- `browser_profile: Option<BrowserProfile>` - mimics specific browser congestion patterns

The state transitions are simplified compared to the real BBR3 algorithm:
- Missing round-count tracking for bandwidth growth validation
- Missing bandwidth growth checks between probe phases
- Simplified PROBE_BW gain cycling

Additionally, at `recovery.rs:412-413`, jitter injection via `Xoshiro256++` is applied to pacing intervals for stealth purposes, which is a non-standard modification that affects congestion control behavior.

## Root Cause
The implementation intentionally deviates from standard BBR3 for stealth/obfuscation purposes, but these deviations are not documented. A reader comparing against the BBR3 RFC/paper would be confused about what is intentional vs accidental.

## Fix Plan
1. Rename struct or add module-level doc comment clearly labeling this as "Stealth-BBR3" - a QuicFuscate-specific variant
2. Add inline comments at each deviation point explaining:
   - What standard BBR3 does
   - What this implementation does differently
   - Why (stealth requirement)
3. Document the jitter injection mechanism at line 412-413:
   - Purpose: prevent timing-based traffic fingerprinting
   - RNG: Xoshiro256++ (fast, non-cryptographic - appropriate for jitter)
   - Jitter bounds and distribution
4. Add a section in `docs/documentation.md` under congestion control explaining the Stealth-BBR3 variant
5. Document which BBR3 features are fully implemented vs simplified vs omitted

## Acceptance Criteria
- Clear documentation that this is a modified BBR3 variant, not standard BBR3
- Every deviation from standard BBR3 has an inline comment
- Jitter injection mechanism documented with rationale
- `docs/documentation.md` updated with Stealth-BBR3 section
- A reader can distinguish intentional deviations from implementation gaps

## Dependencies
- None (documentation-only change)

## Affected Files
- `src/transport/recovery.rs`
- `docs/documentation.md`
