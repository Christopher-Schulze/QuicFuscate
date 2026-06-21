# TODO 82: FEC Capability Preservation and Decoder Surface Simplification

## Scope
- `src/fec.rs`
- FEC config/runtime/docs surface
- public FEC contract versus internal math/decoder strategy

## Problem Statement
- FEC is strategically important and should remain strong.
- The project wants to keep broad real capability, including Fountain and Streaming/RLNC-style recovery behavior.
- Internal decoder mathematics such as Wiedemann should not remain noisy product-facing surface.

## Desired End State
- Public FEC contract focuses on effect and runtime behavior.
- Internal FEC implementation remains sophisticated.
- Fountain remains.
- Streaming/RLNC-style recovery remains.
- Stable links stay close to `Zero/Light` behavior for efficiency.
- Worse links escalate into stronger recovery modes without exposing internal solver clutter as headline posture.

## Public Contract Direction
- Product-facing FEC should read like:
  - Off
  - Auto
- Internal runtime may still use:
  - `Zero`
  - `Light`
  - `Normal`
  - `Medium`
  - `Strong`
  - `Extreme`
  - `Ultra`
  - `Fountain`
  - `Streaming`

## Internal Retentions
- Keep Fountain capability.
- Keep Streaming/Tetrys-like behavior.
- Keep RLNC-style linear recovery behavior where already present.
- Keep solver/math backends such as Wiedemann only as internal policy.

## Work Breakdown
- [x] Split public FEC contract from internal FEC mode/decoder machinery.
- [x] Audit decoder-selection surfaces and demote math backend names out of product posture.
- [x] Collapse the public product contract to `Off` / `Auto` while preserving internal adaptation behavior. [x] 2026-03-08
- [x] Ensure stable-link behavior minimizes overhead and unstable-link behavior preserves strong recovery. [x] 2026-03-08
- [x] Update docs/config surfaces so effect is emphasized more than internal solver names.

## Acceptance Criteria
- [x] Public FEC contract is reduced to `Off` / `Auto`. [x] 2026-03-08
- [x] Fountain remains part of the retained canonical capability set. [x] 2026-03-08
- [x] Streaming/RLNC-style recovery remains part of the retained canonical capability set. [x] 2026-03-08
- [x] Wiedemann is treated as internal decoder strategy, not product headline surface.
- [x] Public FEC story becomes simpler while internal capability remains broad.

## Relationship to TODO 87
- TODO 82 is the broad capability-preservation and decoder-surface program.
- TODO 87 is the exact public-contract simplification plan that reduces the visible product contract to `Off` / `Auto` while preserving internal capability.

## Notes
- The point is not to weaken FEC.
- The point is to make FEC look and behave like a disciplined product subsystem instead of an exposed math laboratory.
- March 6, 2026:
  - Canonical docs now describe Fountain and Streaming/RLNC behavior as retained capability.
  - Decoder family overrides remain available only as advanced/internal tuning knobs.
  - Large-window decode acceleration is documented without presenting Wiedemann as product headline posture.
