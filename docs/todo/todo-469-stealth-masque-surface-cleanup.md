---
id: TODO-469
title: MASQUE production path and experimental surface cleanup
severity: MEDIUM
phase: K
priority: P1
status: DONE
created: 2026-06-30
depends_on:
  - TODO-422
  - TODO-466
---

# TODO-469: MASQUE production path and experimental surface cleanup

## Goal

Make the MASQUE story impossible to misread: Core H3/MASQUE is the production VPN/TUN carrier;
`stealth::MasqueManager` is retained compatibility and experiment machinery.

## Current State

- TUN data plane is implemented through H3/MASQUE routing.
- The documentation still contains compatibility-only MASQUE wording in places that can be read as
  applying to the production TUN carrier.
- The stealth module also has a `MasqueManager` surface that is not the canonical data-plane owner.

## Problem

Two MASQUE surfaces with similar names create architectural drift. Agents and reviewers can mistake
the compatibility manager for the production hot path or falsely conclude MASQUE is not the main TUN
carrier.

## Implementation Plan

1. Read the H3/MASQUE data-plane code and `stealth::MasqueManager` signatures before editing.
2. Document and, where useful, rename comments around the two surfaces:
   - production: transport/H3/Core MASQUE TUN data plane;
   - retained compatibility: `stealth::MasqueManager`.
3. Ensure public docs, environment variable descriptions, and API notes do not imply the retained
   manager is the canonical path.
4. Add code comments at ownership boundaries if needed.
5. Add or update tests only if a behavior path is ambiguous, not for documentation-only changes.

## Files To Inspect

- `src/core.rs`
- `src/transport/h3.rs`
- `src/stealth/mod.rs`
- `src/implementations/server/mod.rs`
- `src/implementations/client/`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`

## Acceptance Criteria

- Documentation clearly states that production VPN/TUN traffic uses Core H3/MASQUE.
- Documentation clearly states that `stealth::MasqueManager` is compatibility/experimental.
- No docs claim canonical Stealth, Performance, or Anti-DPI disable the production TUN carrier.
- No code is deleted.
- Any comments added are short, English-only, and tied to real ownership boundaries.

## Implementation Result

- `docs/DOCUMENTATION.md` and `docs/MAP.md` state Core/H3/MASQUE owns the production VPN/TUN carrier.
- `stealth::MasqueManager` remains retained compatibility/experiment machinery and is not expanded.
- WebTransport cover was added as an H3 cover session only, not a competing MASQUE or VPN carrier.

## Non-Goals

- Do not replace the production H3/MASQUE path.
- Do not delete `stealth::MasqueManager`.
- Do not add Docker/K8s/Helm deployment work.
