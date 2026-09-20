---
id: TODO-1022
title: Reorder window never arms on the wire-FEC send path
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1015, TODO-1016, TODO-1017, TODO-1018]
---

# TODO-1022: `reorder_window_tick` is unreachable while a wire FEC profile is active

## Context

Surfaced during TODO-1021 Omega validation. Both validation runs
(60 M and 140 M UDP) reported `yield_window = 0` / `drain_entries = 0`:
no reorder window ever armed, so the ChameleonFlow reorder machinery
(TODO-1015/1016/1017) was completely inactive in that regime.

## Mechanism (verified against source)

`src/core/connection/send.rs`: `reorder_window_tick(&send_info, now)`
is invoked only inside the `else` branch taken when
`wire_profile.is_none()`. When the adaptive FEC controller commits a
wire profile (streaming GF8 since TODO-1018, or any block codec), every
packet is produced through the `if let Some(profile)` branch instead —
which classifies `bulk_only` and stamps `WirePacketMeta` but never
ticks the reorder window. Net effect: wire-FEC-active traffic cannot
arm reorder windows at all, so the stealth reorder feature silently
disables itself exactly when FEC protection is on.

The historical TODO-1017 baseline (38 % loss, `yield_window` ~320k)
ran in a regime where no wire profile was committed, which is why
windows armed there.

## Objective

Decide and implement the intended interaction between wire FEC and
ChameleonFlow reorder:

- Option A: tick the reorder window in the wire-FEC branch too, gated
  on `send_info.bulk_only` — repairs and systematic sources share the
  same emission machinery, so window holds apply to both. Check
  invariants: repairs are latency-sensitive (a held repair delays
  recovery); consider whether repair packets should bypass the
  deferral window or be excluded from `bulk_only` gating.
- Option B: declare the bypass intentional (wire-FEC sessions get
  FEC-based loss recovery instead of reorder cover) and document it —
  but then the reorder feature is de-facto unreachable under the
  product-default adaptive FEC, which is probably not intended.

Also worth checking while in the area: `bulk_only` requires no
coalesced control/stream frames on the same packet, so reorder arming
is fragile whenever H3 control data or ACKs coalesce — under clean
flow this may starve window arming even without wire FEC.

## Acceptance

- Reorder windows arm under wire-FEC-active bulk load (or an explicit,
  documented decision that they must not, with the gating made
  deliberate rather than incidental).
- Repairs are not held long enough to break the loss-recovery latency
  budget (bounded by `REORDER_HOLD_MAX_US`).
- Omega rerun shows `yield_window > 0` / `drain_entries > 0` with the
  wire profile committed, and no regression in `tun_drops`/`qtun0`.
- Unit test: wire-FEC path emits a reorder-window hold for bulk
  traffic.
