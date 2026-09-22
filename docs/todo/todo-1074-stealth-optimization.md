---
id: TODO-1074
title: Stealth optimization cluster
severity: MED
phase: M
priority: P2
status: OPEN
created: 2026-09-22
depends_on: [TODO-1071]
---

# TODO-1074: Stealth optimization

## Why

Stealth bytes are paid twice — on the wire and in CPU. The ledger (TODO-1052)
bounds the spend, but nobody has measured what each defense actually costs or
buys. This cluster builds the cost/effect table and cuts waste.

## Scope

- Wire-image/persona-trace overhead per mode (bytes added per second, packets
  per second emitted vs carried).
- Maybenot (TODO-1061): pad share vs machine quality; run the real WF
  overhead/accuracy measurement whose command TODO-1061 recorded.
- ChameleonFlow / Adaptive-Tamaraw / UPGen as candidate machines or shaping
  policies — evaluated for adopt/evolve/reject under TODO-1075's method.
- Timing/reorder/padding/cover budget efficiency inside the ledger cap.
- Persona fidelity per byte spent (which stealth bytes actually contribute).

## Non-goals

- Packet shape is never a runtime actuator (TODO-1060 invariant).
- No unmeasured stealth claims — every "helps" needs a wire or sim number.

## Methodology

- Omega pcaps + `tun-e2e-traffic-analysis-netns.sh` (byte-exact payload
  analysis) + the maybenot simulator harness.
- Cost/effect table per defense: bytes/s, CPU share, detection surface claim
  with its evidence class (measured / plausible / speculative).

## Acceptance

- [ ] Per-defense cost/effect table committed.
- [ ] Maybenot overhead/accuracy measured on real traffic, not just the smoke
      trace.
- [ ] At least one quantified waste reduction landed, or per-item verdicts
      explaining why the current spend is optimal.

## Risks

- Over-optimizing stealth into detectability — the wire evidence decides,
  never the throughput number alone.

## Rollback

Per-commit revert; stealth knobs stay operator-visible.
