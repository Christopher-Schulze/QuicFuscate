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
- Freeze the trace corpus, train/test split, classifier, run count, and
  network impairment before evaluating any defense. Cost/effect cells record
  bytes/s, CPU per application byte, application p99 latency, and classifier
  accuracy/false-positive rate with spread. Mark an untested detection claim
  as unproven, not as a benefit.

## Acceptance

- [ ] Per-defense cost/effect table names the exact baseline/candidate
      configs, trace corpus, commit, packet parser, and at least five paired
      runs. Preserve the single wire-budget ledger and persona invariants.
- [ ] Maybenot overhead/accuracy measured on real traffic, not just the smoke
      trace.
- [ ] At least one quantified waste reduction lands without worse detection
      results outside the predeclared test variance, or each candidate gets a
      measured no-change/reject verdict. A selected implementation gets its
      own linked task and wire proof.

## Risks

- Over-optimizing stealth into detectability — the wire evidence decides,
  never the throughput number alone.

## Rollback

Per-commit revert; stealth knobs stay operator-visible.
