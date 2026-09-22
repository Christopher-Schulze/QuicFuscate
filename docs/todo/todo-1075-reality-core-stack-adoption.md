---
id: TODO-1075
title: Xray Reality / core-stack high-tech stealth adoption analysis
severity: LOW
phase: S
priority: P2
status: OPEN
created: 2026-09-22
depends_on: []
---

# TODO-1075: Reality / core-stack stealth adoption analysis

## Why

Xray Vision/Reality and adjacent stacks are the current frontier of
censorship-circumvention transport. Some concepts may fill real gaps in our
stealth surface; others duplicate what we already do or fail our
authenticated-tunnel model. Copying features blindly adds detection surface —
so each candidate gets a verdict with evidence, not a port.

## Candidates (initial, extend during research)

- Xray Vision / XTLS flow control (splice-style early-data cut-through).
- REALITY-style destination camouflage (borrow a real site's certificate and
  handshake vs our persona emulation).
- ShadowTLS v3 (relay a genuine TLS session as cover for a second channel).
- MASQUE CONNECT-IP / CONNECT-UDP hop composition patterns.
- uTLS/browser-fingerprint research beyond our current persona tables.
- Website-fingerprinting defenses (FRONT-style, WTF-PAD successors).
- GFW QUIC-blocking behavior research — confirm or update the current
  "residual/compute-limited" classification with fresh evidence.

## Per-candidate verdict template

- Threat model addressed (active probe, passive DPI, fingerprint DB, traffic
  analysis).
- Wire effect (what changes on the wire, byte and timing level).
- Detection surface added or removed.
- Implementation cost and ownership boundary.
- Measurement plan (how we'd prove it helps).
- Verdict: adopt / evolve (build our variant) / reject — with rationale.

## Non-goals

- No blind feature copying.
- Domain fronting stays rejected (earlier research verdict stands; re-open
  only with new evidence).
- No claim that any defense is "undetectable" — only measured properties.

## Output

- Ranked candidate table committed to this file.
- Follow-up TODOs created only for adopt/evolve verdicts.

## Acceptance

- [ ] Every candidate above has a filled verdict row.
- [ ] At least the top-2 candidates get a wire-level feasibility sketch.
- [ ] Rejected candidates record the reason, not just "no".
