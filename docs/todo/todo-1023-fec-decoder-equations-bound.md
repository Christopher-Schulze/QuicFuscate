---
id: TODO-1023
title: FEC decoder equation matrices grow unbounded under adversarial repairs
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1018]
---

# TODO-1023: Bound `Decoder8`/`Decoder16` equation storage (memory-DoS hardening)

## Context

Surfaced during the TODO-1018 sliding-window implementation. The lazy
layer (`lazy.rs`) bounds admission: `pending_repairs` is capped at 64
and `pending_sources`/`pending_covers` are bounded. But once a repair
is admitted into the inner field decoder (`Decoder8::equations` /
`Decoder16` equivalent), its row lives in the solver matrix with **no
explicit bound** — equations only leave when they solve or the window
rotates.

## Mechanism

`Decoder8::take_packet` appends each admitted repair's coefficient row
to `self.equations` (plus the sparse `pending_covers` maps). Rows are
removed by Gaussian elimination progress, but a stream of
well-formed-but-unsolvable repairs (distinct anchors, sources the
attacker knows are missing) accumulates rows indefinitely for the life
of the receive window. Per-row cost is `k` field elements + payload
symbol (`symbol_size` bytes when seeded), so a hostile peer can grow
receiver memory at repair rate. With sliding windows (TODO-1018) the
coding window is persistent — there is no periodic `clear_window`
boundary that previously flushed stale rows as a side effect.

Note: repairs are authenticated by the QUIC channel itself, so this is
a malicious-peer / corrupted-peer surface, not a passive-observer one.
Severity medium, not critical.

## Objective

Introduce an explicit equation bound per receive window:

- Hard cap on `equations.len()` (suggested: `k * depth * 2` or a
  fixed budget like 128 rows — enough for legitimate k+x redundancy
  headroom, far below memory-risk territory).
- Eviction policy on overflow: prefer dropping the **oldest
  unsolved** row (FIFO) — a row that never solved contributes the
  least; alternatively drop the row with the lowest coverage overlap
  with the current delivery frontier (least useful first).
- Count evictions in telemetry (new counter, e.g.
  `fec_decoder_equation_evictions_total`) so adversarial pressure is
  observable.
- Apply symmetrically to `Decoder8`, `Decoder16`, and check the
  fountain/interleaved decoder paths for equivalent unbounded
  collections (`pending_covers` maps are already bounded — verify).
- Verify sliding-mode interaction: in sliding mode equations legit-
  imately live longer (persistent window), so the cap must scale with
  `k * depth` rather than block size alone.

## Acceptance

- Unit test: flood a decoder with >cap unsolvable repairs -> memory
  bounded, oldest/least-useful rows evicted, eviction counter
  increments, legitimate recovery unaffected.
- Unit test: sliding-mode decoder under cap still recovers a burst
  loss of `n-k` sources (cap must not break the TODO-1018 recovery
  path).
- No regression in the 104 qf-fec tests; clippy/fmt clean.
