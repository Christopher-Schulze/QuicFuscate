---
id: TODO-1073
title: FEC optimization cluster
severity: MED
phase: M
priority: P1
status: OPEN
created: 2026-09-22
depends_on: [TODO-1071]
---

# TODO-1073: FEC optimization

## Why

FEC is the loss-resistance layer and one of the highest CPU consumers per
byte. TODO-899 landed multi-RHS elimination; the remaining costs — encode
parallelism, matrix build, repair scheduling under the wire budget — are
unmeasured since the rebuild.

## Scope

- Sliding-window/streaming GF(2^8) encode path (TODO-924/936/964 relate).
- Decoder matrix construction and elimination costs beyond multi-RHS.
- Repair-ratio cost/benefit under netem loss profiles (1/5/10/25%).
- Block-size and window selection vs observed loss burstiness.
- Decode-under-load stability (no unbounded queues, no priority inversion).

## Non-goals

- No codec-family change (GF8 stays; GF16 kernels are TODO-907/908's lane).
- No correctness tradeoffs — recovery guarantees unchanged.

## Methodology

- Omega `netem` loss profiles on the netns e2e harness; scripted loss
  patterns, not anecdotes.
- Criterion cells: encode MB/s, decode MB/s, elimination ms at K=8/16,
  recovery success rate per loss profile.
- Run the current `qf-fec` suite and the relevant live recovery gates at the
  same revision; never use a historical test count as a current pass claim.

## Acceptance

- [ ] Record same-host encode/decode throughput and CPU per recovered byte at
      K=8/16 with at least five repetitions, exact features, payload sizes,
      commit, and median/spread against TODO-1071.
- [ ] Record recovery success, p99 decode latency, application goodput, and
      repair bytes for 1/5/10/25% loss crossed with the current configured
      repair ratios. Keep the current wire-budget cap and fail-closed decoder
      behavior under every candidate.
- [ ] At least one measured encode or decode win landed, or a documented
      no-change verdict tied to a measured cost/effect cell for every inspected
      path. Give each selected fix a linked task and its own proof.

## Risks

- Parallel encode can starve single-core Omega — measure concurrency levels,
  default conservatively.

## Rollback

Per-commit; failed cells revert with recorded numbers.
