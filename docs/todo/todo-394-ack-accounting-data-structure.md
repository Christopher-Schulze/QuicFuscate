---
id: TODO-394
title: Replace sent_bytes_by_pn full-scan ACK accounting
severity: HIGH
phase: B
priority: P1
status: DONE
created: 2026-06-05
resolved: 2026-07-23
---

# TODO-394: ACK Accounting Data Structure Redesign

## Problem

On each ACK frame, `Connection::recv` (~1382-1408) iterates entire `sent_bytes_by_pn: HashMap<u64, usize>` and checks every PN against all ACK ranges. O(in_flight * ack_ranges) per ACK.

## Acceptance

- ACK processing scales with acked/lost PNs, not all in-flight PNs
- Loss detection semantics unchanged (packet_threshold = 3)
- Stress test with 10k+ in-flight PNs (TODO-400)
- Recovery/CC stats unchanged under equivalence test

## Fix Plan

1. Replace or augment HashMap with sorted BTreeMap keyed by PN or range-indexed structure
2. For each ACK range, walk only overlapping PNs
3. Alternative: bitmap over PN window if window bounded

## Files

- `src/transport/connection.rs`
- `src/transport/recovery.rs` (if API changes)

## Risk

Medium: loss detection bugs are subtle. Requires strong regression tests.
