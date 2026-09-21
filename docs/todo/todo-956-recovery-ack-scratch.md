---
id: TODO-956
title: Recovery ACK path: reuse scratch vectors instead of per-ACK allocations
status: DONE
created: 2026-09-18
---

# TODO-956 - Recovery ACK path: reuse scratch vectors instead of per-ACK allocations

## Status
DONE

## Problem
`Recovery::on_ack_received` runs once per inbound ACK frame on the connection
hot path (`transport/connection/recv.rs`). Each call allocated up to three
heap vectors for bookkeeping that was only ever iterated, never consumed:

1. `newly_acked: Vec<SentPacket>` - collected acknowledged packets via
   `drain_range`, then sorted and walked for RTT sampling, persistent
   congestion and CC accounting. Fresh allocation per ACK frame.
2. `detect_lost_packets` allocated `lost_pns: Vec<u64>` **and**
   `lost: Vec<SentPacket>` on every invocation - from both the ACK path and
   the loss-detection-timeout path.
3. `finish_ack_loss_accounting` took `newly_acked` by value, so the vector
   (and its capacity) was dropped at the end of every ACK.

`SentPacket` is ~56 bytes; a busy connection ACKs thousands of frames per
second, so each ACK paid `alloc + move + free` for ~56-byte elements purely
for scratch space.

## Solution
Persistent scratch buffers on `Recovery`, moved out (`mem::take`) while in
use so `&mut self` calls stay borrow-clean, then moved back:

- `acked_scratch: Vec<SentPacket>` - `on_ack_received` takes it into
  `newly_acked`, clears, drains ranges into it, sorts (ordering semantics
  unchanged), and passes `&newly_acked` to `finish_ack_loss_accounting`
  (signature `Vec<SentPacket>` -> `&[SentPacket]` - all uses were
  iteration/length only). Restored to the field afterwards.
- `lost_scratch: Vec<SentPacket>` - `detect_lost_packets` now takes
  `lost: &mut Vec<SentPacket>` out-param; both call sites
  (`finish_ack_loss_accounting`, `on_loss_detection_timeout`) take the
  scratch out, fill it, and restore it before returning.
- `lost_pn_scratch: Vec<u64>` - same take/clear/restore pattern inside
  `detect_lost_packets` for the lost packet-number prefix.

Steady state: zero allocations in ACK/loss bookkeeping (capacity persists).
Ordering, RTT sampling, persistent-congestion, packet-space and path-epoch
semantics are unchanged; `AckOutcome` fields still own their vectors.

## Verification
- `cargo test -p qf-transport-recovery`: 50/50 pass (ACK ordering, loss
  thresholds, persistent congestion, PTO - semantics covered).
- `cargo check -p qf-transport-recovery --all-targets`, `cargo clippy`,
  `cargo fmt --check`: clean.
- Omega: native `cargo check` + `cargo clippy -p qf-transport-recovery
  --all-targets` + `cargo test -p qf-transport-recovery` all green on Linux.
