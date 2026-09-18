# TODO-959 - FlowShaper: lock-free history length on the jitter path

## Status
DONE

## Problem
On stealth/anti-DPI connections every outbound packet took the
`packet_history` mutex **twice**:

1. `apply_jitter` -> `jitter_range_for_traffic` locked the
   `Arc<Mutex<VecDeque<PacketInfo>>>` purely to read `history.len()`.
2. `record_and_prune` locked it again to push the new entry and prune.

Two mutex acquisitions per packet on the send hot path for what is, in
effect, a single counter read.

## Solution
`history_count: AtomicUsize` mirrors `packet_history.len()`:

- `jitter_range_for_traffic` reads it with `Relaxed` - no lock, no
  contention with the recording path.
- `record_and_prune` stores `history.len()` into the mirror once, while it
  already holds the lock after push+prune - exact by construction (it is
  the only mutator of the deque).
- `history_len()` (diagnostics/tests) reads the atomic instead of locking.

Steady-state: one mutex acquisition per packet instead of two, and the
read side can never stall behind the writer.

Semantics: identical - the same count drives the same thresholds
(burst >=32, idle <8); `Relaxed` is sufficient for a heuristic input.
Poisoned-lock behavior is unchanged (read path previously fell back to 0;
now it simply reads the last stored count - strictly more accurate).

## Verification
- `cargo test -p qf-stealth`: 127/127.
- `cargo check -p qf-stealth --all-targets`, clippy, fmt: clean.
- Omega: native check + clippy + 127/127 tests green on Linux.
