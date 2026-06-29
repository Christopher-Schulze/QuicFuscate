---
id: TODO-450
title: Connection migration cwnd preservation
severity: HIGH
phase: "J"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-450: Connection Migration cwnd Preservation

## Problem

When a connection migrates to a new path (e.g. WiFi → LTE), the transport
**resets the congestion window to `INITIAL_WINDOW` and zeroes
`bytes_in_flight`**. This causes a complete throughput collapse on every
migration — the connection behaves as if it just started, even though the network
path may have similar or only slightly different capacity.

Evidence:

- `src/transport/connection.rs:683-684` — inside `commit_path_validation()`:
  ```rust
  self.cwnd = INITIAL_WINDOW;
  self.bytes_in_flight = 0;
  ```
  This is the nuclear option: throw away all learned capacity information.
- `src/transport/connection.rs:17` — `MIGRATION_COOLDOWN` is hardcoded to
  `Duration::from_millis(750)`. It is not configurable.
- `src/transport/connection.rs:596` and `:648` — the cooldown gates
  re-migration, but the cwnd reset happens regardless of cooldown state.
- `src/transport/connection.rs:173-174` — `cwnd` and `bytes_in_flight` are
  single scalar fields; there is no "old path cwnd" to preserve or reference.

The correct behavior per RFC 9000 §9.4 ("Loss Detection and Congestion Control
on Path Change"): a peer SHOULD NOT reuse the old path's congestion controller
directly, but it also SHOULD NOT reset to initial. The recommended approach is
to **reduce cwnd** (e.g. halve it) and gradually probe the new path, preserving
the bytes_in_flight estimate so in-flight packets are accounted for.

## Goal

Replace the cwnd reset-to-initial with a graceful migration strategy:

1. **Preserve cwnd** — do not reset to `INITIAL_WINDOW`. Instead reduce cwnd by
   a configurable factor (default 50%) on migration.
2. **Preserve bytes_in_flight estimate** — do not zero it; the in-flight packets
   on the old path are still unacknowledged and must be tracked until ACKed or
   declared lost.
3. **Probe new path before full send rate** — use a temporary slow-start-like
   probe phase on the new path before restoring full cwnd.
4. **Make `MIGRATION_COOLDOWN` configurable** — currently hardcoded 750ms.

## Implementation Plan

### Step 1: Make migration cooldown configurable

In `src/transport/config.rs`:

- Add field `migration_cooldown_ms: u64` (default `750`).
- Add setter `set_migration_cooldown(&mut self, ms: u64)`.
- In `Config::new_with_version` (line 109+), set default to `750`.

In `src/transport/connection.rs`:

- Remove the `const MIGRATION_COOLDOWN` at line 17.
- Replace usages at lines 596 and 648 with
  `Duration::from_millis(self.config.migration_cooldown_ms)`.

### Step 2: Add migration cwnd reduction factor config

In `src/transport/config.rs`:

- Add field `migration_cwnd_reduction_factor: f32` (default `0.5` — halve cwnd).
- Add setter `set_migration_cwnd_reduction_factor(&mut self, factor: f32)`.
- Validate: factor must be in `[0.0, 1.0]`; clamp otherwise.

### Step 3: Implement graceful cwnd transition in `commit_path_validation`

In `src/transport/connection.rs`, replace lines 683-684:

```rust
// BEFORE:
self.cwnd = INITIAL_WINDOW;
self.bytes_in_flight = 0;

// AFTER:
let reduction = self.config.migration_cwnd_reduction_factor;
let new_cwnd = (self.cwnd as f32 * reduction) as usize;
self.cwnd = new_cwnd.max(INITIAL_WINDOW);
// Preserve bytes_in_flight: in-flight packets are still unacked.
// Do NOT zero — they will be accounted as ACKed or lost on the new path.
// self.bytes_in_flight remains unchanged.
```

The `.max(INITIAL_WINDOW)` floor ensures we never go below the minimum safe
window.

### Step 4: Add path-probe phase

Add a `path_probe` state flag to `Connection`:

```rust
path_probe_active: bool,
path_probe_start: Option<Instant>,
path_probe_target_cwnd: usize,  // the cwnd we'll restore to after probe
```

On migration in `commit_path_validation`:

- Set `path_probe_active = true`.
- Set `path_probe_start = Some(Instant::now())`.
- Set `path_probe_target_cwnd = old_cwnd` (the pre-reduction cwnd).
- Set `cwnd = reduced_cwnd`.

During the probe phase (checked in the send path, ~line 2370):

- Use slow-start growth (cwnd += acked_bytes per ACK) until cwnd reaches
  `path_probe_target_cwnd` or a probe timeout elapses (e.g. 2 × smoothed_RTT).
- Once probe completes, set `path_probe_active = false` and restore normal CC
  behavior.

### Step 5: Preserve bytes_in_flight correctly

`bytes_in_flight` (line 174) tracks unacknowledged sent bytes. On migration:

- Do **not** zero it. The packets sent on the old path are still in flight from
  the connection's perspective.
- When ACKs arrive for packets sent before migration, decrement
  `bytes_in_flight` normally.
- When the PTO fires for old-path packets (they won't be ACKed on the new path),
  the loss detection will reduce `bytes_in_flight` via `on_loss`.

This requires no code change beyond removing the `= 0` assignment, but the loss
detection path must correctly handle packets sent on the old 4-tuple.

### Step 6: Update loss detection for post-migration packets

In `src/transport/recovery.rs`, ensure that:

- Packets sent before migration (on the old path) that are not ACKed within
  `2 × PTO` are declared lost and `bytes_in_flight` is decremented.
- The PTO timer is armed for the new path's RTT, not the old path's.

## Files to Modify/Create

- `src/transport/config.rs` — `migration_cooldown_ms`,
  `migration_cwnd_reduction_factor` fields + setters + defaults.
- `src/transport/connection.rs` — remove `MIGRATION_COOLDOWN` const (line 17);
  update `commit_path_validation` (lines 683-684); add `path_probe_*` fields;
  add probe-phase logic in send path; update cooldown references (lines 596,
  648).
- `src/transport/recovery.rs` — ensure post-migration loss detection handles
  old-path in-flight packets.
- Tests: migration throughput test, cooldown config test, cwnd reduction test.

## Acceptance Criteria

- [ ] On migration during active data transfer, throughput drops by < 50% (not
      100% as with the current reset-to-initial).
- [ ] Throughput recovers to pre-migration levels within 2 seconds after
      migration.
- [ ] `bytes_in_flight` is preserved across migration (not zeroed) — verified by
      asserting `bytes_in_flight > 0` immediately after `commit_path_validation`.
- [ ] `cwnd` after migration equals `old_cwnd * migration_cwnd_reduction_factor`
      (clamped to `INITIAL_WINDOW` minimum).
- [ ] `migration_cooldown_ms` is configurable and respected (setting it to 0
      allows immediate re-migration; setting it to 5000 blocks re-migration for
      5s).
- [ ] The path-probe phase restores cwnd to `path_probe_target_cwnd` within
      `2 × smoothed_RTT` of migration.
- [ ] No regression in existing migration tests (path validation still works,
      PATH_CHALLENGE/RESPONSE still required).
- [ ] Unit test: migrate with `cwnd = 100_000`, verify post-migration
      `cwnd == 50_000` (default factor 0.5).
- [ ] Unit test: migrate with `cwnd = 100_000`, factor `0.25`, verify
      post-migration `cwnd == 25_000`.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Migration throughput test (tc-netem path switch) | < 45s | Measure pre/post throughput |
| Recovery time assertion | < 2s to 90% of pre-migration throughput | |
| cwnd reduction unit tests | < 2s | Multiple factor values |
| Cooldown config test | < 10s | 0ms, 750ms, 5000ms |
| Probe-phase completion test | < 5s | 2×RTT probe window |
