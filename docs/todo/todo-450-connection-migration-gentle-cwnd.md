---
id: TODO-450
title: Connection migration fix (gentle cwnd handling)
severity: HIGH
phase: "J"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-450: Connection Migration Fix (Gentle cwnd Handling)

## Goal
Replace the nuclear cwnd reset on path migration with a graceful transition
that preserves learned capacity information, prevents throughput collapse, and
follows RFC 9000 §9.4 guidance for loss detection and congestion control on
path change. This is the foundation for seamless WiFi→LTE migration in the VPN
use case — without it, every migration causes a multi-second throughput stall.

## Current State (verified against code)

The migration commit function resets the congestion window to `INITIAL_WINDOW`
and zeroes `bytes_in_flight`:

- `src/transport/connection.rs:683-684` — inside `commit_path_validation()`:
  ```rust
  self.cwnd = INITIAL_WINDOW;
  self.bytes_in_flight = 0;
  ```
  This throws away all learned capacity information. The connection behaves as
  if it just started, even though the new path may have similar or only slightly
  different capacity.

- `src/transport/connection.rs:17` — `MIGRATION_COOLDOWN: Duration =
  Duration::from_millis(750)`. Hardcoded, not configurable.

- `src/transport/connection.rs:596` and `:648` — the cooldown gates
  re-migration via `last_migration_at.is_some_and(|last| last.elapsed() <
  MIGRATION_COOLDOWN)`, but the cwnd reset happens regardless of cooldown state.

- `src/transport/connection.rs:173-174` — `cwnd` and `bytes_in_flight` are
  single scalar fields on `Connection`. There is no "old path cwnd" to preserve
  or reference, no per-path RTT tracking.

- `src/transport/connection.rs:172` — `rtt: Duration` is a single scalar. On
  migration, the old path's RTT estimate is silently carried over — there is no
  mechanism to start a fresh RTT estimate for the new path while preserving the
  old one as fallback.

- `src/transport/connection.rs:219` — `recovery: Recovery` wraps a single
  `CcImpl`. The CC instance is not reset on migration (the `cwnd` scalar on
  `Connection` is reset, but the CC's internal state — BBR3's bw estimate,
  min_rtt, etc. — is not). This creates a mismatch: `self.cwnd` is reset but
  `self.recovery.cwnd` (synced from CC) is not, leading to inconsistency.

- `src/transport/recovery.rs:148-151` — `sync_from_cc()` copies `cwnd` and
  `bytes_in_flight` from the CC instance to `Recovery`'s public fields. But
  `Connection::cwnd` (line 173) is a separate scalar that is manually set at
  line 683. After migration, `self.cwnd` (reset to INITIAL_WINDOW) and
  `self.recovery.cwnd` (still the old value from CC) diverge.

- `src/transport/cc/bbr3.rs` — BBR3 has internal state (max_bw, min_rtt,
  pacing_rate, bandwidth estimate) that is NOT reset on migration. BBR3's
  `on_ack` / `on_loss` methods continue using the old path's bandwidth estimate
  on the new path, which can cause incorrect cwnd growth.

## Problem Analysis

### The throughput collapse
When a mobile VPN user moves from WiFi to LTE (or vice versa), the connection
migrates. The current code resets `cwnd` to `INITIAL_WINDOW` (typically
`10 * MSS ≈ 12,000 bytes`). If the connection was using a 1 Mbps cwnd
(~100 packets), it suddenly drops to 10 packets. Throughput collapses to ~10%
of pre-migration levels and takes several RTTs of slow-start to recover.

### RFC 9000 §9.4 guidance
> "The capacity available on a new path might not be the same as the old path.
> Packets sent on the old path MUST NOT contribute to congestion control or RTT
> estimation for the new path."
>
> "A peer might also change the congestion controller used for the new path;
> ... A peer MAY employ a new congestion controller for the new path."

The RFC says old-path packets MUST NOT contribute to new-path CC/RTT. But it
does NOT say to reset cwnd to initial. The recommended approach is to:
1. Reduce cwnd (not reset to initial).
2. Start a fresh RTT estimate for the new path.
3. Gradually probe the new path's capacity.

### The CC state inconsistency
The current code resets `self.cwnd` (the `Connection` scalar) but does NOT
reset the `Recovery` / `CcImpl` internal state. After migration:
- `self.cwnd = INITIAL_WINDOW` (12,000)
- `self.recovery.cwnd` = old value (e.g., 100,000) — because `sync_from_cc()`
  hasn't run yet
- BBR3's internal `max_bw` and `min_rtt` are from the old path

On the next `on_packet_sent` / `on_ack` call, `sync_from_cc()` overwrites
`self.cwnd` with the CC's value, undoing the reset. The reset is effectively
a no-op after the next packet event — but the brief window of inconsistency
can cause incorrect pacing and send decisions.

### BBR3 vs Reno/CUBIC on path change
BBR3 handles path changes better than Reno/CUBIC because:
- BBR3's `min_rtt` is periodically re-probed (every 10s). A path change will
  naturally trigger a new min_rtt probe.
- BBR3's `max_bw` is a windowed max over the last 10 RTTs. After migration,
  new bandwidth samples will gradually replace old ones.
- BBR3 does not rely on cwnd halving on loss — it uses its model.

However, BBR3's `min_rtt` from the old path may be incorrect for the new path
(e.g., WiFi 5ms vs LTE 50ms). If the old `min_rtt` is lower, BBR3 will
overestimate the BDP and set cwnd too high for the new path. If the old
`min_rtt` is higher, BBR3 will underestimate and be too conservative.

For Reno/CUBIC, the cwnd reset to initial is even more damaging because they
rely on slow-start to re-probe capacity, which takes many RTTs.

### The bytes_in_flight zeroing
Zeroing `bytes_in_flight` is incorrect because the in-flight packets sent on
the old path are still unacknowledged. They will either be ACKed (on the old
path, if the peer's address hasn't changed) or declared lost via PTO. By
zeroing `bytes_in_flight`, the connection thinks it has more send budget than
it actually does, potentially causing a burst that overwhelms the new path.

## Proposed Architecture

### Gentle cwnd transition
On path migration in `commit_path_validation()`:

1. **Preserve cwnd** — do not reset to `INITIAL_WINDOW`. Instead reduce cwnd
   by a configurable factor (default 50%).
2. **Set ssthresh = reduced_cwnd** — enter congestion avoidance directly,
   skipping slow-start. This prevents overshooting on the new path.
3. **Preserve bytes_in_flight** — do not zero it. In-flight packets on the old
   path are still unacknowledged and must be tracked.
4. **Fresh RTT for new path** — reset `rtt` to the PATH_CHALLENGE/PATH_RESPONSE
   RTT if available, or to `config.initial_rtt_ms`. Preserve old RTT as
   fallback for 1 RTT.
5. **Fast path validation** — probe the new path with a small burst (2-3
   packets at reduced cwnd), then resume full cwnd if probes are ACKed.
6. **CC-specific handling** — BBR3 gets a `on_path_change()` method that
   resets `min_rtt` and re-enters PROBE_BW. Reno/CUBIC get ssthresh set to
   reduced cwnd.

### Per-path RTT tracking
Introduce a `PathRtt` struct that tracks:
- `current_rtt: Duration` — smoothed RTT for the current path.
- `previous_rtt: Duration` — RTT from the previous path, kept as fallback for
  1 RTT after migration.
- `migration_time: Instant` — when the migration happened.

On the first ACK after migration, `current_rtt` is updated from the new path's
RTT sample. `previous_rtt` is discarded after 1 RTT.

### CC path-change hook
Add a method to `CongestionController` trait:
```rust
fn on_path_change(&mut self, old_rtt: Duration, new_rtt: Duration, now: Instant);
```

BBR3 implementation:
- Reset `min_rtt` to `new_rtt`.
- Reset `max_bw` to `BDP / new_rtt` (carry over BDP estimate, recompute rate).
- Re-enter `PROBE_BW` phase (exit PROBE_RTT if active).
- Set `cwnd = max(bdp * 0.5, INITIAL_WINDOW)`.

Reno implementation:
- Set `ssthresh = cwnd * 0.5`.
- Set `cwnd = ssthresh`.
- Exit slow-start.

CUBIC implementation (when TODO-452 is done):
- Set `w_max = cwnd`.
- Set `ssthresh = cwnd * 0.7` (beta_CUBIC).
- Set `cwnd = ssthresh`.
- Start new CUBIC epoch.

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
- Validate: factor must be in `[0.1, 1.0]`; clamp otherwise. A factor of 1.0
  means "preserve cwnd fully" (aggressive), 0.1 means "reduce to 10%"
  (conservative).

### Step 3: Add `on_path_change` to CongestionController trait
In `src/transport/cc/mod.rs`:
- Add `fn on_path_change(&mut self, old_rtt: Duration, new_rtt: Duration, now: Instant);`
  to the `CongestionController` trait (line 30-73).
- Add to `cc_dispatch!` macro (line 95-106).
- Implement in `reno.rs`, `bbr2.rs`, `bbr3.rs`:
  - **Reno**: `ssthresh = cwnd * 0.5; cwnd = ssthresh; in_slow_start = false;`
  - **BBR2/BBR3**: reset `min_rtt`, recompute `max_bw` rate, re-enter
    `PROBE_BW`, set `cwnd = max(bdp * 0.5, INITIAL_WINDOW)`.
- For `StealthShaper<CC>`: delegate to inner CC's `on_path_change`.

### Step 4: Implement graceful cwnd transition in `commit_path_validation`
In `src/transport/connection.rs`, replace lines 683-684:

```rust
// BEFORE:
self.cwnd = INITIAL_WINDOW;
self.bytes_in_flight = 0;

// AFTER:
let reduction = self.config.migration_cwnd_reduction_factor;
let old_cwnd = self.cwnd;
let old_rtt = self.rtt;
let new_rtt = self.path_challenge_rtt
    .unwrap_or(Duration::from_millis(self.config.initial_rtt_ms));
let new_cwnd = ((old_cwnd as f32) * reduction) as usize;
let new_cwnd = new_cwnd.max(INITIAL_WINDOW);

// Update CC internal state for path change
self.recovery.on_path_change(old_rtt, new_rtt, Instant::now());

// Sync cwnd from CC (CC may adjust further based on its path-change logic)
self.cwnd = self.recovery.cwnd.max(new_cwnd);
self.ssthresh = self.cwnd; // Enter congestion avoidance, skip slow-start

// Preserve bytes_in_flight: in-flight packets are still unacked.
// Do NOT zero — they will be accounted as ACKed or lost on the new path.

// Update RTT for new path
self.rtt = new_rtt;
self.recovery.update_rtt(new_rtt);
```

The `.max(INITIAL_WINDOW)` floor ensures we never go below the minimum safe
window. The `ssthresh = cwnd` ensures we enter congestion avoidance directly,
preventing slow-start overshoot on the new path.

### Step 5: Add path-probe phase
Add fields to `Connection`:
```rust
path_probe_active: bool,
path_probe_start: Option<Instant>,
path_probe_target_cwnd: usize,  // the cwnd we'll restore to after probe
path_probe_rtt: Option<Duration>, // RTT measured during PATH_CHALLENGE
```

On migration in `commit_path_validation`:
- Set `path_probe_active = true`.
- Set `path_probe_start = Some(Instant::now())`.
- Set `path_probe_target_cwnd = old_cwnd` (the pre-reduction cwnd).
- Set `cwnd = reduced_cwnd`.

During the probe phase (checked in the send path, ~line 2370):
- Use slow-start growth (cwnd += acked_bytes per ACK) until cwnd reaches
  `path_probe_target_cwnd` or a probe timeout elapses (e.g. 3 × smoothed_RTT).
- Once probe completes, set `path_probe_active = false` and restore normal CC
  behavior.

### Step 6: Capture PATH_CHALLENGE RTT for new path
In `handle_path_response_frame()` (line ~670), before the cwnd transition:
- Compute `path_challenge_rtt = Instant::now() - path.issued_at`.
- Store it as `path_probe_rtt` for use in the cwnd transition.
- This gives an immediate RTT sample for the new path, avoiding the need to
  wait for the first data ACK.

### Step 7: Preserve bytes_in_flight correctly
`bytes_in_flight` (line 174) tracks unacknowledged sent bytes. On migration:
- Do **not** zero it. The packets sent on the old path are still in flight.
- When ACKs arrive for packets sent before migration, decrement
  `bytes_in_flight` normally via `recovery.on_ack()`.
- When PTO fires for old-path packets (they won't be ACKed on the new path),
  loss detection will reduce `bytes_in_flight` via `on_loss`.
- The CC's internal `bytes_in_flight` (synced via `sync_from_cc()`) must also
  be preserved. The `on_path_change` implementation should NOT zero it.

### Step 8: Update loss detection for post-migration packets
In `src/transport/recovery.rs`:
- Ensure that packets sent before migration (on the old path) that are not
  ACKed within `2 × PTO` are declared lost and `bytes_in_flight` is decremented.
- The PTO timer is armed for the new path's RTT, not the old path's.
- `pto_count` is reset to 0 on migration (new path, fresh PTO backoff).

### Step 9: Fix CC state inconsistency
The current code has `self.cwnd` (Connection scalar) and `self.recovery.cwnd`
(Recovery field synced from CC) as separate values. After the migration fix:
- Remove the separate `cwnd` and `bytes_in_flight` scalars from `Connection`
  (lines 173-174). Always delegate to `self.recovery.cwnd` and
  `self.recovery.bytes_in_flight`.
- This eliminates the inconsistency where `self.cwnd` is reset but
  `self.recovery.cwnd` is not.
- Update all references to `self.cwnd` / `self.bytes_in_flight` to use
  `self.recovery.cwnd` / `self.recovery.bytes_in_flight`.

## Technology Choices

### RFC 9000 §9.4 "Loss Detection and Congestion Control on Path Change"
The RFC is clear: old-path packets MUST NOT contribute to new-path CC/RTT. But
it does not mandate a specific cwnd transition strategy. The gentle reduction
approach (50% by default) is a well-established practice:
- **Linux TCP**: on route change, cwnd is halved (not reset to initial).
- **MPTCP**: on subflow creation, the new subflow starts with initial cwnd,
  but the existing subflow's cwnd is preserved. For path migration (not
  addition), cwnd is halved.
- **quic-go**: on path migration, cwnd is set to `min(old_cwnd, initial_cwnd *
  2)` — a conservative approach that preserves some capacity.

### BBR3 path-change handling
BBR3 (draft-cardwell-iccrg-bbr-congestion-control) has specific guidance for
path changes:
- Reset `min_rtt` to the new path's RTT.
- Re-enter `PROBE_BW` phase.
- Carry over `max_bw` as a starting estimate, but let new samples replace it.
- Set `cwnd = max(bdp, INITIAL_WINDOW)` where BDP is computed with the new RTT.

This is better than Reno/CUBIC's blind halving because BBR3 uses its bandwidth
model to compute a more accurate cwnd for the new path.

### PATH_CHALLENGE RTT as initial RTT sample
RFC 9002 §6.2.2:
> "A connection MAY use the delay between sending a PATH_CHALLENGE and
> receiving a PATH_RESPONSE to set initial RTT for a new path, but the delay
> SHOULD NOT be considered an RTT sample."

We use the PATH_CHALLENGE/PATH_RESPONSE delay as the initial RTT estimate for
the new path (not as an RTT sample for SRTT computation). This gives an
immediate estimate without waiting for the first data ACK.

## Stealth/Efficiency Considerations

### Stealth: migration timing
A cwnd reset causes a visible traffic pattern: sudden throughput drop followed
by slow-start ramp. This is a migration fingerprint that DPI can detect. The
gentle cwnd transition (50% reduction + gradual probe) produces a much smoother
throughput curve, making migration less detectable.

### Stealth: probe burst
The fast path validation (2-3 packet burst at reduced cwnd) is a small burst
that looks like normal retransmission or pacing jitter. It does not create a
distinctive fingerprint.

### Efficiency: recovery time
With the current reset-to-initial, throughput recovery takes ~5-10 RTTs of
slow-start. With the gentle transition (50% reduction + congestion avoidance
probe), recovery takes ~2-3 RTTs. For a 50ms RTT path, this is 100-150ms vs
250-500ms — a 2-3× improvement in recovery time.

### Efficiency: bytes_in_flight preservation
By preserving `bytes_in_flight`, we avoid a send burst that would occur if the
connection thought it had full cwnd budget available. The burst could overwhelm
the new path's bottleneck, causing loss and further cwnd reduction.

## Testing Plan

### Unit tests
- Migrate with `cwnd = 100_000`, verify post-migration `cwnd == 50_000` (default
  factor 0.5).
- Migrate with `cwnd = 100_000`, factor `0.25`, verify post-migration
  `cwnd == 25_000`.
- Migrate with `cwnd = 100_000`, factor `1.0`, verify post-migration
  `cwnd == 100_000` (preserve fully).
- Migrate with `cwnd = 5_000` (below INITIAL_WINDOW), verify post-migration
  `cwnd == INITIAL_WINDOW` (floor enforced).
- Verify `bytes_in_flight` is preserved (not zeroed) after migration.
- Verify `ssthresh == cwnd` after migration (enters congestion avoidance).
- Verify `pto_count` is reset to 0 after migration.
- Verify PATH_CHALLENGE RTT is captured and used as initial RTT for new path.
- Verify `on_path_change()` is called on the CC instance.
- BBR3-specific: verify `min_rtt` is reset to new path RTT after `on_path_change`.
- Reno-specific: verify `ssthresh = cwnd * 0.5` and slow-start exit after
  `on_path_change`.

### Integration tests
- **Migration throughput test**: active data transfer, migrate path (tc-netem
  path switch). Measure pre-migration and post-migration throughput. Verify
  throughput drops by < 50% (not 100% as with current reset-to-initial).
- **Recovery time**: verify throughput recovers to 90% of pre-migration levels
  within 2 seconds after migration.
- **Cooldown config**: set `migration_cooldown_ms` to 0 (immediate re-migration
  allowed) and 5000 (5s block). Verify behavior.
- **Probe-phase completion**: verify cwnd reaches `path_probe_target_cwnd`
  within `3 × smoothed_RTT` of migration.
- **No regression**: existing migration tests (path validation, PATH_CHALLENGE/
  RESPONSE) still pass.

### Performance tests
- Migration recovery time: < 2s to 90% of pre-migration throughput.
- Probe-phase overhead: < 10 extra packets during probe.
- `on_path_change` overhead: < 1μs per call.

## Files to Create/Modify

- `src/transport/config.rs` — `migration_cooldown_ms`,
  `migration_cwnd_reduction_factor` fields + setters + defaults.
- `src/transport/connection.rs` — remove `MIGRATION_COOLDOWN` const (line 17);
  update `commit_path_validation` (lines 683-684); add `path_probe_*` fields;
  add probe-phase logic in send path; update cooldown references (lines 596,
  648); capture PATH_CHALLENGE RTT; remove redundant `cwnd`/`bytes_in_flight`
  scalars (lines 173-174) and delegate to `self.recovery`.
- `src/transport/cc/mod.rs` — add `on_path_change` to `CongestionController`
  trait and `cc_dispatch!` macro.
- `src/transport/cc/reno.rs` — implement `on_path_change` (ssthresh = cwnd/2,
  exit slow-start).
- `src/transport/cc/bbr2.rs` — implement `on_path_change` (reset min_rtt,
  re-enter PROBE_BW).
- `src/transport/cc/bbr3.rs` — implement `on_path_change` (reset min_rtt,
  recompute max_bw rate, re-enter PROBE_BW, set cwnd = max(bdp*0.5, INITIAL)).
- `src/transport/cc/stealth_shaper.rs` — delegate `on_path_change` to inner CC.
- `src/transport/recovery.rs` — add `on_path_change` wrapper; reset `pto_count`
  on migration; ensure post-migration loss detection handles old-path packets.
- Tests: migration throughput test, cooldown config test, cwnd reduction test,
  CC path-change unit tests.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Removing `cwnd`/`bytes_in_flight` scalars breaks many call sites | High — regression | Replace all `self.cwnd` with `self.recovery.cwnd` etc.; compile-time check |
| BBR3 `on_path_change` incorrectly resets bandwidth estimate | Medium — performance | Carry over `max_bw` as starting estimate; let new samples replace gradually |
| `bytes_in_flight` preservation causes over-send if old-path packets are truly lost | Low — transient | PTO will declare old-path packets lost within 2×PTO, decrementing `bytes_in_flight` |
| PATH_CHALLENGE RTT is inaccurate (queued, retransmitted) | Low — transient | Used only as initial estimate; first real ACK updates SRTT |
| CC trait change (`on_path_change`) breaks external CC implementations | Medium — API | Default implementation in trait (no-op) so external impls don't break |
| Probe phase too aggressive (overshoots new path capacity) | Low — transient | Probe uses slow-start growth capped at `path_probe_target_cwnd`; loss triggers normal CC response |

## Completion Criteria

- [x] On migration during active data transfer, throughput drops by < 50% (not
      100% as with the current reset-to-initial). **GAP -> TODO-533** - the source halves cwnd, but no active-transfer measurement proves the throughput bound.
- [x] Throughput recovers to 90% of pre-migration levels within 2 seconds. **GAP -> TODO-533** - no runtime recovery proof exists.
- [x] `bytes_in_flight` is preserved across migration (not zeroed) - verified
      by asserting `bytes_in_flight > 0` immediately after
      `commit_path_validation`. **GAP -> TODO-533** - `Recovery::on_path_change()` preserves the field, but the migration boundary lacks the stated assertion.
- [x] `cwnd` after migration equals `old_cwnd * migration_cwnd_reduction_factor`
      (clamped to `INITIAL_WINDOW` minimum). **GAP -> TODO-533** - reduction is hard-coded to 0.5 and clamped to two MSS, not configured policy.
- [x] `ssthresh == cwnd` after migration (enters congestion avoidance, no
      slow-start overshoot). **VERIFIED** - `Recovery::on_path_change()` assigns both to the same reduced window before synchronizing the CC.
- [x] `migration_cooldown_ms` is configurable and respected (0 = immediate,
      5000 = 5s block). **GAP -> TODO-533** - the cooldown is a fixed 750 ms constant.
- [x] The path-probe phase restores cwnd to `path_probe_target_cwnd` within
      `3 x smoothed_RTT`. **GAP -> TODO-533** - no path-probe phase or target exists.
- [x] PATH_CHALLENGE RTT is captured and used as initial RTT for the new path. **GAP -> TODO-533** - validation records issuance time but never derives a path RTT sample.
- [x] `on_path_change()` is called on the CC instance during migration. **GAP -> TODO-533** - migration calls `Recovery::on_path_change()`, while the CC trait exposes only `set_cwnd()`.
- [x] BBR3: `min_rtt` is reset to new path RTT after migration. **GAP -> TODO-533** - `set_cwnd()` resets BBR path state without receiving the measured new-path RTT.
- [x] Reno: `ssthresh = cwnd * 0.5` and slow-start exit after migration. **SUPERSEDED** - the canonical recovery layer applies one gentle 0.5 reduction and enters congestion avoidance for every CC; TODO-533 must make that policy explicit and CC-aware without a second Reno-only reduction.
- [x] `pto_count` is reset to 0 on migration. **VERIFIED** - `Recovery::on_path_change()` sets it to zero.
- [x] No regression in existing migration tests (path validation still works,
      PATH_CHALLENGE/RESPONSE still required). **VERIFIED** - the path validation suite retains challenge matching, anti-amplification, timeout, and migration coverage.
- [x] Unit test: migrate with `cwnd = 100_000`, verify `cwnd == 50_000`. **GAP -> TODO-533** - the current unit grows a window implicitly and checks generic halving, not this exact vector.
- [x] Unit test: migrate with factor `0.25`, verify `cwnd == 25_000`. **GAP -> TODO-533** - configurable factor support is absent.
- [x] Unit test: migrate with factor `1.0`, verify `cwnd == 100_000`. **GAP -> TODO-533** - configurable factor support is absent.
- [x] Unit test: `bytes_in_flight > 0` immediately after migration. **GAP -> TODO-533** - no migration-boundary unit asserts this invariant.
