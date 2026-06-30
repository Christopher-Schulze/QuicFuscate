---
id: TODO-433
title: InterleavedDecoder coefficient-to-packet-ID mapping bug — FEC recovery fails with interleave=1
severity: CRITICAL
phase: "G"
priority: P0
status: DONE
created: 2026-06-30
depends_on: []
---

# TODO-433: InterleavedDecoder Coefficient-to-Packet-ID Mapping Bug

## Problem

The `InterleavedDecoder` (`src/fec/internal.rs:909`) routes packets to interleaved blocks
correctly by sequence number (`seq % depth` for source, `seq & 0x0F` for repair), but the
underlying per-block decoders (`Decoder8`, `Decoder16`, `Decoder4`) assume that the source
packet IDs within a block form a **consecutive range** `(base_id - k + 1) ..= base_id`.
With interleaving, the packet IDs within each block are **non-consecutive** (spaced `depth`
apart), so this assumption is wrong and FEC recovery fails completely.

### Root Cause: The Consecutive-ID Assumption

The GF(2^8) streaming decoder (`Decoder8` in `src/fec/mod.rs:1890`) maps repair equation
coefficients to source packet IDs using this formula (appears in 8+ places):

**`unknown_ids_for`** (`src/fec/mod.rs:1994-2008`):
```rust
fn unknown_ids_for(&self, base_id: u64, coeffs: &[u8]) -> Vec<(usize, u64)> {
    coeffs.iter().enumerate().take(self.k).filter_map(|(j, &c)| {
        let sid = base_id.saturating_sub(self.k as u64 - 1) + j as u64;  // ← ASSUMES CONSECUTIVE
        if c != 0 && !self.known.contains_key(&sid) {
            Some((j, sid))
        } else {
            None
        }
    }).collect()
}
```

**`try_solve_equation`** (`src/fec/mod.rs:2010-2068`):
```rust
fn try_solve_equation(&mut self, eq: &mut Equation8) -> bool {
    for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
        let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;  // ← ASSUMES CONSECUTIVE
        if let Some((ref kdata, klen)) = self.known.get(&sid) { ... }
    }
    // ...
    let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;  // ← ASSUMES CONSECUTIVE
}
```

**`try_eliminate` (Gaussian elimination)** (`src/fec/mod.rs:2138-2145`):
```rust
for (i, eq) in self.equations.iter().enumerate() {
    for (col, sid) in unknowns.iter().enumerate() {
        let base = eq.base_id.saturating_sub(self.k as u64 - 1);  // ← ASSUMES CONSECUTIVE
        if *sid >= base && *sid < base + self.k as u64 {
            let j = (*sid - base) as usize;
            a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
        }
    }
}
```

The same pattern exists in:
- `Decoder16` (`src/fec/mod.rs:2854-2889`) — `base_id.saturating_sub(self.k as u64 - 1) + j`
- `Decoder4` (`src/fec/mod.rs:2640`) — `eq.base_id.wrapping_add(j as u64)` (different but
  equivalent consecutive assumption)
- `try_eliminate` RHS computation (`src/fec/mod.rs:2162`)

### How Interleaving Breaks the Assumption

The `InterleavedEncoder` (`src/fec/internal.rs:857-862`) distributes source packets
round-robin across `depth` blocks:

```rust
pub fn take_packet(&mut self, p: FecPacket) {
    let block_idx = self.packet_idx % self.depth;
    self.blocks[block_idx].take_packet(p);
    self.packet_idx = self.packet_idx.wrapping_add(1);
}
```

With `depth=4` and source packet IDs 0,1,2,3,4,5,6,7,8,9,10,11,...:
- Block 0 receives IDs: 0, 4, 8, 12, ... (spaced 4 apart)
- Block 1 receives IDs: 1, 5, 9, 13, ... (spaced 4 apart)
- Block 2 receives IDs: 2, 6, 10, 14, ... (spaced 4 apart)
- Block 3 receives IDs: 3, 7, 11, 15, ... (spaced 4 apart)

Each block's `block_k = k / depth`. With `k=8, depth=4`, each block has `block_k=2`.
A repair equation for Block 0 with `base_id=8` (the max source ID in the block's window)
would have coefficients for positions `j=0` and `j=1`.

The decoder computes: `sid = 8 - 2 + 1 + j = 7 + j` → `sid=7` (j=0), `sid=8` (j=1).
But the actual source IDs in Block 0's window are **0 and 4** (or 4 and 8, depending on
windowing), not 7 and 8. The coefficient-to-ID mapping is completely wrong.

### Consequence

When `QUICFUSCATE_FEC_INTERLEAVE=1` is set, FEC recovery fails with DATA LOSS. The decoder
either:
1. Looks up `known[7]` and `known[8]` — finds nothing (the real IDs are 0 and 4) → treats
   all coefficients as unknowns → cannot solve.
2. If by coincidence some IDs match, it solves for the wrong packet → corrupt data.

### Current Workaround

The E2E test suite explicitly disables interleaving (`src/fec/e2e_tests.rs:98-103`):

```rust
// Disable interleaving for E2E recovery tests. The interleaved decoder
// has a known bug where it assumes consecutive packet IDs (base_id - k + 1
// .. base_id) but interleaving distributes IDs across blocks non-consecutively.
// This is tracked as a separate TODO. With interleaving disabled, the
// decoder correctly maps repair coefficients to source packet IDs.
let interleave_off = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");
```

This means interleaving — the primary burst-loss protection mechanism — is disabled in all
tests and effectively unusable in production. Burst losses (common on wireless/mobile links)
cannot be recovered, defeating a core FEC feature.

## Goal

Fix the coefficient-to-packet-ID mapping so that interleaved FEC recovery works correctly.
With `QUICFUSCATE_FEC_INTERLEAVE=1`, FEC recovery achieves 0% data loss at 5% packet loss
(matching the non-interleaved performance). Burst losses up to `depth` consecutive packets
are fully recoverable.

## Implementation Plan

### Step 1: Add source ID map to per-block decoders

The fundamental fix: instead of assuming `sid = base_id - k + 1 + j`, each per-block decoder
must know the **actual source packet IDs** in its current window. Add a field to `Decoder8`,
`Decoder16`, and `Decoder4`:

```rust
struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoder_policy: String,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation8>,
    emit_q: VecDeque<FecPacket>,
    /// Map from coefficient index (j) to actual source packet ID.
    /// In non-interleaved mode: j → (base_id - k + 1 + j) (consecutive, implicit).
    /// In interleaved mode: j → actual source ID from the block's window.
    /// If empty, falls back to the consecutive assumption (backward compatible).
    source_id_map: Vec<u64>,
}
```

### Step 2: Populate source_id_map from source packets

When a source packet arrives via `take_packet()`, record its ID in the map:

```rust
fn take_packet(&mut self, p: FecPacket) {
    if p.is_systematic {
        // Record the actual source ID for this position
        // The position in the window is determined by arrival order within the block
        if !self.source_id_map.contains(&p.id) {
            self.source_id_map.push(p.id);
            // Keep only the last k entries (sliding window)
            if self.source_id_map.len() > self.k {
                self.source_id_map.remove(0);
            }
        }
        // ... rest of existing logic ...
    }
}
```

### Step 3: Replace consecutive-ID formula with map lookup

Replace all occurrences of:
```rust
let sid = base_id.saturating_sub(self.k as u64 - 1) + j as u64;
```

With a helper method:
```rust
#[inline]
fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
    if !self.source_id_map.is_empty() {
        // Interleaved mode: use actual source IDs from the window
        // Find the position of base_id in the map, then offset by j
        // The map stores the last k source IDs in arrival order
        // base_id corresponds to the last entry; j=0 is the first
        let map_len = self.source_id_map.len();
        if map_len > 0 {
            let base_idx = map_len - 1; // base_id is the last (max) ID
            if base_idx >= j && base_idx - j < map_len {
                return self.source_id_map[base_idx - j];
            }
        }
        // Fallback if map is incomplete
        base_id.saturating_sub(self.k as u64 - 1) + j as u64
    } else {
        // Non-interleaved mode: consecutive assumption is correct
        base_id.saturating_sub(self.k as u64 - 1) + j as u64
    }
}
```

**Important:** The `source_id_map` must be consistent with the encoder's window. The encoder
generates repair packets with `base_id = max(source IDs in window)` (see `src/fec/mod.rs:1652`:
`let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0)`). The decoder's
map must contain the same set of source IDs.

### Step 4: Update all coefficient-to-ID mapping sites

Update every site in `Decoder8` that uses the consecutive formula. Search for the pattern
`base_id.saturating_sub(self.k as u64 - 1)` and `base_id.wrapping_add(j` in `src/fec/mod.rs`
and replace each with `self.source_id_for(base_id, j)`:

1. `unknown_ids_for` (line 2000) — `sid = base_id.saturating_sub(self.k as u64 - 1) + j`
2. `try_solve_equation` (line 2016) — known subtraction loop
3. `try_solve_equation` (line 2027) — unknown counting
4. `try_solve_equation` (line 2043) — final solve for `sid`
5. `try_eliminate` (line 2140) — `base = eq.base_id.saturating_sub(self.k as u64 - 1)`
6. `try_eliminate` (line 2142) — `j = (*sid - base) as usize`
7. `try_eliminate` (line 2162) — RHS known subtraction

Apply the same fix to `Decoder16` (lines 2854-2977) and `Decoder4` (line 2640).

### Step 5: Update InterleavedDecoder to pass source IDs to blocks

The `InterleavedDecoder::take_packet` (`src/fec/internal.rs:946`) currently routes packets
to blocks and strips the block index from repair seq. It must also ensure that source
packets carry their **original** ID (not the block-local index) so the per-block decoder
can build the `source_id_map` correctly.

Verify that source packets arriving at `InterleavedDecoder::take_packet` have `p.id` set
to the original source packet ID (the global sequence number). The `LazyDecoder` wrapper
(`src/fec/internal.rs:646`) passes `p.id` through to the inner decoder, so this should
already work — but verify that the `id` field is not remapped during interleaving.

### Step 6: Update LazyDecoder to preserve source_id_map

The `LazyDecoder` (`src/fec/internal.rs:646`) wraps `DecoderVariant` and defers decoding
until loss is detected. It buffers repair packets in `pending_repairs` and flushes them
on loss detection. The `source_id_map` must be built from source packets even in lazy mode
(source packets are always forwarded to the inner decoder, line 737). Verify this works.

### Step 7: Remove the interleave-disable workaround in E2E tests

In `src/fec/e2e_tests.rs:98-103`, remove the `EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0")`
line and the `_env_guards` field. The E2E tests must now pass with interleaving **enabled**
(the production default when `QUICFUSCATE_FEC_INTERLEAVE=1`).

### Step 8: Add interleaved FEC recovery test

Add a test in `src/fec/e2e_tests.rs` that explicitly tests interleaved recovery:

```rust
#[test]
fn test_fec_recovery_with_interleave() {
    let _guard = acquire_env_lock();
    let _interleave_on = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "1");
    let mut sim = TransportSim::new(0.05, 42); // 5% loss

    // Send 1000 source packets
    for i in 0..1000 {
        sim.send_source(i, 1024);
    }

    // Drain receiver
    sim.drain_receiver();

    // Verify 0% data loss (all 1000 packets delivered, possibly out of order)
    assert_eq!(sim.delivered_count(), 1000, "FEC recovery with interleave=1 lost packets");
    assert_eq!(sim.duplicate_count(), 0, "FEC produced duplicate packets");
}
```

### Step 9: Add burst-loss interleaved recovery test

```rust
#[test]
fn test_fec_recovery_with_interleave_burst_loss() {
    let _guard = acquire_env_lock();
    let _interleave_on = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "1");
    // Simulate burst loss: drop 4 consecutive packets out of every 16
    let mut sim = TransportSim::new_burst(0.25, 4, 16, 42);

    for i in 0..1000 {
        sim.send_source(i, 1024);
    }
    sim.drain_receiver();

    // With depth=4, a burst of 4 = 1 per block = recoverable
    assert_eq!(sim.delivered_count(), 1000, "Burst loss not recovered with interleave");
}
```

## Files to Modify/Create

- `src/fec/mod.rs` — add `source_id_map: Vec<u64>` to `Decoder8`, `Decoder16`, `Decoder4`;
  add `source_id_for()` helper; replace all `base_id.saturating_sub(self.k - 1) + j` and
  `base_id.wrapping_add(j)` formulas with `source_id_for()` calls; populate `source_id_map`
  in `take_packet()`.
- `src/fec/internal.rs` — verify `InterleavedDecoder::take_packet` preserves original source
  IDs; verify `LazyDecoder` passes source IDs through to inner decoder.
- `src/fec/e2e_tests.rs` — remove `QUICFUSCATE_FEC_INTERLEAVE=0` workaround; add
  `test_fec_recovery_with_interleave` and `test_fec_recovery_with_interleave_burst_loss`.
- `src/fec/tests.rs` — add unit tests for `source_id_for()` with interleaved and
  non-interleaved maps.

## Acceptance Criteria

- [ ] `source_id_map` is populated correctly from source packet IDs in each block.
- [ ] `source_id_for(base_id, j)` returns the correct source ID for both interleaved and
      non-interleaved modes.
- [ ] All 7+ sites in `Decoder8` that used the consecutive formula are updated.
- [ ] All sites in `Decoder16` and `Decoder4` are updated.
- [ ] `QUICFUSCATE_FEC_INTERLEAVE=1` + 5% random loss: 0% data loss (1000/1000 packets).
- [ ] `QUICFUSCATE_FEC_INTERLEAVE=1` + burst loss (4 consecutive per 16): 0% data loss.
- [ ] `QUICFUSCATE_FEC_INTERLEAVE=0` (non-interleaved): still works (no regression).
- [ ] E2E tests pass with interleaving **enabled** (workaround removed).
- [ ] No duplicate packets emitted by the decoder.
- [ ] No corrupt packets (verify payload integrity with checksums in test).
- [ ] `cargo build --release` clean, `cargo clippy --lib -D warnings` green.
- [ ] All unit and integration tests pass.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| source_id_for() lookup | <5ns | Vec index (O(1)) vs current arithmetic (O(1)) |
| source_id_map push per source packet | <20ns | Vec push + occasional remove(0) |
| Memory overhead per block | <128B | Vec<u64> of max k entries (k ≤ 64 → 512B worst case) |
| FEC recovery latency (interleaved) | <2ms | Same as non-interleaved (peeling/Gaussian) |
| Burst loss recovery (depth=4) | 100% | 4 consecutive = 1 per block = recoverable |
