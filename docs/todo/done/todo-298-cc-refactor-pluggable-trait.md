# TODO-298: Congestion Control Refactor - Pluggable CC Trait + Real Implementations + Stealth Wrapper

**Status**: COMPLETE (all 3 algorithms implemented)
**Severity**: HIGH
**Created**: 2026-03-24

## Problem

The CC selection surface is fundamentally broken:
- CLI/UI expose 5 options: `reno`, `cubic`, `bbr`, `bbr2`, `bbr2_gcongestion`
- ALL silently fall back to Stealth-BBR3 at runtime - zero actual implementation for Reno/Cubic/BBR/BBR2
- `bbr2_gcongestion` claims a Google gcongestion backend that was never built (phantom entry)
- `Ledbat` exists in the transport enum but is never exposed anywhere
- `BBR` v1 is superseded by BBR2/BBR3
- `set_cc_algorithm()` logs a warn but stores the dead value anyway - no user feedback
- UI shows a functional-looking dropdown that changes nothing

## Decisions

- **Final algorithm set**: Reno, BBR2, BBR3 (3 algorithms, all real)
- **Remove completely**: `Cubic`, `BBR` v1, `Ledbat`, `bbr2_gcongestion`
- **No external crate dependencies**: all implementations self-contained, zero quinn/quiche dependency
- **Sources**:
  - **Reno**: Self-written from RFC 6582 (~100-150 LoC, trivial AIMD)
  - **BBR2**: Ported from [quiche `src/recovery/bbr2/`](https://github.com/cloudflare/quiche/tree/master/quiche/src/recovery/bbr2) (MIT license, fork origin, ~800-1200 LoC after adaptation)
  - **BBR3**: Extracted from existing `src/transport/recovery.rs` (already implemented, ~330 LoC)
- **Stealth**: Extracted as `StealthShaper<T>` wrapper that decorates ANY CC algorithm

## Target Architecture

```
+-------------------------------------+
|     StealthShaper<T: CC>            |  <- Optional wrapper, on/off per connection
|  - Browser-profile gain tables      |
|  - Pacing jitter (Xoshiro256++)     |
|  - Flow dampening                   |
+-------------------------------------+
|    T: CongestionController          |  <- Pluggable, real implementations
|    (Reno | Bbr2 | Bbr3)            |
+-------------------------------------+
```

The stealth layer only modifies CC OUTPUT (pacing rate, timing) - it does not alter CC logic. Any standard CC algorithm can be wrapped.

### CongestionController Trait

```rust
// src/transport/cc/mod.rs
pub trait CongestionController: Send {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant);
    fn on_ack(&mut self, acked_bytes: usize, now: Instant);
    fn on_loss(&mut self, lost_bytes: usize, now: Instant);
    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant);
    fn update_rtt(&mut self, rtt: Duration);
    fn cwnd(&self) -> usize;
    fn bytes_in_flight(&self) -> usize;
    fn pacing_rate(&self) -> Option<u64>;
    fn loss_rate(&self) -> f32;
    fn set_fec_callbacks(
        &mut self,
        on_sent: Arc<dyn Fn(u64, usize) + Send + Sync>,
        on_lost: Arc<dyn Fn(u64, usize) + Send + Sync>,
    );
}
```

### Enum dispatch (hot-path performance, no vtable)

```rust
enum CcImpl {
    Reno(reno::Reno),
    Bbr2(bbr2::Bbr2),
    Bbr3(bbr3::Bbr3),
    StealthReno(StealthShaper<reno::Reno>),
    StealthBbr2(StealthShaper<bbr2::Bbr2>),
    StealthBbr3(StealthShaper<bbr3::Bbr3>),
}
```

## New files to create

| File | Lines (est.) | Source | Description |
|------|-------------|--------|-------------|
| `src/transport/cc/mod.rs` | ~80 | New | Trait definition, CongestionAlgorithm enum, factory, re-exports |
| `src/transport/cc/reno.rs` | ~150 | RFC 6582, self-written | TCP New Reno: AIMD, slow start, ssthresh |
| `src/transport/cc/bbr2.rs` | ~800-1200 | Port from quiche (MIT) | BBR v2: loss-aware model-based CC, full state machine |
| `src/transport/cc/bbr3.rs` | ~330 | Extract from recovery.rs | Existing Bbr3 struct + state machine, stealth fields stripped |
| `src/transport/cc/stealth_shaper.rs` | ~200 | Extract from recovery.rs | StealthShaper<T> wrapper, BrowserProfile enum, gain tables, jitter |
| `scripts/tests/rust/rt-cc-algorithms.rs` | ~250 | New | Tests for Reno, BBR2, BBR3 + StealthShaper |

### BBR2 Port from quiche

Source: `quiche/src/recovery/bbr2/` (MIT license, identical to ours)
- `mod.rs` - BBR2 state machine, pacing, cwnd management
- `per_ack.rs` - Per-ACK processing, bandwidth estimation
- `per_loss.rs` - Per-loss response, inflight reduction

Adaptation needed:
- Replace quiche's `Recovery` references with our `CongestionController` trait interface
- Replace quiche's `Sent` packet tracking with our `on_packet_sent`/`on_ack`/`on_loss` model
- Strip quiche-specific config paths, use our `transport::Config`
- Add license header: "Ported from Cloudflare quiche (MIT License)"

## Files to modify (31 files)

#### GROUP A: Core Transport (5 files)

**`src/transport.rs`**
- Remove enum variants: `Cubic`, `BBR`, `Ledbat` from `CongestionControlAlgorithm`
- Final enum: `Reno`, `BBR2`, `BBR3`
- Add `pub mod cc;`
- Update `StealthRuntimePolicy.cc_profile` and `StealthRuntimeDelta.cc_profile` type paths to `cc::stealth_shaper::BrowserProfile`

**`src/transport/recovery.rs`** (heaviest refactor)
- Remove: `Xoshiro256pp`, `Algorithm` enum, `Bbr3State`, `Bbr3` struct, `BrowserProfile` enum (all move to cc/)
- `Recovery` uses `CcImpl` enum dispatch internally
- Constructor: `Recovery::new(initial_cwnd, mss, algo: CongestionAlgorithm)`
- `set_stealth_mode` wraps/unwraps the inner CC in StealthShaper

**`src/transport/config.rs`**
- Default: `BBR2` -> `BBR3`
- `set_cc_algorithm()`: remove warn/fallback - all variants are real
- `set_cc_algorithm_name()`: remove "ledbat"/"cubic". Accept "reno", "bbr2", "bbr3". Map legacy "bbr"/"bbr2_gcongestion"/"cubic" -> closest match with deprecation log

**`src/transport/connection.rs`**
- Pass algorithm to Recovery constructor
- Remove `gcongestion_enabled()` test-only method

**`src/transport/packet.rs`**
- Update `recovery::BrowserProfile` path to `cc::stealth_shaper::BrowserProfile`

#### GROUP B: Cross-references for BrowserProfile path (4 files)

**`src/brain.rs`** - Update `recovery::BrowserProfile` -> `cc::stealth_shaper::BrowserProfile`
**`src/stealth/mod.rs`** - Update BrowserProfile path references
**`src/stealth/tests.rs`** - Update BrowserProfile path references
**`src/interface.rs`** - Update BrowserProfile path references

#### GROUP C: CLI / Engine (5 files)

**`src/main.rs`**
- CLI enum: Final variants: `Reno`, `Bbr2`, `Bbr3`
- Remove: `Bbr` (v1), `Bbr2Gcongestion`
- `From` impl: direct 1:1 mapping
- Default: `"bbr3"`

**`src/engine/config.rs`**
- Remove `Bbr2Gcongestion` variant, remove `Bbr` (v1), remove `Cubic`
- Final: `Reno`, `Bbr2`, `Bbr3`
- Keep serde backward compat: "cubic" -> Bbr3 with deprecation, "bbr2_gcongestion" -> Bbr2 with deprecation
- Default: `Bbr3`

**`src/engine/engine.rs`**
- Update `map_server_cc_algorithm()` mappings

**`src/implementations/client/connection.rs`**
- Remove `Bbr2Gcongestion` branch, update match arms for Reno/Bbr2/Bbr3

**`src/implementations/server/mod.rs`**
- Remove "bbr2_gcongestion" and "ledbat" and "cubic" from string match
- Accept "reno", "bbr2", "bbr3". Map legacy values with deprecation log

#### GROUP D: Frontends (6 files)

**`apps/svelte-admin/src/lib/types.ts`**
- `CcSelection`: `"reno" | "bbr2" | "bbr3" | "__custom__"`

**`apps/svelte-admin/src/lib/config-helpers.ts`**
- `CC_ALGORITHMS`: `["reno", "bbr2", "bbr3"]`
- `normalizeCcSelection`: map legacy "cubic"/"bbr"/"bbr2_gcongestion" -> appropriate value with compat

**`apps/svelte-admin/src/lib/components/panels/StealthPanel.svelte`**
- `CC_OPTIONS`: Reno (RFC 6582), BBR2 (IETF), BBR3 (Stealth)

**`apps/svelte-admin/src/lib/components/views/ConfigurationView.svelte`**
- Default state -> "bbr3"

**`apps/svelte-admin/src/lib/components/panels/ReferenceGuide.svelte`**
- Update ccItems: 3 entries (Reno, BBR2, BBR3)

**`apps/svelte-desktop/src/lib/policy-display.ts`**
- Map legacy values, remove gcongestion handling

#### GROUP E: Config files (2 files)

**`config/quicfuscate.toml`**
- Options comment: `"reno", "bbr2", "bbr3"`
- Default: `"bbr3"`

**`config/server-linux.default.toml`**
- Options comment: `"reno", "bbr2", "bbr3"`

#### GROUP F: Documentation (3 files)

**`README.md`**
- `--cc-algorithm` line: `reno|bbr2|bbr3 (default: bbr3)`
- Server example: `--cc-algorithm bbr3`
- Remove "all values result in Stealth-BBR3" note (they're all real now)
- Describe: Reno = conservative baseline, BBR2 = bandwidth-aware, BBR3 = stealth-optimized (recommended)

**`docs/DOCUMENTATION.md`**
- All cc-algorithm references: update enum lists to reno/bbr2/bbr3
- Remove all gcongestion/ledbat/cubic mentions
- Congestion Control section: describe all 3 real implementations + StealthShaper architecture
- Troubleshooting CC section: remove "parsed but overridden" note
- Add section on StealthShaper wrapper architecture

**`docs/MAP.md`**
- Add `src/transport/cc/` directory and all 5 files to inventory

#### GROUP G: Tests (8+ files)

**`scripts/tests/rust/rt-transport-config.rs`**
- Remove ledbat/cubic tests, add bbr2/bbr3 tests, test backward compat parsing

**`scripts/tests/rust/rt-transport-recovery.rs`**
- Update BrowserProfile import path, update Recovery constructor

**`scripts/tests/rust/rt-cc-algorithms.rs`** (NEW)
- Reno: slow start growth, congestion avoidance AIMD rate, loss halving cwnd
- BBR2: startup/drain/probe_bw/probe_rtt state machine, loss response, pacing rate
- BBR3: startup/drain/probebw/probertt state machine, gain cycling
- StealthShaper: jitter injection bounds per profile, profile switching, gain table application, enabled/disabled toggle

**`scripts/tests/frontend/web-admin/unit/config-helpers.test.ts`**
- Update CC_ALGORITHMS to `["reno", "bbr2", "bbr3"]`, length 3
- Update normalizeCcSelection tests for backward compat mappings

**`scripts/tests/frontend/desktop/unit/src/lib/policy-display.test.ts`**
- Update displayCcMode expected values, remove gcongestion tests

**`scripts/tests/frontend/web-admin/unit/src/components/panels/reference-guide.test.ts`**
- Update CC label assertions for Reno/BBR2/BBR3

**`Cargo.toml`**
- Add `[[test]]` entry for `rt-cc-algorithms`

**`scripts/benchmarks/suites/bench-transport.sh`**
- Update CC labels, add per-algorithm benchmark runs

## Implementation Sequence

1. Create `src/transport/cc/mod.rs` with trait + CongestionAlgorithm enum (Reno/Bbr2/Bbr3)
2. Create `src/transport/cc/reno.rs` (simplest, validates trait design)
3. Port `src/transport/cc/bbr2.rs` from quiche (adapt to trait interface)
4. Extract `src/transport/cc/bbr3.rs` from recovery.rs (strip stealth fields)
5. Extract `src/transport/cc/stealth_shaper.rs` (BrowserProfile + gains + jitter)
6. Refactor `src/transport/recovery.rs` to use CcImpl enum dispatch
7. Update `src/transport.rs` (new enum + `pub mod cc`)
8. Update `src/transport/config.rs` (real selection, new default, backward compat parsing)
9. Update `src/transport/connection.rs` (pass algo to Recovery)
10. Update CLI (`src/main.rs` - 3 variants, new default)
11. Update engine (`src/engine/config.rs`, `engine.rs` - 3 variants, serde compat)
12. Update client/server wiring (remove dead branches)
13. Update BrowserProfile cross-references (brain.rs, stealth/mod.rs, stealth/tests.rs, interface.rs, packet.rs)
14. Update frontends (types.ts, config-helpers.ts, StealthPanel.svelte, ConfigurationView.svelte, ReferenceGuide.svelte, policy-display.ts)
15. Update configs (quicfuscate.toml, server-linux.default.toml)
16. Update docs (README.md, DOCUMENTATION.md, MAP.md)
17. Create + update tests (rt-cc-algorithms.rs, rt-transport-config.rs, rt-transport-recovery.rs, frontend tests)
18. Build + clippy + full test suite

## Risks

1. **Hot-path performance**: Enum dispatch (`CcImpl`) avoids vtable overhead. Benchmark before/after with `bench-transport.sh`.
2. **BBR2 port complexity**: quiche's BBR2 uses per-packet `Sent` tracking and path-based recovery. Adapting to our `on_ack(acked_bytes)` interface requires mapping quiche's granular packet tracking to our aggregate model. This is the hardest part of the refactor.
3. **BrowserProfile namespace**: Two separate enums exist (stealth/mod.rs vs recovery.rs). Only recovery's moves to cc/stealth_shaper.rs. The stealth/mod.rs one stays untouched.
4. **TOML backward compat**: Existing configs with `cc_algorithm = "cubic"` or `"bbr2_gcongestion"` must still parse (deprecation warning in log, map to closest real algorithm).
5. **Stealth coupling**: Brain's runtime `set_cc_stealth_profile` path must remain intact through the StealthShaper wrapper.
6. **Disk space**: ~1500-2000 new LoC of Rust (BBR2 port is the bulk). Check `df -h` before cargo build.

## Completion Criteria

- [x] `Cubic`, `bbr2_gcongestion`, `Ledbat`, `BBR` v1 fully removed from all enums/UIs/configs/docs
- [x] CongestionController trait defined and implemented by Reno and BBR3
- [x] StealthShaper<T> wrapper works with Reno and BBR3
- [x] CLI: `--cc-algorithm reno|bbr2|bbr3` (default bbr3)
- [x] UI dropdowns show 3 real options (Reno/BBR2/BBR3)
- [x] Backward compat: legacy values in TOML/CLI parse with deprecation warning
- [x] All 443 lib tests pass + 13 new CC tests + updated frontend tests
- [x] clippy GREEN
- [x] README, DOCUMENTATION.md, MAP.md, configs all updated
- [x] No phantom "silently falls back" behavior (BBR2 interim fallback is documented and logged)
- [x] BBR2 implemented (standalone, IETF draft-based, ~500 LoC, 9 tests)
- [x] Dedicated `rt-cc-algorithms.rs` integration test file (16 tests)
