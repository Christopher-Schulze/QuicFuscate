# TODO-141: 0-RTT Early Data Lacks Replay Protection

## Status
**COMPLETE** (2026-03-20)

## Severity
**MEDIUM** (was CRITICAL before implementation)

## Summary
Full 0-RTT anti-replay protection implemented via SHA-256 strike register with TTL eviction, capacity bounds, configurable max_early_data_size, and telemetry counters. 0-RTT is now safely re-enabled with one-round-trip latency savings on reconnect.

## What Was Implemented
1. **Strike Register** (`src/transport/anti_replay.rs` - NEW):
   - `StrikeRegister` with `RwLock<HashMap<[u8; 32], Instant>>` for thread-safe deduplication
   - `compute_fingerprint(dcid, scid, payload) -> [u8; 32]` via SHA-256
   - `check_and_insert()` - atomic check+insert, returns false on replay
   - `cleanup()` - rate-limited TTL sweep (configurable interval)
   - Capacity eviction: oldest entry removed when `max_entries` reached
   - 9 unit tests covering insertion, duplication, TTL expiry, capacity, cleanup, determinism

2. **Configuration** (`src/engine/config.rs` + `config/quicfuscate.toml`):
   - `AntiReplaySection`: enabled (default: true), max_ticket_age_secs (10), max_entries (100,000), max_early_data_size (16384)
   - Validation warning if 0-RTT enabled without anti-replay

3. **Transport Integration** (`src/transport/config.rs` + `src/transport/connection.rs`):
   - `strike_register: Option<Arc<StrikeRegister>>` on Config and Connection
   - Anti-replay gate in `Connection::recv()` after PN dedup, before frame parsing
   - Silent discard on replay (client falls back to 1-RTT automatically)

4. **Server Wiring** (`src/implementations/server/mod.rs`):
   - Shared `Arc<StrikeRegister>` created at server startup
   - Housekeeping tick calls `cleanup()` periodically

5. **TLS Fix** (`src/qftls.rs`):
   - Replaced hardcoded `max_early_data_size = 0xffffffff` with configurable `AtomicU32` (default: 16384)

6. **Telemetry** (`src/optimize/telemetry.rs`):
   - `ZERO_RTT_ACCEPT_TOTAL` and `ZERO_RTT_REPLAY_REJECT_TOTAL` counters

7. **0-RTT Re-enabled** in `config/quicfuscate.toml` (`enable_0rtt = true`)

## Acceptance Criteria - All Met
- 0-RTT data protected against replay attacks via strike register
- Replayed 0-RTT packets silently rejected (client falls back to 1-RTT)
- Ticket age validation enforced via TTL eviction
- Configurable anti-replay parameters ([anti_replay] config section)
- 9 unit tests demonstrate replay rejection, TTL, capacity, cleanup
- Legitimate 0-RTT connections unaffected (1-RTT path has zero overhead)

## Verification
- `cargo fmt --all` - clean
- `cargo clippy --workspace --all-targets -- -D warnings` - 0 warnings
- `cargo test --workspace --all-targets` - 404 passed, 0 failed (including 9 new anti_replay tests)

## Files Modified
- `src/transport/anti_replay.rs` (NEW - StrikeRegister + 9 tests)
- `src/transport.rs` (module wiring + re-exports)
- `src/transport/config.rs` (strike_register field + setter)
- `src/transport/connection.rs` (strike_register field + recv() gate)
- `src/engine/config.rs` (AntiReplaySection + validation)
- `src/implementations/server/mod.rs` (runtime wiring + housekeeping)
- `src/qftls.rs` (configurable max_early_data_size)
- `src/optimize/telemetry.rs` (0-RTT counters)
- `config/quicfuscate.toml` ([anti_replay] section + 0-RTT re-enabled)
