---
id: TODO-950
title: Per-datagram `format!("{:?}")` for snapshot stealth mode -> `&'static str`
status: DONE
created: 2026-09-18
---

# TODO-950 - Per-datagram `format!("{:?}")` for snapshot stealth mode -> `&'static str`

## Status
DONE

## Problem
`process_live_server_client_datagram` built `format!("{:?}", conn.stealth_mode())`
for every inbound datagram - a heap `String` plus enum formatting per packet,
only so `ClientSnapshot` could store the mode label. The mode changes at most
once per connection; the allocation ran millions of times.

Adjacent breakage found while verifying: `qf-stealth`'s own test suite could not
compile - its tests call `EnvSnapshot::from_pairs`, which is gated behind
qf-common's `rust-tests` feature. Every sibling crate that uses test helpers
enables the feature unconditionally on the dependency; qf-stealth's dep lacked
it, so `cargo test -p qf-stealth` failed with 5 E0599 errors.

## Solution
- `StealthMode::as_str()` returns the static variant name (identical to the
  `Debug` output: `Off`/`Performance`/`Stealth`/`AntiDpi`/`Manual`/`Intelligent`).
- `ClientSnapshot.stealth_mode` is now `&'static str`; `new`/`new_at`/
  `record_bytes_in` take `&'static str`; `to_client_info` materializes the
  `String` once per admin query instead of per datagram.
- `record_live_snapshot_bytes_in` accepts `&'static str`; the hot-path caller
  passes `conn.stealth_mode().as_str()` - zero allocation, zero formatting.
- `crates/qf-stealth/Cargo.toml`: `qf-common` dep gains `features =
  ["rust-tests"]` matching the repo convention - repairs the broken test suite.

## Verification
- `cargo check --lib --all-targets` clean locally and natively on Omega.
- `cargo clippy --lib --all-targets` clean; `cargo fmt` clean.
- snapshot tests 17/17 (local + Omega); qf-stealth suite **127/127** (was: did
  not compile) on both platforms.

## Files
- `crates/qf-stealth/src/config.rs` - `StealthMode::as_str`.
- `crates/qf-stealth/Cargo.toml` - `rust-tests` on qf-common dep.
- `src/implementations/server/admin.rs` - `ClientSnapshot` field/signatures.
- `src/implementations/server/live_auth.rs` - snapshot callsite.
