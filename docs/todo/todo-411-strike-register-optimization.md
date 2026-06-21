---
id: TODO-411
title: StrikeRegister 0-RTT anti-replay optimization
severity: LOW
phase: B
priority: P3
status: DONE
created: 2026-06-05
---

# TODO-411: StrikeRegister Anti-Replay Optimization

## Problem

`StrikeRegister::check_and_insert` (~62-94) computes SHA-256 per 0-RTT packet and uses write-lock on HashMap with O(n) `min_by_key` eviction.

## Acceptance

- Reduced CPU on 0-RTT path (ring buffer + bloom filter fronting full hash)
- Semantics unchanged: no replay accepted within TTL/window
- Existing anti-replay unit tests + rt-anti-replay pass

## Result

- Added a FIFO ring of fingerprints so capacity eviction is O(1) instead of scanning `HashMap` timestamps with `min_by_key`.
- Added an in-memory Bloom filter as a fast-negative before full-fingerprint `HashMap` lookup.
- Kept SHA-256 fingerprints as the canonical replay identity; Bloom only narrows lookup work and never accepts a replay by itself.
- Cleanup now rebuilds the ring/Bloom view from retained entries after TTL expiry.
- `max_entries = 0` is clamped to one tracked entry instead of disabling replay protection by accident.

## Files

- `src/transport/anti_replay.rs`

## Verification

- `cargo fmt --all`
- `cargo test --lib --features rust-tests anti_replay` GREEN, 11 passed.
- `cargo test --features rust-tests --test rt-anti-replay` GREEN, 13 passed.
