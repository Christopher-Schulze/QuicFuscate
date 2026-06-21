---
id: TODO-405
title: Wire PN decode SIMD into production
severity: MEDIUM
phase: D
priority: P2
status: DONE
created: 2026-06-05
---

# TODO-405: Wire Packet Number Decode SIMD into Production

## Problem

`optimize::transport::decode_packet_number` exists with SIMD paths but is only compiled under `cfg(test)` or `rust-tests`. Production uses scalar decode in `packet.rs` (~421-438).

## Acceptance

- Prod recv path calls SIMD PN decode when CPU features available
- Parity tests prove scalar == SIMD for all PN lengths
- No change to PN semantics

## Fix Plan

1. Remove test-only gate or add prod dispatch wrapper
2. Call from `packet::decode_packet_number` or equivalent
3. Extend `optimize/transport.rs` tests to run in CI feature matrix

## Result

- `optimize::transport::decode_packet_number` is now compiled into the production build.
- `transport::packet::unprotect_and_decrypt_with_key` reconstructs the encoded packet number bytes and calls the centralized decoder after header protection is removed.
- x86_64 dispatch uses BMI2 when available; aarch64 dispatch uses SVE2, then NEON, then the scalar fallback.
- MORUS Vec-return helper methods and `Decoder8::is_complete` are now `cfg(test)` only, removing dead-code warnings from external `rust-tests` targets without changing runtime behavior.

## Verification

- `cargo fmt --all`
- `cargo check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --features rust-tests --test rt-packet-number-parity --test rt-transport-packet-headers`
- `cargo test --lib --features rust-tests` - 1161 passed
- `cargo test --workspace --all-targets`

## Files

- `src/optimize/transport.rs`
- `src/transport/packet.rs`
