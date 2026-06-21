---
id: TODO-407
title: Enum AEAD dispatch instead of Box dyn
severity: LOW
phase: B
priority: P3
status: DONE
created: 2026-06-05
---

# TODO-407: Enum AEAD Dispatch in CryptoContext

## Problem

`CryptoContext` stores `Box<dyn AeadSeal>` / `Box<dyn AeadOpen>`. Vtable dispatch every 1-RTT packet.

## Acceptance

- Enum dispatch (`AegisL | AegisX4 | AegisX8 | Morus`) with compile-time or match dispatch
- No performance regression on small packets (measure)
- All crypto differential tests pass

## Result

- Added `DataAead` enum wrapping `Aegis128L`, `Aegis128X4`, `Aegis128X8`, and `Morus`.
- Added `PacketAeadSeal` / `PacketAeadOpen` wrappers. Normal data-plane 0-RTT/1-RTT keys use the enum `Data` arm. Rustls-provided packet keys use the explicit `Dynamic` arm.
- Changed `CryptoContext` 0-RTT/1-RTT AEAD slots and previous-read-key window to store the packet wrappers instead of raw boxed trait objects.
- Kept Initial/Handshake AES-GCM and public benchmark/test selector APIs boxed where they are not the packet hot path.
- Measured the small 1-RTT packet path with Criterion: `connection_1rtt_send_recv/payload_256B` = `32.010-43.874 us`, median `36.533 us`, throughput `11.129-15.254 MiB/s`.
- Verification:
  - `cargo fmt --all`
  - `cargo check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --lib --features rust-tests data_aead`
  - `cargo test --features rust-tests --test rt-packet-number-parity --test rt-transport-packet-headers`
  - `cargo test --workspace --all-targets`
  - `cargo bench --features benches --bench ci_regression -- connection_1rtt_send_recv/payload_256B --sample-size 10 --warm-up-time 1 --measurement-time 2`

## Files

- `src/transport/packet.rs`
- `src/crypto/mod.rs`
- `src/qftls.rs`
