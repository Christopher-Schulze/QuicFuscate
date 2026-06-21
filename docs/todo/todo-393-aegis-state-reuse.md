---
id: TODO-393
title: Reuse AEGIS cipher state across packets
severity: MEDIUM
phase: A
priority: P1
status: OPEN
created: 2026-06-05
---

# TODO-393: AEGIS Cipher State Reuse Across Packets

## Problem

`Aegis128LAead::seal_with_u64_counter` / `open_with_u64_counter` rebuild cipher state via `Aegis128L::new` every packet. In-place encrypt/decrypt exists but state init repeats ~8 AES rounds per PN.

## Acceptance

- Persistent state in `Aegis128LAead` (and X4/X8 variants if applicable)
- Only nonce/counter updated per packet
- Differential tests: output identical to current implementation
- Bench shows reduced seal/open CPU (TODO-399 or crypto bench)

## Fix Plan

1. Store mutable `Aegis128L` state in AEAD struct
2. Update counter/nonce fields per `seal`/`open`
3. Verify thread-safety: one AEAD instance per connection direction (existing model)

## Files

- `src/crypto/aegis.rs`
- `src/transport/packet.rs` (if install path changes)
