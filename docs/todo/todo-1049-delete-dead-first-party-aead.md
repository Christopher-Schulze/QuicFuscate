---
id: TODO-1049
title: Delete dead first-party AES-GCM and ChaCha
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1034, TODO-1035, TODO-1050]
---

# TODO-1049: Delete dead first-party AES-GCM and ChaCha

## Why

The live packet path seals with ring and, for `off` / `performance` 1-RTT payload, libaegis. The first-party AES-GCM and ChaCha implementations remain in the tree. They are the "we rolled our own" surface. They are slower than the libraries, which is why they are not the owners. Dead code still counts.

## Current code

Live owners, do not touch except call-site updates:

- `RingAesGcm128`, `RingAesHp` for Initial, handshake, header protection, and stealth 1-RTT.
- libaegis for `off` and `performance` post-auth payload.
- `RingChaCha20Poly1305` for TLS-cover records and QKey registry encrypt/decrypt, including legacy `QFENC1` open (`src/implementations/server/qkey_registry_storage.rs` `decrypt`).

Dead or test-only:

- `crates/qf-crypto/src/lib.rs` modules `aes`, `gcm`, `chacha`, `poly1305`, and types `AesGcm128`, `ChaCha20Poly1305`.
- `src/optimize/simd/crypto.rs` `chacha20_blocks_x4` and the reexport in `src/optimize/crypto/mod.rs`. Callers: `examples/microbench.rs`, `src/optimize/simd/tests.rs`, `scripts/tests/rust/rt-chacha-x4-parity.rs`. Not the packet path.
- QKey test `legacy_envelope_is_authenticated_and_upgraded_without_plaintext_leakage` seals with `ChaCha20Poly1305::new` and then expects ring to open it.

HKDF stays until TODO-1050 lands. This task depends on that so packet-key derivation is not left calling a module that is about to move. AES/ChaCha deletion can proceed once no production function in `aes`/`gcm`/`chacha` is required by `quic_kdf`. If `quic_kdf` does not call them, deletion can start immediately and TODO-1050 stays independent. Verify before deleting `hkdf.rs`.

## Target

- Those modules and `chacha20_blocks_x4` are gone.
- The legacy-envelope test seals with `RingChaCha20Poly1305` and still proves ring can open `QFENC1`.
- Packet tests in `src/transport/packet/tests.rs` that construct `AesGcm128` and `AesHp` use the ring types.
- Microbench and `rt-chacha-x4-parity.rs` either disappear or call ring, not a private permutation.
- `cargo test -p qf-crypto --lib` and the packet tests pass.
- No behavior change on the wire.

## Non-goals

- Do not remove ring, libaegis, or rustls.
- Do not remove HKDF in this task if TODO-1050 has not switched callers. If a symbol is shared, stop and finish 1050 first.
- No new SIMD ChaCha.

## Design

1. `rg` every `AesGcm128`, `AesHp::`, `ChaCha20Poly1305::`, `chacha20_blocks_x4`, `crate::crypto::aes`, `qf_crypto::chacha`, `poly1305::`.
2. Retarget tests to ring. The legacy test must still emit magic `QFENC1`, the same nonce layout, and ciphertext ring will open. If first-party and ring ciphertexts differ, the test is wrong; ring is the compatibility owner.
3. Delete the modules and the optimize reexport.
4. Fix `lib.rs` `pub mod` and any `crypto` prelude exports.
5. Confirm `examples/aead_bakeoff.rs` does not need the deleted types (bakeoff owners are ring, aws-lc feature, libaegis).

## Sub-Tasks

- [ ] Call-site inventory committed in this file's Notes before deletion.
- [ ] QKey legacy test seals with ring.
- [ ] Packet tests use ring fixtures.
- [ ] Delete modules, reexports, and the x4 parity test or retarget it.
- [ ] `cargo test -p qf-crypto --lib --offline` and packet-header tests pass.

## Acceptance

- `rg` over `crates/` and `src/` finds no `chacha20_blocks_x4`, no `struct AesGcm128`, no first-party `ChaCha20Poly1305`.
- Live seal owners unchanged: ring and libaegis only.
- Legacy QKey fixture still upgrades.

## Risks

- A hidden caller in `scripts/tests/fuzz` or `examples/microbench.rs` fails the build. The inventory step is mandatory before delete.
- Do not "fix" a test by deleting the assertion. Retarget the fixture.
