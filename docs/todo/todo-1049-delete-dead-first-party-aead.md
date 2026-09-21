---
id: TODO-1049
title: Delete dead first-party AES-GCM and ChaCha
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1034, TODO-1035, TODO-1050]
---

# TODO-1049: Delete dead first-party AES-GCM and ChaCha

## Why

The live packet path seals with ring and, for `off` / `performance` 1-RTT payload, libaegis. The first-party AES-GCM and ChaCha implementations remain in the tree. They are the "we rolled our own" surface. They are slower than the libraries, which is why they are not the owners. Dead code still counts.

## Plan at open

The modules below were present when this task opened. They are gone. See Result.

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

- [x] Call-site inventory committed in this file's Notes before deletion.
- [x] QKey legacy test seals with ring.
- [x] Packet tests use ring fixtures.
- [x] Delete modules, reexports, and the x4 parity test or retarget it.
- [x] `cargo test -p qf-crypto --lib --offline` and packet-header tests pass.

## Acceptance

- `rg` over `crates/` and `src/` finds no `chacha20_blocks_x4`, no `struct AesGcm128`, no first-party `ChaCha20Poly1305`.
- Live seal owners unchanged: ring and libaegis only.
- Legacy QKey fixture still upgrades.

## Result

Done. Removed: `aes.rs`, `gcm.rs`, `chacha.rs`, `poly1305.rs` from `crates/qf-crypto/src/` together with `AesGcm128`, `AesHp`, `ChaCha20Poly1305`, `Aes128Ctx`, `chacha20_blocks_x4`/`x16`, and the whole `src/optimize/simd/crypto.rs` + `src/optimize/crypto/` trees. The `subtle` dependency is gone (ring owns tag comparison). The retry integrity tag now uses `aes128_gcm_tag_aad_only` backed by ring AES-128-GCM. Runtime parity targets `rt-chacha-x4-parity`, `rt-chacha-x16-parity`, and `rt-ghash-sse-parity` plus the `micro-aes-block`/`micro-aes-gcm`/`micro-chacha-x4`/`micro-ghash` scripts are deleted; `micro-crypto-all.sh` measures the surviving `sha256`/`hmac-sha256` cells. `rt-baseline-oracles`, `rt-property-suite`, `rt-security-suite`, `rt-tls-cover-cipher`, the fuzz crypto target, `examples/aead_bakeoff.rs`, and `examples/microbench.rs` run on ring/libaegis owners. qf-simd keeps only SHA-256/HMAC/varint/bitstream delegates (`qf_crypto::hkdf` stays until TODO-1050).

Verified: `cargo test -p qf-crypto --lib --offline` 59/59, packet tests 42/42 (including `retry_integrity_roundtrips_for_v1_and_v2` on the ring tag helper), QKey registry 13/13 (legacy `QFENC1` envelope seals with `RingChaCha20Poly1305` and upgrades), rt-baseline 6/6, rt-property 12/12, rt-security 26/26, rt-tls-cover 2/2, `cargo check --lib --bins --tests --examples --bench ci_regression` clean. `audit-runtime-guardrails.sh` check 4n rewritten to assert the ring/libaegis owner contract plus absence of the removed primitives.

Post-sweep reconciliation: the safety-contract inventory now passes vacuously when qf-crypto holds zero `unsafe fn` (the removed kernels owned all of them); check 4n matches the macro-generated `libaegis_owner!(LibAegis128L)` declaration; the private-control bootstrap order check follows the refactored `finalize_authenticated_assignment()` sequence; the forked-posture doc wording moved into `PrivateAeadFamily`; `src/stealth/tests.rs` asserts the current `dynamic mode requires dynamic_enabled` message; the orphaned crypto doc comment in `src/optimize/simd/mod.rs` is removed; MAP.md/DOCUMENTATION.md drop the deleted rt-parity targets and scripts from the tree. Root library 1772/1772, full `--all-targets --features rust-tests` check clean, clippy clean.

## Risks

- A hidden caller in `scripts/tests/fuzz` or `examples/microbench.rs` fails the build. The inventory step is mandatory before delete.
- Do not "fix" a test by deleting the assertion. Retarget the fixture.
