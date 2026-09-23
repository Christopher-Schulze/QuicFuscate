---
id: TODO-1050
title: Derive QUIC packet keys with ring HKDF
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: []
---

# TODO-1050: Derive QUIC packet keys with ring HKDF

## Why

Packet keys are derived by an in-tree HKDF-Expand-Label. The algorithm is RFC 5869 and RFC 9001, but it is a second implementation. A label bug means peers only talk to each other, or do not talk at all. Ring already ships HKDF. Key install is not the per-packet hot path, so this is a correctness cut, not a speed cut.

## Current code

- `crates/qf-crypto/src/hkdf.rs`: `hkdf_extract`, `hkdf_expand`.
- `crates/qf-crypto/src/quic_kdf.rs`: `hkdf_expand_label`, `derive_pkt_key`, `derive_pkt_key_for_version`, version-specific labels.
- Live callers: `src/transport/packet/context.rs` `install_aes_gcm_initial` and `src/transport/packet/secrets.rs` call `derive_pkt_key_for_version`. Output key and IV are then installed into `RingAesGcm128` / `RingAesHp`.
- rustls still owns the handshake and the traffic secrets. This code only expands those secrets into packet key, IV, and header-protection key.
- Production `expect` calls that must disappear with the hand-rolled expander: `crates/qf-crypto/src/hkdf.rs` (`HmacSha256::new_from_slice`, `Hkdf::from_prk`, `hk.expand`). A bad PRK or an over-long expand must return `ConnectionError`, not panic. Test-only `expect` in `quic_kdf.rs` tests may stay.

## Target

- Expand-Label is `ring::hkdf` with the RFC 9001 info struct: length-prefixed label `tls13 ` + QUIC label, and the hash length.
- v1 and v2 labels stay the ones QUIC specifies (`quic key`, `quic iv`, `quic hp`, `quic ku`, plus version-specific salt only where RFC 9369 changes it). No private prefix.
- Function names at the crate boundary can remain `derive_pkt_key_for_version` so callers stay stable, but the body is ring.
- Delete `hkdf.rs` if nothing else calls it after the switch.
- Known-answer tests from RFC 9001 Appendix A (Initial key derivation for the published client Initial) must pass. Those vectors catch a label mismatch immediately.

## Non-goals

- Do not re-derive secrets rustls already derived.
- Do not change AEAD.
- Do not keep the old expander behind a flag. One implementation.

## Design

1. Write the RFC 9001 Appendix A Initial test first, against the current function. If it fails, the current labels are private. Fix the labels to the RFC as part of this task. Both ends of a QuicFuscate connection move together. Interop with rustls-derived keys is the point.
2. Implement expand via `ring::hkdf::Prk::expand` and `Salt::extract` as required. Match output length (16 for AES-128 key, 12 for IV, 16 for HP).
3. Keep version dispatch in `packet_labels` but store only standard label byte strings.
4. Remove the hand-rolled expand loop once the vectors match.

## Sub-Tasks

- [x] Appendix A test on the current code, record pass or fail in Notes.
- [x] Ring-backed expand, same public signatures.
- [x] Appendix A passes.
- [x] Existing `quic_kdf` length tests still pass.
- [x] Delete unused `hkdf.rs` symbols.
- [x] One connection test: Initial keys produced here open a packet sealed by rustls for the same secret, and the reverse.

## Notes

The existing `initial_secret_v1_matches_rfc9001` test already asserted the RFC 9001 Appendix A.1 initial secret, client initial secret, and server initial secret. Those tests passed on the hand-rolled expander before the switch, so the labels were the RFC labels (`quic key`, `quic iv`, `quic hp`, `quic ku`, and the v2 `quicv2 *` forms). No private prefix was in use. An in-flight peer therefore still agrees after this change.

`hkdf_extract` returns the raw PRK. `ring::hkdf::Salt::extract` is HMAC-SHA256(salt, ikm) and does not expose those bytes, so extract calls `ring::hmac` directly. Expand uses `Prk::new_less_safe` plus `Prk::expand`. The `hmac`, `hkdf`, and `sha2` crates are no longer dependencies of qf-crypto. SHA-256, HMAC, and the TLS Cover / private-protocol callers stay on the same function names.

`hkdf_expand` now returns `Result`. A 64-byte private-shape expand that ring rejects falls back to the canonical layout. TLS Cover maps the same rejection to an I/O error and zeroizes the PRK first. Neither length is above the 8160-byte ceiling.

## Result

RFC 9001 Appendix A.1 client and server key, IV, and header-protection values match, including `1f369613dd76d5467730efcbe3b1a22d` and `cf3a5331653c364c88f0f379b6067e37`. RFC 9369 Appendix A still matches. `derived_initial_keys_match_rustls_initial_seal` seals with rustls Initial keys and opens with `RingAesGcm128` from `derive_pkt_key_for_version`, then the reverse. qf-crypto 60/60. `cargo clippy -p qf-crypto --lib --offline -- -D warnings` is clean. `distinct_seeds_produce_distinct_shapes` and the TLS Cover domain-separation test passed. No production `.expect(` remains in `hkdf.rs`. `derive_pkt_key_for_version` keeps its signature.

## Acceptance

- Appendix A hex matches.
- No `hkdf_expand` loop remains in `qf-crypto`.
- `hkdf.rs` has no production `.expect(`.
- Packet install callers are unchanged at the signature level.
- Until this task is done, "no homemade crypto" is false for key derivation. Do not close TODO-1049's narrative as if HKDF were ring.

## Risks

- If current labels were accidentally private, in-flight peers across an upgrade will fail the handshake until both sides roll. That is acceptable. Document it in the TODO result. Do not preserve the bug for compatibility.
