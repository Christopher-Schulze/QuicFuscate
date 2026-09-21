---
id: TODO-1034
title: Replace first-party Initial AES-GCM and AesHp with ring or aws-lc
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1033]
---

# TODO-1034: Replace live Initial AesGcm128 and AesHp

## Why

QUIC Initial must stay AES-128-GCM and AES header protection (RFC 9001). The algorithm is not the review problem. The first-party `aes.rs`/`gcm.rs`/`AesHp` implementations on the live Initial path are. rustls does not own Initial keys. The replacement is `ring` or `aws-lc-rs` AEAD and HP, not a new cipher.

## Live owners today

- `CryptoContext::install_aes_gcm_initial` boxes `AesGcm128`
- `install_hp_initial` boxes `AesHp`
- `KeyScheduleHooks` Initial arm also builds `AesGcm128` + `AesHp`
- Handshake and 1-RTT live keys already come from rustls `PacketKey` / `HeaderProtectionKey`

## Acceptance

- [ ] Live Initial seal/open uses ring or aws-lc AES-128-GCM, not `AesGcm128`
- [ ] Live Initial HP uses ring or aws-lc AES-ECB/HP, not `AesHp`
- [ ] RFC 9001 Initial secret/KDF ownership stays in `quic_kdf.rs` (hkdf crate)
- [ ] NIST AES-GCM and RFC 9001 Initial vectors still pass
- [ ] rustls Handshake/1-RTT install paths are unchanged
- [ ] First-party `aes.rs`/`gcm.rs`/`AesHp` have no production Initial caller
- [ ] Those files may remain as bench/oracle only, behind `rust-tests` or `benches`
- [ ] Microbench vs the old first-party Initial path is recorded; a regression >5 percent on Omega 1200 B Initial seal/open fails the task
- [ ] No packet-shape change (16-byte tag, 5-byte HP mask)

## Sub-Tasks

- [ ] Read `AesGcm128` and `AesHp` signatures and the rustls HP wrapper in `src/qftls/rustls_provider.rs`
- [ ] Add a ring/aws-lc Initial owner that implements `AeadSeal`/`AeadOpen`/`PacketHeaderProtector`
- [ ] Switch `install_aes_gcm_initial` and `install_hp_initial`
- [ ] Switch `KeyScheduleHooks` Initial arms
- [ ] Keep first-party modules as oracle tests only
- [ ] Run qf-crypto AES-GCM/HP tests plus packet Initial fixtures

## Notes

Do not invent a new AES. Do not point Initial at AEGIS or MORUS. Handshake HP already rustls; do not touch it except to share the same audited AES-HP helper if that is strictly smaller.
