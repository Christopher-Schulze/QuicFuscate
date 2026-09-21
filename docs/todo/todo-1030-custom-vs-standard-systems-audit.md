---
id: TODO-1030
title: Custom-vs-standard systems audit (crypto, stealth, FEC, 0-RTT)
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-884, TODO-885, TODO-720, TODO-1031, TODO-1032]
---

# TODO-1030: Custom-versus-standard systems audit

## Why

First-party AEGIS/MORUS/AES-GCM/ChaCha/Poly1305/AesHp exist from speed and private-ciphertext assumptions. Those assumptions are not proven on a same-API path, FEC does not consume the AEAD family, and browser-shaped stealth wants rustls AES-GCM, not a private payload cipher. This task is the decision record for what stays custom, what becomes a standard owner, and what can still be optimized without rolling primitives.

Do not implement posture changes here. Inventory, compare, decide.

## Acceptance

- [ ] Every first-party crypto primitive has one row: owner, live path, standard alternative, speed evidence, stealth effect, FEC effect, keep/replace/feature-gate
- [ ] 0-RTT has a keep-disabled or later-standard-only verdict with replay and fingerprint rationale
- [ ] Private 1-RTT has a keep-as-opt-in or drop-from-default verdict that does not claim stealth from ciphertext
- [ ] FEC and stealth rows state they are AEAD-agnostic on the current pipeline
- [ ] Standard-cipher speed path names rustls/ring or rustls/aws-lc-rs, not a new AES-GCM
- [ ] Recommended ship default is explicit (`packet_protection_mode=standard` vs `auto`)
- [ ] No code move until a follow-up task is opened from this record

## Sub-Tasks

- [ ] Crypto primitives: AEGIS L/X4/X8, MORUS, AesGcm128, ChaCha20-Poly1305, AesHp, TLS-Cover ciphers, QUIC Initial KDF
- [ ] Protocol custom: private exporter schedule, private negotiation, packet-number AEAD boundary
- [ ] 0-RTT later investigation is owned by TODO-1031 (rustls + strike only)
- [ ] Stealth: padding, timing, persona, probe, REALITY vs private AEAD
- [ ] FEC: encode-after-seal, epoch isolation, repair cover vs AEAD family
- [ ] Same-API speed evidence is owned by TODO-1032
- [ ] Write the keep/replace table into this file and point DOCUMENTATION.md at it when executed

## Notes

First-pass keep/replace recommendations from 2026-09-21 (not executed):

- AEGIS first-party: feature only until TODO-1032. Speed claim unproven on a same-API path.
- MORUS first-party: feature or drop after TODO-1032. No audited owner.
- AesGcm128 Initial and AesHp: replace with ring/aws-lc. Same RFC 9001 algorithm, first-party impl is the review hit.
- ChaCha/Poly1305 and TLS-Cover: move to rustls/ring. Cover needs an AEAD, not a private one.
- Private negotiation: keep inert by default. Protocol, not a primitive.
- Selector/planner: keep. Not crypto.
- First-party AEAD SIMD: dies with the impl or lives behind the same feature.
- FEC and stealth pad/timing/persona: keep. AEAD-agnostic.
- 0-RTT: stay off until TODO-1031.
- XOR: stay gone.

Do not implement replacements from this list until this audit is accepted and TODO-1032 has same-API numbers where speed is the claimed reason.
