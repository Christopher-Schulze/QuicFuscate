---
id: TODO-1030
title: Custom-vs-standard systems audit (crypto, stealth, FEC, 0-RTT)
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-884, TODO-885, TODO-720, TODO-1031, TODO-1032, TODO-1033, TODO-1034, TODO-1035, TODO-1036, TODO-1037, TODO-1038, TODO-1039, TODO-1040, TODO-1041, TODO-1042, TODO-1043, TODO-1044]
---

# TODO-1030: Custom-versus-standard systems audit

## Why

First-party AEGIS/MORUS/AES-GCM/ChaCha/Poly1305/AesHp exist from speed and private-ciphertext assumptions. Those assumptions are not proven on a same-API path, FEC does not consume the AEAD family, and browser-shaped stealth wants rustls AES-GCM, not a private payload cipher. This task is the decision record for what stays custom, what becomes a standard owner, and what can still be optimized without rolling primitives.

Do not implement posture changes here. Inventory, compare, decide.

## Acceptance

- [x] Every first-party crypto primitive has one row: owner, live path, standard alternative, speed evidence, stealth effect, FEC effect, keep/replace/feature-gate
- [x] 0-RTT has a keep-disabled or later-standard-only verdict with replay and fingerprint rationale
- [x] Private 1-RTT has a keep-as-opt-in or drop-from-default verdict that does not claim stealth from ciphertext
- [x] FEC and stealth rows state they are AEAD-agnostic on the current pipeline
- [x] Standard-cipher speed path names rustls/ring or rustls/aws-lc-rs, not a new AES-GCM
- [x] Recommended ship default is explicit (`packet_protection_mode=standard` vs `auto`)
- [x] No code move until a follow-up task is opened from this record

## Sub-Tasks

- [x] Crypto primitives: AEGIS L/X4/X8, MORUS, AesGcm128, ChaCha20-Poly1305, AesHp, TLS-Cover ciphers, QUIC Initial KDF
- [x] Protocol custom: private exporter schedule, private negotiation, packet-number AEAD boundary
- [x] 0-RTT later investigation is owned by TODO-1031 (rustls + strike only)
- [x] Dormant compat hooks in `src/transport/packet/context.rs` (`install_read_1rtt_secret`, `key_update_1rtt_*` secret arm reaching `select_packet_data_aead`, `install_0rtt_keys`): decide test-only gate or removal; a re-enabled secret arm would silently swap 1-RTT to AEGIS/MORUS under rustls peers
- [x] Stealth: padding, timing, persona, probe, REALITY vs private AEAD
- [x] FEC: encode-after-seal, epoch isolation, repair cover vs AEAD family
- [x] Same-API speed evidence is owned by TODO-1032 through TODO-1044
- [x] Write the keep/replace table into this file and point DOCUMENTATION.md at it when executed

## Cluster index (2026-09-21)

Settled stealth default (no bakeoff required):

- TODO-1033 ship `packet_protection_mode=standard` (rustls AES-GCM default)
- TODO-1034 replace live Initial `AesGcm128` + `AesHp` with ring/aws-lc
- TODO-1035 move TLS-Cover and first-party ChaCha20-Poly1305 onto rustls/ring
- TODO-1036 evaluate rustls `aws-lc-rs` for the standard path
- TODO-1031 later rustls 0-RTT
- TODO-1029 Omega pcap for the private upgrade path

Bakeoff and optional post-auth owner:

- TODO-1032 parent bakeoff program
- TODO-1037 pin standard owners and licenses
- TODO-1038 same-API harness and matrix
- TODO-1039 profile why first-party AEGIS/MORUS is slow
- TODO-1040 ciphertext distinguishability under QUIC shape
- TODO-1041 FEC/stealth/transport integration contract (honest hooks only)
- TODO-1042 next-gen custom design (gated)
- TODO-1043 next-gen custom impl and re-bench (gated)
- TODO-1044 post-auth owner decision; default stays rustls AES-GCM unless a winner clears stealth and FEC gates

TODO-1028 is blocked. Do not freeze a family from the old ARM cells.

## Notes

First-pass keep/replace recommendations from 2026-09-21 (not executed):

- AEGIS first-party: feature only until TODO-1044.
- MORUS first-party: feature or drop after TODO-1044.
- AesGcm128 Initial and AesHp: replace (TODO-1034).
- ChaCha/Poly1305 and TLS-Cover: move (TODO-1035).
- Private negotiation: keep inert by default (TODO-885 + TODO-1033).
- Selector/planner: keep.
- First-party AEAD SIMD: same feature as the impl.
- FEC and stealth pad/timing/persona: keep. Pipeline stays pad -> AEAD+HP -> timing -> FEC.
- 0-RTT: stay off until TODO-1031.
- XOR: stay gone.

Do not implement bakeoff-gated replacements until TODO-1044. TODO-1033 through TODO-1036 may start only when explicitly requested. They do not wait on the bakeoff.

## Result (2026-09-21)

| item | decision |
| --- | --- |
| Ship default | `packet_protection_mode=standard`. rustls AES-GCM Handshake/1-RTT. ring AES-128-GCM + AES HP for Initial. |
| `aead_preference=auto` | installs no family |
| Post-auth opt-in | S-AEGIS via non-default `advanced-aead` (TODO-1044). Explicit preference required. |
| First-party AEGIS L/X4/X8 | keep as default-build private fallback and oracle. Not the chosen owner. X4/X8 stay first-party even with the feature. |
| First-party MORUS | keep as oracle / explicit private family. Lost the bakeoff to S-AEGIS and to R-RING. |
| First-party AesGcm128 + AesHp | removed from live Initial. Bench oracle only (TODO-1034). |
| ChaCha20-Poly1305 + TLS-Cover | live path is ring (TODO-1035). |
| rustls crypto provider | stay ring. `rustls-aws-lc` is an explicit feature (TODO-1036). |
| Secret-schedule compat arms | `install_0rtt_keys`, `install_*_1rtt_secret`, `key_update_1rtt_*` now call `standard_aes128_gcm`. They cannot silently install AEGIS/MORUS. Private install stays `select_private_packet_data_aead`. |
| 0-RTT | stay off. TODO-1031 remains open. rustls + strike only, never private AEAD. |
| FEC | keep. Encode runs on the sealed datagram from `conn.send` (`produce_one_queued`). FEC never sees plaintext. |
| Stealth pad/timing/persona/probe/REALITY | keep. Padding frames are inside QUIC before AEAD. Private AEAD is not a stealth upgrade. |
| XOR on sealed packets | stay gone. |
| Next-gen custom AEAD | SKIP (TODO-1042, TODO-1043). |
| Production private enable | blocked on TODO-1029 pcap. |
