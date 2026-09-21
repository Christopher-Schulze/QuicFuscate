---
id: TODO-1041
title: Honest AEAD FEC stealth transport integration contract
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1038]
---

# TODO-1041: AEAD integration contract

## Why

Custom AEAD is only worth keeping if it can do something rustls/libaegis cannot do on this pipeline, or if it is faster on the same API. FEC and stealth must keep working. Fantasy "AEAD helps GF multiply" is forbidden. This task writes the real hooks.

## Current pipeline (must stay)

Outbound: H3 frames -> stealth PADDING inside QUIC -> AEAD seal + header protection -> timing gate -> FEC encode of the sealed datagram -> UDP.

Inbound: UDP -> FEC decode -> probe detect -> header unprotect + AEAD open -> frames.

FEC never sees plaintext. AEAD never sees GF coefficients. Changing that order would break both stealth padding-before-seal and QUIC integrity.

## Honest hooks (allowed)

1. Batch seal/open width matches FEC `source_count` and drain budget (8/16/32/128).
2. Seal in-place into the `MemoryPool` block FEC already owns. Zero extra copy.
3. Epoch fence: a FEC window contains one AEAD epoch only. Already required by TODO-885.
4. Padding stays inside the QUIC packet before seal. AEAD must not add a second length side-channel.
5. Timing stays after seal. Seal cost must be stable enough that the timing gate still owns IAT.
6. Repair datagrams are combinations of sealed datagrams. No second AEAD on repairs.
7. Tag stays 16 bytes. IV stays 12. Key stays 16 for private families, rustls size for standard.
8. Header protection stays rustls/standard AES regardless of payload owner.

## Forbidden hooks

- FEC-then-seal of plaintext symbols
- Changing AEGIS/MORUS ciphertext to carry FEC hints
- Secret-dependent padding or timing inside the AEAD
- Trial-decrypt across families
- Using XOR obfuscation on sealed packets

## Acceptance

- [ ] Each honest hook has: current owner, whether rustls/libaegis can do it, whether first-party can do it better
- [ ] Each forbidden hook is listed as rejected with a one-line reason
- [ ] FEC correctness test plan: same source packets, two AEAD owners, recovered plaintext identical
- [ ] Epoch-mix test: window that spans the private boundary must not combine epochs
- [ ] Stealth test: padding decision bytes are inside AEAD AAD/ciphertext, not after the tag
- [ ] Written verdict: "custom has unique hook X" or "no unique hook; custom only lives if it wins TODO-1038/1043 speed"
- [ ] No implementation except fixtures needed to prove the contract

## Sub-Tasks

- [ ] Read `src/core/connection/send.rs` FEC materialization and `select_private_seal`
- [ ] Map batch APIs of rustls PacketKey, libaegis, and first-party `seal_batch`
- [ ] Write the hook table into this file
- [ ] Gate TODO-1042: design starts only if a unique hook exists or 1039 shows a closable speed gap

## Notes

Unique product value is FEC, stealth, GSO, io_uring, pools. Those already work with rustls. Custom AEAD must attach to that machine, not replace it.
