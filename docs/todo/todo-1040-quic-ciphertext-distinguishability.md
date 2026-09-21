---
id: TODO-1040
title: QUIC-shaped ciphertext distinguishability AES-GCM vs AEGIS vs MORUS
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1038]
---

# TODO-1040: Ciphertext distinguishability under QUIC shape

## Why

Max stealth is the product goal. After auth, a private cipher is allowed only if it does not make 1-RTT cheaper to spot than rustls AES-GCM. Handshake and Initial stay AES-GCM. This task asks whether the payload blob, with the same header, PN length, and 16-byte tag, is cheaply distinguishable.

## What is already known

- First byte, CID, PN length, and tag length can stay QUIC.
- Without keys, AES-GCM and AEGIS both look like high-entropy blobs.
- A classifier with rustls keys can fail-open AES-GCM. That is not a public oracle.
- Chrome 1-RTT is AES-GCM or ChaCha. A private cipher is never "more Chrome".

## Acceptance

- [ ] Capture or synthesize equal-length short-header packets for R-RING, S-AEGIS, C-AEGIS-L, C-MORUS
- [ ] Tests: byte-histogram, runs, chi-square, autocorrelation, length/PN correlation, timing of seal on the same host
- [ ] A distinguisher is "cheap" if a script on 10k packets of 1400 B beats 60 percent accuracy without keys
- [ ] Record whether any cheap distinguisher exists
- [ ] If yes: private owner cannot be a stealth win; TODO-1044 may still allow an explicit performance opt-in
- [ ] If no: stealth cost is "not Chrome-identical", not "visible AEGIS banner"
- [ ] No claim that AEGIS is stealthier than AES-GCM

## Sub-Tasks

- [ ] Reuse 1038 packet-path output buffers
- [ ] Do not put keys or QKeys in artifacts
- [ ] Write the result into TODO-1032 and TODO-1044

## Notes

Stealth lives in padding, timing, persona, probe, REALITY. This task only prices the cipher-family residue. Do not start until explicitly requested.
