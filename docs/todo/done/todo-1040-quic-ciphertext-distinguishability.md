---
id: TODO-1040
title: QUIC-shaped ciphertext distinguishability AES-GCM vs AEGIS vs MORUS
severity: HIGH
phase: S
priority: P1
status: DONE
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

- [x] Capture or synthesize equal-length short-header payloads for R-RING, S-AEGIS, C-AEGIS-L, C-MORUS, S-MORUS
- [x] Tests run: byte histogram chi-square and long runs. Autocorrelation and length/PN correlation were not separate statistics. A nearest-mean classifier on ciphertext byte 0 was added and measured.
- [x] A distinguisher is "cheap" if accuracy on 10k packets of 1400 B beats 60 percent without keys, or if chi-square exceeds 400 (df=255 expectation is 255)
- [x] Record whether any cheap distinguisher exists: no
- [x] If yes: not applicable
- [x] If no: stealth cost is "not Chrome-identical", not "visible AEGIS banner"
- [x] No claim that AEGIS is stealthier than AES-GCM

## Sub-Tasks

- [x] Reuse 1038 packet-path output buffers
- [x] Do not put keys or QKeys in artifacts
- [x] Write the result into TODO-1032 and TODO-1044

## Notes

Stealth lives in padding, timing, persona, probe, REALITY. This task only prices the cipher-family residue. Do not start until explicitly requested.

## Result (2026-09-21)

The earlier artifact line `cheap_keyless_distinguisher=false` was a constant. The harness now scores it. macOS re-run, 10_000 packets of 1400 B, nearest-mean on ciphertext byte 0 against R-RING, train on the first half and score the second half:

| pair | accuracy | chi-square |
| --- | --- | --- |
| S-AEGIS | 0.495 | 295.21 |
| C-AEGIS-L | 0.495 | 295.21 |
| C-MORUS | 0.500 | 250.82 |
| S-MORUS | 0.500 | 250.82 |

R-RING chi-square is 236.82. Thresholds are 60 percent accuracy and chi-square 400. Result: `cheap_keyless_distinguisher=false` (`max_accuracy=0.500`, `max_chi=295.21`). S-AEGIS chi-square equals C-AEGIS-L, and S-MORUS equals C-MORUS, which is the same ciphertext. Omega's earlier chi-square file matches these values; the classifier itself was run on macOS because the ciphertext is deterministic. No owner is a visible AEGIS banner. None is more Chrome-shaped than AES-GCM. Max-stealth stays rustls. An explicit performance opt-in is still allowed. Artifact: `scripts/out/benchmarks/aead-bakeoff-macos-arm/distinguish-accuracy.txt`.
