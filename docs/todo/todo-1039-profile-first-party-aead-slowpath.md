---
id: TODO-1039
title: Profile why first-party AEGIS and MORUS lose
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1038]
---

# TODO-1039: Profile first-party AEAD slow path

## Why

macOS primitive already showed first-party AEGIS ~23x slower than rustls AES-GCM and first-party MORUS ~2.5x slower. Before any next-gen rewrite we need the actual waste: copies, AES-round quality, missing assembly, Drop/zeroize, trait dispatch, nonce setup, or just a weaker kernel.

## Acceptance

- [ ] Instruments or `perf` on the TODO-1038 P0 and P1 1400 B cells for C-AEGIS-L, C-MORUS, R-RING, S-AEGIS
- [ ] Written split of time: key setup, AES/MORUS rounds, GHASH-equivalent, tag, copies, zeroize, dispatch
- [ ] Count of heap allocs and extra 16-byte copies per seal
- [ ] Whether C-AEGIS uses hardware AES on the measured host
- [ ] Whether Drop/zeroize on `AesBlock` is gone on the hot path (TODO-895) or a sibling still pays
- [ ] A keep/rewrite/abandon note per waste item
- [ ] No rewrite in this task

## Sub-Tasks

- [ ] Use the 1038 binary, do not invent a second bench
- [ ] Record host, governor, and isolation
- [ ] Feed the waste list into TODO-1042

## Notes

If S-AEGIS is already faster than C-AEGIS by a wide margin, the next-gen design must start from that kernel or wrap it, not polish the losing state machine by habit.
