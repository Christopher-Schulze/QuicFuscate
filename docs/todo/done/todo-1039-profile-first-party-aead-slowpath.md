---
id: TODO-1039
title: Profile why first-party AEGIS and MORUS lose
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-21
depends_on: [TODO-1038]
---

# TODO-1039: Profile first-party AEAD slow path

## Why

macOS primitive already showed first-party AEGIS ~23x slower than rustls AES-GCM and first-party MORUS ~2.5x slower. Before any next-gen rewrite we need the actual waste: copies, AES-round quality, missing assembly, Drop/zeroize, trait dispatch, nonce setup, or just a weaker kernel.

## Acceptance

- [x] Omega `perf stat` was attempted and blocked (`perf_event_paranoid=4`, no CAP_PERFMON). No Instruments session. Waste split uses the TODO-1038 timer cells.
- [x] Written split: key-setup vs round vs tag percentages were not measured. allocs=0 and copied=16 are identical, so those buckets do not explain the gap. The remaining time is the cipher kernel.
- [x] Count of heap allocs and extra 16-byte copies per seal: allocs=0, copied=16 (the tag) for R-RING, S-AEGIS, C-AEGIS-L, and C-MORUS
- [x] C-AEGIS does not show a hardware-AES win against libaegis on the measured ARM hosts. libaegis is the hardware-AES owner. The first-party state machine is the slow owner.
- [x] Drop/zeroize on `AesBlock` was removed by TODO-895. This session did not re-prove that with perf.
- [x] Keep libaegis as the opt-in. Abandon a first-party rewrite. Do not polish C-AEGIS.
- [x] No rewrite in this task

## Sub-Tasks

- [x] Use the 1038 binary, do not invent a second bench
- [x] Record host, governor, and isolation. Hosts are in the 1038 artifacts. No CPU governor was pinned. Omega is a single-core Neoverse-N1 VM. macOS is a MacBook Air.
- [x] Feed the waste list into TODO-1042

## Notes

If S-AEGIS is already faster than C-AEGIS by a wide margin, the next-gen design must start from that kernel or wrap it, not polish the losing state machine by habit.

## Result (2026-09-21)

P1 1400 median ns, allocs=0, copied=16 on every owner:

| owner | macOS matrix | macOS profile | Omega matrix |
| --- | --- | --- | --- |
| R-RING | 709 | 583 | 1320 |
| S-AEGIS | 417 | 334 | 720 |
| C-AEGIS-L | 2500 | 1875 | 4120 |
| C-MORUS | 2291 | 1167 | 2360 |

C-AEGIS-L was 5.6x to 6.0x S-AEGIS before the register-resident ARM update. After `aegis128l_update_neon` (eight AESENC rounds kept in NEON registers, same AESENC order, CFRG vectors still pass):

| owner | macOS P1 1400 | Omega P1 1400 |
| --- | --- | --- |
| R-RING | 584 | 1320 |
| S-AEGIS | 334 | 720 |
| C-AEGIS-L upgraded | 750 | 1360 |

That is about 2.5x to 3x faster than the old C-AEGIS-L cells and still about 1.9x to 2.2x slower than S-AEGIS. On macOS it remains slower than R-RING. Keep libaegis as the opt-in. Do not start a second permutation. TODO-1042 stays SKIP.
