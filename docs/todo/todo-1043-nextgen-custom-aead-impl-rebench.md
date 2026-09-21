---
id: TODO-1043
title: Next-gen custom AEAD implementation and re-bench
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1042]
---

# TODO-1043: Next-gen custom impl and re-bench

## Why

If TODO-1042 proceeds, the design must be implemented and run through the same 1038 matrix as N-AEGIS / N-MORUS. Old first-party stays as C-* until N-* wins or this task is abandoned.

## Acceptance

- [ ] TODO-1042 is `proceed`, not `SKIP`
- [ ] N-* is spec-byte-identical to official vectors and to S-* where S-* exists
- [ ] All 1038 cells for N-AEGIS and/or N-MORUS filled on macOS ARM and Omega
- [ ] Comparison table: N-* vs C-* vs S-* vs R-RING vs R-LC on P1 1400 B
- [ ] Unique 1041 hooks have tests (batch-into-pool, epoch fence, no repair AEAD)
- [ ] FEC recovery fixture: rustls vs N-* recovered TUN payload identical
- [ ] If N-* does not beat both C-* and the best of S-*/R-* on P1 1400 B, N-* is not promoted
- [ ] Feature-gated; default binary still rustls AES-GCM
- [ ] No ship-default change

## Sub-Tasks

- [ ] Implement only the 1042 module map
- [ ] Reuse the 1038 harness
- [ ] Keep C-* until N-* wins, then archive C-* in `archive/` only if 1044 says so
- [ ] Feed numbers to TODO-1044

## Notes

Do not start if 1042 is `SKIP`. Disk check before builds. `cargo clean` if needed.
