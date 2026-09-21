---
id: TODO-1038
title: Same-API AEAD harness and matrix execution
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1037]
---

# TODO-1038: Same-API harness and matrix

## Why

884 compared different APIs. This task builds one wrapper and fills every required cell. No winner speech until the table exists.

## Harness

One trait, existing `AeadSeal` / `AeadOpen` plus a rustls `PacketKey` adapter that uses the same counter, AAD, and tag layout as live 1-RTT.

No extra copies that a live owner would not pay. If an owner cannot avoid a copy, the copy is part of its score.

## Matrix

Owners: R-RING, R-LC, R-CHACHA, S-AEGIS, C-AEGIS-L, C-AEGIS-X4, C-AEGIS-X8, S-MORUS, C-MORUS. N-* rows stay empty until TODO-1043.

Paths:

- P0 primitive seal/open
- P1 packet path: rustls-standard HP + short-header AAD + PN + 16-byte tag
- P2 batch 8 and batch 16 on P1

Sizes: 64, 256, 512, 1024, 1200, 1400, 8192.

Hosts: macOS ARM64, Omega ARM64. x86_64 `UNAVAILABLE` until a witness.

## Acceptance

- [ ] Every owner/path/size/host cell is a number or `UNAVAILABLE`/`SKIP` with a reason
- [ ] Artifact directory under `scripts/out/benchmarks/` with command, commit, compiler, CPU
- [ ] Median, p95, p99, ns/packet, bytes/s, allocs, copied bytes
- [ ] C-AEGIS-X4/X8 ciphertext matches C-AEGIS-L on the same key/nonce/AAD
- [ ] S-AEGIS matches CFRG AEGIS-128L vectors through the wrapper
- [ ] C-MORUS still matches CAESAR vectors through the wrapper
- [ ] rustls owners use real `PacketKey` for P1, not a reimplementation
- [ ] Table copied into TODO-1032 and TODO-1030
- [ ] No default-policy change

## Sub-Tasks

- [ ] Bench-only deps from TODO-1037
- [ ] Wrappers in a benches/rust-tests target, not the default server binary
- [ ] Disk check + `cargo clean` if free space would drop under 2 GB
- [ ] Run macOS ARM, then Omega ARM
- [ ] Publish the table

## Notes

1400 B P1 is the decision size. Primitive-only wins do not count. Do not start until explicitly requested.
