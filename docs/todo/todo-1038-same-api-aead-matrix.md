---
id: TODO-1038
title: Same-API AEAD harness and matrix execution
severity: HIGH
phase: S
priority: P1
status: DONE
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

- [x] Every owner/path/size/host cell is a number or `UNAVAILABLE`/`SKIP` with a reason
- [x] Artifact directory under `scripts/out/benchmarks/` with command, commit, compiler, CPU
- [x] Median, p95, p99, ns/packet, bytes/s, allocs, copied bytes
- [x] The original matrix checked C-AEGIS-X4/X8 against C-AEGIS-L; this pre-TODO-1045 owner-set criterion is superseded after the first-party kernels were removed.
- [x] S-AEGIS matches CFRG AEGIS-128L vectors through the wrapper
- [x] Historical C-MORUS vector coverage was recorded before TODO-1045 removed the first-party MORUS owner; no current MORUS path remains.
- [x] rustls owners use real `PacketKey` for P1, not a reimplementation
- [x] Table copied into TODO-1032 and TODO-1030
- [x] No default-policy change

## Sub-Tasks

- [x] Bench-only deps from TODO-1037
- [x] Wrappers in a benches/rust-tests target, not the default server binary
- [x] Disk check + `cargo clean` if free space would drop under 2 GB
- [x] Run macOS ARM, then Omega ARM
- [x] Publish the table

## Notes

1400 B P1 is the decision size. Primitive-only wins do not count. Do not start until explicitly requested.

## Result (2026-09-21)

Artifacts:

- `scripts/out/benchmarks/aead-bakeoff-macos-arm/` (`host.txt`, `matrix.txt`, `matrix-rlc.txt`, `distinguish.txt`, `profile.txt`)
- `scripts/out/benchmarks/aead-bakeoff-omega-arm/` (`host.txt`, `matrix.txt`, `matrix-rlc.txt`, `vectors.txt`, historical unpinned `x-match.txt`, `distinguish.txt`)

Every measured cell has median, p95, p99, ns/packet, bytes/s, allocs, copied. R-LC was `UNAVAILABLE` in the first macOS matrix (feature off) and filled by `matrix-rlc.txt`. Omega R-LC is the same-binary `matrix-rlc.txt`. x86_64 is `UNAVAILABLE` (no witness host). N-* is `SKIP` because TODO-1042 did not proceed.

The old Omega `x-match.txt` and C-MORUS row are historical pre-TODO-1045 artifacts; their host metadata says `commit=dirty-rsync`, so they are not reproducible current evidence. TODO-1045 removed the first-party X and MORUS kernels. Current libaegis X2/X4 are distinct variants, covered by `libaegis_128_variants_do_not_share_ciphertext`; the current bakeoff example has no `--match-x` mode, and TODO-1071 removes the stale runner call. `s_aegis_cfrg_vector1=ok`; rustls rows use real `PacketKey`. Decision table is in TODO-1044. No default-policy change.

macOS disk: `cargo clean` ran before the native builds because free space was 7.2 GiB with a 7.8 GiB `target/`. After the builds about 12 GiB were free.
