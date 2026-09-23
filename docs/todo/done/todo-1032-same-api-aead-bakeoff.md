---
id: TODO-1032
title: Same-API AEAD bakeoff rustls/ring aws-lc libaegis first-party
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-884, TODO-1037, TODO-1038, TODO-1039, TODO-1040]
---

# TODO-1032: Same-API AEAD bakeoff

## Why

Existing 884 numbers cannot decide a cipher owner. macOS compared primitives and rustls won. Omega compared first-party data-AEAD primitives to a full rustls 1-RTT path. No run has rustls/ring, rustls/aws-lc-rs, libaegis, first-party AEGIS, and first-party MORUS on one API. Until that matrix exists, speed cannot justify custom crypto and cannot justify promoting AEGIS or MORUS.

Do not start until explicitly requested. Bench and record only. No default-policy change in this task.

## Acceptance

- [x] One harness seals and opens through the same `AeadSeal`/`AeadOpen` (or rustls `PacketKey`) wrapper for every owner
- [x] Owners: rustls+ring AES-128-GCM, rustls+aws-lc-rs AES-128-GCM, rustls ChaCha20-Poly1305, libaegis or `aegis` AEGIS-128L, first-party AEGIS-128L, first-party MORUS-1280-128
- [x] Paths: primitive seal/open and full packet path (header protection + AAD + packet number) at 64, 1024, 1400, 8192 bytes; batch 8 on the packet path
- [x] Hosts: local ARM64 and Omega ARM64 in the first pass; x86 is recorded `UNAVAILABLE` until a witness exists
- [x] Each cell has median, p95, commit, compiler, CPU, and the exact command
- [x] A short note explains why first-party AEGIS lost the macOS primitive run (copies, AES-round quality, missing assembly, zeroize, dispatch)
- [x] Verdict answers three questions only: does any AEGIS/MORUS owner beat rustls AES-GCM on the full packet path by at least 10 percent; is that owner an audited crate or first-party; does first-party still have a path to win after a focused speed pass
- [x] No ship-default change, no feature-flag flip, no IETF/QUIC-standard wording

## Sub-Tasks

- [x] Add bench-only deps (`aws-lc-rs` rustls backend, `aegis`/`libaegis`). Do not put them on the default runtime graph
- [x] Wrap each owner in the existing packet AEAD trait
- [x] Run the matrix on macOS ARM and Omega
- [x] Write the table into TODO-884 / TODO-1030
- [x] Leave x86 and side-channel on TODO-884 / TODO-681

## Notes

RFC 9001 Initial and Handshake stay AES-GCM regardless of this bakeoff. A non-QUIC AEAD can only be a post-auth private payload owner. This parent measures and indexes. It does not change the ship default.

## Parent program

Goal: decide whether any AEGIS or MORUS owner (standard crate or first-party, current or next-gen) beats rustls AES-GCM on a fair path hard enough to become an opt-in post-auth owner, without harming stealth or FEC.

Ship default stays rustls AES-GCM (TODO-1033) even if a private owner later wins.

### Owners that must appear

| ID | Owner | Algorithm | Role |
|---|---|---|---|
| R-RING | rustls + ring | AES-128-GCM | current standard 1-RTT |
| R-LC | rustls + aws-lc-rs | AES-128-GCM | legal standard speed candidate |
| R-CHACHA | rustls + ring | ChaCha20-Poly1305 | portable standard |
| S-AEGIS | libaegis or `aegis` crate | AEGIS-128L | audited AEGIS |
| C-AEGIS-L | first-party Aegis128L | AEGIS-128L | current custom |
| C-AEGIS-X4 | first-party Aegis128X4 | AEGIS-128L width | current custom backend |
| C-AEGIS-X8 | first-party Aegis128X8 | AEGIS-128L width | current custom backend |
| S-MORUS | independent MORUS crate or CAESAR ref | MORUS-1280-128 | standard-or-ref MORUS; `UNAVAILABLE` if none is license-clean |
| C-MORUS | first-party MorusAead | MORUS-1280-128 | current custom |
| N-AEGIS | next-gen first-party AEGIS | AEGIS-128L | only after TODO-1043 |
| N-MORUS | next-gen first-party MORUS | MORUS-1280-128 | only after TODO-1043 |

X4/X8 must stay byte-identical to AEGIS-128L. They are backends, not product families.

### Paths

1. Primitive seal/open through one wrapper trait.
2. Full packet path: header protection + QUIC AAD + packet number + 16-byte tag.
3. Batch 8 and batch 16 on the packet path.
4. Optional later: `QuicFuscateConnection` send/recv and TUN e2e (recorded, not required for the first verdict).

### Sizes

64, 256, 512, 1024, 1200, 1400, 8192 bytes. 1400 is the VPN decision size.

### Hosts

- macOS ARM64
- Omega ARM64 Linux
- x86_64: `UNAVAILABLE` until a witness exists; never infer from ARM

### Metrics per cell

Median, p95, p99, bytes/s, ns/packet, allocations, copied bytes, commit, compiler, CPU, command. A missing cell is `UNAVAILABLE` or `SKIP` with a reason.

### Decision rule (this parent, not ship policy)

1. Compare owners on path 2 at 1400 B first.
2. A private owner needs >=10 percent geometric-mean gain over R-RING and R-LC on path 2 at 1200-1400 B, and must not regress either ARM host by more than 5 percent.
3. TODO-1040 must not find a cheap distinguisher against Chrome-shaped AES-GCM 1-RTT.
4. TODO-1041 must prove FEC epoch isolation and no FEC correctness change.
5. TODO-1044 writes the opt-in owner. It must not flip the TODO-1033 default.

### Child tasks

- TODO-1037 pin owners
- TODO-1038 harness and matrix
- TODO-1039 first-party slow-path profile
- TODO-1040 stealth distinguishability
- TODO-1041 integration contract
- TODO-1042 next-gen design (gated)
- TODO-1043 next-gen impl and re-bench (gated)
- TODO-1044 decision

### Out of scope

- Changing Initial or Handshake off AES-GCM
- Claiming AEGIS/MORUS is a QUIC/TLS standard
- Promoting from the old 884 ARM tables
- Fancy AEAD-inside-FEC math that changes ciphertext or GF recovery

## Result (2026-09-21)

Harness: `examples/aead_bakeoff.rs`, runner `scripts/benchmarks/suites/bench-aead-bakeoff.sh`. Owners share short-header AAD, `RingAesHp`, QUIC nonce, and a 16-byte tag. rustls rows use `Keys::initial` `PacketKey`. Artifacts: `scripts/out/benchmarks/aead-bakeoff-macos-arm/` and `scripts/out/benchmarks/aead-bakeoff-omega-arm/` (including `matrix-rlc.txt`). x86_64 UNAVAILABLE.

Verdict:

1. Yes. S-AEGIS beats R-RING and R-LC by more than 10 percent geometric mean on P1 1200-1400 on both ARM hosts. Omega same binary: 1.76x vs R-RING, 1.85x vs R-LC. macOS conservative cross-run vs R-LC: 1.29x. No other private owner does.
2. That owner is the audited `aegis` 0.9.18 crate (libaegis), not first-party.
3. First-party has no focused-pass path that this program should take. C-AEGIS-L is about 6x slower than S-AEGIS at the same allocs=0 / copied=16 cost. TODO-1042 is SKIP.

No ship-default change. Numbers and the pick are in TODO-1044.
