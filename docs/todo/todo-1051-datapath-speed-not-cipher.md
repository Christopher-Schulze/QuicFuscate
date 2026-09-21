---
id: TODO-1051
title: Remaining datapath speed without a new cipher
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1041]
---

# TODO-1051: Remaining datapath speed without a new cipher

## Why

ring AES-128-GCM at about 1280 ns per 1400 B is about 1.1 GB/s per core. One gigabit is one core of crypto. A faster cipher is single-digit once copies and syscalls dominate. libaegis is already the opt-in speed owner for `off` and `performance`. Another AES or ChaCha kernel is out of scope (TODO-1049).

## Already done, do not reopen

- TODO-923 GSO/GRO, Omega-verified.
- TODO-935 `flush_outbound` sendmmsg.
- TODO-937 TUN downlink GSO and sendmmsg.
- TODO-913 through TODO-921 and the fountain alloc cuts marked DONE in `docs/todo.md`.
- `seal_batch` exists. TODO-1041 measured about 1.7x per packet versus single-packet ring on an 8-packet Omega batch. That gain dies if each packet is sealed and then sent with its own syscall.

## Still open elsewhere

- TODO-902: io_uring TX flat adoption is in. The 2x throughput acceptance still needs an x86_64 bench host.
- TODO-901: sharding works on Omega (1 core). The >=3x pps criterion needs multicore x86_64.
- TODO-1036 x86 VAES remeasure decides whether `rustls-aws-lc` beats ring on that ISA. It does not belong in this task.

## Target

1. Prove whether the GSO run is sealed with `seal_batch` or with N single seals. If N single seals, seal the uniform-length run once, then hand the same buffers to `plan_gso_run` / `sendmmsg`. Do not seal eight packets and then send them one by one.
2. Inventory `docs/todo.md` items 925 through 964. Anything not marked DONE stays listed in this file's Notes with its existing TODO id. This task does not duplicate those ids.
3. SIMD gap audit for non-crypto kernels only: GF multiply, XOR, checksum, varint, QPACK Huffman, in `qf-simd` and `qf-fec`. For each kernel record: scalar, AVX2, AVX-512, NEON, SVE2, and whether Apple is NEON-only. Add a missing kernel only when a benchmark at MTU size shows at least 20 percent. No AES-NI, GHASH, or ChaCha work.

## Non-goals

- No new AEAD, no aws-lc default flip, no Apple accelerator, no Intel QAT, no kTLS (QUIC is UDP).
- No rewrite of DONE GSO code.

## Design

- Measurement first: one existing bench, packet size 1400, batch 8, report seal time and send-syscall count separately.
- Coupling point is the send path that already has a uniform run (`plan_gso_run`). The seal must happen before the syscall, into the pooled buffers the syscall already uses.
- SIMD additions land behind the current `qf-simd` dispatch with a scalar fallback. `cfg` is target-feature only.

## Sub-Tasks

- [ ] Bench: seals per GSO run, syscalls per burst. Write the numbers here.
- [ ] If seals are per packet, switch that run to `seal_batch`.
- [ ] Notes table of still-open 925-964 items. Do not implement them here.
- [ ] SIMD matrix. Implement only kernels that clear 20 percent at 1400 B.
- [ ] Leave TODO-902 and TODO-901 acceptance on their own files. Link them.

## Acceptance

- A burst of 8 equal-length packets on Linux uses one seal batch and one GSO sendmsg when GSO is available, or one sendmmsg when it is not.
- No diff under `crates/qf-crypto/src/aes.rs` or `chacha.rs` (those files should already be gone via TODO-1049; this task must not recreate them).
- Bench note in this file: before and after syscall count.

## Risks

- Sealing a batch that the congestion controller will not send wastes work. Seal only the run that is already admitted.
- AVX-512 on a Mac is not a target. Apple is NEON only.
