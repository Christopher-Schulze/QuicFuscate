---
id: TODO-390
title: AEAD selection uses MTU workload length
severity: MEDIUM
phase: A
priority: P0
status: SCRAP
created: 2026-06-05
resolved: 2026-07-23
---

# TODO-390: AEAD Backend Selection MTU Workload Length

## Problem

The TODO claimed `select_data_aead()` used a workload length tied to Initial
packet size (~1200 B), causing X4/X8 backends to be under-selected on
AVX-capable hosts.

## Investigation Result

**The premise was incorrect.** Code inspection shows the selection already
used `crate::transport::TYPICAL_1RTT_PAYLOAD_LEN` (defined as 1400 in
`src/transport.rs:510`), not Initial sizing. The value 1400 is already
appropriate for path-MTU-sized 1-RTT datagrams and clears the X8 threshold
on VAES hosts.

The prior implementation renamed the local constant to a module-level
`DEFAULT_DATA_PLANE_AEAD_LEN` with the same value (1400) — a no-op rename
with no behavioral change. The rename is retained for documentation clarity
(the constant name now explicitly says "data-plane AEAD"), and a regression
guard test in `src/simd.rs` ensures the value never drops below
`AEGIS_X8_MIN_LEN`.

## Status: SCRAP

No fix was needed — the code was already correct. The constant rename and
regression test are retained as minor documentation hardening.
