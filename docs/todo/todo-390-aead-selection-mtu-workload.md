---
id: TODO-390
title: AEAD selection uses MTU workload length
severity: MEDIUM
phase: A
priority: P0
status: DONE
created: 2026-06-05
---

# TODO-390: AEAD Backend Selection MTU Workload Length

## Problem

`select_data_aead()` uses `DEFAULT_TRANSPORT_AEAD_WORKLOAD_LEN` tied to Initial packet size (~1200 B). Typical 1-RTT datagrams are closer to path MTU (~1400 B). X4/X8 backends may be under-selected on AVX-capable hosts.

## Acceptance

- Selection uses representative 1-RTT payload length (configurable constant, default ~1400)
- Document constant in `crypto/mod.rs`
- Existing backend selection tests updated or extended
- No behavior change for forced overrides (TODO-389)

## Fix Plan

1. Introduce `DEFAULT_DATA_PLANE_AEAD_LEN` (~1400) separate from Initial sizing
2. Update `select_data_aead` and `resolve_data_aead_plan` call sites
3. Add test: on x86 with VAES, bulk length selects X8 when auto

## Files

- `src/crypto/mod.rs`
- `src/simd.rs`
