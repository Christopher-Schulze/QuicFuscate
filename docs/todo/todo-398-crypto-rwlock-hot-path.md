---
id: TODO-398
title: CryptoContext RwLock scope reduction
severity: MEDIUM
phase: B
priority: P2
status: DEFERRED
superseded_by: TODO-417
created: 2026-06-05
---

# TODO-398: CryptoContext RwLock Hot Path Reduction

> **Note (2026-07-23):** This task is **superseded by TODO-417** (Hot-Path-Lock-Elimination), which bundles TODO-396 + TODO-397 + TODO-398 into a single coordinated change with profiling validation. The replacement approach uses `ArcSwap<DataAead>` for lock-free 1-RTT key access. Do not implement this task separately.

## Problem

`CryptoContext` behind `RwLock` in `Connection`. Every `seal_short_header_packet` and `unprotect_and_decrypt` acquires read lock (~1761, ~1045).

## Acceptance

- 1-RTT keys accessible without lock on steady-state data path
- Key update rotation still safe
- Transport connection tests pass

## Fix Plan

1. Cache `Arc` or cloned seal/open handles for active 1-RTT keys on connection
2. Invalidate cache only on key update / space transition
3. Keep RwLock for install/rotation only

## Files

- `src/transport/connection.rs`
- `src/transport/packet.rs`
