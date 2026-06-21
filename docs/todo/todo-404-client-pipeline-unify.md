---
id: TODO-404
title: Unify client pipeline with core pooled path
severity: LOW
phase: D
priority: P3
status: DONE
created: 2026-06-05
---

# TODO-404: Unify Client Pipeline with Core Pooled Path

## Problem

`src/implementations/client/pipeline.rs` uses `Vec` allocations on TUN path. `core::QuicFuscateConnection` uses `MemoryPool`. Two parallel implementations.

## Acceptance

- Client TUN path uses same pool + FEC integration as core
- No duplicate stealth/FEC logic
- Desktop client integration tests pass

## Fix Plan

1. Route client pipeline through `QuicFuscateConnection` APIs
2. Deprecate duplicate alloc paths in pipeline.rs
3. Archive or shrink pipeline.rs to thin adapter

## Result

- Removed the legacy `pipeline` module from the production client module graph and stopped publicly re-exporting its types.
- Left `src/implementations/client/pipeline.rs` on disk as a non-runtime legacy adapter note instead of deleting the file.
- Removed empty `StealthManager::obfuscate_payload` / `deobfuscate_payload` compatibility shims that only existed for the legacy pipeline.
- Production TUN/UDP flow remains owned by `IoDriver` and `QuicFuscateConnection`, which route inbound packets through `MemoryPool`, FEC, and transport receive APIs.

## Verification

- `cargo fmt --all`
- `cargo check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets` - 1160 lib tests passed; workspace all-targets passed

## Files

- `src/implementations/client/pipeline.rs`
- `src/core.rs`
- `src/implementations/client/` (subsystems)

## Risk

Large refactor. Defer until Phase A/B wins landed.
