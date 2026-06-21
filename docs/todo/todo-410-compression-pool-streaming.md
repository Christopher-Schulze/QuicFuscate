---
id: TODO-410
title: Zstd compression streaming into pool
severity: LOW
phase: B
priority: P3
status: DONE
created: 2026-06-05
---

# TODO-410: Zstd Compression Streaming into Memory Pool

## Problem

`CompressionManager::compress_to_pool` uses intermediate `Vec` from zstd encoder then copies to pool block.

## Acceptance

- Compress directly into pool-allocated buffer (or single allocation)
- H3 compress path unchanged semantically
- compress tests pass

## Result

- `CompressionManager::compress_to_pool()` now compresses directly into the caller pool block after the `0x5A` header with `zstd::bulk::Compressor::compress_to_buffer`.
- `compress_with_dict()` now compresses directly into the body-pool block after the `0x5D` dictionary header with `zstd::bulk::Compressor::with_dictionary(...).compress_to_buffer(...)`.
- H3 compression semantics and frame headers are unchanged.
- Added roundtrip tests for normal and dictionary pool compression.

## Files

- `src/compress.rs`
- `src/transport/h3.rs`

## Verification

- `cargo fmt --all`
- `cargo test --lib --features rust-tests compress` GREEN, 24 passed.
- `cargo check` GREEN.
- `cargo clippy --workspace --all-targets -- -D warnings` GREEN.
- `cargo test --workspace --all-targets` GREEN, 1162 lib tests passed.
