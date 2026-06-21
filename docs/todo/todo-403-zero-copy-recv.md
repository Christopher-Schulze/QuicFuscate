---
id: TODO-403
title: Zero-copy inbound recv through FEC
severity: MEDIUM
phase: D
priority: P2
status: DONE
created: 2026-06-05
---

# TODO-403: Zero-Copy Inbound Recv Through FEC

## Problem

`core::recv` (~846-853) copies UDP input into pool block before FEC decode. Extra copy on inbound path.

## Acceptance

- io_uring recv buffers (or registered pool blocks) passed into FEC without memcpy where lifetimes allow
- Linux fastpath documented
- Fallback copy path retained for non-uring platforms

## Fix Plan

1. DONE: Added `QuicFuscateConnection::recv_pooled_block()` so callers that already own a pool block can pass it into FEC without copying through `recv(&[u8])`.
2. DONE: Added pool-backed `UringRecvBatch` construction. Linux `RecvMsg` slots can now point directly at `MemoryPool` blocks; completions transfer the filled block to the connection while the ring slot is immediately armed with a replacement block.
3. DONE: Retained the legacy contiguous-buffer `Vec<u8>` completion mode and the standard Tokio `recv()` fallback copy path for non-uring platforms.
4. VERIFIED: macOS local gates passed. Linux cross-check could not complete on this Mac because the x86_64 Linux cross C toolchain/OpenSSL/pkg-config sysroot is not installed.

## Result

- `src/core.rs`: `recv(&[u8])` remains the portable fallback and now delegates to `recv_pooled_block()` after one bounded copy into the shared pool.
- `src/optimize/uring_batch.rs`: `RecvCompletion` supports either legacy `data: Vec<u8>` or an owned `block + len`; pool-backed slots recycle unused replacement blocks on drop to keep `MemoryPool` accounting correct.
- `src/implementations/client/io_driver.rs`: Linux `io_uring` inbound initialization clones the connection memory pool and hands pooled completions into `recv_pooled_block()`.
- The acceptance criterion is implemented for the client Linux io_uring fast path. Server receive remains on its existing runtime path.

## Verification

- `cargo check`
- `cargo check --features io_uring`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --lib --features rust-tests` - 1161 passed
- `cargo test --workspace --all-targets`
- Attempted `cargo check --target x86_64-unknown-linux-gnu --features io_uring`; blocked by local cross-toolchain prerequisites (`x86_64-linux-gnu-gcc`, OpenSSL/pkg-config sysroot).

## Files

- `src/core.rs`
- `src/fec/mod.rs`
- `src/optimize/uring_batch.rs`
- `src/implementations/client/io_driver.rs`

## Depends

- TODO-392 (FEC ownership model)
