---
id: TODO-359
title: "Add SAFETY comments to ~25 unsafe blocks"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-359: Add SAFETY comments to ~25 unsafe blocks


## Problem
~25 unsafe blocks across 5 files lack the required `// SAFETY:` comment documenting
why the unsafe operation is sound. This violates Rust best practices and makes auditing
harder.

### Affected files and approximate block counts:
- `src/transport/batch.rs` - 12 unsafe blocks (mem::zeroed, from_raw_fd, recvmmsg, sockaddr parsing)
- `src/implementations/client/platform/linux.rs` - 5 blocks (TUN device ioctls)
- `src/implementations/client/platform/macos.rs` - 8 blocks (utun creation/cleanup)
- `src/implementations/client/io_driver.rs` - 4 blocks (from_raw_fd, libc calls)
- `src/transport/connection.rs` - 1 block (prefetch)

Note: `src/optimize/unsafe.rs` and `src/simd.rs` are exemplary - every unsafe block
has multi-line SAFETY comments. Use those as reference for the style.

## Fix Plan
For each unsafe block:
1. Read the surrounding code context
2. Identify the safety invariant that makes the operation sound
3. Add a `// SAFETY: <explanation>` comment immediately above the `unsafe` keyword
4. Document: what precondition must hold, why it holds, what could go wrong

## Files to Modify
- src/transport/batch.rs
- src/implementations/client/platform/linux.rs
- src/implementations/client/platform/macos.rs
- src/implementations/client/io_driver.rs
- src/transport/connection.rs