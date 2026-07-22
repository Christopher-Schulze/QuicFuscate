---
id: TODO-516
title: Implement mlock/mlockall for key material and memory pools
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-07-03
depends_on: [TODO-440, TODO-511]
---

# TODO-516: Implement mlock/mlockall for Key Material and Memory Pools

## Context

TODO-440 implemented `ZeroizeOnDrop` / manual `Drop` zeroization for
all AEAD key material (ChaCha20Poly1305, AesGcm128, Aegis128LAead,
Aegis128X4Aead, Aegis128X8Aead, MorusAead, Morus1280State) and PKI
secrets (`GeneratedCert`, `key_der`). That half of TODO-440 is
verified and complete.

The TODO-511 security/ops acceptance audit found that the
**memory-locking half of TODO-440 is not implemented**:
- `rg 'mlock|mlockall|munlock|VirtualLock' src` returns zero matches.
- `src/engine/config.rs` has no `lock_memory` or `lock_blocks` field.
- `scripts/install/quicfuscate-server.service` now includes
  `LimitMEMLOCK=infinity` (added during TODO-511), but the runtime
  never calls `mlockall`.

This means sensitive key material, AEAD state, QKey tokens, and
crypto pool buffers remain eligible for swap-out, where they persist
across reboots and can be recovered by an attacker with disk access.

## Desired Outcome

- `mlockall(MCL_CURRENT | MCL_FUTURE)` is called on server startup
  during the privileged phase, before key material is loaded, when
  `lock_memory = true` (default true on server, false on client).
- `MemoryPool` blocks are `mlock`ed on allocation and
  `munlock`ed + zeroized on deallocation when `lock_blocks = true`.
- `lock_memory` and `lock_blocks` are configurable via engine TOML.
- `LimitMEMLOCK=infinity` is already present in the systemd service
  file (added during TODO-511).
- Tests verify `mlockall` is called (Linux integration test checking
  `/proc/<pid>/status` for `VmLck > 0`, gated behind root privileges).
- `docs/DOCUMENTATION.md` is updated to reflect the wired state.

## Acceptance Criteria

- [x] `rg 'mlockall|mlock\b' src` returns matches in the server
      startup path and in `MemoryPool` allocation/deallocation.
- [x] `src/engine/config.rs` has `lock_memory` and `lock_blocks`
      fields with sensible defaults.
- [x] `scripts/install/quicfuscate-server.service` retains
      `LimitMEMLOCK=infinity`.
- [x] At least one test verifies `mlockall` succeeds when run with
      sufficient privileges, or is gracefully skipped otherwise.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [x] `cargo test --workspace --all-targets --features rust-tests`
      passes.
- [x] `docs/DOCUMENTATION.md` key-erasure section reflects the wired
      state, not just zeroization.

## Non-Goals

- Do not implement Windows `VirtualLock` in this TODO unless trivial;
  Linux/macOS `mlock`/`mlockall` is the priority.
- Do not change UI surfaces.
- Do not remove the zeroization that is already in place.

## Completion Evidence (2026-07-03)

- `SecurityConfig` in `src/engine/config.rs` extended with
  `lock_memory: bool` (default true) and `lock_blocks: bool` (default true).
- `static LOCK_BLOCKS: AtomicBool` in `src/optimize/mod.rs` controls
  block-level mlocking. Set via `MemoryPool::set_lock_blocks(enabled)`.
- `mlock_block()` / `munlock_block()` helper functions in
  `src/optimize/mod.rs` — best-effort, log on failure, no panic.
  No-op on non-Unix targets.
- `alloc_numa_block()` calls `mlock_block()` after block creation when
  `LOCK_BLOCKS` is true.
- `run_server()` in `src/main.rs` reads `security.lock_memory` and
  `security.lock_blocks` from the EngineConfig TOML and:
  - Reads `RLIMIT_MEMLOCK` before key material is loaded.
  - Calls `mlockall(MCL_CURRENT | MCL_FUTURE)` only for an unlimited budget.
  - Uses `MCL_CURRENT` for finite or unreadable limits so future allocations cannot fail with `ENOMEM` after a superficially successful lock.
  - Calls `MemoryPool::set_lock_blocks(lock_blocks)` before pool creation.
- `scripts/install/quicfuscate-server.service` already has
  `LimitMEMLOCK=infinity` (added during TODO-511).
- 3 new tests: `test_set_and_check_lock_blocks_flag`,
  `test_pool_alloc_with_lock_blocks_enabled`,
  `test_pool_alloc_with_lock_blocks_disabled`. All pass.
- `cargo build --lib` PASS, `cargo clippy --workspace --all-targets -- -D warnings` PASS,
  `cargo test --workspace --all-targets --features rust-tests` PASS (0 failures).
- `rg 'mlockall|mlock\b' src` now returns matches in `src/main.rs` (mlockall)
  and `src/optimize/mod.rs` (mlock_block, munlock_block, LOCK_BLOCKS).
- TODO-520 live proof added a finite-limit regression for flag selection after Omega exposed the future-allocation hazard. The systemd path remains fully locked through `LimitMEMLOCK=infinity`; standalone finite-limit runs degrade safely.

## 2026-07-22 Acceptance Reconciliation

TODO-521 reopened this task because the implementation tests cover flag selection and best-effort pool allocation only. No test invokes the production `mlockall` boundary and proves `VmLck > 0` with sufficient privileges or explicitly exercises the documented graceful-skip path. The runtime wiring remains implemented, but the task's required operating-system evidence is missing.

The production boundary is now isolated in `lock_process_memory()` and used unchanged by `run_server()`. Its unit test invokes that exact boundary, asserts `VmLck > 0` when the operating system succeeds, releases the process lock through `munlockall()`, and accepts only documented resource/permission/unsupported errors when the host cannot lock. macOS returned `ENOSYS` and passed the explicit graceful-degradation branch.

Native ARM64 Omega proof used a transient systemd unit with `LimitMEMLOCK=infinity` and the retained release artifact under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-bef00fe`. The live process reported `VmLck: 967860 kB`, logged `Process memory locked against swap (mlockall flags=3)`, and listened on isolated loopback UDP port 54433. The unit stopped cleanly, `MainPID=0`, the port was closed, and all generated certificate/key files plus the temporary proof directory were removed.

Final local verification passes `cargo fmt --all -- --check`, workspace all-target Clippy with `rust-tests` and warnings denied, the two memory-lock tests, and `cargo test --workspace --all-targets --features rust-tests` with 1677 library tests, 16 binary tests, and every integration/runtime target green. TODO-516 is closed again on direct OS evidence rather than implementation presence alone.
