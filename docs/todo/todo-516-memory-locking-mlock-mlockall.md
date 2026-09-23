---
id: TODO-516
title: Prove current process and pool memory-lock lifecycle
severity: HIGH
phase: S
priority: P1
status: BLOCKED
created: 2026-07-03
depends_on: [TODO-440, TODO-511]
---

# TODO-516: Prove current process and pool memory-lock lifecycle

## Current execution gate

The dated sections below describe earlier implementation and reopening
stages. Current process-lock ownership is
`crates/qf-memory-lock/src/lib.rs`; per-block ledger, zeroization and
`munlock_block` are in `crates/qf-memory-pool/src/lib.rs` and
`ownership.rs`. The former `src/optimize/parts/memory_pool.rs` path is
historical, and the old zero-match/absent-unlock statements are not current
source claims. The remaining BLOCKED acceptance is a fresh privileged
post-extraction native server/pool lifecycle proof at an exact revision:
observe successful `VmLck`, block lock/unlock balance through allocation,
cache return, shrink and teardown, and zero residual locked pages after
process exit. Run the current focused and workspace gates at that revision;
record any unavailable privilege/platform gate explicitly. Do not replay
the completed implementation from the historical checklist.

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
- [x] Every successful MemoryPool `mlock` has a matching release owner and
      `munlock`/zeroization path on deallocation.

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
- `mlock_block()` helper function in
  `src/optimize/parts/memory_pool.rs` - best-effort, logs on failure, and has
  no panic. No `munlock_block()` implementation is present in the current
  source. Non-Unix remains a no-op.
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
- `rg 'mlockall|mlock\b' src` returns matches in the server startup path and
  `src/optimize/parts/memory_pool.rs` (`mlock_block`, `LOCK_BLOCKS`). A
  matching `munlock` production call is not present in the current source.
- TODO-520 live proof added a finite-limit regression for flag selection after Omega exposed the future-allocation hazard. The systemd path remains fully locked through `LimitMEMLOCK=infinity`; standalone finite-limit runs degrade safely.

## 2026-07-22 Acceptance Reconciliation

The exhaustive acceptance reconciliation reopened this task because the implementation tests covered flag selection and best-effort pool allocation only. No test invoked the production `mlockall` boundary and proved `VmLck > 0` with sufficient privileges or explicitly exercised the documented graceful-skip path. The runtime wiring remained implemented, but the task's required operating-system evidence was missing.

The production boundary is now isolated in `lock_process_memory()` and used unchanged by `run_server()`. Its unit test invokes that exact boundary, asserts `VmLck > 0` when the operating system succeeds, releases the process lock through `munlockall()`, and accepts only documented resource/permission/unsupported errors when the host cannot lock. macOS returned `ENOSYS` and passed the explicit graceful-degradation branch.

Native ARM64 Omega proof used a transient systemd unit with `LimitMEMLOCK=infinity` and the retained release artifact under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-bef00fe`. The live process reported `VmLck: 967860 kB`, logged `Process memory locked against swap (mlockall flags=3)`, and listened on isolated loopback UDP port 54433. The unit stopped cleanly, `MainPID=0`, the port was closed, and all generated certificate/key files plus the temporary proof directory were removed.

Final local verification passes `cargo fmt --all -- --check`, workspace all-target Clippy with `rust-tests` and warnings denied, the two memory-lock tests, and `cargo test --workspace --all-targets --features rust-tests` with 1677 library tests, 16 binary tests, and every integration/runtime target green. TODO-516 is closed again on direct OS evidence rather than implementation presence alone.

## 2026-08-03 Audit Reopening

The current-source audit reopened TODO-516. `src/optimize/parts/memory_pool.rs`
calls `mlock_block()` when block locking is enabled, but the repository has no
`munlock`, `munlock_block`, or `VirtualUnlock` implementation outside the
process-wide test call to `munlockall()`. The historical completion evidence
above therefore does not prove the required MemoryPool release lifecycle and
must not be used as current acceptance evidence. The process-wide `mlockall`
boundary, configuration fields, and best-effort allocation lock remain
implemented; block release ownership, unlock, and zeroization are open again.

The qftls preloaded-key lock is tracked separately in TODO-643. The broader
raw-pointer and unsafe MemoryPool review remains tracked in TODO-678.

## 2026-08-04 Local Implementation

- `BlockLockLedger` records only successful `mlock` calls for each `MemoryPool` instance and removes the entry exactly once before `munlock`.
- `MemoryPool::free()` owns the caller return boundary; full-queue disposal, capacity shrink, pool `Drop`, and thread-local cache `Drop` zeroize and unlock before the `AlignedBox` allocation is released.
- The pool captures `lock_blocks` at construction so toggling the process flag later cannot strand a lock or suppress its release path. Thread-local cache entries retain the ledger after pool destruction and release their blocks when the owning thread drops the cache.
- Focused verification passed: `cargo fmt --all -- --check`, `cargo check --lib --features rust-tests`, `cargo clippy --lib --features rust-tests -- -D warnings`, the five-test `memory_pool` filter, and the three-test `mlock_tests` filter. A small `BoxedDataAeadPair` alias removes an unrelated active `type_complexity` diagnostic needed by the library Clippy gate.
- The full workspace test gate reached 2,204/2,206 passing tests. The two unrelated failures are `dns::tests::test_doh_client_is_cached_and_shared` due unavailable DNS resolution for `cloudflare-dns.com` and `qftls::tests::rustls_client_hello_policy_excludes_chacha_for_chrome_and_firefox` due its existing `initial ClientHello` assertion.
- The full workspace Clippy gate remains non-pass on three unrelated existing diagnostics: one `type_complexity` return type in `src/implementations/client/backend.rs:717` and two `needless_borrow` calls in `src/implementations/client/dns_runtime.rs:279,289`. Those are separate ownership/lint boundaries and were not absorbed into TODO-516.
- The implementation is locally complete, but a fresh native post-change Omega proof and remote push remain blocked: the local SSH client fails before connection with `No user exists for uid 501`, and GitHub push currently fails DNS resolution for `github.com`.
