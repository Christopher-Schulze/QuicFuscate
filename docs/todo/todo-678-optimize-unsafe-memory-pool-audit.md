---
id: TODO-678
title: Prove remaining unsafe memory-pool and platform gates
severity: HIGH
phase: S
priority: P0
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-678: Prove remaining unsafe memory-pool and platform gates

## Current execution gate

The historical inventory below records the original source locations and
completed TODO-826..TODO-833 fixes. The production pool is now owned by
`crates/qf-memory-pool/src/lib.rs`, `ownership.rs` and
`zero_copy_buffers.rs`; `src/optimize/unsafe.rs` is test/`unsafe_rust`
gated. Do not reimplement the old findings at deleted
`src/optimize/parts/memory_pool.rs` paths. The remaining parent gate is a
native Miri run of the owned pool/unsafe test targets plus the separately
named Linux/Windows/ISA gates in the successor tasks. The earlier pinned
`1.97.1` component failure is historical: this checkout currently has a
nightly aarch64 toolchain but no installed Miri component. First check that
nightly's component availability and run only the supported owned targets
after the mandatory disk preflight; use an isolated build target and retain
the exact unsupported dependency if the component or test cannot run. This
task is OPEN for that local feasibility and proof step; unavailable native
cells block closure. Record toolchain, target, command, test count, result,
and any unsupported Miri dependency. A newly reproduced failure gets a
source-specific follow-up, not a repeat of the historical fix list.

## Why

`src/optimize/unsafe.rs` is the central unsafe optimization module. It contains the `UnsafeMemoryPool`, `UnsafePacket`, zero-copy I/O, and raw-pointer SIMD helpers. Several functions perform raw pointer arithmetic with `debug_assert!` checks that are stripped in release builds, and the memory pool's field named `tls_cache` is accessed through `UnsafeCell` without actual thread-local storage or thread-affinity verification. `optimize/parts/memory_pool.rs` wraps and extends this behavior.

## Audit Completion Status (2026-08-03)

The source, feature gates, direct callers, wrappers, allocation and lifetime paths, concurrency contracts, tests, scripts, documentation, and relevant history for this owner were read without changing production code or executing a remediation gate. The original inventory below is retained as the historical starting point, and the current-source reconciliation split every confirmed implementation boundary into TODO-826 through TODO-833. Those successor implementations are complete on the available ARM64 macOS workspace. TODO-678 remains blocked only on the parent-level Miri proof and unavailable native Linux/Windows evidence; it is not a claim that those external gates passed.

The `unsafe.rs` module is compiled only under `cfg(all(test, feature = "unsafe_rust"))`. No active production caller of `UnsafeMemoryPool` or `UnsafeCompressor` was found. This narrows runtime reachability but does not close the unsafe API contract, because the explicit feature lane and the Clippy matrix still compile the module. The safe `MemoryPool`, FEC, compression, TUN, transport-frame, and zero-copy-datagram paths are active production surfaces and are tracked separately below.

## Detailed Unsafe-Site Inventory

### `src/optimize/unsafe.rs`

| Line | Unsafe operation | Verified issue | Suggested fix | Regression test |
|------|------------------|----------------|---------------|-----------------|
| 139-191 | `alloc_uninit` / `NonNull::new_unchecked` / `alloc` | `NonNull::new_unchecked` OK; counters updated with two separate `Relaxed` RMWs | Combine into one atomic op or update both with `SeqCst`/`AcqRel` and add invariant `assert!(in_use + available <= capacity)` | Spawn threads allocating/freeing, assert counters match live blocks |
| 146 | `&mut *self.tls_cache.get()` | The field is an `UnsafeCell<Vec<*mut u8>>`, not actual thread-local storage. Cross-thread `Arc` access can race on the same Vec despite the manual `Sync` implementation | Use `thread_local!`, a lock, or a proven owner token; do not rely only on a comment or debug-only thread-ID check | Run pool from multiple threads and check with Miri for UB |
| 159, 175, 190 | `NonNull::new_unchecked` | Null is checked before call; OK but missing documentation link to `alloc` contract | Keep; add explicit `# Safety` note that null was just handled | - |
| 202-234 | `free` / `&mut *self.tls_cache.get()` | Same non-TLS `UnsafeCell` race as `alloc_uninit`; `dealloc` layout is correct | Replace the shared mutable cache with actual thread-local storage or synchronization; define `Release`/`Acquire` pairing for global-pool free/alloc | Concurrent free stress test |
| 240-247 | `copy_from_slice` | `len` is clamped to `block_size`, but `ptr` may be a sub-slice or foreign pointer; the function relies on its unsafe caller contract and debug-only alignment/size assertions | Add a pool token or runtime ownership/range validation where feasible; otherwise make the unsafe precondition explicit and test mismatched pool/pointer use | Fuzz with mismatched pool/pointer |
| 253-263 | `prefetch_block` | Prefetches offsets through 512 bytes even when a pool block is only 64 bytes. The pointer `add` operations are outside the allocation even if a particular CPU treats the prefetch as a non-faulting hint | Clamp the address range to the actual block size and keep the prefetch contract architecture-specific | Run with 64-byte and small blocks on supported architectures |
| 275-290 | `Drop::drop` | `slot.load(Ordering::Relaxed)` is a memory-order/documentation question, but exclusive `&mut self` during drop means the old claim of a proven concurrent visibility race is not established | Review the ownership precondition and use Acquire if required by the publication proof; do not describe this as a demonstrated race without a concurrent-drop path | Verify drop only occurs after all pool users are gone |
| 315-327 | `UnsafePacket::from_raw_parts` | `len` and `capacity` are debug-only checked, so release builds rely entirely on the unsafe caller contract. The current `PhantomData<&'static [u8]>` does not by itself create a use-after-free because `as_slice` borrows `&self` and the packet frees only in its Drop | Enforce or prove the length/capacity and pool-membership contract at construction; remove the misleading lifetime claim from the audit | Pass wrong lengths and wrong-pool pointers through a dedicated unsafe-boundary test |
| 331-337 | `as_slice` | The current reference lifetime is tied to `&self`; no `Clone` implementation or `data()`/`data_mut()` escape was found. The remaining risk is invalid raw parts supplied to the constructor, not a proven phantom-induced use-after-free | Keep constructor invariants explicit and test invalid raw-part admission | Miri test for invalid constructor inputs |
| 349-363 | `extend_from_slice` | Has `new_len > self.capacity` check; uses `ptr::copy_nonoverlapping` from `data` to `self.data` | OK, but convert `debug_assert` in `from_raw_parts` to runtime assert | Test extending beyond capacity |
| 457-514 | `gf256_mul_avx2` | `#[target_feature(enable = "avx2")]`; good safety doc; `slice::from_raw_parts(src_ptr, remainder)` where `src_ptr` is offset by `chunks*32` | Already well documented; verify public caller validates `dst` and `src` have same length (it does `len = min`) | Test with `dst.len() != src.len()` |
| 528-565 | `xor_blocks_avx512` | `#[cfg(all(target_arch="x86_64", target_feature="avx512f"))]` | Public unsafe fn needs caller guarantee; add runtime `is_x86_feature_detected` guard at dispatch | Test on AVX2-only CPU that AVX-512 path is not called |

### `src/optimize/parts/memory_pool.rs`

| Line | Unsafe operation | Verified issue | Suggested fix | Regression test |
|------|------------------|----------------|---------------|-----------------|
| 290-292 | `Layout::from_size_align_unchecked` | The current fallback uses `block_size.max(1)` and `align_of::<u8>().max(1)`, so its local preconditions are constructed safely. The surrounding allocation/layout ownership still needs boundary proof | Keep the checked constructor as the normal path and document why the fallback cannot fail | Exercise zero, overflow, and valid block sizes |
| 295 | `std::alloc::alloc(layout)` | Null check present; OK | - | - |
| 301 | `std::ptr::write_bytes(ptr, 0u8, block_size)` | `block_size` bytes allocated; OK | - | - |
| 302 | `std::slice::from_raw_parts_mut(ptr, block_size)` | OK | - | - |
| 305-307 | `AlignedBox::<[u8]>::from_raw_parts(slice, layout)` | Relies on `AlignedBox` invariants; must track layout for dealloc; no `Drop` visible here | Add `assert!` that `layout.size() == slice.len()` in `AlignedBox::from_raw_parts` and implement `Drop` with `dealloc` | Miri test for `AlignedBox` |
| 315-319 | `libc::madvise` | Ignores return value; not UB but may hide NUMA/hugepage errors | Check return and log warning | - |
| 350 | `mlock_block` | `block.as_mut_ptr()`; `mlock_block` likely calls `libc::mlock` | Ensure `mlock_block` checks return and falls back gracefully | - |
| 731-767, 864-941 | (other unsafe sites) | Need inspection; likely raw pointer copies and `AlignedBox` access | Add per-site `# Safety` comments and runtime bounds checks | - |

## Findings

### 1. `UnsafeMemoryPool::copy_from_slice` has no runtime bounds check
- **File:** `src/optimize/unsafe.rs:240-247`
- **Severity:** HIGH
- **Impact:** The comment claims `len` is clamped to `block_size`, but the function does not verify that `ptr` was allocated from this pool or that it has `block_size` bytes available. A caller passing a shortened sub-slice or a foreign pointer causes out-of-bounds writes.
- **Fix:** Add `debug_assert!` and, where possible, a runtime length/capacity check. Document the exact precondition that `ptr` must be a pool block returned by `alloc_uninit`.

### 2. `UnsafeMemoryPool::tls_cache` is `UnsafeCell<Vec<*mut u8>>` without thread-affinity enforcement
- **File:** `src/optimize/unsafe.rs:47, 146, 202`
- **Severity:** CRITICAL
- **Impact:** `Send` and `Sync` are implemented manually, but `tls_cache` is a normal field, not a `thread_local!` value. A cross-thread call to `alloc_uninit`/`free` through an `Arc<UnsafeMemoryPool>` can race on the same `Vec`.
- **Fix:** Use actual thread-local storage, a lock, or a proven owner token. A debug-only thread-ID assertion is not sufficient for the release safety contract.

### 3. `UnsafeMemoryPool` `in_use`/`available` counters can desync
- **File:** `src/optimize/unsafe.rs:149-150, 167-168, 188, 204-206, 222-223, 232-233`
- **Severity:** MEDIUM
- **Impact:** The counters are updated with separate `Relaxed` operations, and fallback allocations increment `in_use` without adding capacity. Returning a fallback pointer can then increase `available` beyond the preallocated capacity and mix two ownership classes in the cache.
- **Fix:** Track fallback blocks separately or deallocate them directly on return, then define an invariant for `in_use`, `available`, preallocated slots, and fallback allocations.

### 4. `drop` uses `Ordering::Relaxed` for global-pool pointer loads
- **File:** `src/optimize/unsafe.rs:284-289`
- **Severity:** MEDIUM
- **Impact:** `free` stores pointers with `Release`, while `drop` loads with `Relaxed`. Because `drop` has exclusive access, this is not by itself proof of a concurrent race, but the publication and ownership contract is not documented strongly enough to justify the ordering.
- **Fix:** Prove the no-concurrent-drop precondition and use Acquire if the publication proof requires it.

### 5. `prefetch_block` may prefetch beyond allocation
- **File:** `src/optimize/unsafe.rs:253-263`
- **Severity:** LOW
- **Impact:** The loop performs pointer arithmetic through offset 512 for blocks that can be only 64 bytes. Even if hardware ignores the prefetch, the Rust pointer arithmetic is outside the allocation and needs a valid provenance contract.
- **Fix:** Clamp the offsets to the actual block size or remove the optimization for small blocks.

### 6. `UnsafePacket` exposes `data()` and `data_mut()` without lifetime tracking
- **File:** `src/optimize/unsafe.rs:330-380`
- **Severity:** MEDIUM
- **Impact:** The current file has no `data()` or `data_mut()` methods, and `as_slice` returns a reference tied to `&self`. The hardcoded phantom marker is misleading, but the previously claimed phantom-induced use-after-free is not reproduced. Invalid `from_raw_parts` inputs remain the actual boundary risk.
- **Fix:** Enforce constructor invariants and remove or correct the misleading lifetime marker as part of the raw-parts API review.

### 7. Inventory reconciliation: no `copy_to_block` exists at the cited location
- **File:** `src/optimize/parts/memory_pool.rs`
- **Severity:** INFO
- **Impact:** The earlier inventory named `copy_to_block` at lines 236-247, but the current file has no such function there. `alloc_from_slice` copies from a safe slice into an owned `AlignedBox`; the active raw allocation boundary is around `alloc_numa_block` at lines 289-362.
- **Disposition:** Remove the stale `copy_to_block` claim. Continue the audit at the actual `AlignedBox`, `madvise`, NUMA, and mlock boundaries.

### 8. `UnsafeMemoryPool` fallback allocations lack a separate ownership path
- **File:** `src/optimize/unsafe.rs:179-190,197-234`
- **Severity:** HIGH
- **Impact:** A fallback allocation increments `in_use` but not `capacity` or the preallocated-slot ownership. When it is returned, `free` may place the pointer in the TLS/global cache and increment `available`, allowing accounting to exceed configured capacity and changing what `Drop` believes it owns.
- **Fix:** Track fallback blocks separately or deallocate them directly on free; maintain an invariant that cached/global pointers and counters represent the same ownership set.

### 8. `UnsafeCompressor` has an unproven FFI, failure, and concurrency contract
- **File:** `src/optimize/unsafe.rs:611-1188`
- **Severity:** HIGH
- **Impact:** The native and fallback zstd paths use local `c_void` aliases described as placeholder types, but own different pointer representations (`zstd_sys` contexts versus boxed fallback values). `UnsafeCompressor` declares `unsafe impl Sync`, while `compress_direct(&self)` mutates the shared zstd context through per-call `ZSTD_CCtx_setParameter` calls and then compresses without a lock or other serialization. `Sync` therefore permits concurrent calls whose safety is not established by the current comment or implementation. Context allocation failure aborts the process, dictionary allocation failure is silently converted to a no-dictionary compressor, and multiple zstd parameter return codes are ignored. The feature-off and feature-on branches consequently do not have a fully explicit equivalent error, ownership, or concurrency contract.
- **Fix:** Establish the actual zstd context thread-safety rule and either serialize shared use or remove the `Sync` guarantee; replace misleading placeholder terminology with the canonical FFI/fallback ownership model; define and test context, dictionary, parameter, capacity, and compression failure behavior; decide explicitly whether initialization may abort or must return a recoverable error; prove cleanup and feature-on/feature-off parity.
- **Regression test:** Exercise both `compression_zstd_ffi` states, dictionary and no-dictionary paths, every allocation/parameter/compression error branch that can be induced, drop cleanup, and concurrent `compress_direct` calls under the selected `Send`/`Sync` contract.

### 9. The safe `MemoryPool` has a distinct ephemeral and cache ownership failure
- **File:** `src/optimize/parts/memory_pool.rs:412-580, 567-590`
- **Severity:** CRITICAL
- **Impact:** The hard-cap fallback allocates an ephemeral block without incrementing `in_use` or `capacity`, while `free()` decrements `in_use` and may place the same-sized block into TLS or a global queue. This can underflow counters, let the cache contain blocks outside the accounted pool, and make the documented capacity invariant false. The same `free()` boundary accepts any same-sized `AlignedBox`, so foreign pool blocks are not distinguishable from owned blocks.
- **Fix owner:** TODO-827. TODO-689 retains the process-global auto-tuner and cache lifecycle boundary.

### 10. Capacity shrink does not account for TLS-owned blocks and can stop making progress
- **File:** `src/optimize/parts/memory_pool.rs:95-170, 567-590`
- **Severity:** HIGH
- **Impact:** `set_capacity()` removes only queue blocks. When available blocks are held in the thread-local cache, the queue can be empty while `available > 0`; the shrink loop then repeats without reducing `diff`, so a capacity reduction can spin indefinitely. Shrinking also leaves TLS blocks outside the new capacity, and subsequent allocation/free counter operations no longer describe one ownership set.
- **Fix owner:** TODO-827.

### 11. Plain `AlignedBox` drop bypasses pool accounting on active error paths
- **Files:** `src/compress.rs:233-276, 683-731`, `src/interface.rs:593-597`, `src/transport/frames.rs:322-331`
- **Severity:** HIGH
- **Impact:** `MemoryPool::alloc()` returns a plain `AlignedBox<[u8]>`. The dependency's `Drop` deallocates the allocation directly, while `MemoryPool::free()` is the only path that updates `available` and `in_use`. Compression/decompression failure returns, a TUN read error, and a frame-encoding error drop the block directly before the explicit return-to-pool call. This loses pool accounting and reusable capacity even though the success-path documentation presents the block as pool-owned.
- **Fix owner:** TODO-831. FEC-specific failure paths are TODO-832 and zero-copy datagram ownership is TODO-833.

### 12. FEC allocation failure paths bypass the pool return contract and `alloc_from_slice` truncates silently
- **Files:** `src/fec/parts/codecs_and_observers.rs:835-850, 1043-1160, 1261-1355`, `src/fec/wire.rs:506-558`, `src/fec/internal.rs:213-229, 421-477`
- **Severity:** HIGH
- **Impact:** `from_stream_raw()` and GF4/GF8/GF16 repair generation allocate one or more pool blocks and then use `return Err`, `return None`, or `?` without calling `pool.free()`. The wire repair path has the same fallible boundary after data and coefficient allocation. `MemoryPool::alloc_from_slice()` copies only `min(data.len(), block.len())` while callers retain the original length, so an oversized fountain or repair symbol can become a truncated buffer with an overstated logical length.
- **Fix owner:** TODO-832. FEC arithmetic and decoder safety remain TODO-686, TODO-690, TODO-715, and TODO-679 where applicable.

### 13. Feature-gated `DatagramBuffer` stores a pool but never returns its block
- **Files:** `src/transport/connection/parts/types.rs:185-192`, `src/transport/connection/parts/impl_api.rs:299-309`, `src/transport/connection/parts/impl_recv.rs:489-499`
- **Severity:** HIGH
- **Impact:** `DatagramBuffer` contains `data: AlignedBox<[u8]>` and `_pool: Arc<MemoryPool>` but has no `Drop` implementation. Queue pop and connection teardown therefore directly drop the `AlignedBox` instead of returning it through the pool. The Arc keeps the pool alive but does not perform the required accounting transition.
- **Fix owner:** TODO-833.

### 14. `ZeroCopyBuffer` has platform-specific raw-count and narrowing contracts
- **Files:** `src/optimize/parts/memory_pool.rs:774-1070`
- **Severity:** HIGH
- **Impact:** Unix wrappers expose raw `isize` send/receive results and leave partial-count and error interpretation to callers. Windows casts buffer lengths and buffer counts to `u32`, then casts successful byte counts to `i32`, so large valid operations can truncate or become indistinguishable from errors. `zc_batch` delegates into the transport raw-UDP owner without adding a typed boundary.
- **Fix owner:** TODO-830, linked to TODO-682 and TODO-683.

### 15. Allocation layout and process-abort behavior are not a recoverable contract
- **Files:** `src/optimize/unsafe.rs:74-113`, `src/optimize/parts/memory_pool.rs:270-362`
- **Severity:** HIGH
- **Impact:** `UnsafeMemoryPool::new()` rounds `block_size + 63` without checked arithmetic and uses `Layout::from_size_align_unchecked`; zero and overflow values are not rejected by a typed constructor. The safe allocator's fallback `Layout::from_size_align_unchecked` is also not valid for an arbitrarily huge requested size if its constructor boundary is bypassed. Both pools eagerly allocate and use `handle_alloc_error`, while `UnsafeCompressor::new()` aborts on context allocation failure.
- **Fix owner:** TODO-829 for pool layout/allocation policy; TODO-828 for compressor initialization failure. TODO-516 retains mlock release ownership.

### 16. Tests prove normal ownership but do not prove misuse, concurrency, or feature parity
- **Files:** `src/optimize/unsafe.rs` tests, `src/optimize/parts/memory_pool.rs` tests, `scripts/tests/rust/rt-security-suite.rs`, FEC resource tests, `.github/workflows/clippy-matrix.yml`
- **Severity:** HIGH
- **Impact:** Existing tests cover ordinary allocation, free, packet construction, selected SIMD/compression paths, and bounded parallel safe-pool activity. They do not cover cross-thread `UnsafeMemoryPool`, foreign or double-free pointers, fallback accounting, TLS-aware shrink, same-sized foreign `AlignedBox`, compressor concurrency, FFI/fallback parity, pooled error cleanup, or the `zero_copy_dgram` queue teardown. Feature-gated compilation therefore remains the primary evidence for several unsafe surfaces.
- **Fix owner:** TODO-826 through TODO-833 according to boundary; TODO-734 and TODO-730 retain feature-lane and audit-result integrity.

## Acceptance

- All `unsafe` blocks in `optimize/unsafe.rs` and `optimize/parts/memory_pool.rs` have explicit `# Safety` comments matching the actual preconditions.
- Runtime bounds checks exist for every raw pointer write in release builds where feasible.
- The cache is actually synchronized or thread-local; debug-only thread affinity is not the safety mechanism.
- Fallback allocations have an explicit ownership and accounting path separate from preallocated slots.
- Counter invariants hold under panic and concurrent access.
- The zstd FFI and safe fallback paths have explicit ownership, error, null, and feature-parity contracts, and `UnsafeCompressor` has a proven non-concurrent or synchronized context contract.
- Miri clean on the memory-pool test suite.
- Local Rust gates and strict Clippy pass.

## Sub-Tasks

- [x] Read the current source, all direct callers and wrappers, feature gates, tests, scripts, documentation, and relevant history for the umbrella scope.
- [x] Reconcile stale inventory claims and split every confirmed remediation boundary into exactly one owner: TODO-826 through TODO-833.
- [x] Add runtime ownership and bounds checks to `copy_from_slice` where feasible (TODO-826).
- [x] Replace the non-TLS `UnsafeCell` cache with an actually synchronized or thread-local design (TODO-826).
- [x] Fix counter desync in `alloc`/`free` paths (TODO-826 and TODO-827).
- [x] Define fallback-block ownership and correct the capacity counters (TODO-826 and TODO-827).
- [x] Review the `Drop` memory-order proof (TODO-826).
- [x] Clamp or remove `prefetch_block` out-of-allocation pointer arithmetic (TODO-826).
- [x] Correct `UnsafePacket` lifetimes and release constructor contracts (TODO-826).
- [x] Audit and prove `UnsafeCompressor` FFI/fallback ownership, failure handling, and `Send`/`Sync` behavior (TODO-828).
- [ ] Check current nightly Miri availability with a 2-GiB disk reserve, then run the supported owned memory-pool and feature-gated unsafe tests under Miri or retain a precise unsupported-component/dependency result. Keep Linux/Windows/ISA closure evidence separate.
- [x] Add regression tests for pool misuse and ownership transitions (TODO-826); a separate fuzz result is not claimed.

## Notes

- Primary surfaces: `src/optimize/unsafe.rs`, `src/optimize/parts/memory_pool.rs`.
- Active safe-pool callers include compression, FEC, TUN, transport frames, io_uring, and feature-gated DATAGRAM queues. `AlignedBox` drops allocations directly; only `MemoryPool::free()` updates pool accounting.
- TODO-826 owns the feature-gated raw-pointer pool; TODO-827 owns safe-pool capacity, origin, TLS, and counter invariants; TODO-828 owns zstd FFI and `Sync`; TODO-829 owns allocation layouts and recoverability; TODO-830 owns zero-copy syscall wrappers; TODO-831 owns generic pooled-buffer error cleanup; TODO-832 owns FEC cleanup and symbol-length propagation; TODO-833 owns DATAGRAM queue return.
- Existing owners remain separate: TODO-516 for mlock release, TODO-587 for its historical unsafe-copy scope, TODO-646/TODO-687 for io_uring lifecycle, TODO-682/TODO-683 for underlying transport/interface FFI, TODO-689 for auto-tuner and auxiliary optimize contracts, TODO-734 for feature-gated test non-vacuity, and TODO-730 for audit-runner scope/result integrity.

## Deviations

- The audit phase was read-only. TODO-826 through TODO-833 subsequently implemented and locally verified the split ownership boundaries; their individual details retain feature, native-target, disk, and Miri limitations without duplicating them here.

## Verification

- TODO-826 through TODO-833 are complete on the available ARM64 macOS workspace and record their focused tests, library checks, strict Clippy, formatting, and diff evidence in their completed details.
- The parent-level Miri gate is unavailable because the pinned Rust `1.97.1-aarch64-apple-darwin` toolchain has no installed or downloadable Miri component in this environment.
- Native Linux/Windows and native ISA execution remain external boundaries under TODO-682/TODO-683 and the successor details. No external proof is inferred from the ARM64 runs.

## Closure Boundary

The implementation split is closed, but TODO-678 stays `BLOCKED` until the Miri and native-target evidence gates are supplied. Documentation of this boundary was committed as `15838f9f1c06706debf87dae183e59145998b062` (`TASK 678: record memory pool proof boundary`) and pushed with exact local/remote parity. TODO-835, TODO-836, TODO-682, and TODO-683 retain their independent release-safe, safety-proof, transport, and platform boundaries.
