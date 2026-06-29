---
id: TODO-440
title: "Key erasure via zeroize and memory locking (mlock)"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-440: Key erasure via zeroize and memory locking (mlock)

## Problem

Cryptographic key material is not reliably erased from memory, and
sensitive data is not locked against swap-out. This allows key
recovery via memory dumps, core dumps, swap file inspection, and
cold-boot attacks.

### 1. Only ChaCha20Poly1305 keys are zeroized on Drop

The only `Drop` implementation that calls `zeroize` is
`ChaCha20Poly1305` (`src/crypto/mod.rs:141-143`):
```rust
impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
```

The `zeroize` crate is imported at `src/crypto/mod.rs:91`:
```rust
use zeroize::Zeroize;
```

But no other AEAD struct has a `Drop` impl or uses `Zeroize` /
`ZeroizeOnDrop`.

### 2. AES-128-GCM keys are NOT zeroized

`AesGcm128` (`src/crypto/mod.rs:489-496`):
```rust
pub struct AesGcm128 {
    key: [u8; 16],
    iv: [u8; 12],
    #[cfg(target_arch = "x86_64")]
    rk: Option<[core::arch::x86_64::__m128i; 11]>,
}
```

The `key: [u8; 16]` field contains the raw AES key. The `rk` field
contains the expanded round keys (11 × 128-bit = 176 bytes of key
material). Neither is zeroized on `Drop`. When an `AesGcm128` instance
goes out of scope, the key material remains in the heap allocation
until the allocator reuses the memory — which may be never, depending
on allocation patterns.

`AesGcm128` is used for QUIC Initial and Handshake packets
(`src/crypto/mod.rs:571`: `impl AeadSeal for AesGcm128`), so the
initial secret material persists in memory after the handshake
completes.

### 3. AEGIS keys are NOT zeroized

Three AEGIS AEAD wrappers in `src/crypto/aegis.rs` hold key material
that is never zeroized:

- `Aegis128LAead` (line 11-18):
  ```rust
  pub struct Aegis128LAead {
      key: [u8; 16],
      iv: [u8; 12],
      cipher: parking_lot::Mutex<Option<Aegis128L>>,
  }
  ```
  The `key: [u8; 16]` and the `Aegis128L` state (which is derived
  from the key) are not zeroized.

- `Aegis128X4Aead` (line 33-38): same pattern, `key: [u8; 16]` not
  zeroized.
- `Aegis128X8Aead` (line 51-56): same pattern, `key: [u8; 16]` not
  zeroized.

The underlying `Aegis128L` struct (line 518-522) has
`state: [AesBlock; 8]` — 128 bytes of AES state derived from the key
and nonce. The `Aegis128X4` (line 850) and `Aegis128X8` (line 1189)
structs hold 4× and 8× the state, respectively. None of these
implement `Drop` with zeroization.

### 4. MORUS keys are NOT zeroized

`MorusAead` (`src/crypto/morus.rs:970-974`):
```rust
#[derive(Clone)]
pub struct MorusAead {
    key: [u8; 16],
    iv: [u8; 12],
}
```

No `Drop` impl. The `key: [u8; 16]` is not zeroized. `MorusAead` is
used as the data-plane AEAD when `CryptoAeadPlan::Morus` is selected
(`src/crypto/mod.rs:719-720, 739`), so long-lived connections have
MORUS key material in memory for the entire session duration.

### 5. No mlock for sensitive data

There are no calls to `mlock`, `mlockall`, or any memory-locking
function anywhere in the codebase. A grep for `mlock` returns zero
results. The `MemoryPool` (`src/optimize/mod.rs:2118-2126`):
```rust
pub struct MemoryPool {
    pools: Vec<Arc<SegQueue<AlignedBox<[u8]>>>>,
    block_size: usize,
    ...
}
```
allocates buffers that are used for crypto operations (packet
encryption/decryption), but these buffers are not locked in RAM. The
kernel may swap them to disk at any time, where they persist across
reboots and can be recovered by an attacker with disk access.

### 6. No mlockall on server start

The server process does not call `mlockall(MCL_CURRENT | MCL_FUTURE)`
on startup. This means all of the server's address space — including
QKey tokens, TLS secrets, AEAD keys, and session state — is eligible
for swapping.

## Goal

- All AEAD key material (AES-GCM, AEGIS, MORUS, ChaCha20Poly1305) is
  zeroized on `Drop` via `ZeroizeOnDrop`.
- TLS secret material and QKey tokens are zeroized after use.
- `MemoryPool` blocks containing crypto data are locked with `mlock`.
- The server calls `mlockall(MCL_CURRENT | MCL_FUTURE)` on startup to
  prevent any address space from being swapped.
- Tests verify that `zeroize` is called on `Drop` and that `mlock`
  returns 0.

## Implementation Plan

### Step 1: Add `ZeroizeOnDrop` to `AesGcm128`

**File:** `src/crypto/mod.rs`

- Add `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` to the
  `AesGcm128` struct (line 489):
  ```rust
  use zeroize::{Zeroize, ZeroizeOnDrop};

  #[derive(ZeroizeOnDrop)]
  pub struct AesGcm128 {
      key: [u8; 16],
      iv: [u8; 12],
      #[cfg(target_arch = "x86_64")]
      rk: Option<[core::arch::x86_64::__m128i; 11]>,
  }
  ```
- The `ZeroizeOnDrop` derive macro automatically implements `Drop`
  by calling `self.key.zeroize()` and `self.iv.zeroize()`. For the
  `rk` field (which is `__m128i` arrays, not plain bytes), implement
  a manual `Drop` that zeroizes the expanded key schedule:
  ```rust
  impl Drop for AesGcm128 {
      fn drop(&mut self) {
          self.key.zeroize();
          self.iv.zeroize();
          #[cfg(target_arch = "x86_64")]
          if let Some(ref mut rk) = self.rk {
              for word in rk.iter_mut() {
                  // SAFETY: __m128i is a POD type; zeroing via store is safe
                  unsafe {
                      *word = std::arch::x86_64::_mm_setzero_si128();
                  }
              }
          }
      }
  }
  ```

### Step 2: Add `ZeroizeOnDrop` to AEGIS AEAD wrappers

**File:** `src/crypto/aegis.rs`

- For `Aegis128LAead` (line 11), `Aegis128X4Aead` (line 33), and
  `Aegis128X8Aead` (line 51):
  - Add `use zeroize::{Zeroize, ZeroizeOnDrop};`
  - Derive `ZeroizeOnDrop` on each struct (the derive handles
    `key: [u8; 16]` and `iv: [u8; 12]`).
  - The `cipher: Mutex<Option<Aegis128L>>` field holds the AES state.
    Implement a manual `Drop` that locks the mutex and zeroizes the
    state:
    ```rust
    impl Drop for Aegis128LAead {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
            if let Some(ref mut cipher) = *self.cipher.lock() {
                for word in cipher.state.iter_mut() {
                    // Zeroize each AesBlock (128 bits)
                    // AesBlock is [u8; 16] or similar — zeroize in place
                    word.zeroize();
                }
            }
        }
    }
    ```
- For the underlying `Aegis128L` (line 518), `Aegis128X4` (line 850),
  `Aegis128X8` (line 1189) structs: implement `Zeroize` on the
  `state` field (array of `AesBlock`). If `AesBlock` is a wrapper
  around `[u8; 16]`, derive or impl `Zeroize` for `AesBlock`.

### Step 3: Add `ZeroizeOnDrop` to `MorusAead`

**File:** `src/crypto/morus.rs`

- Add `use zeroize::{Zeroize, ZeroizeOnDrop};` at the top of the file.
- Derive `ZeroizeOnDrop` on `MorusAead` (line 970):
  ```rust
  #[derive(Clone, ZeroizeOnDrop)]
  pub struct MorusAead {
      key: [u8; 16],
      iv: [u8; 12],
  }
  ```
  The derive handles `key` and `iv` automatically. Note: `Clone` is
  already derived; `ZeroizeOnDrop` is compatible with `Clone` (the
  clone retains the key, but each copy zeroizes independently on
  drop).

### Step 4: Zeroize TLS secret material

**File:** `src/qftls.rs`, `src/crypto/mod.rs`

- Audit all TLS-related key material in `src/qftls.rs` and the TLS
  handshake path in `src/crypto/mod.rs`.
- Add `ZeroizeOnDrop` to any struct holding TLS secrets (e.g.
  handshake keys, traffic secrets, exporter secrets).
- If TLS secrets are stored as `Vec<u8>` or `[u8; N]`, wrap them in
  `zeroize::Zeroizing<Vec<u8>>` or derive `ZeroizeOnDrop` on the
  containing struct.
- Specifically check `AesGcm128` instances created for Initial /
  Handshake protection — these are now covered by Step 1.

### Step 5: Zeroize QKey tokens after use

**File:** `src/implementations/server/qkey_registry.rs`,
`src/implementations/server/mod.rs`

- In `QKeyRecord` (line 62), the `token_sha256: Vec<u8>` field is a
  SHA-256 hash (not the raw token), but the raw token is handled
  during `insert_with_ttl` (line 150). Wrap the raw token parameter
  in `zeroize::Zeroizing<&[u8]>` or zeroize the local variable after
  hashing.
- In `parse_live_server_initial_auth` (the function that extracts the
  QKey token from the initial packet), zeroize the token buffer after
  the SHA-256 hash is computed.
- In `QKeyAuthState` (the struct at `mod.rs:1942`), if it holds the
  raw token or token hash, ensure `expected_token_sha256` is zeroized
  on drop.

### Step 6: Add `mlock` to `MemoryPool` blocks

**File:** `src/optimize/mod.rs`

- In `MemoryPool::new` (line 2127) or in the block allocation path,
  after allocating each `AlignedBox<[u8]>`, call `mlock` on the
  block's memory:
  ```rust
  #[cfg(unix)]
  unsafe {
      let ptr = block.as_ptr() as *const libc::c_void;
      let len = block.len();
      if libc::mlock(ptr, len) != 0 {
          log::warn!("mlock failed for MemoryPool block: {}", std::io::Error::last_os_error());
      }
  }
  ```
- In the block deallocation path (when a block is removed from the
  pool or the pool is dropped), call `munlock` and `zeroize` the
  block before freeing:
  ```rust
  #[cfg(unix)]
  unsafe {
      libc::munlock(ptr as *const libc::c_void, len);
  }
  block.zeroize();
  ```
- Add a `lock_blocks: bool` config field to `MemoryPool` (default:
  `true` on server, `false` on client to avoid requiring elevated
  privileges on client systems where `RLIMIT_MEMLOCK` may be low).
- On non-Unix (Windows), use `VirtualLock` / `VirtualUnlock`.

### Step 7: Add `mlockall` on server startup

**File:** `src/implementations/server/mod.rs` or `src/main.rs`

- After the server binds its UDP socket, opens the TUN interface, and
  sets up routing/iptables (i.e. after all privileged operations are
  complete), call:
  ```rust
  #[cfg(target_os = "linux")]
  unsafe {
      let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
      if libc::mlockall(flags) != 0 {
          log::warn!("mlockall failed: {}. Process memory may be swapped to disk.", std::io::Error::last_os_error());
      }
  }
  ```
- This should be called **before** any key material is loaded into
  memory (QKey registry, TLS certificates, etc.) so that `MCL_FUTURE`
  locks all future allocations.
- Add a `lock_memory: bool` config field (default: `true` on server).
- On systemd, ensure `LimitMEMLOCK=infinity` is set in the service
  file (`scripts/install/quicfuscate-server.service`).

### Step 8: Update systemd service file for mlockall

**File:** `scripts/install/quicfuscate-server.service`

- Add `LimitMEMLOCK=infinity` to the `[Service]` section to allow
  `mlockall` to lock all process memory:
  ```ini
  LimitMEMLOCK=infinity
  ```

### Step 9: Tests

**File:** `src/crypto/mod.rs`, `src/crypto/aegis.rs`,
`src/crypto/morus.rs` (inline tests), `tests/key_erasure_test.rs` (new)

- Unit test: Create an `AesGcm128` instance, encrypt a packet, drop
  the instance. Allocate a new buffer of the same size and verify
  the key bytes are not present (the memory was zeroized). This test
  is probabilistic but catches obvious non-zeroization.
- Unit test: Create an `Aegis128LAead`, drop it. Verify the key field
  is zero (use a test-only accessor or inspect via unsafe pointer
  read before the allocation is freed).
- Unit test: Create a `MorusAead`, drop it. Verify the key field is
  zero.
- Unit test (Unix): `mlock` on a `MemoryPool` block returns 0 (when
  running with sufficient privileges). `munlock` returns 0.
- Unit test (Linux): `mlockall(MCL_CURRENT | MCL_FUTURE)` returns 0
  (when running as root or with `CAP_IPC_LOCK`).
- Integration test: Start the server with `lock_memory = true`.
  Verify `mlockall` was called (check `/proc/<pid>/status` for
  `VmLck` > 0 on Linux).
- Test: Verify no key material appears in a core dump (if core dumps
  are enabled). This is a manual / CI-specific test.

## Files to Modify/Create

- `src/crypto/mod.rs` — add `ZeroizeOnDrop` / manual `Drop` to
  `AesGcm128`, audit TLS secret zeroization
- `src/crypto/aegis.rs` — add `ZeroizeOnDrop` / manual `Drop` to
  `Aegis128LAead`, `Aegis128X4Aead`, `Aegis128X8Aead`; impl
  `Zeroize` for `AesBlock`, `Aegis128L`, `Aegis128X4`, `Aegis128X8`
- `src/crypto/morus.rs` — derive `ZeroizeOnDrop` on `MorusAead`
- `src/implementations/server/qkey_registry.rs` — zeroize raw QKey
  tokens after hashing
- `src/implementations/server/mod.rs` — zeroize QKey token in auth
  path, add `mlockall` on startup
- `src/optimize/mod.rs` — add `mlock`/`munlock` to `MemoryPool`
  blocks, add `lock_blocks` config
- `src/qftls.rs` — zeroize TLS secret material
- `scripts/install/quicfuscate-server.service` — add
  `LimitMEMLOCK=infinity`
- `src/engine/config.rs` — add `lock_memory` config field
- `tests/key_erasure_test.rs` — **new**: tests for zeroize and mlock

## Acceptance Criteria

- [ ] `AesGcm128` implements `Drop` that zeroizes `key`, `iv`, and
      `rk` (expanded round keys).
- [ ] `Aegis128LAead`, `Aegis128X4Aead`, `Aegis128X8Aead` implement
      `Drop` that zeroizes `key`, `iv`, and cipher state.
- [ ] `MorusAead` derives `ZeroizeOnDrop` (key and iv zeroized on
      drop).
- [ ] `ChaCha20Poly1305` continues to zeroize on `Drop` (no
      regression).
- [ ] QKey raw tokens are zeroized after SHA-256 hashing.
- [ ] `MemoryPool` blocks are `mlock`ed on allocation and
      `munlock`ed + zeroized on deallocation (Unix).
- [ ] Server calls `mlockall(MCL_CURRENT | MCL_FUTURE)` on startup
      when `lock_memory = true`.
- [ ] `scripts/install/quicfuscate-server.service` includes
      `LimitMEMLOCK=infinity`.
- [ ] `lock_memory` and `lock_blocks` are configurable.
- [ ] Tests verify `zeroize` is called on `Drop` for each AEAD.
- [ ] Tests verify `mlock` returns 0 (when run with privileges).
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| `Drop` zeroize overhead | < 100 ns | `memset` on 16-176 bytes; negligible |
| `mlock` per MemoryPool block | < 10 µs | Single syscall per block; 4096-byte blocks |
| `mlockall` on startup | < 1 ms | Single syscall; locks entire address space |
| Locked memory (server) | ~10-50 MB | Depends on connection count and buffer pool size |
| `RLIMIT_MEMLOCK` requirement | infinity | Set via systemd `LimitMEMLOCK=infinity` or `ulimit -l` |
