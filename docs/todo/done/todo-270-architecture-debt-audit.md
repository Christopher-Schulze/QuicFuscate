# TODO-270: Architecture Debt Audit - CRITICAL FINDINGS

## Severity: CRITICAL (errors) / HIGH (design) / MEDIUM (config)

**Date:** 2026-03-22
**Rating:** C+ (Production-capable with significant technical debt)

---

## CRITICAL - Must Fix

### 1. Incompatible Error Types (Severity: CRITICAL)
**Location:** `src/lib.rs:Error` vs `src/transport/Error`

Two separate error types with no `From` relationship:
- `crate::error::ConnectionError` 
- `crate::transport::Error`

**Impact:** Error propagation across module boundaries requires manual matching or lossy `.map_err()` conversion. Forces callers to handle two different error types for what should be a unified error domain.

**Fix:** Implement `From<transport::Error> for ConnectionError` (or vice versa) and audit all call sites for missing conversions.

---

### 2. Untracked JoinHandle in Reality Proxy (Severity: CRITICAL)
**Location:** `src/reality.rs:87`

```rust
tokio::spawn(reality_proxy_loop(...));
```

No `JoinHandle` stored. If the reality proxy task panics after spawn, the panic is silently lost and the fallback never starts.

**Fix:** Store `JoinHandle<()>` in `RealityProxy` struct and `.await` or `.abort()` on drop.

---

## HIGH - Should Fix

### 3. Circular Dependency: TransportObserver -> brain.rs
**Location:** `src/transport.rs:TransportObserver` -> `src/brain.rs`

`FecTransportObserver` in `transport.rs` calls `brain.adaptive_fec_policy()` which returns a policy that references `brain` internals. This creates a tight coupling loop.

**Fix:** Extract `TransportObserver` trait to `src/transport/observer.rs` and make policy references opaque (trait objects or sealed traits).

---

### 4. Layer Violations: Domain/Application/Infrastructure Leakage
**Location:** `src/transport/connection.rs` (3168 lines)

`Connection<...>` struct mixes:
- **Domain:** QUIC state machine, frame types, packet numbers
- **Application:** H3 event handling, stream windows
- **Infrastructure:** UDP socket I/O, buffer management

**Fix:** Extract `Connection<...>` into `transport/connection/` with clear submodule boundaries. Split frames.rs, packet.rs, h3.rs into separate files.

---

### 5. Global Mutable State Via Atomics
**Location:** Multiple brain hint atomics (`BRAIN_HINT_*`)

Brain hints passed as `AtomicU64` globals rather than structured channels. Makes testing parallelism hard and hides data flow.

**Fix:** Replace global hints with `Sender<BrainHint>` channel passed to transport during initialization.

---

### 6. pub(crate) Overuse Blocks Testing
**Location:** Throughout `src/transport/`, `src/fec/`, `src/stealth/`

Excessive `pub(crate)` visibility prevents unit testing these modules in isolation without integration test harness.

**Fix:** Identify key public APIs needed for testing; add targeted `pub` for test-only interfaces behind `#[cfg(test)]` or a `test-utils` module.

---

## MEDIUM - Consider Fixing

### 7. Feature Flag Explosion (25+ flags)
**Location:** `Cargo.toml`

Flags: `aes`, `avx2`, `avx512f`, `gfni`, `neon`, `sse2`, `sve2`, `vaes`, `aggressive_inline`, `compression_zstd_ffi`, `crc`, `orchestrator`, `pq`, `internal_af_xdp_experimental`, `rust_fuzz`, `blake3`, `memmap2`, `socket`, `tokio_unstable`, `unsafe`, `fuzzing`, `danger天真` (transliterated), `fec_test`, `bench`, `elk`...

**Fix:** Consolidate into meta-features:
- `cpu-simd` (enables all SIMD variants)
- `stealth-all` (enables all stealth features)  
- `experimental` (pq, xdp, fuzzing)
- `test` (fuzzing, bench, fec_test)

---

### 8. Missing Backpressure in FEC Pipeline
**Location:** `src/fec/mod.rs`

FEC encoding/decoding can buffer unbounded packets if encoding is slower than wire rate.

**Fix:** Add bounded channels with `Backpressure` metric emitted to brain.

---

### 9. No Async Runtime Isolation
**Location:** `src/reality.rs` uses tokio; `src/core.rs` creates separate runtime

Reality proxy spawns tasks on tokio runtime created in `core.rs`, but there's no guarantee the runtime lives long enough.

**Fix:** Document runtime lifetime requirements; ensure `RealityProxy` drops before runtime shutdown.

---

### 10. Configuration Management: Inconsistent Defaults
**Location:** Multiple `Default` impls scattered across modules

No centralized config validation. Some defaults are zero, some are "sensible", no enforced ranges.

**Fix:** Centralize all config in `src/config.rs` with `#[validate]` annotations.

---

## Module Boundary Issues

| File | Lines | Issue |
|------|-------|-------|
| `stealth/mod.rs` | 5335 | Monolith - mixes XOR, domain fronting, probe detection, cover traffic, MASQUE |
| `fec/mod.rs` | 4598 | Monolith - mixes Reed-Solomon, fountain codes, adaptive controller |
| `transport/connection.rs` | 3168 | Monolith - QUIC connection + H3 + recovery + framing |
| `optimize/simd.rs` | 6200 | Large but cohesive - acceptable as "machine room" |

---

## Dependency Health

**Count:** 52 direct dependencies
**Status:** No critical vulnerabilities found, but `aead` still on rc.10

**Concerns:**
- `tokio` with `features = ["full"]` (TODO-149: partial fix, could trim more)
- `ring` for crypto (acceptable, standard)
- `rustls` + `webpki` (sound TLS stack)

---

## Testability Assessment

**Score:** B (Good)

Strengths:
- 417 tests, all green
- Fuzz targets present
- Property-based tests added

Weaknesses:
- `pub(crate)` limits unit test isolation
- No mock transport for FEC testing
- Integration tests require full stack

---

## API Design Issues

1. **`ConnectionId` heap allocation** (FIXED in TODO-258)
2. **Missing `Send`/`Sync` bounds on `TransportObserver`** - prevents safe sharing across tasks
3. **`Transport::new()` consumes `self`** - prevents connection reuse without re-binding sockets

---

## Error Propagation Analysis

**Score:** D+ (Poor)

- `crate::error::ConnectionError` and `crate::transport::Error` are incompatible
- `?` operator usage inconsistent - some paths drop context
- No centralized error domain - errors lose meaning when crossing module boundaries

**Required fix:** Unify error types behind a single `QuicFuscateError` enum with `source()` chaining.

---

## Recommendations (Priority Order)

1. **Immediate:** Fix error type incompatibility (blocks clean error propagation)
2. **Immediate:** Track `JoinHandle` in RealityProxy (blocks reliability)
3. **High:** Extract `TransportObserver` trait to break circular deps
4. **High:** Replace global atomics with typed channels
5. **Medium:** Feature flag consolidation
6. **Medium:** Centralize configuration validation
7. **Low:** Module extraction (stealth, fec) - only if needed for testability

---

## Files Analyzed

- `src/lib.rs` - Error types and exports
- `src/main.rs` - CLI and benchmarks
- `src/core.rs` - Connection lifecycle
- `src/transport.rs` - Transport module root
- `src/transport/connection.rs` - QUIC connection (3168 lines)
- `src/stealth/mod.rs` - Stealth module (5335 lines)
- `src/brain.rs` - Adaptive policy engine (1508 lines)
- `src/fec/mod.rs` - FEC module (4598 lines)
- `src/crypto/mod.rs` - Crypto module (948 lines)
- `src/qftls.rs` - TLS provider (1864 lines)
- `src/reality.rs` - Reality proxy (206 lines)
- `src/engine/engine.rs` - Engine control plane (1422 lines)
- `src/implementations/server/mod.rs` - Server runtime (4520 lines)
- `src/implementations/client/mod.rs` - Client runtime (492 lines)
- `src/optimize/mod.rs` - Optimization module (3293 lines)
- `Cargo.toml` - 52 dependencies, 25+ feature flags

