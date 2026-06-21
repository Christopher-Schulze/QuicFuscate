# QuicFuscate SIMD & Hardware Acceleration Matrix

This document is the authoritative map for every hardware-accelerated path in QuicFuscate. It captures the runtime profile concept, the coverage that is already implemented, and the remaining opportunities - all in one place. Whenever new acceleration work happens, update this file (and only this file) so engineering, QA, and docs stay aligned.

## 1. Runtime Strategy & Profile Concept

### Legend & Notation
- **Coverage markers**: `OK` fully implemented & parity-tested, `WARN` partial/prototype, `NO` missing.
- **Telemetry** references the counters exported via `optimize::telemetry::dump` (names mirror snake_case).
- **Validation** lists the canonical tests or benchmark scripts we rely on when touching the respective backend.
- **Profiles** are mutually exclusive; once the runtime picks one profile, every module follows that decision to avoid mixed dispatch.

### 1.1 Profile Sets (Feature Bundles)

| Profile ID | Feature Set (detected by `FeatureDetector`) | Typical CPUs | Default Accelerations | Telemetry (examples) | Validation & Benches |
| --- | --- | --- | --- | --- | --- |
| `X86_P0a` | SSE2 baseline (no AES) | Pentium 4, early Core2 | SSE2 XOR/memcpy, scalar crypto | `SIMD_USAGE_SCALAR`, `ITER_SUM_SCALAR_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs`, `scripts/tests/rust/rt-bitmap-range-parity.rs` |
| `X86_P0b` | SSSE3 (byte-shuffle) | Core2 (Merom/Penryn) | SSSE3 base64 & GF LUTs | `FEC_SSSE3_OPS`, `BASE64_ENC_SSSE3_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs::gf_mul_slice_telemetry_tracks_backend` |
| `X86_P1a` | SSE4.2 + POPCNT + CRC32 | Westmere, Sandy Bridge | POPCNT bitmaps, CRC32 fast paths | `CRC32_SSE42_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` |
| `X86_P1b` | `P1a` + AES-NI + PCLMULQDQ | Ivy/Haswell (no AVX) | AES-GCM hardware, GHASH | `AES_BLOCK_AESNI_OPS`, `GHASH_PCLMUL_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `scripts/benchmarks/micro/micro-aes-gcm.sh` |
| `X86_P1f` | `P1b` + AVX | Ivy Bridge AVX | AVX gather/prefetch helpers | `AVX2_OPS` (prefetch) | `scripts/tests/rust/rt-iter-reductions.rs` |
| `X86_P2a` | `P1b` + AVX2 | Haswell/Broadwell | AVX2 FEC / transport kernels | `FEC_AVX2_GF_OPS`, `CONGESTION_AVX2_BATCHES` | `scripts/tests/rust/rt-packet-number-parity.rs`, `scripts/benchmarks/suites/bench-fec.sh` |
| `X86_P2b` | `P2a` + BMI2 + LZCNT | Haswell refresh, Skylake | BMI2 varint/bitmap ops | `VARINT_BMI2_OPS`, `ACK_MERGE_BMI2_OPS` | `scripts/tests/rust/rt-varint-roundtrip.rs`, `scripts/tests/rust/rt-ack-merge-parity.rs` |
| `X86_P3a` | AVX-512F baseline | Xeon Skylake-SP, Ice Lake | AVX-512 XOR/memcpy/FEC | `AVX512_OPS`, `FEC_AVX512_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs`, `scripts/benchmarks/suites/bench-fec.sh` |
| `X86_P3b` | `P3a` + VAES + VPCLMULQDQ | Ice Lake, Sapphire Rapids | VAES GHASH, AES-X8 lanes | `AES_BLOCK_VAES_OPS`, `GHASH_VPCLMUL_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `scripts/benchmarks/micro/micro-aes-gcm.sh` |
| `X86_P3c` | `P3b` + VBMI2 | Sapphire Rapids | VBMI2 pattern/histogram kernels | `PATTERN_AVX512_VBMI2_OPS` | `scripts/benchmarks/suites/bench-stealth.sh` |
| `X86_P3d` | `P3c` + VPOPCNTDQ | Sapphire Rapids | Bitmap popcount | `ECN_VPOPCNTDQ_OPS` | `scripts/tests/rust/rt-ecn-popcount.rs` |
| `X86_P3e` | `P3d` + GFNI (+ optional AMX) | Sapphire/Emerald Rapids | GFNI GF(256), AMX Wiedemann, GFNI padding | `FEC_GFNI_OPS`, `STEALTH_PADDING_GFNI_OPS`, `WIEDEMANN_AMX_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs`, `tests/fec::matrix_multiply_avx512_matches_scalar_when_available` |
| `X86_P4a` | AVX10.1 (256-bit vectors, legacy AVX-512 reuse) | Next-gen AVX10 client CPUs | Reuses AVX2/AVX-512 kernels via AVX10 dispatch | `SIMD_USAGE_AVX10_256`, `SIMD_USAGE_AVX2` | `scripts/tests/smoke/smoke-avx10.sh` (skip if unavailable) |
| `X86_P4b` | `P4a` + AVX10.1 (512-bit vectors) | Next-gen AVX10 server/HPC CPUs | Reuses AVX-512 GF/crypto kernels; AVX10 telemetry captured separately | `SIMD_USAGE_AVX10_512`, `AVX512_OPS` | `scripts/tests/smoke/smoke-avx10.sh`, `scripts/benchmarks/micro/micro-aes-gcm.sh` |
| `ARM_A0` | NEON baseline | Cortex-A53 | NEON XOR, ChaCha20/Poly1305 | `NEON_OPS`, `PATTERN_NEON_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs`, `scripts/benchmarks/micro/micro-crypto-all.sh` |
| `ARM_A1a` | `A0` + CRC32 | Cortex-A57 | NEON CRC32/DoH | `CRC32_ARM_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` |
| `ARM_A1b` | `A1a` + AES | Cortex-A72 | NEON AES TLS Cover | `AES_BLOCK_NEON_TABLE_OPS`, `AES_CTR_NEON_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs` |
| `ARM_A1c` | `A1b` + PMULL | Cortex-A75+ | GHASH PMULL | `GHASH_PMULL_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `scripts/tests/rust/rt-telemetry-counters.rs` |
| `ARM_A1d` | `A1c` + SHA | Cortex-A76+ | SHA-256 hardware | `SHA256_NEON_OPS`, `HMAC_SHA256_NEON_OPS` | `cargo test sha256_matches_reference --lib` |
| `ARM_A2` | SVE2 (+ optional crypto) | Neoverse V1, N2 | SVE2 XOR/memcpy, GF kernels, pattern inject, QUIC varint | `SVE2_OPS`, `FEC_SVE2_OPS`, `PATTERN_SVE2_OPS` | Planned SVE2 CI (Task 9) |
| `Apple_M` | NEON + AES/PMULL + Apple AMX | M1/M2/M3 | NEON crypto, AMX matmul | `NEON_OPS`, `APPLE_AMX_OPS` | `scripts/benchmarks/micro/micro-crypto-all.sh`, `scripts/tests/rust/rt-telemetry-counters.rs` |
| `Scalar` | fallback | any | Scalar reference implementations | `SIMD_USAGE_SCALAR`, `SCALAR_OPS` | Full unit/integration suite |

*Profiles are deterministic: once `FeatureDetector` resolves a profile, every module (crypto, fec, transport, stealth, brain, memory) queries the same profile to pick its fastest backend. This keeps decisions consistent across the stack.*

### 1.4 Profile -> Module Acceleration Map

| Profile ID | Instruction Flags (subset) | Key Backends & Hotpaths | Telemetry Hooks | Validation |
| --- | --- | --- | --- | --- |
| `X86_P1a` | `SSE4.2`, `POPCNT`, `CRC32`, `SSE2` | CRC32 + POPCNT utilities (`simd::crc32`, `accelerate::string`) | `CRC32_SSE42_OPS`, `PATTERN_SCALAR_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` |
| `X86_P1b` | `P1a` + `AESNI`, `PCLMULQDQ` | AES-GCM (CTR + GHASH) via `CryptoAeadPlan` | `AES_BLOCK_AESNI_OPS`, `GHASH_PCLMUL_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, AES microbenches |
| `X86_P1f` | `P1b` + `AVX` | Prefetch/gather helpers (`accelerate::memory`) | `AVX2_OPS` | `scripts/tests/rust/rt-iter-reductions.rs` |
| `X86_P2a` | `P1b` + `AVX2` | GF(256) AVX2, transport varints, memory pool | `FEC_AVX2_GF_OPS`, `CONGESTION_AVX2_BATCHES` | `scripts/tests/rust/rt-packet-number-parity.rs`, `test-fec.sh` |
| `X86_P2b` | `P2a` + `BMI2`, `LZCNT` | BMI2 varint encode/decode, bitmap ops | `VARINT_BMI2_OPS`, `ACK_MERGE_BMI2_OPS` | `scripts/tests/rust/rt-varint-roundtrip.rs`, `scripts/tests/rust/rt-ack-merge-parity.rs` |
| `X86_P3a` | `AVX512F`, `AVX512VL`, `AVX512DQ` | AVX-512 GF kernels, XOR/memcpy | `AVX512_OPS`, `FEC_AVX512_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs`, `test-fec.sh` |
| `X86_P3b` | `P3a` + `VAES`, `VPCLMULQDQ` | Wide AES-GCM / AEGIS | `AES_BLOCK_VAES_OPS`, `GHASH_VPCLMUL_OPS` | `micro-aes-gcm.sh` |
| `X86_P3c` | `P3b` + `AVX512VBMI2` | Pattern search + histogram VBMI2 | `PATTERN_AVX512_VBMI2_OPS` | `test-stealth.sh` |
| `X86_P3d` | `P3c` + `AVX512VPOPCNTDQ` | Bitmap ECN popcount | `ECN_VPOPCNTDQ_OPS` | `scripts/tests/rust/rt-ecn-popcount.rs` |
| `X86_P3e` | `P3d` + `GFNI`, optional `AMX_TILE` | GFNI GF(256), AMX Wiedemann, GFNI padding | `FEC_GFNI_OPS`, `WIEDEMANN_AMX_OPS`, `STEALTH_PADDING_GFNI_OPS` | `tests/fec::matrix_multiply_avx512_matches_scalar_when_available`, AMX smoke tests |
| `X86_P4a` | `AVX10.1-256` (+ legacy AVX-512 aliasing) | Reuses AVX2/AVX-512 kernels via AVX10 dispatch | `SIMD_USAGE_AVX10_256`, `SIMD_USAGE_AVX2` | `scripts/tests/smoke/smoke-avx10.sh` |
| `X86_P4b` | `AVX10.1-512` (+ optional VAES/GFNI) | AVX10 dispatch for 512-bit lanes, telemetry captured separately | `SIMD_USAGE_AVX10_512`, `AVX512_OPS`, `FEC_GFNI_OPS` | `scripts/tests/smoke/smoke-avx10.sh`, `micro-aes-gcm.sh` |
| `ARM_A0` | `NEON` | NEON XOR/memcpy, ChaCha20-Poly1305, transport bitmap | `NEON_OPS`, `PATTERN_NEON_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs`, `micro-crypto-all.sh` |
| `ARM_A1a` | `A0` + `CRC32` | NEON CRC32, compressor counters | `CRC32_ARM_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` |
| `ARM_A1b` | `A1a` + `AES` | NEON AES TLS Cover | `AES_BLOCK_NEON_TABLE_OPS`, `AES_CTR_NEON_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs` |
| `ARM_A1c` | `A1b` + `PMULL` | GHASH PMULL, FEC nibble PMULL | `GHASH_PMULL_OPS`, `FEC_NEON_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` |
| `ARM_A1d` | `A1c` + `SHA2`, `SHA1` | SHA-256 hardware (`simd::sha`) | `SHA256_NEON_OPS`, `HMAC_SHA256_NEON_OPS` | `cargo test sha256_matches_reference --lib` |
| `ARM_A2` | `SVE2`, optional `SVE_AES`, `SVE_PMULL` | SVE2 XOR/memcpy, varints, GF kernels, brain stats | `SVE2_OPS`, `FEC_SVE2_OPS`, `PATTERN_SVE2_OPS` | Planned SVE2 CI (Task 9) |
| `Apple_M` | `NEON`, `AES`, `PMULL`, `APPLE_AMX` | NEON crypto, AMX Wiedemann prototype | `NEON_OPS`, `APPLE_AMX_OPS` | `micro-crypto-all.sh`, `scripts/tests/rust/rt-telemetry-counters.rs` |
| `Scalar` | none | Scalar reference implementations | `SIMD_USAGE_SCALAR`, `SCALAR_OPS` | Baseline unit/integration suite |

*Tip:* `FeatureDetector::features_full` (see `src/optimize.rs`) records the raw flags. Use `log::info!` output during init to confirm which paths lit up on a given machine.

### 1.2 Dispatch Flow Overview

1. **Feature detection** - `FeatureDetector::detect()` gathers instruction-set bits, cache sizes, and emits a `CpuProfile`.
2. **Acceleration plan** - each subsystem (SIMD core, transport::accelerate, crypto, fec, stealth, brain) exposes functions that map `(CpuProfile, CpuFeatures)` to concrete function pointers. This plan is cached so hot paths only branch once.
3. **Telemetry loop** - the profile ID and chosen code paths are exported through `optimize::telemetry` counters. This makes it easy to confirm (in production or tests) that the intended backend is active.

### 1.3 Recommended Enhancements

* Move profile logic to a unified `AccelerationPlanner` builder that emits per-module vtables (`CryptoPlan`, `FecPlan`, `TransportPlan`, ...). This removes repeated feature checks at call sites and gives us one place to audit coverage.
* Add a validation harness (`cargo test --features simd-selfcheck`) that runs micro-kernels for every accelerated op and reports missing coverage or wrong profile mapping.
* Extend telemetry to record `(profile, module, backend)` triplets so we can spot regressions when adding new hardware support.
* Support profile overrides (`QUICFUSCATE_FORCE_PROFILE=X86_P3c`) for debugging and reproducibility when benchmarking.

---

## 2. Current Coverage (Present)

### 2.1 Crypto (`src/crypto.rs`, `src/simd.rs::crypto`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| AEGIS-128L/X round functions | SSE2, AVX2, AVX-512 (VAES/VPCLMUL) | NEON AES | `AES_BLOCK_*`, `FAKETLS_*` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `micro-crypto-all.sh` | Runtime-dispatched via `CryptoAeadPlan`; scalar fallback retained |
| MORUS-1280 state updates | SSE2/SSSE3/SSE4.1/SSE4.2 | NEON | `MORUS1280_SCALAR_OPS`, `MORUS1280_SSE2_OPS`, `MORUS1280_SSSE3_OPS`, `MORUS1280_SSE41_OPS`, `MORUS1280_SSE42_OPS`, `MORUS1280_NEON_OPS` | `crypto::morus_kat_vectors`, `crypto::morus_encrypt_decrypt_cross_compat`, `scripts/tests/suites/test-crypto.sh` (with MORUS override) | Selected when AES is absent or via env override; scalar fallback retained |
| AES-GCM (CTR + GHASH) | AESNI/VAES + PCLMUL/VPCLMUL | AESE + PMULL (NEON/SVE2) | `AES_BLOCK_*`, `GHASH_*` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `micro-aes-gcm.sh` | Key schedule cached per session; GHASH dispatch order: VPCLMUL -> PCLMUL -> SVE2 PMULL -> NEON PMULL -> scalar |
| ChaCha20-Poly1305 | SSE4.1/SSSE3 -> AVX -> AVX2 -> AVX-512 for ChaCha, Poly1305 SSSE3/AVX2/AVX-512 | NEON & SVE2 for ChaCha + Poly1305 | `CHACHA20_X4_AVX2_OPS`, `CHACHA20_X4_AVX_OPS`, `CHACHA20_X4_SSE41_OPS`, `POLY1305_*` | `micro-crypto-all.sh`, `scripts/tests/rust/rt-chacha-x4-parity.rs`, `scripts/tests/rust/rt-telemetry-counters.rs` | ChaCha uses VL-scaling quarter rounds; Poly1305 leverages `mac_sve2_block_wide` on ARM |
| HKDF / SHA-256 / HMAC | SHA extensions (SHA-NI, AVX2, VNNI) | ARM SHA (A1d), SVE2 batch helper | `SHA256_*`, `HMAC_SHA256_*` | `cargo test sha256_matches_reference --lib`, `scripts/tests/rust/rt-simd-selfcheck.rs` | VNNI gather experiments tracked in TODO Task 7 |
| RFC 7748 (X25519) | AVX2 ladder prototype (WIP) | NEON scalar fallback | `X25519_SCALAR_OPS` (planned) | `scripts/tests/rust/rt-baseline-oracles.rs` | Prototype only; production hardening + telemetry pending |

### 2.2 FEC (`src/fec.rs`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| GF(256) multiply / XOR | AVX-512F+GFNI, AVX2, SSSE3 nibble LUT | NEON + SVE2 LUT | `FEC_GFNI_OPS`, `FEC_AVX2_GF_OPS`, `FEC_NEON_OPS`, `FEC_SVE2_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs`, `scripts/tests/rust/rt-telemetry-counters.rs` | GFNI runs in 64-byte streaming mode; SSSE3 covers legacy x86; SVE2 uses VL-aware loops |
| Berlekamp-Massey solver | AVX-512F, AVX2 | NEON skeleton, **SVE2** runtime path | `FEC_BERLEKAMP_AVX_OPS`, `FEC_BERLEKAMP_NEON_OPS`, `FEC_BERLEKAMP_SVE2_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs::berlekamp_massey_matches_scalar` | SVE2 kernel is active (VL-aware, telemetry); NEON/scalar fallback remains |
| Wiedemann matmul (GF(256)) | AVX-512 tiles, AMX-INT8 prototype | NEON | `WIEDEMANN_AMX_OPS`, `WIEDEMANN_SCALAR_OPS` | `tests/fec::test_wiedemann_amx_telemetry_increments`, `tests/wiedemann_scalar_telemetry_increments` | AMX via `target_feature="amx-int8"`; Planner-Wiring pending |
| GF(65536) nibble loops | AVX2, AVX-512F, **AVX-512 VBMI2** | NEON | `FEC_GF16_AVX_OPS`, `FEC_GF16_NEON_OPS`, `FEC_GF16_VBMI2_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs::gf16_vbmi2_matches_scalar` | VBMI2 nibble-gather is active (32x u16 per iteration); benchmarking on real VBMI2 hardware is still pending |
| CRC/Checksum | SSE4.2 | NEON CRC32 | `CRC32_SSE42_OPS`, `CRC32_ARM_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` | Called regularly in transport and compressor paths |

### 2.3 Transport (`src/transport/accelerate.rs`, `src/transport/*.rs`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| UDP batch send (`send_batch`) | `sendmmsg` + MSG_ZEROCOPY (fastpath) | `sendmsg_x` (macOS) + sendmsg fallback | `ZEROCOPY_SEND_CALLS`, `ZEROCOPY_SEND_FALLBACKS` | `scripts/tests/suites/test-transport.sh` (I/O section) | `io_uring` fast path active on Linux; Apple path uses `sendmsg_x` when available |
| ACK range search | AVX2, AVX-512 vector compare | SVE2 | `ACK_RANGE_AVX_OPS`, `ACK_RANGE_SVE2_OPS` | `scripts/tests/rust/rt-ack-merge-parity.rs` | `x86_ack.rs` + `arm_stream.rs` wrappers; scalar fallback retained |
| ACK bitmap range fill | BMI2 `_bzhi_u64` | NEON chunk fill + SVE2 stores | `ACK_BITMAP_BMI2_OPS`, `ACK_BITMAP_SVE2_OPS` | `scripts/tests/rust/rt-bitmap-range-parity.rs` | SVE2 uses `svwhilelt` + `svst1`; parity guards in place |
| Packet varint encode/decode | BMI2 (`pext/pdep`) | NEON, SVE2 | `VARINT_BMI2_OPS`, `VARINT_NEON_OPS`, `VARINT_SVE2_OPS` | `scripts/tests/rust/rt-varint-roundtrip.rs`, `scripts/tests/rust/rt-simd-selfcheck.rs` | Encode dispatch order: AVX512 -> AVX2 -> SSE2 -> NEON -> SVE2 -> scalar |
| Bitmap ECN counting | AVX-512 VPOPCNTDQ, POPCNT | SVE2 nibble LUT, NEON `vcntq_u8` | `ECN_VPOPCNTDQ_OPS`, `ECN_SVE2_OPS`, `ECN_NEON_OPS` | `scripts/tests/rust/rt-ecn-popcount.rs` | Rolling summaries feed `ConnectionStats` |
| Header validation | AVX2/AVX-512 shuffle compare | NEON + SVE2 wrappers | `HEADER_VALIDATE_AVX_OPS`, `HEADER_VALIDATE_SVE2_OPS` | `scripts/tests/rust/rt-header-validate-parity.rs` | Path sits in HTTP/3 parser and MASQUE masks |
| ZEROCOPY ring operations | SSE2 flush + CLDEMOTE prototype | NEON/SVE2 prefetch + DMB fences | `URING_SEND_ATTEMPTS`, `URING_FALLBACKS` | `scripts/tests/suites/test-transport.sh` | ARM path now prefetches payload + sockaddr and inserts DMB around io_uring submit/completion |

### 2.4 Stealth (`src/accelerate.rs::stealth`, `src/stealth.rs`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| Pattern injection | AVX2, SSE2/SSE4.2 | NEON, SVE2 | `PATTERN_AVX2_OPS`, `PATTERN_NEON_OPS`, `PATTERN_SVE2_OPS` | `scripts/benchmarks/suites/bench-stealth.sh`, `scripts/tests/rust/rt-telemetry-counters.rs` | SIMD backend selected via `AsciiSimdBackend`; scalar used only for legacy profiles |
| Entropy mixing (TLS Cover) | AES-NI CTR + SSE2 XOR | AES-NEON | `FAKETLS_AESNI_OPS`, `FAKETLS_NEON_OPS` | `scripts/tests/rust/rt-tls-cover-cipher.rs` | SSE2 fallback uses vector XOR for `X86_P0*`/`P1a`; AESNI active from `X86_P1b` |
| TLS padding | AVX2 fill | NEON fill (SVE2 wrapper) | `STEALTH_PADDING_GFNI_OPS`, `STEALTH_PADDING_NEON_OPS` | `tests/tls_padding_matches_scalar.rs` | GFNI path on `X86_P3e`, NEON copies on ARM; telemetry differentiates backend |
| Fake HMAC | SHA-NI | SHA2 NEON | `HMAC_SHA256_SHA_OPS`, `HMAC_SHA256_NEON_OPS`, `HMAC_SHA256_SVE2_OPS`, `HMAC_SHA256_SCALAR_OPS` | `scripts/tests/rust/rt-fake-hmac.rs` | Default builds now dispatch to `simd::crypto::hmac_sha256` on SHA-capable x86/ARM profiles; scalar XOR fallback increments `HMAC_SHA256_SCALAR_OPS`. |

### 2.5 Brain (`src/accelerate.rs::brain`, `src/brain.rs`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| Statistics (mean/variance) | AVX2/FMA, SSE2/SSE4.2 | NEON, SVE2 | `BRAIN_STATS_AVX_OPS`, `BRAIN_STATS_NEON_OPS` | `scripts/tests/rust/rt-brain-histogram.rs`, `scripts/tests/rust/rt-iter-reductions.rs` | SSE2 uses `_mm_mul_ps` + horiz sum; SVE2 path VL-aware |
| Correlation matrix | AVX2 dot product, SSE2 | NEON, SVE2 | `BRAIN_CORR_AVX_OPS`, `BRAIN_CORR_NEON_OPS` | `scripts/tests/rust/rt-brain-histogram.rs` | Dot product pipelines share telemetry with statistics |
| Moving average | AVX-512, AVX2, SSE2 | NEON (Apple M, ARM_A1c+) | `MOVING_AVG_*` counters | `scripts/tests/rust/rt-moving-average-parity.rs` | Planner selects best backend per `CpuProfile`; scalar fallback for `Scalar` |
| Activation (ReLU batch) | AVX2, SSE2 | NEON, SVE2 | `BRAIN_RELU_AVX_OPS`, `BRAIN_RELU_NEON_OPS`, `BRAIN_RELU_SVE2_OPS` | `scripts/tests/rust/rt-brain-activation-parity.rs` | SIMD polynomial exp used for negative clip detection |
| Softmax batch | AVX2 (poly exp), SSE2 | NEON, SVE2 | `BRAIN_SOFTMAX_AVX_OPS`, `BRAIN_SOFTMAX_NEON_OPS` | `scripts/tests/rust/rt-brain-activation-parity.rs` | Uses log-sum-exp trick; SVE2 wrapper redispatches to NEON polynomial |
| Percentile (quickselect) | AVX2, SSE2 | NEON, SVE2 | `BRAIN_PERCENTILE_AVX_OPS`, `BRAIN_PERCENTILE_NEON_OPS` | `scripts/tests/rust/rt-brain-activation-parity.rs` | Scalar quickselect fallback for degenerate windows |
| Histogram decay & Jensen-Shannon | AVX-512, AVX2, SSE4.1 | NEON, SVE2 | `BRAIN_HISTOGRAM_{AVX512,AVX2,SSE,NEON,SVE2,SCALAR}_OPS` | `scripts/tests/rust/rt-brain-histogram.rs`, `scripts/tests/rust/rt-simd-selfcheck.rs` | x86 backends use fixed-point SIMD conversions with tail dispatch (AVX-512->AVX2->SSE); NEON/SVE2 remain unchanged; AVX-512 benchmarking pending Sapphire Rapids access |
| Cover traffic heuristics | Scalar | Scalar | `COVER_TRAFFIC_SCALAR_OPS` (planned) | Integration tests | Candidate for future SIMD once heuristics stabilize |

### 2.6 Memory & Optimize (`src/accelerate.rs::memory`, `src/optimize.rs`, `src/optimize/unsafe.rs`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| `memcpy_non_temporal` | SSE2 streaming stores + CLDEMOTE prototype | NEON prefetch (`prfm`) | `MEMCPY_STREAMING_OPS`, `MEMCPY_NEON_OPS` | `scripts/benchmarks/suites/bench-transport.sh` | ARM version currently scalar + prefetch; SVE2 non-temporal stores TBD |
| Matrix transpose | AVX2 8x8 | NEON 4x4 + SVE2 VL-aware tiles | `TRANSPOSE_*` (pending) | `scripts/tests/rust/rt-transpose-parity.rs` | SVE2 backend handles tail columns/rows via VL-aware tiles; telemetry wiring still pending |
| Cache-aware bit ops | AVX2, POPCNT | Scalar | `BITOPS_AVX_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` | Could benefit from SVE2 gather masks |
| NUMA migration | Linux-specific syscalls | N/A | `NUMA_MIGRATION_CALLS` | Manual testing | Not vectorised; stays OS-level |

### 2.7 Utility Kernels (`src/accelerate.rs::random/sort/iter/string`)

| Operation | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| RNG (RDRAND/RDSEED/AES-CTR) | P1a-P3e (hardware RNG + AES-CTR) | ARM_A1b+ (AES-CTR DRBG) | `RNG_RDRAND_OPS`, `RNG_AES_CTR_OPS` | `scripts/tests/rust/rt-random-aes-ctr.rs` | Apple M/ARM profiles now use AES-CTR DRBG via thread-local seed; scalar fallback remains for legacy targets |
| Sorting (`sort_u32`, `sort_f32`) | AVX-512, AVX2 | Scalar | `SORT_AVX_OPS` | `scripts/tests/rust/rt-argsort-parity.rs` | NEON bitonic & SVE2 extensions planned |
| Iterator reductions (sum/filter/map) | AVX-512/AVX2/SSE2 | NEON, SVE2 | `ITER_SUM_*_{AVX512,AVX2,SSE,NEON,SVE,SCALAR}` | `scripts/tests/rust/rt-iter-reductions.rs`, `scripts/tests/rust/rt-telemetry-counters.rs` | SSE2 path covers legacy x86; SVE2 VL scaling verified |
| String equals/contains | AVX2/VBMI2 | NEON equality, SVE2 planned | `STRING_AVX_OPS`, `STRING_NEON_OPS` | `scripts/tests/rust/rt-stealth-ascii-count.rs` | NEON currently equality-only; SVE2 substring backlog |
| Base64 encode/decode | AVX2 shuffle | NEON + SVE2 | `BASE64_ENC_*`, `BASE64_DEC_*` | `scripts/tests/rust/rt-base64-decode-parity.rs` | SVE2 version VL aware; fallback to NEON tables |

### 2.8 SIMD Core (`src/simd.rs`)

| Area | x86 Coverage | ARM64 Coverage | Telemetry | Validation | Notes |
| --- | --- | --- | --- | --- | --- |
| Core XOR/memcpy/popcnt | AVX-512F/AVX2/SSE4.2 | SVE2 XOR/memcpy, NEON popcnt (`vcntq_u8`) | `AVX512_OPS`, `AVX2_OPS`, `SVE2_OPS`, `NEON_OPS` | `scripts/tests/rust/rt-xor-parity.rs`, `scripts/tests/rust/rt-telemetry-counters.rs` | SVE2 popcnt routes via NEON wrapper until native implementation lands |
| Galois GF operations | AVX-512 GFNI, AVX2 shuffle | NEON + SVE2 nibble LUT | `FEC_GFNI_OPS`, `FEC_AVX2_GF_OPS`, `FEC_NEON_OPS`, `FEC_SVE2_OPS` | `scripts/tests/rust/rt-simd-selfcheck.rs` | Scalar fallback preserved for portability |
| Crypto AES/GHASH/SHA | VAES/VPCLMUL/AESNI/SHA | AESE/PMULL/SHA2 | `AES_BLOCK_*`, `GHASH_*`, `SHA256_*` | `scripts/tests/rust/rt-tls-cover-cipher.rs`, `cargo test sha256_matches_reference --lib` | SHA3/SHA512 hardware backlog |
| Compress histogram | AVX-512F+CD, AVX2 | NEON | `COMPRESS_HIST_AVX_OPS`, `COMPRESS_HIST_NEON_OPS` | `scripts/tests/rust/rt-telemetry-counters.rs` | VBMI2 improvements tracked in stealth backlog |
| Pattern search | AVX-512 VBMI2, AVX2 | SVE2 (planned) | `PATTERN_AVX512_VBMI2_OPS`, `PATTERN_AVX2_OPS`, `PATTERN_SVE2_OPS` | `test-stealth.sh` | SVE2 implementation pending |
| Bitstream pack/unpack | BMI2 | NEON widths 1-8 (SVE2 wrapper) | `BITPACK_BMI2_OPS`, `BITPACK_NEON_OPS` | `scripts/tests/rust/rt-bitstream-parity.rs` | SVE2 currently jumps to NEON; native version backlog |
| Neural / matrix ops | AVX-512, AVX2, AMX INT8, Apple AMX | Apple AMX | `APPLE_AMX_OPS`, `AMX_USAGE_OPS` | `tests/fec::test_wiedemann_amx_telemetry_increments` | Integrate AMX planner hook for general matmul |

### 2.9 Compression (zstd)

- Implementation: `src/optimize/unsafe.rs::unsafe_compress::{UnsafeCompressor, UnsafeDecompressor}`
- Feature flag: `compression_zstd_ffi` (optional; default OFF). When ON (usually together with `unsafe_rust`), compression/decompression uses native `libzstd` via `zstd-sys`.
- Acceleration model: Delegated to `libzstd`, which auto-detects CPU features (x86 SSE2/AVX2/AVX-512, ARM NEON/SVE2 when available). Our code configures per-call tuning (workers, block size, strategy, window log, checksum/content-size flags) but does not re-implement kernels.
- Fallback: If the feature is OFF, we use the safe `zstd` crate; behavior (headers, dictionary handling) remains identical.

| Operation | File/Function | Telemetry | Validation | Notes | X86_P0a | P0b | P1a | P1b | P1f | P2a | P2b | P3a | P3b | P3c | P3d | P3e | ARM_A0 | A1a | A1b | A1c | A1d | A2 | Apple_M | Scalar |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| zstd compress/decompress (FFI via libzstd) | `src/optimize/unsafe.rs::unsafe_compress::{compress_direct, compress_streaming, decompress_direct}` | `ZSTD_COMPRESS_CALLS`, `ZSTD_DECOMPRESS_CALLS` | `scripts/benchmarks/suites/bench-compression.sh` | Delegates to `libzstd`; inherits compiled library SIMD coverage | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd | OK libzstd |


Notes:
- Coverage derives from the linked `libzstd` build; on some platforms, only a subset of SIMD backends may be compiled-in. Our path remains functional and will still benefit from any available kernels.
- Environment knobs: `QUICFUSCATE_ZSTD_MODE=manual`, `QUICFUSCATE_ZSTD_LEVEL`, `QUICFUSCATE_ZSTD_WORKERS`, `QUICFUSCATE_ZSTD_TARGET_BLOCK`, `QUICFUSCATE_ZSTD_STRATEGY`, `QUICFUSCATE_ZSTD_WINDOW_LOG`, `QUICFUSCATE_ZSTD_CHECKSUM`, `QUICFUSCATE_ZSTD_CONTENTSIZE`.

---

## 3. Gap Analysis & Roadmap

### 3.1 High-Priority Backlog

_Update 2025-10-12_: No open high-priority items. The AMX-INT8 Wiedemann path is integrated (`matmul_gf256_amx` via `simd::amx`), including planner gating and telemetry. ARM Poly1305 wide reduction is complete (`mac_sve2_block_wide` with a 256-bit carry chain), including telemetry wiring.

### 3.2 Medium-Priority Backlog

Previously planned mid-priority items (for example SVE2 AES, VBMI2 Brain, SVE2 Transpose, RVV scaffolding) are classified as *Future Hardware Updates*. They are only revisited once corresponding hardware and test environments are available and therefore no longer appear in the active backlog.

### 3.3 Low-Priority / Nice to Have

* SHA3/SHA512 hardware paths (x86 SHA-NI 512 and ARM).
* Cross-profile fuzz tests to ensure fallbacks remain correct.

---

## 4. Implementation Guidelines

1. Keep SIMD intrinsics in `src/simd.rs`, `src/accelerate.rs`, `src/fec.rs`, or `src/crypto.rs` - other files should call helpers, not inline intrinsics.
2. Gate decisions by `CpuProfile` or cached plan structs so per-packet hot paths do not repeat feature detection.
3. Add scalar cross-checks in debug builds (`QUICFUSCATE_SIMD_VERIFY=1`) when introducing a new backend.
4. Expose telemetry counters whenever a backend is selected or when falling back to scalar code.
5. Update **this** document every time coverage changes.

---

## 5. Full Acceleration Matrix (Authoritative)

This section enumerates every performance-relevant operation, mapping it to the exact CPU profiles that activate accelerated implementations. It is generated from code review of `src/` and should be kept in lock-step with implementations. Symbols are:

- OK accelerated path present
- WARN partially accelerated, routed via a central helper, prototype, or limited coverage
- NO no dedicated SIMD path (scalar fallback)

Column order for profiles: `X86_P0a, X86_P0b, X86_P1a, X86_P1b, X86_P1f, X86_P2a, X86_P2b, X86_P3a, X86_P3b, X86_P3c, X86_P3d, X86_P3e, ARM_A0, ARM_A1a, ARM_A1b, ARM_A1c, ARM_A1d, ARM_A2, Apple_M, Scalar`. (The new AVX10 profiles `X86_P4a`/`X86_P4b` currently follow the `X86_P3*` columns; dedicated columns are only introduced once dedicated backends exist.)

### Crypto (AEAD/Hash)

| Operation | File/Function | X86_P0a | P0b | P1a | P1b | P1f | P2a | P2b | P3a | P3b | P3c | P3d | P3e | ARM_A0 | A1a | A1b | A1c | A1d | A2 | Apple_M | Scalar |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MORUS state update (SIMD) | `src/crypto.rs::{update_simd_sse2, update_simd_neon, update}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK (NEON) | OK | OK | OK | OK | OK | OK | NO |
| AES-128 encrypt block (GCM core) | `src/crypto.rs::Aes128Ctx::encrypt_block` | OK | OK | OK | OK (AESNI) | OK | OK | OK | OK | OK (VAES) | OK | OK | OK | OK | OK | OK | OK | OK | OK (SVE2) | OK | OK |
| AEGIS-128L AESENC round | `src/crypto.rs::aegis_aes_block::AesBlock::aes_round` | WARN | WARN | WARN | OK | OK | OK | OK | OK | OK | OK | OK | OK | WARN | WARN | WARN | WARN | WARN | WARN | WARN | WARN |
| GHASH (GCM) | `src/simd.rs::{x86::ghash_pclmulqdq, x86::ghash_vpclmulqdq, arm::ghash_pmull}` + SSE4.1/SSSE3 fallback via `simd::crypto::ghash()` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | NO |
| SHA-256 | `src/simd.rs::{x86::sha256_avx2, x86::sha256_vnni, x86::sha256_hw, arm::sha256_hw}` via `simd::crypto::sha256()` | NO | NO | WARN dep: SHA | OK (SHA) | OK (SHA) | OK (AVX2) | OK (AVX2) | OK (AVX2) | OK (AVX2) | OK (AVX2/VNNI) | OK (AVX2/VNNI) | OK (AVX2/VNNI) | OK (AVX2/VNNI) | WARN dep: SHA256 | WARN dep: SHA256 | OK (SHA256) | OK (SHA256) | OK (SHA256) | OK (SHA256) | OK |
| HMAC-SHA256 | `src/simd.rs::crypto::hmac_sha256` | NO | NO | WARN dep: SHA | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | WARN dep: SHA256 | WARN dep: SHA256 | OK | OK | OK | OK | OK |
| ChaCha20-Poly1305 | `src/crypto.rs::{chacha, poly1305, chacha20poly1305::ChaCha20Poly1305}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |

Notes:
- MORUS runtime dispatch is in `Morus1280State::update()` (x86_64 SSE2 via `is_x86_feature_detected!`, aarch64 NEON via `#[cfg(target_feature="neon")]`).
- GHASH VPCLMUL-VL is implemented (parallel 256-bit Karatsuba) and used when available; otherwise it falls back to PCLMUL (x86), the SSE4.1/SSSE3 byte-table fallback (`GHASH_SSE_OPS`), or PMULL (ARM).
- New SSE4.1/SSSE3 tables (16x256) reduce the number of `mul_x4` operations per block to pure XOR lookups; benchmarks on real >=SSE4.1 hardware are still pending (TODO #14).
- AVX10.1 hosts are treated as AVX2/AVX-512 compatible by `FeatureDetector`; telemetry (`SIMD_USAGE_AVX10_256`/`SIMD_USAGE_AVX10_512`) tracks usage separately until dedicated planner profiles are introduced.
- AEGIS-128L uses per-round dispatch to AES instructions when available (AESNI on x86_64, Arm AES on aarch64) and otherwise falls back to a portable software AESENC equivalent. Default plan selection avoids AEGIS when AES is not present.
- MORUS SSSE3 path is enabled with in-register word rotations using `_mm_alignr_epi8` to minimize loads/stores in rotation steps.

#### AEAD Selection Matrix (default)

| Platform/Features | Default Plan (`CryptoAeadPlan`) | Cipher | Notes |
|---|---|---|---|
| x86_64 AESNI (`X86_P1b+`) | `LAesni` | AEGIS-128L | Hardware AES present -> AEGIS-128L. |
| x86_64 no AESNI (`X86_P0a/P0b/P1a`) | `Morus` | MORUS-1280-128 | SIMD MORUS where available, otherwise scalar. |
| aarch64 NEON + AES | `LNeon` | AEGIS-128L | ARM AES present -> AEGIS-128L. |
| aarch64 NEON (no AES) | `Morus` | MORUS-1280-128 | NEON MORUS where available, otherwise scalar. |
| RVV / Scalar | `Morus` | MORUS-1280-128 | Scalar fallback. |
| Test-only override | `QUICFUSCATE_MORUS` | Forced | Forces MORUS plan selection under tests. |

### FEC (GF kernels, Matrix)

| Operation | File/Function | X86_P0a | P0b | P1a | P1b | P1f | P2a | P2b | P3a | P3b | P3c | P3d | P3e | ARM_A0 | A1a | A1b | A1c | A1d | A2 | Apple_M | Scalar |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GF(256) multiply (slice/scalar x vector) | `src/fec.rs` (e.g. `gf_mul_scalar_slice_ssse3`, `gf_mul_scalar_slice_avx2`, `gf_mul_gfni`, `gf_mul_scalar_slice_neon`, `gf_mul_scalar_slice_sve2`) | OK (SSSE3) | OK | OK | OK (AVX2) | OK | OK (AVX512) | OK | OK | OK | OK (GFNI) | OK (NEON) | OK | OK | OK (PMULL) | OK | OK (SVE2 LUT) | OK | NO |
| GF(16) multiply (slice) | `src/fec.rs::{gf16_mul_slice_avx2, gf16_mul_slice_avx512, gf16_mul_slice_neon}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | NO |
| Matrix multiply | `src/fec.rs::{matrix_multiply_avx2_fma, matrix_multiply_avx512, matrix_multiply_ssse3, matrix_multiply_neon, matrix_multiply_sve2}` | NO | OK (SSSE3) | OK | OK | OK | OK | OK | OK (AVX2 fallback) | OK (AVX2 fallback) | OK (AVX2 fallback) | OK (AVX2 fallback) | OK (AVX512 GFNI) | WARN | WARN | WARN | WARN | OK | NO |
| Wiedemann (AMX-INT8 prototype) | `src/fec.rs::wiedemann_amx` | NO | NO | NO | NO | NO | NO | NO | NO | NO | WARN | NO | NO | NO | NO | NO | NO | WARN | NO |

Notes:
- GFNI paths (AVX-512 GFNI) are present both for byte-wise gf(256) (`gf_mul_gfni`) and scalar x vector slice update (`gf_mul_scalar_slice_gfni`), guarded by `target_feature`; the AVX-512 matrix multiply now uses `_mm512_gf2p8mul_epi8` when GFNI is available and falls back to the AVX2 FMA kernel otherwise.
- NEON PMULL slice kernels accelerate GCM/GF math on ARM (`gf16_mul_slice_neon`, `gf_mul_neon_pmull_block16`); the SVE2 path uses VL load/store plus a nibble LUT (`gf_mul_scalar_slice_sve2`).
- SSSE3 `pshufb` nibble-LUT kernel (`gf_mul_scalar_slice_ssse3`) covers `X86_P0a`; dispatch only falls back to scalar when neither SSSE3 nor higher profiles are available.

### Transport / Utility / Memory

| Operation | File/Function | X86_P0a | P0b | P1a | P1b | P1f | P2a | P2b | P3a | P3b | P3c | P3d | P3e | ARM_A0 | A1a | A1b | A1c | A1d | A2 | Apple_M | Scalar |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Varint encode/decode (SIMD-helpers) | `src/simd.rs::transport::{encode_varint, decode_varint}` - AVX512->AVX2->SSE2 encode (x86), BMI2/SSE2 decode; NEON/SVE2 encode/decode (ARM) | OK (SSE2 encode) | OK | OK | OK | OK | OK (AVX2 encode) | OK (AVX2/BMI2) | OK (AVX512 encode) | OK | OK | OK | OK (NEON) | OK | OK | OK | OK | OK (SVE2) | OK | OK |
| Packet-number decode | `src/accelerate.rs::decode_packet_number` (BMI2 / NEON / SVE2) | NO | NO | NO | NO | NO | NO | OK | OK | OK | OK | OK | OK (NEON) | OK | OK | OK | OK | OK (SVE2) | OK | OK |
| QUIC stream frame parse | `src/accelerate.rs::parse_stream_frames_avx2` / `parse_stream_frames_neon` | NO | NO | NO | WARN | WARN | OK (AVX2) | OK | OK | OK | OK | NO | OK (NEON) | OK | OK | OK | OK | OK (NEON via SVE2 wrapper) | OK |
| Base64 encode | `src/accelerate.rs::{base64_encode_ssse3, base64_encode_avx2, base64_encode_neon, base64_encode_sve2}` | NO | OK | NO | NO | NO | OK | OK | OK | OK | OK | NO | OK | OK | OK | OK | OK | OK (SVE2) | OK | OK |
| Base64 decode | `src/accelerate.rs::base64_decode` (SSE4.1/AVX2/NEON/SVE2 dispatch) | NO | NO | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK (SVE2) | OK | OK |
| Argsort indices (f32, len <= 8) | `src/accelerate.rs::sort::{argsort_f32_avx2_small, argsort_f32_neon_small}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | NO | OK (NEON) | OK | OK | OK | OK | OK (NEON) | OK | OK |
| XOR repeating key | `src/optimize.rs::simd::core::{xor_repeating_key_32,xor_repeating_key}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK (NEON) | OK | OK | OK | OK | OK | OK | NO |
| ASCII printable count (Text heuristic) | `accelerate::count_ascii_printable` (used in `compress::looks_textual`) | OK (SSE2) | OK (SSE2) | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK (NEON) | OK | OK | OK | OK | OK | OK | OK |
| Congestion stats aggregation (rolling) | `accelerate::transport::aggregate_congestion` | WARN | WARN | WARN | WARN | WARN | OK | OK | OK | OK | OK | OK | OK (VNNI) | OK | OK | OK | OK | OK | OK | OK |
| memcpy non-temporal / large copy (SSE2+ / ARM prefetch) | `src/accelerate.rs::{memcpy_non_temporal_sse, memcpy_non_temporal_arm}` | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| CRC32 HW | `src/optimize.rs::simd::crc32_{sse42,armv8}` | NO | NO | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |

Notes:
- BMI2 varint helpers exist both in `src/simd.rs` and `src/accelerate.rs` (for packet number and header utilities).
- Large-copy path now exists for x86 (SSE2+ streaming stores) and aarch64 (NEON loads plus `prfm` prefetch). The ARM path uses prefetch plus regular stores as the pragmatic portable approach.
- Congestion aggregation uses AVX-512 VNNI (`aggregate_congestion`) on `X86_P3e` when `avx512vnni` is available; otherwise it falls back to scalar. Telemetry `CONGESTION_VNNI_BATCHES` records the number of VNNI-aggregated windows.
- Congestion aggregation includes AVX2/SSE4.1 backends (for `X86_P2x/P3[a-d]`) and a NEON backend (`ARM_A0+`). Older x86 without AVX2 are intentionally scalar fallbacks; telemetry (`CONGESTION_AVX2_BATCHES`, `CONGESTION_NEON_BATCHES`) records the new paths.
- GHASH now includes a NEON LUT path for ARM profiles without PMULL/SVE2 (`GHASH_NEON_OPS`) as well as an SSE4.1/SSSE3 fallback for older x86 hosts (`GHASH_SSE_OPS`).
- SHA-256/HMAC uses `Sha256Plan`: AVX2/VNNI stream 64-byte blocks zero-copy into `sha2-asm::compress256` (batch size 1/2 with `_mm{256,512}_zeroupper`, T0/T1 prefetch prepared), SHA-NI serves older x86 profiles, and NEON/SVE2 use the same assembly helper; telemetry (`SHA256_*`, `HMAC_SHA256_*`) mirrors the active path.

### Stealth / QPACK

| Operation | File/Function | X86_P1a-P3e | ARM_A0-Apple_M | Scalar |
|---|---|---:|---:|---:|
| TLS Cover record encrypt (ChaCha20-Poly1305 & AES-128-GCM) | `src/stealth.rs` (`install_tls_cover_chacha` / `install_tls_cover_aes_gcm`, `encrypt_tls_cover_record`) | OK (ChaCha SSE4.1/SSSE3/AVX/AVX2, AESNI/VAES) | OK (ChaCha NEON; AES with NEON crypto) | OK (auto + overrides via `QUICFUSCATE_TLS_COVER_CIPHER`, `QUICFUSCATE_CHACHA20_X4`) |
| Jitter/Padding (runtime knobs) | `src/stealth.rs::generate_fake_crypto_frame` | - | - | OK |
| Header Templates & Title-Case (Safari/Firefox Personas) | `Http3Masquerade::generate_headers` via `PersonaTemplate` + `AsciiSimdBackend` (Title-Case byte-slices; no runtime postprocessing) | OK (SSE2/AVX2 dispatch) | OK (NEON) | OK |
| Payload Byte Classification (Compression Preprocessor) | `accelerate::compress::classify` (ASCII/newline/null/high-bit counters) -> `CompressionAnalysis` | OK (AVX512/AVX2/SSE2) | OK (NEON) | OK |
| Wiedemann AMX Block Multiply | `simd::amx::matmul_gf256_amx` (16x64 tiles) used via `Decoder8::solve_wiedemann_system` | OK (AMX-INT8) | - | OK |
| QPACK encode | `src/simd.rs::h3::qpack_encode` -> `src/simd.rs::{x86::qpack_encode_avx2, arm::qpack_encode_neon, arm::qpack_encode_sve2_impl}`; scalar fallback `src/transport/h3.rs::qpack::huff_encode_into` | OK | OK (NEON; SVE2 wrapper) | OK |
| QPACK decode | `src/simd.rs::h3::qpack_decode` -> `src/simd.rs::{arm::qpack_decode_sve2_impl (wrapper), arm::qpack_decode_neon}`; scalar fallback in `h3::qpack` | OK (where applicable) | OK (SVE2 wrapper -> existing infrastructure; NEON) | OK |

Notes:
- QPACK encoding now covers AVX2/SSSE3 on x86, NEON on ARM, plus an SVE2 wrapper that integrates with variable-length, predicated loads; scalar fallback retains correctness for edge profiles.
- QPACK decoding adds an SVE2 wrapper that delegates to the existing `h3::qpack` infrastructure, maintaining identical semantics.
- AVX2 path uses register-only lookups with `_mm256_i32gather_epi32` from `HUFF_CODES` and a prebuilt `LENS32` (u32 view of `HUFF_LENS`) to avoid lane->array materialization; only the bitpacking stage is scalar due to variable code lengths.

### Additional Acceleration Candidates (no current SIMD, but worthwhile)

- Stealth cookie/referer generator (`generate_realistic_cookies_at`, `generate_realistic_referer_for`) uses `AsciiSimdBackend` (SSE2/AVX2 for x86, NEON for ARM, scalar fallback) to accelerate decimal/hex formatting and copy paths without branches; parity tests protect persona-specific outputs.
- Persona header templates (`Http3Masquerade::generate_headers` -> `PersonaTemplate`) ship Safari/Firefox Title-Case as well as Chrome/Edge header lists as prebuilt byte-slices; `AsciiSimdBackend` handles copy/batching (SSE2/AVX2/NEON, with `Header::from_parts` as the scalar fallback).
- Compression preprocessor (`CompressionAnalysis::from_full`) uses `accelerate::compress::classify` (SSE2/NEON) plus chunk hashing, feeds telemetry `COMPRESS_PREPROC_*`, and adapts encoder parameters dynamically.
- AMX-INT8 Wiedemann (`simd::amx::matmul_gf256_amx`) processes 16x64 GF(256) blocks in hardware; runtime gating is via `FecPlan.has_amx_int8`; scalar fallback remains.
- QPACK Huffman/encode tables (`src/transport/h3.rs`): evaluate a true SVE2-wide encoder/decoder beyond the current wrapper.
- ChaCha20-Poly1305 SVE2: once stable intrinsics are available, consider a true SVE2 kernel (currently NEON).
- RVV scaffold: `FeatureDetector` detects RVV/Zvbb/Zvbc/Zvkg, telemetry (`SIMD_USAGE_RVV`, `ITER_SUM_*_RVV_OPS`) records hits; until intrinsics are stable, these paths use scalar fallbacks.

Implementation notes:
- Dispatch policy is driven by `FeatureDetector::instance()` and `CpuProfile` mapping (see `src/optimize.rs`).
- Crypto AEGIS/MORUS: choose via `Morus1280State::update()` and `simd::CryptoAeadPlan`.
- FEC kernels use `optimize::dispatch(..)` hooks inside `src/fec.rs` to select AVX2/AVX-512/NEON/GFNI.

## 5. Summary
QuicFuscate covers the key SIMD units of modern x86 and ARM CPUs. In addition to SSE2/SSE4.2 backends (stealth pattern/entropy/padding as well as brain statistics/activation/softmax/percentile/moving average) and the SVE2 keystream for ChaCha20, AES-128 block/CTR paths (SVE2), persona header templates, the cookie/referer generator, and the compression preprocessor are now SIMD-accelerated. SVE2 paths remain strictly behind feature gates and automatically fall back to NEON/scalar when no backend is available. Open focus areas include AMX-INT8 Wiedemann and future RVV/AVX10 integrations.
