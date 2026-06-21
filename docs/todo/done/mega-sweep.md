# Mega Sweep Plan (Forensic Performance + Security Review)

## Scope
- Crypto/AEAD + telemetry/dispatch
- Optimize/SIMD core (iter/sort/string/compress/memory/udp/transport)
- Stealth + Brain + orchestration
- FEC + transport integration + ringbuffers/cache

## Method
- Read each module end-to-end.
- Identify correctness risks, perf bottlenecks, SIMD gaps, and missing telemetry.
- For each block: produce Findings + Opportunities + Suggested fixes (no code changes unless approved).

## Output Format
- **Findings** (bugs, risks, regressions)
- **Performance Opportunities** (SIMD, cache, algorithmic, memory/layout)
- **Coverage Gaps** (missing tests, missing telemetry)
- **Roadmap** (prioritized, actionable steps)

## Blocks
1) Crypto/AEAD + telemetry/dispatch  
2) Optimize/SIMD core  
3) Stealth + Brain  
4) FEC + Transport integration

## Completion Criteria
- All four blocks reviewed and reported.
- Redos listed as Yes/No with rationale.
- If changes are proposed, they are tracked in `docs/todo.md`.

## Block 1 - Crypto/AEAD (2026-01-25)
**Findings**
- MORUS optimized and scalar paths are now enforced as interoperable (cross-decrypt tests added).
- AEAD tag verification is constant-time across ChaCha20-Poly1305, AEGIS, AES-GCM, and MORUS (centralized compare).
- MORUS KATs are present for the 1280-128 variant (native + optimized).
- MORUS telemetry coverage includes scalar, SSE2, SSSE3, SSE4.1, and NEON counters.

**Performance Opportunities**
- None for MORUS on AES-capable CPUs (hard cut: AES -> AEGIS). MORUS SIMD remains targeted at non-AES profiles only.

**Coverage Gaps**
- Add explicit tag-compare microtests for each AEAD path to guard constant-time regressions.

**Roadmap**
- Extend KATs to optimized MORUS paths (x86 + ARM).
- Add per-AEAD constant-time verification tests (negative/positive cases).
- Keep MORUS SIMD limited to non-AES profiles; do not add AVX/AVX2/AVX-512 MORUS paths.

## Block 2 - Optimize/SIMD core (2026-01-25)
**Findings**
- `compress::classify` now has AVX2/AVX512 fast paths (x86) in addition to SSE2/NEON.
- `memory::memcpy_non_temporal` still uses SSE2 for x86_64 and defers ARM to `accelerate::transport_io::memcpy_non_temporal_arm` (cross-module dependency).

**Performance Opportunities**
- Evaluate additional AVX512 usage in string/base64/UTF-8 paths (no new SSE requested).

**Coverage Gaps**
- SIMD parity tests for string/base64/utf8 paths across AVX2/AVX512 remain limited.

**Roadmap**
- Add targeted parity tests for string/base64/utf8 and `compress::classify` across scalar vs AVX2/AVX512.

## Block 3 - Stealth + Brain (2026-01-25)
**Findings**
- `shape_traffic_pattern` now has a NEON path for ARM; AVX2 remains for x86.
- Brain Jensen-Shannon NEON uses vector math for ratios/logs; log remains per-lane inside `vlogq_f64_neon` (correct but slower).
- `stealth::generate_fake_hmac` XOR fallback remains for scalar-only profiles (must stay scoped to obfuscation).

**Performance Opportunities**
- Evaluate further vectorized exp/log approximations for Brain to improve throughput beyond vectorized ratios/logs.

**Coverage Gaps**
- Parity tests for stealth SIMD paths remain limited.
- ARM parity coverage for Brain kernels still thin.

**Roadmap**
- Add explicit SIMD parity tests for Stealth functions (pattern inject + padding + entropy mix).
- Add ARM parity tests for Brain kernels (JS divergence, moving average, softmax).

## Block 4 - FEC + Transport integration (2026-01-25)
**Findings**
- `fec::matrix_multiply_neon` now has a dedicated NEON kernel (no longer defers to portable).
- Transport SIMD coverage on x86 remains AVX2/BMI2 only (no SSE fallback requested).

**Performance Opportunities**
- Evaluate additional AVX512 usage in transport hot paths where available.

**Coverage Gaps**
- Limited transport SIMD parity tests beyond `simd-selfcheck`.
- FEC SIMD parity on ARM relies on broader tests; targeted parity for GF(256) kernels remains sparse.

**Roadmap**
- Add targeted parity tests for transport SIMD functions (AVX2 vs scalar, NEON vs scalar).
- Add dedicated ARM NEON GF(256) matmul tests.
