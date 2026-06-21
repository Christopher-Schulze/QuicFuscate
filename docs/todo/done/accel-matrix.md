# Acceleration Matrix and AEAD Selection

## Scope
- SIMD and acceleration coverage across modules.
- AEAD selection policy and instruction set compatibility.

## Tasks
1) [x] Build an explicit table of SIMD coverage by module and ISA. OK 2026-01-25
2) [x] Document AEAD selection: AES present => AEGIS, no AES => MORUS. OK 2026-01-25
3) [x] Verify MORUS code paths only run on non-AES hosts in production. OK 2026-01-25
4) [x] Map SIMD coverage gaps for NEON/AVX2/AVX512 without adding new SSE. OK 2026-01-25

## Completion Criteria
- [x] Table is complete and reflected in `docs/MAP.md`. OK 2026-01-25
- [x] AEAD selection logic is aligned with runtime behavior. OK 2026-01-25
