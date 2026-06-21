---
id: TODO-304
title: src/crypto/aegis.rs - add inline unit tests (KAT + state machine)
severity: HIGH
status: done
created: 2026-03-25
---

# TODO-304: AEGIS Inline Tests

## Problem

`src/crypto/aegis.rs` is 1665 LoC of SIMD crypto code (Aegis128l, Aegis256, Aegis128X4, Aegis128X8) with **zero inline `#[cfg(test)]` unit tests**. Current coverage is only:
- Fuzz: `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs` (random inputs, no correctness guarantees)
- Selection: `rt-profile-aegis-selection.rs` (which variant is chosen, not whether it encrypts correctly)

This is a critical gap: SIMD register misalignment or state update bugs would be silent.

## What Tests Are Needed

### 1. Known-Answer Tests (KAT) per variant (4 tests)
```rust
#[test]
fn aegis128l_known_answer_vector() { ... }
#[test]
fn aegis128x4_known_answer_vector() { ... }
#[test]
fn aegis128x8_known_answer_vector() { ... }
#[test]
fn aegis256_known_answer_vector() { ... }
```
Use test vectors from IETF draft-irtf-cfrg-aegis-aead (Appendix A).

### 2. Encrypt-then-decrypt roundtrip (1 per variant, 4 tests)
- Verify decrypt(encrypt(msg)) == msg
- Test with empty, 1-byte, block-aligned, unaligned payloads

### 3. Associated data handling (2 tests)
- Empty AD
- Non-empty AD - tag must differ from same ciphertext with different AD

### 4. Tag forgery detection (1 test)
- Flip a ciphertext bit -> decrypt returns Err

### 5. Nonce uniqueness requirement (1 test)
- Same key + same nonce + different plaintext must produce different ciphertext

**Total: ~12 tests**

## Completion Criteria

- All 12 tests pass with `cargo test --lib`
- Tests are in `src/crypto/aegis.rs` inside `#[cfg(test)]` module
- No `#[allow(dead_code)]` or `#[allow(unused)]` in test code
- Clippy GREEN after adding tests
