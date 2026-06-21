---
id: TODO-361
title: "hkdf_expand panics on large out_len instead of returning Result"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-361: hkdf_expand panics on large out_len instead of returning Result


## Problem
`src/crypto/hkdf.rs` line 37: `hkdf_expand()` uses `expect()` which will panic if
`out_len > 255 * 32 = 8160` bytes. While no current caller passes such values, this
is a crypto function that should be defensive.

Also: `hmac_sha256()` at line 17 and line 35 use `expect()` on HMAC operations that
theoretically cannot fail (HMAC accepts any key length), but the Result is unwrapped
with expect rather than propagated.

## Fix Plan
Option A (minimal): Add a bounds check `assert!(out_len <= 255 * 32)` with a clear
message before the loop, or document the precondition.

Option B (robust): Change return type to `Result<Vec<u8>, CryptoError>` and propagate
errors instead of panicking. Update all callers.

Recommendation: Option A is sufficient since the HKDF-Expand spec requires N <= 255.
A clear assert with message is better than the generic expect.

## Files to Modify
- src/crypto/hkdf.rs