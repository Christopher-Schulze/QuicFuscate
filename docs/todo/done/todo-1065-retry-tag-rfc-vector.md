---
id: TODO-1065
title: Retry integrity tag must match the RFC vector and must not panic
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-22
depends_on: [TODO-1049]
---

# TODO-1065: Retry integrity tag must match the RFC vector and must not panic

## Why

`bbc93fe2` moved the Retry integrity tag onto ring. The only test, `retry_integrity_roundtrips_for_v1_and_v2` in `src/transport/packet/tests.rs`, appends a tag and checks it with the same function. If both sides share a wrong construction, the test stays green. The new helper also panics in library code.

## Current code

- `crates/qf-crypto/src/ring_aead.rs` `aes128_gcm_tag_aad_only`:
  - `bind_key(...).expect("fixed-size AES-128-GCM key is valid")`
  - `seal_in_place_separate_tag(...).expect("sealing an empty payload cannot fail")`
- Callers: `append_retry_tag` and `verify_retry_tag` in `src/transport/packet/retry.rs`.
- Fixed keys and nonces are the RFC 9001 v1 and v2 Retry pairs (`KEY_V1` starts `be 0c 69 0b`, `NONCE_V1` starts `46 15 99 d3`, v2 pair likewise).
- `verify_retry_tag` compares all 16 bytes with `diff |= tag[i] ^ tag_in[i]` and no per-byte return. That compare is data-independent. Do not replace it with an early-exit `==` on the slices.
- There is no checked-in tag taken from an RFC sample packet.

## Target

- `aes128_gcm_tag_aad_only` returns `Result<[u8; 16], ConnectionError>`. Callers propagate the error. No `.expect` on this path.
- One test builds the sample Retry packet from RFC 9000 Appendix A (the packet whose integrity tag is specified together with the RFC 9001 v1 Retry key) and asserts the last 16 bytes equal `append_retry_tag` output. Copy the header bytes and the tag from the RFC text into the test. Do not generate the expected tag by calling the function under test.
- A second assertion flips one tag byte and expects `CryptoError`.
- v2 keeps a roundtrip, plus the v1 known-answer. If the RFC publishes a v2 sample, add that too. If it does not, say so in Notes and do not invent v2 tag bytes.
- The 16-byte XOR compare stays, or the verify path compares the ring tag with the same full-width XOR. No short-circuit.

## Non-goals

- No new AEAD.
- No change to the Retry key or nonce constants.
- No frontend change.

## Design

1. Change the helper signature first. Fix both call sites in `retry.rs`.
2. Add the RFC fixture test before any other cleanup so a wrong AAD layout fails immediately. The pseudo-packet is `ODCID length || ODCID || Retry packet without the tag`, per RFC 9001 section 5.8.
3. Keep `retry_integrity_roundtrips_for_v1_and_v2`. It is necessary and not sufficient.

## Sub-Tasks

- [x] `Result` signature, both call sites updated, no `.expect` in `aes128_gcm_tag_aad_only`.
- [x] RFC sample bytes pasted into `src/transport/packet/tests.rs` with the RFC section named in a comment.
- [x] Mismatch byte fails closed.
- [x] `cargo test --offline --lib retry_integrity` passes.

## Result

`aes128_gcm_tag_aad_only` returns `Result<[u8; 16], ConnectionError>`. `append_retry_tag` and `verify_retry_tag` propagate that error. The verify loop is still a full 16-byte XOR with no early exit. `retry_integrity_matches_rfc9001_appendix_a4` copies the RFC 9001 Appendix A.4 unprotected Retry packet and tag `04a265ba2eff4d829058fb3f0f2496ba` for ODCID `8394c8f03e515708`. No v2 sample is published in that appendix, so v2 stays a roundtrip only. `cargo test --offline --lib retry_integrity`: 2 passed.

## Acceptance

- The known-answer tag matches the RFC bytes, not a self-generated tag.
- `rg expect crates/qf-crypto/src/ring_aead.rs` finds no `expect` inside `aes128_gcm_tag_aad_only`.
- A corrupted tag returns `ConnectionError::CryptoError`.
- v1 and v2 roundtrip still pass.

## Risks

- The sample in RFC 9000 includes the tag. The test must hash the packet with the tag stripped, using the ODCID from that same example. Using a different ODCID makes a correct implementation fail. Quote both fields from the same example.
