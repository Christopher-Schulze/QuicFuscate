---
id: TODO-1068
title: Audit the crypto owner by behavior, not only by source strings
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-22
depends_on: [TODO-1049, TODO-1065]
---

# TODO-1068: Audit the crypto owner by behavior, not only by source strings

## Why

`scripts/tests/audits/audit-runtime-guardrails.sh` check 4n, rewritten in `bbc93fe2`, passes when source text contains `pub struct RingAesGcm128`, `libaegis_owner!(LibAegis128L`, `self.iv.zeroize()`, and does not contain `pub mod aes`. A comment with those strings satisfies it. A renamed function that still seals with a private AES would fail the absence check only if the old name remained. The 1772 library tests are a real run, but they are not what 4n executes. The guardrail should fail when the owner changes behavior, not only when a name disappears.

## Current code

Check 4n starts at the comment "Crypto key and nonce material must have explicit owners" and is a chain of `rg` predicates. It does not compile or run a seal. The negative `rg` for `AesGcm128`, `ChaCha20Poly1305`, `chacha20_blocks_x4`, `QUICFUSCATE_GHASH`, and `pub mod aes` must stay. Those are the tripwire if the deleted files return.

The safety-contract inventory already fails on a new `unsafe fn` without a `# Safety`/`SAFETY` contract in the preceding 12 lines: the Python collects every `unsafe fn` declaration into `missing` and exits 1. Zero `unsafe fn` passes vacuously, and any future unsafe fn without a contract fails. No change needed there — do not "fix" a gate that already works.

## Target

- Keep every current 4n string predicate.
- Add one executed check, in the same script or in a tiny `cargo test` the script invokes, that:
  - seals and opens 16 bytes with `RingAesGcm128` and checks the NIST vector already in `crates/qf-crypto/src/tests.rs` (`ring_aes_gcm128_matches_nist_vector`), and
  - seals and opens 16 bytes with `select_libaegis128_packet` / `LibAegis128L` against the existing CFRG vector test, and
  - builds a v1 Retry tag through `append_retry_tag` and compares it to the RFC bytes from TODO-1065.
- If `cargo test` is too heavy for the audit script's budget, a `cargo test -p qf-crypto --lib --offline ring_aes_gcm128_matches_nist_vector` plus the libaegis CFRG test name plus `cargo test --offline --lib retry_integrity` is the budget. Record the exact commands in the script comment.
- Unsafe gate: verify the existing safety-contract inventory still rejects an `unsafe fn` without a `# Safety` contract (it does today). Keep that behavior; zero `unsafe fn` still passes.

## Non-goals

- Do not delete the string checks.
- Do not require x86, Miri, or a sanitizer in this task.
- No frontend change.
- Do not reintroduce first-party AES to have something to compare.

## Design

1. Read the current 4n block and leave it intact.
2. Add 4n-behavior immediately after it, failing critical on non-zero test status.
3. Do not add a second unsafe-fn gate. The existing crypto safety-contract inventory in `audit-runtime-guardrails.sh` already exits 1 when an `unsafe fn` in `crates/qf-crypto/src` has no `# Safety` or `SAFETY` comment in the preceding 12 lines. Verify that behavior and record the probe in Notes. Do not duplicate it.
4. Run the script far enough to see 4n and 4n-behavior pass locally. The six pre-existing criticals (AMX, Windows, Linux evidence) are out of scope. Do not weaken them to make the script exit 0.

## Sub-Tasks

- [x] 4n string checks unchanged and still passing.
- [x] Behavior invocation of the three named tests.
- [x] Confirm the existing unsafe-fn contract gate still rejects a contract-free `unsafe fn` (no code change; document the probe).
- [x] Script comment lists the three test filters.
- [x] A dry run is recorded in Notes with the pass line for 4n-behavior. Full-script exit may stay non-zero because of the unrelated criticals.

## Notes

Check 1c already exits when a crypto `unsafe fn` lacks `# Safety` or `SAFETY` in the preceding 12 lines. Live tree: 0 unsafe functions, 0 missing contracts. A synthetic `pub unsafe fn` with an empty preceding window matches the same predicate and would be reported. No second gate was added.

`cargo test --exact` exits 0 when the filter matches nothing. 4n-behavior therefore requires `test result: ok. 1 passed` for each of:

- `tests::ring_aes_gcm128_matches_nist_vector`
- `libaegis_aead::tests::libaegis_matches_pinned_cfrg_aegis128l_vector_1`
- `transport::packet::tests::retry_integrity_matches_rfc9001_appendix_a4`

A missing-name probe (`tests::this_test_does_not_exist`) does not contain that line.

Dry run 2026-09-22: "Crypto lifecycle and removed-primitive contracts are wired" and "Crypto owner behavior matches NIST, CFRG, and RFC 9001 Retry vectors". Exit 1, Critical: 6. The six errors are AMX proof, WFP cleanup, interface negative-proof matrix, privilege/memory-lock/TLS Windows wiring, native Linux resolver proof, and multi-client dual-stack proof. Those lines were not edited.

## Result

4n stays a source-string check. 4n-behavior runs the three owner tests and fails closed if a test fails or disappears. The unsafe-fn inventory stays the existing check 1c.

## Acceptance

- Removing `pub struct RingAesGcm128` still fails 4n.
- Breaking the NIST test fails 4n-behavior.
- An `unsafe fn` in `qf-crypto` without `# Safety` fails (already true today; verify, do not reimplement).
- Zero `unsafe fn` still passes that predicate.
- The AMX/Windows/Linux criticals are not edited.

## Risks

- The audit script is already long. Call `cargo test` once with a filter, not three process spawns, if the filters can be combined. `cargo test` accepts one filter. Three invocations are acceptable. Do not use a filter so wide that it hides a failure in an unrelated test.
