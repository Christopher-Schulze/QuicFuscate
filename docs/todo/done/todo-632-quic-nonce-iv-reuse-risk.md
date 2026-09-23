---
id: TODO-632
title: QUIC nonce construction depends on IV uniqueness without enforcement
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-01
depends_on: []
---

# TODO-632: Document and Defend Against QUIC Nonce Reuse

## Why

`src/crypto/mod.rs::make_nonce16` constructs the 12-byte QUIC nonce by XORing the 64-bit packet counter into bytes 4-12 of the IV. For one fixed IV this mapping is injective over the 64-bit counter; the security dependency is that the IV/key epoch must not repeat across connections or key updates. Nonce reuse with AEADs is catastrophic, but the current finding is an unverified key/IV lifecycle contract rather than a proven collision for different counters.

## Findings

### 1. Nonce construction trusts IV uniqueness
- **File:** `src/crypto/mod.rs:611-625`
- **Severity:** HIGH
- **Impact:** A repeated IV combined with a reused packet counter or key epoch can repeat a nonce. The current code documents the dependency in a local comment, but does not expose a lifecycle invariant proving unique traffic secrets or preventing counter reset with the same IV.
- **Fix:** Define the key-update/packet-number invariant at the connection owner, reject counter reuse under one traffic secret, and document why runtime nonce-history storage is not required if the invariant is enforced.

## Acceptance

- The IV uniqueness assumption is documented in the code and in `docs/DOCUMENTATION.md`.
- The connection owner proves that packet counters are never reused with the same traffic secret, or a runtime mechanism detects reuse and returns a fatal crypto error.
- Local Rust gates, strict Clippy, and all crypto/transport tests pass.

## Sub-Tasks

- [x] Document the nonce construction and the IV uniqueness requirement.
- [x] Add a deterministic per-connection packet-number guard instead of a runtime nonce-history table.
- [x] Add regressions for key-update preservation, the 62-bit boundary, overflow, and pre-mutation rejection.
- [x] Update `docs/DOCUMENTATION.md` and `docs/MAP.md`.

## Notes

- Primary surface: `src/crypto/mod.rs`.
- This is a design-hardening task; the current HKDF usage is correct if keys are unique.
- `Connection::next_send_packet_number()` rejects values above `pnspace::PktNumSpace::MAX_PACKET_NUMBER`, and `advance_send_packet_number()` uses checked arithmetic. Initial/Handshake, normal 1-RTT, and targeted path-control send paths use the shared owner guard.
- `key_update()` does not reset the Application packet number. The historical Retry Initial-key counter reset was corrected in TODO-1118: every packet-number space stays monotonic across Retry. Counters reset only for a new connection/version attempt.

## Verification

- Locked all-target/all-feature check, strict Clippy, format, and diff checks passed.
- The full Connection group passed 119/119, Crypto passed 144/144, Packet passed 28/28, and baseline/property/security integration targets passed 6/6, 12/12, and 24/24.
- The full local library passed 2,203/2,205. The only failures are the pre-existing environment-dependent `dns::tests::test_doh_client_is_cached_and_shared` resolution failure owned by TODO-807 and `qftls::tests::rustls_client_hello_policy_excludes_chacha_for_chrome_and_firefox` readiness failure owned by TODO-768.

## Deviations

None.
