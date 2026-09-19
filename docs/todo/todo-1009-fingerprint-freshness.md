---
id: TODO-1009
title: TLS/browser fingerprint freshness management and rotation validation
severity: MEDIUM
phase: M
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1009: Fingerprint freshness and rotation contract

## Objective
Fingerprint mimicry rots. Concrete 2025 evidence: a uTLS ECH-GREASE bug
(mismatched ECH/cipher-suite GREASE) made the Chrome parrot passively
identifiable (~50% per connection, near-100% across many connections) from
2023-12 through 2025-10 before being patched; Xray had to warn users
explicitly. JA4/JA4+ families also fingerprint beyond JA3's fields (HTTP/2
settings, timing, ALPS, extension order).

QuicFuscate's `browser_profiles/*.chlo` dumps + persona rotation +
`fingerprint_profile.rs` face the same risks:
- A recorded profile becomes detectable when the real browser's ClientHello
  evolves (new extensions, GREASE placement, post-quantum group additions
  like X25519MLKEM768).
- A fixed rotation set is itself a signature if all connections draw from a
  small static pool.

## Implementation plan

Files: `crates/qf-stealth/src/fingerprint_profile.rs`,
`crates/qf-stealth/src/tls_client_hello.rs`, `crates/qf-stealth/src/rotation.rs`,
`browser_profiles/*.chlo` (+ `.b64`), `src/stealth/fingerprint.rs`.

Step 1 - Schema: extend the `.chlo` profile format with
`recorded_from` (browser + version, e.g. "chrome/131") and
`recorded_at` (capture date). Backward compatible: missing metadata =
unknown age = treated as stale.

Step 2 - Audit gate: new `scripts/audits/verify-fingerprint-freshness.sh`
(or extend an existing audit): fails if zero profiles are <= 6 months old;
warns per stale profile. Wire into the audit suite (and clippy-matrix's
`feature-matrix-coverage`-style companion job if a natural host exists -
check `scripts/audits/` conventions first).

Step 3 - GREASE variance test (unit/rt): two consecutive generated
ClientHellos from the same profile must differ at GREASE value positions
while keeping GREASE *placement* identical to the recorded profile - real
browsers randomize values, not positions. Byte-identical hellos across
consecutive connections = fail.

Step 4 - JA4-field coverage self-check: diff emitted hello vs profile on
the fields JA4/JA4+ actually fingerprint: extension order, ALPS,
supported_groups order, key_share groups (post-quantum: X25519MLKEM768
presence), ECH extension shape. A profile with no ECH field at all is
flagged (real Chrome/Firefox send ECH GREASE since 2024 - its absence is
becoming the tell).

Step 5 - Refresh policy doc: capture/update procedure into CONTRIBUTING.md
or a profile-adjacent README note (who captures, from what, cadence).

## Risks
- Staleness is an arms race - the gate makes it *visible*, not solved;
  refresh cadence is an ops decision.
- Profile schema change must stay readable by older builds (additive
  fields only).

## Acceptance
- Staleness audit gate + per-connection GREASE variance test +
  JA4-coverage check green.
- Documented refresh policy.
