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

## Scope
- Add a profile-freshness contract: each bundled profile carries a
  `recorded_from` browser version/date; profiles older than N months get a
  staleness warning and the audit gate checks that at least one current
  browser fingerprint exists.
- Extend the rotation tests: consecutive connections must not re-emit the
  identical ClientHello bytes (GREASE positions/values must vary like real
  browsers).
- Track JA4-relevant fields (not just JA3): extension order, ALPS,
  ECH-GREASE shape, supported-groups ordering - write a self-check that
  diffs our emitted hello against the recorded profile byte-for-byte except
  sanctioned variance points.
- Watch ECH deployment reality (Chrome/Firefox now ship ECH GREASE; real
  browsers send ECH extensions - a profile without any ECH field is
  becoming the anomaly).

## Acceptance
- Staleness audit gate + per-connection GREASE variance test green.
- Documented policy for how/when profiles are refreshed.
