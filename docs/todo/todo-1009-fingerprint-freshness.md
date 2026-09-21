---
id: TODO-1009
title: TLS/browser fingerprint freshness management and rotation validation
severity: MEDIUM
phase: M
priority: P2
status: PARTIAL
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

## Implementation status (2026-09)

Reality correction: the persona catalog is **code**, not `.chlo` files -
`fingerprint_profile.rs` holds UA constants and `tls_profile.rs` holds the
TlsProfile descriptors consumed by `profile_from_fingerprint` (timing/SNI/
ALPN/QPACK knobs; the wire ClientHello itself is emitted by rustls, while
`tls_cover.rs` builds the separate synthetic cover hello).

DONE:
- `PROFILE_CATALOG_SNAPSHOT` marker in `fingerprint_profile.rs` replaces the
  `.chlo` recorded_at schema (Step 1 adapted: the catalog is compiled in).
- `scripts/audits/verify-fingerprint-freshness.sh` (Step 2): fails when the
  snapshot is >6 months old; enforces UA major-version coherence (Chrome/Edge
  aligned, Firefox rv: aligned, Safari Version == iOS major); guards that the
  zero `hello_random` placeholder stays inside cfg(test) code; guards that the
  production builder draws per-call entropy. Registered in
  `audit-all-comprehensive.sh` as `fingerprint_freshness`.
- Catalog refreshed to the verified 2026-09 fleet: Chrome/Edge 153,
  Firefox 156 (rv:156), Safari 26.0 (iOS 26), Opera 136, Brave 1.95
  (Chromium 153). The gate immediately caught a stale inline Edge-Android UA
  (Chrome/136) during first run.
- Synthetic cover hello entropy (Step 3): `generate_client_hello` now draws
  per-call `rand::rng()` for hello random, session ID, key-share seed, GREASE
  value indices, ECH-GREASE seed, and padding length. Two consecutive hellos
  from one persona are no longer byte-identical (previously: `random` was
  literally `[0u8;32]` and every field was persona-seeded - an instant
  synthetic tell). Regression test
  `generate_client_hello_per_call_entropy_varies_random_sid_and_key_share`
  asserts variance; GREASE *placement* stays fixed by construction (cipher
  slot 0, fixed extension positions) matching real browsers.
- Step 4 partial: non-Safari cover hellos now emit the modern
  X25519MLKEM768 (0x11EC, 1216B) + X25519 (0x001D, 32B) key-share pair via
  `key_share_ext_multi`; Safari keeps the classic X25519-only shape.
  `generate_client_hello_modern_key_share_shape` guards it.
- Step 4 JA4 field-level diff (reproducible): test-only
  `dump_persona_client_hellos_as_hex` exports every persona hello;
  `scripts/audits/ja4_diff.py` parses a TLS-record hello into JA4 + field
  lists (FoxIO-compliant: GREASE excluded from counts, sorted
  cipher/extension hashes, signature algorithms folded into the c-hash).
  Diffing the synthetic output against the FoxIO Chrome QUIC reference
  (`q13d0312h3_55b375c5d22e_178839b6cec1`) surfaced and fixed three real
  tells:
  1. **ECH-GREASE was opt-in** (`QUICFUSCATE_TLS_COVER_ULTRA`) while real
     browsers emit it unconditionally - now always on; ULTRA only adds the
     padding extension.
  2. **TLS 1.2 cipher suites in an h3 hello** - QUIC hellos only carry
     TLS 1.3 suites; the list is now filtered to 0x1301..=0x1305 when ALPN
     leads with h3, and the ChaCha-removal handshake policy no longer
     applies to the cover path (every real browser offers 0x1303). The
     cipher hash now matches the real Chrome QUIC hash `55b375c5d22e`
     byte-for-byte.
  3. **Missing quic_transport_params (0x0039)** - mandatory per RFC 9001,
     its absence is an instant QUIC-aware DPI tell. Emitted for all
     h3-first personas with Chrome-plausible values + fresh
     initial_source_connection_id per call. Chrome/Edge additionally emit
     ALPS (0x4469) + compress_certificate (0x001B); Firefox compress_cert
     only; Safari QTP only.
  Result: Chrome persona now reads `t13d0312h3_55b375c5d22e_*` - identical
  a/b segments to the real Chrome QUIC reference (the `t`/`q` prefix
  difference is the TLS-record wrapping our cover path uses, not a field
  deviation). Regression tests:
  `h3_first_hello_advertises_tls13_only_and_quic_transport_params`,
  `chrome_hello_matches_browser_quic_extension_shape` (12 non-GREASE
  extensions with SNI, matching the reference count).

OPEN:
- JA4 c-hash byte-parity against the specific FoxIO reference build was
  deliberately not chased: it fingerprints one Chrome snapshot's exact
  extension set and chasing it is over-fitting (different Chrome builds
  differ). Structural parity (counts, cipher hash, mandatory fields) is
  the maintained contract.
- Real-browser packet captures are still absent locally/Omega; the audit
  relies on published FoxIO references instead.
- Refresh policy note (capture procedure/cadence) - Step 5.
- Caveat: key-share and SCID bytes are pseudo-random *shaped* placeholders
  - valid only because this path is strictly synthetic cover, never a
  real handshake.
