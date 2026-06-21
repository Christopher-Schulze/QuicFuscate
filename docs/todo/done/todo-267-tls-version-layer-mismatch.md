# TODO-267: Reconcile TLS Version Claims Across Protocol Layers

## Severity: MEDIUM

## Context
Three different "browser version" claims coexist in the same request stack:
1. `qftls.rs` TLS profiles claim: Chrome 130, Firefox 133, Safari 18
2. `stealth.rs` User-Agent strings claim: Chrome 126, Firefox 127, Safari 17.5
3. ClientHello templates in `stealth.rs` fingerprint: Chrome 120, Firefox 120, Safari 17

A sophisticated DPI system could detect the mismatch between the TLS ClientHello fingerprint, the User-Agent header, and the TLS profile version. All three layers should claim the same browser version.

## Desired Outcome
- Define a single canonical browser version per profile (e.g., Chrome 130) and propagate it to ALL layers: TLS profile, ClientHello template, and User-Agent string.
- Create a centralized `BrowserProfile` struct that owns the version and generates consistent data for all layers.
- Add a test that verifies version consistency across layers for each browser profile.

## Files
- `src/qftls.rs` (TLS profile definitions)
- `src/stealth.rs` (User-Agent strings, ClientHello templates)
- `src/profile.rs` (browser profile synthesis)

## Completion Criteria
- All three layers (TLS profile, ClientHello, User-Agent) claim the same browser version for each profile.
- A unit test enforces cross-layer version consistency.
- `cargo test` passes, clippy clean.
