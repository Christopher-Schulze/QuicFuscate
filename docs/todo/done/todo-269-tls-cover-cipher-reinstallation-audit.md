# TODO-269: Audit TlsCoverProvider Cipher Suite Reinstallation

## Severity: HIGH

## Context
`src/stealth.rs:846-862` conditionally reinstalls the cipher suite when a `cipher_kind` mismatch is detected. The guard prevents unnecessary reinstallation, but under frequent browser profile switching, this could:
1. Cause performance overhead from repeated cipher suite negotiation
2. Create an observable fingerprint if the cipher suite changes mid-session
3. Potentially weaken the TLS cover story if intermediate states are detectable

## Desired Outcome
- Audit the cipher reinstallation path for correctness and performance impact.
- Determine if cipher suite changes mid-session are observable to a network observer.
- If observable: lock the cipher suite for the session lifetime and only change on reconnect.
- If not observable: document why and add a test proving it.
- Measure performance impact of frequent reinstallation under profile switching.

## Files
- `src/stealth.rs` (lines ~846-862, TlsCoverProvider)

## Completion Criteria
- Cipher reinstallation behavior is documented and justified.
- No observable fingerprint leak from cipher suite changes.
- Performance impact measured and acceptable.
- `cargo test` passes, clippy clean.
