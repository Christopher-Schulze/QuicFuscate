# TODO-225: InsecureAcceptAllVerifier Missing Runtime Safety Guard

## Severity: HIGH

## Problem

`src/qftls.rs:829-874` implements `InsecureAcceptAllVerifier` which accepts any TLS certificate without validation. This is a Man-in-the-Middle (MITM) vector when enabled via environment flag.

Current state:
- No `#[deprecated]` annotation
- No runtime warning log when the verifier is activated
- No compile-time guard beyond the env flag check
- An attacker who controls the env var (or a misconfigured deployment) silently disables TLS verification

## Impact

- Silent MITM vulnerability if env flag is set
- No audit trail: nothing in logs indicates verification is bypassed
- No compile-time friction to discourage production use

## Fix

1. Add `#[deprecated(note = "Development only - MITM risk in production")]` annotation
2. Add a prominent `log::warn!("TLS certificate verification DISABLED - InsecureAcceptAllVerifier active. DO NOT USE IN PRODUCTION.")` when the verifier is constructed
3. Consider: only allow activation when a `dev-certs` feature flag is also enabled
4. Document the env var in security documentation with explicit warnings
5. Add a startup check: if InsecureAcceptAllVerifier is active AND the binary is a release build, emit an error-level log

## Affected Files

- `src/qftls.rs:829-874` - verifier implementation
- `src/qftls.rs` - where the verifier is conditionally constructed

## Verification

- `cargo clippy` reports deprecation warnings if used without `#[allow]`
- Log output confirms warning is emitted when verifier is activated
- Unit test: verifier construction emits expected warning
