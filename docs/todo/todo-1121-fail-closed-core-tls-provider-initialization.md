---
id: TODO-1121
title: Fail closed when core TLS provider setup fails
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: []
---

# TODO-1121: Fail-closed core TLS provider initialization

## Why and evidence

`src/core/connection.rs::QuicFuscateConnection::new` calls
`Connection::enable_tls` and `Connection::configure_tls`, logs either error,
and still returns a core connection. `Connection::tls_handshake_complete`
returns `true` when `tls_provider` is `None`; `Connection::is_established`
therefore has no TLS-proof guard in that state. A failed TLS setup can enter
runtime ownership as a seemingly constructed connection, and a missing
provider is treated as a completed handshake. The exact packet-level reach
of this state needs a failing regression; the constructor and readiness
contract are already inconsistent with mandatory authenticated TLS.

## Target contract

- Core client/server construction returns a typed error if TLS provider
  creation or profile configuration fails. It never publishes the partially
  constructed connection, starts H3/authentication, or emits an established
  status. The original TLS error survives without a log-only downgrade.
- A production transport connection without a TLS provider never reports
  authenticated handshake completion or application readiness. Explicit
  test-only/no-TLS transport harnesses, if any, use a separate scoped proof
  path rather than weakening the production readiness check.
- All core constructors, server admission, client startup and their callers
  propagate the failure and release owned resources exactly once. A failed
  profile rebuild follows the same rule. No duplicate TLS provider family or
  parallel constructor implementation is introduced.

## Implementation and proof

- [ ] Map every `QuicFuscateConnection::new` caller, its return contract,
      server/client resource ownership, and tests that intentionally omit
      TLS. Identify the smallest fallible construction boundary.
- [ ] Add a deterministic failure injection through the real provider or
      configuration path. Prove current construction continues after failure
      and whether any public readiness/packet output can be observed.
- [ ] Propagate typed TLS setup failures through the existing constructors
      and runtime admission/startup. Tighten production handshake readiness
      while preserving narrowly scoped transport-only test behavior.
- [ ] Verify caller-visible errors, no H3/1-RTT/established emission, no
      leaked runtime ownership and single cleanup for client/server failures.
      Run focused core/TLS/server gates, Clippy and formatting; update owning
      architecture and task docs with measured behavior.

## Acceptance

- Every TLS construction/configuration failure prevents core connection
  publication; no provider-less production connection reports completion or
  sends application data.
- Success-path v1/v2 direct and Retry handshakes remain green, and no error is
  swallowed by a warning-only branch.
