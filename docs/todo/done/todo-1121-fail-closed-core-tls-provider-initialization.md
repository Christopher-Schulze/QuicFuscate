---
id: TODO-1121
title: Fail closed when core TLS provider setup fails
severity: HIGH
phase: S
priority: P1
status: DONE
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

- [x] Map every `QuicFuscateConnection::new` caller, its return contract,
      server/client resource ownership, and tests that intentionally omit
      TLS. Identify the smallest fallible construction boundary.
- [x] Add a deterministic failure injection through the real provider or
      configuration path. Prove current construction continues after failure
      and whether any public readiness/packet output can be observed.
- [x] Propagate typed TLS setup failures through the existing constructors
      and runtime admission/startup. Tighten production handshake readiness
      while preserving narrowly scoped transport-only test behavior.
- [x] Verify caller-visible errors, no H3/1-RTT/established emission, no
      leaked runtime ownership and single cleanup for client/server failures.
      Run focused core/TLS/server gates, Clippy and formatting; update owning
      architecture and task docs with measured behavior.

## Acceptance

- Every TLS construction/configuration failure prevents core connection
  publication; no provider-less production connection reports completion or
  sends application data.
- Success-path v1/v2 direct and Retry handshakes remain green, and no error is
  swallowed by a warning-only branch.

## Verification record

- A 1199-byte configured UDP budget reaches the real provider and returns its
  `ConnectionError::InvalidState` on both client and server construction. A
  malformed ECHConfigList passes provider creation but returns its original
  `TlsError` from profile configuration. Both regressions failed against the
  prior warning-only constructor and pass with fallible construction. The
  caller receives no partially initialized core connection; the failed
  client/server constructors drop their cloned runtime-owner references.
- Core constructors and live server admission now propagate typed
  `ConnectionError`. The client engine converts to its existing `EngineError`
  string at that boundary; the standalone client logs the typed error and
  returns. A valid QKey Initial with an invalid TLS budget proves that live
  admission publishes no connection, records one abandoned authentication
  attempt, and releases the limiter slot for the same IP.
- A provider-less production transport returns false for authenticated
  completion and establishment, rejects direct TLS progression, and cannot
  serialize queued 1-RTT application data even when a test has installed
  packet keys. Only the explicitly marked test/benchmark transport fixture
  may bypass TLS; that flag is absent from ordinary product builds.
- Full-library verification exposed a related TODO-1120 resumption flaw:
  rustls exposes remembered peer parameters before the new server flight.
  The provider now replaces that snapshot with current peer parameters at
  handshake completion, without copying on steady-state polls. CID and
  version-information validation wait for actual TLS completion. The
  remembered UDP payload limit applies to 0-RTT; the authenticated current
  limit replaces it for 1-RTT, including increases up to the local cap.
  A real ticket-resumption test observes both snapshots and a focused limit
  test proves the transition. No cached CID or version value is treated as
  current-handshake proof.
- Focused core 80/80 and transport 162/162 tests, the QKey TLS/H3 integration
  test, all-target `rust-tests` checking, strict root-library Clippy, and
  formatting pass. The final full root-library suite passed 1,844 tests with
  one ignored; an earlier 1,842-test run also passed in serial and parallel
  modes after the resumption fix. All-target Clippy passes with allowances
  limited to three unrelated Rust 1.98 diagnostics recorded under TODO-1079.
