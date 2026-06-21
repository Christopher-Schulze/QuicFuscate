# TODO 85: TLS Cover and Rustls Boundary Clarification

## Problem Statement

The project intentionally keeps TLS cover / fake-TLS behavior.
That is acceptable.

The requirement is that the boundary remains explicit:
- `rustls` is the real TLS implementation
- `TlsCoverProvider` is a cover/persona/mimicry layer

If this becomes blurred, the code and docs start sounding like the project has "custom TLS suites" or "custom TLS semantics" where it actually has:
- standard TLS
- plus a separate cover layer

## Current State

### Canonical Current Code Anchors
- provider wiring:
  - `src/qftls.rs:528` `CombinedProvider::new(...)`
  - `src/qftls.rs:535` `pub struct CombinedProvider`
- TLS cover hook:
  - `src/qftls.rs:537` `cover: Option<crate::stealth::TlsCoverProvider>`
  - `src/qftls.rs:561` `TlsCoverProvider::new(...)`
- Provider entrypoint:
  - `create_provider(is_server, crypto)` is the single public creation path and always returns a `CombinedProvider`.
- TLS cover implementation:
  - `src/stealth.rs:221` `pub(crate) struct TlsCoverProvider`
  - subsequent `impl TlsCoverProvider`

### What Is Valid and Intended
- `rustls` remains real TLS
- cover/persona/mimicry behavior remains
- the project does not want to remove TLS cover

## Desired End State

### `rustls`
- the real TLS handshake and TLS semantics

### `TlsCoverProvider`
- cover-layer behavior
- persona/mimicry
- synthetic cover framing where intended
- no claim of being the canonical TLS implementation

### `CombinedProvider`
- composition layer only
- not a second ambiguous TLS truth

## Explicit Non-Goals

- Do not remove TLS cover capability.
- Do not fold cover behavior into `rustls`.
- Do not reframe the project as "standard TLS only".

## Why This Change Is Required

### External Review
The project already asks reviewers to accept a custom data-plane crypto posture.
That remains much more defensible if the TLS boundary is crystal clear.

### Internal Engineering
Clear boundaries reduce:
- wording drift
- duplicate helper surface
- accidental policy leakage between cover code and real TLS code

## Detailed Work Breakdown

### A. Boundary Audit
- Trace responsibilities currently split between:
  - `CombinedProvider`
  - `RustlsProviderImpl`
  - `TlsCoverProvider`
- classify each as:
  - real TLS
  - cover-layer behavior
  - telemetry/debug only
  - dead or overexposed wrapper

### B. API and Visibility Cleanup
- keep only productive TLS-cover surface that runtime owners actually need
- push test-only and helper-only surface behind test/crate visibility
- remove wrappers that imply TLS cover is the same layer as real TLS

### C. Documentation Truth
- document `rustls` as the real TLS implementation
- document TLS cover as separate cover/mimicry functionality
- remove wording that implies MORUS/AEGIS or cover logic are TLS suite semantics

### D. Test Coverage
- keep tests for:
  - provider composition
  - TLS cover generation
  - runtime wiring into the cover layer

## Options

### Option A: Remove TLS cover
- simplest boundary
- loses desired stealth capability
- rejected

### Option B: Keep TLS cover, clarify layer split
- preserves capability
- preserves project direction
- reduces ambiguity
- recommended

### Option C: Leave current boundary as-is
- no migration effort
- continued ambiguity
- not recommended

## Acceptance Criteria

- `rustls` remains clearly the real TLS implementation.
- `TlsCoverProvider` remains clearly a separate cover layer.
- `CombinedProvider` does not introduce a second ambiguous TLS truth.
- docs and code comments reflect the same split.
- remaining public surface around TLS cover is minimal and owner-driven.

## Completion Snapshot

- [x] `ProviderStrategy` removed from the TLS wiring API, with `create_provider(is_server, crypto)` remaining as the canonical boundary entrypoint.
- [x] Boundaries are explicit in code and tests: rustls is the protocol owner, TLS cover is an overlay.

## Validation Plan

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted tests on:
  - `qftls`
  - TLS cover generation paths
  - runtime wiring where CLI/runtime still consume TLS cover

## Dependencies

- `docs/todo/todo-76-forked-aead-protocol-posture-clarification.md`
- `docs/todo/todo-84-data-plane-aead-ssot-and-ownership-simplification.md`

## Status

- Focused boundary pass implemented.
- Current status: DONE.

## Progress Notes

- Large amounts of dead TLS-cover helper surface have already been removed or test-gated.
- `rustls` remains the real TLS implementation and must stay that way.
- `CombinedProvider`, `QuicTlsProvider`, and call sites now encode the TLS boundary explicitly:
  - `rustls` owns protocol handshake semantics and secrets.
  - `TlsCoverProvider` is an optional overlay for cover/persona behavior.
  - `CombinedProvider` is composition and wiring only.
