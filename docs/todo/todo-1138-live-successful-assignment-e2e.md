---
id: TODO-1138
title: Prove successful live authenticated assignment over the client UDP path
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1136]
---

# TODO-1138: Prove successful live authenticated assignment

## Why and evidence

`IoDriver::negotiate_assignment` now has two localhost UDP terminal-close
tests, including TODO-1136's peer-protected CRYPTO failure. The control-plane
leaf tests successful capsule reception, but no test drives the successful
client assignment loop over real peer-protected QUIC/H3 output through ready
state. Parser fixes and terminal-branch changes therefore lack a direct
positive runtime regression.

## Target contract

- Establish a real client/server QUIC/TLS pair on connected localhost UDP
  sockets, then run the actual client assignment loop with a nonzero
  generation. Supply the server's authenticated assignment and all required
  CONNECT-IP capsules through its existing MASQUE/H3 control path.
- Observe `negotiate_assignment` return the exact server assignment, reach
  `ClientDataPlane::Ready`, retain the authenticated generation and assigned
  address/route state, and emit no terminal close or Reality fallback.
- Bound handshake, control exchange, socket receives, and total test time.
  Reuse the existing constructor-based UDP/TLS fixture where this reduces
  duplication without creating a parallel product pipeline. A leaf-only
  capsule parser or direct callback injection is insufficient proof.

## Implementation and proof

- [ ] Map the server assignment producer, MASQUE control-stream send path,
      client H3 callback installation, connection readiness, and exact
      `ClientAssignment`/`ClientDataPlane` accessors before editing.
- [ ] Add one real localhost success-path test with peer-protected packets and
      deterministic bounded polling. Assert the returned assignment, ready
      state, no close, and no probe fallback. Cover wrong-generation or
      incomplete CONNECT-IP capsules with existing focused tests if they
      already prove those boundaries.
- [ ] Run the focused test, relevant control-plane/Core regressions, default
      and feature root library suites, strict Clippy, formatting, and diff
      hygiene. Record native-platform scope.

## Acceptance

- The successful live assignment path is demonstrated end to end with real
  QUIC/TLS, H3 control, and UDP, without direct state injection or mocked
  success. All required gates pass.
