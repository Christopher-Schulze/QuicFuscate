---
id: TODO-1094
title: Remove stable QUIC Initial admission marker without losing early routing
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1075, TODO-1095]
---

# TODO-1094: QUIC Initial admission identity and probe routing

## Why and evidence

`src/main/runtime/client.rs` derives the QKey's 12-character ID and passes
it to `QuicFuscateConnection::new_client_with_runtime`; the constructor sets
`TransportConfig::initial_token` in `src/core/connection.rs`. The Initial
packet writer in `src/transport/connection/send.rs` copies that token into
the clear QUIC header. `src/implementations/server/live_auth.rs` accepts that
token as the pre-handshake QKey registry lookup key, and
`src/implementations/server/qkey_registry.rs` explicitly calls the ID public
and stable. The 64-hex-character bearer proof is separate and occurs after
handshake. The current admission design therefore exposes a repeatable
per-key identifier and nonempty ASCII token shape before TLS. This is a
wire-visible linkage and likely classifier input, not proof by itself that
a particular censor detects it. It also couples probe routing to a custom
Initial-token convention rather than a demonstrated browser-faithful flow.

## Target contract

- Under TODO-1075's one-entry design, a new authenticated connection must
  have no stable public per-QKey marker in its first Initial. Preserve
  certificate validation, real QKey proof, revocation, bounded unauthenticated
  work, and the existing Retry integrity semantics.
- Decide from packet captures and a threat model whether a direct QUIC
  listener can distinguish an authorized client before its first response
  without a nonstandard browser-visible signal. Evaluate a rotating,
  cryptographically bound and protocol-valid admission signal, a genuine
  shared-edge route with a normal outer handshake, and any standards-valid
  alternatives. A randomized token alone is not enough if its length or use
  remains a reliable fingerprint. Reject proposals that expose a reusable
  credential or add a conspicuous ClientHello extension.
- If no faithful early discriminant exists, state that direct QUIC cannot
  offer Xray-like unauthorized-probe indistinguishability. Use a declared
  no-response/ordinary-QUIC policy for that carrier, and put the stronger
  cover behavior at a genuine shared ingress. Do not claim universal
  equivalence or make a second tunnel-auth implementation.
- Ensure Retry does not convert a transient routing token into a stable
  identifier, and bound token parsing, registry work, relay resources, and
  replay state per source and globally.

## Implementation and proof

- [ ] Trace exact client, desktop, QKey issue/parse, Initial write, Retry,
      server admission, and revocation call sites and signatures; identify
      every assumption about the 12-character ID and old QKeys.
- [ ] Capture first Initials from fresh QuicFuscate and matching browser
      clients; compare token presence, length, encoding, persistence across
      sessions, Retry behavior, RFC Length framing (TODO-1095), and passive
      linkability. Record corpus, versions, and repeat counts.
- [ ] Produce a threat-modelled early-routing decision with an explicit
      wire format and key lifecycle if a direct admission signal is viable;
      otherwise document the direct-carrier limit and shared-edge ownership.
- [ ] Implement the selected single admission contract atomically across
      client, server, QKey compatibility, Retry, probe relay, tests, UI/config,
      `docs/DOCUMENTATION.md`, and `docs/MAP.md`.
- [ ] Test same QKey across independent sessions, invalid/expired/revoked
      credentials, token replay, Retry, concurrent scanners, resource
      exhaustion bounds, and a full authenticated inner exchange. Run a
      packet-level active-probe comparison with TODO-1080.

## Acceptance

- Zero stable public per-QKey IDs in the first Initial of the supported
  stealth route; zero acceptance of a revoked or replayed admission proof.
- No introduced first-flight token/extension shape outside the declared and
  measured persona envelope. If direct early routing is infeasible, the
  direct path's limitation and exact scanner response are documented instead
  of being called REALITY-equivalent.
- Existing QKeys have a tested migration or a named fail-closed error, and
  all authenticated/unauthenticated resource bounds stay enforced.
