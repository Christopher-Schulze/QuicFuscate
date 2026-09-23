---
id: TODO-1083
title: Make UDP reachability fallback complete and end-to-end proven
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1063]
---

# TODO-1083: UDP-blocked fallback end-to-end

## Why and evidence

TODO-1063 is DONE, but `scripts/tests/rust/integration/outer_hop_fallback.rs`
starts from an already-selected fallback topology. It does not blackhole the
direct UDP path, observe `Engine::connect` switching, or prove application
bytes cross the result. `src/engine/engine.rs` retries only a synchronous
`runtime.connect()` error; its later `wait_handshake` timeout disconnects and
returns without fallback. `dial_failure_is_reachability` matches text such
as `"UDP receive"` and `"timed out"`, so diagnostic wording changes behavior.

## Target contract

- Route selection is TODO-1075's single session state machine. The selected
  carrier changes; QKey identity, tunnel authentication, replay policy, and
  inner application framing do not. A validated shared ingress is the
  primary carrier for a binding that requires its shared-IP property; a
  direct-only binding may select direct QUIC first. Never keep a second idle
  tunnel. An unavailable required shared edge yields a named failure, not a
  dedicated-IP downgrade.
- Use typed reachability causes from the runtime and transport, separating
  no-response timeout, ICMP unreachable, local socket failure, TLS alert,
  authenticated rejection, and peer close. Only an identified reachability
  cause may trigger the single configured outer-hop retry.
- Apply the same one-time decision when the selected primary attempt returns
  early or its handshake deadline expires. Preserve cleanup, firewall
  policy, transport state, the original cause, and the binding's anonymity/
  ECH floor; never retry indefinitely or fallback after a peer-visible
  authentication/protocol rejection.
- The fallback route must carry an actual authenticated inner QUIC session
  and bidirectional application bytes, with no cleartext DNS or accidental
  direct leak in stealth modes. If `tls_http` remains unsupported, validation
  must name that limitation before dialing.

## Implementation and proof

- [ ] Trace exact return types and state transitions in `ClientRuntime`,
      `Engine::connect`, `wait_handshake`, and the outer-hop circuit builder.
- [ ] Introduce or reuse a typed reachability result; remove message-substring
      classification while preserving user-readable diagnostics.
- [ ] Join early dial failure and handshake timeout into one bounded fallback
      decision, with explicit teardown, binding-policy and firewall
      transition checks. Test shared-primary and direct-primary policies.
- [ ] Run a netns test with direct UDP blackholed, a reachable MASQUE outer
      hop, and real bidirectional application payload. Include direct success,
      ICMP unreachable, timeout, TLS alert, relay failure, and retry budget.
- [ ] Reconcile TODO-1063 and `docs/DOCUMENTATION.md` with the observed scope.

## Acceptance

- At most one permitted alternate-carrier attempt after an eligible primary
  reachability failure, including a blackholed handshake; zero fallback
  attempts after a TLS alert or authenticated refusal, and zero dedicated-IP
  dial after a binding requires the shared ingress.
- Captured end-to-end test shows inner application bytes delivered in both
  directions and no direct UDP traffic after the fallback transition.
- All failed attempts release sockets/workers and restore consistent engine
  and firewall state; classification is invariant under error-message edits.
