---
id: TODO-1080
title: Make Reality probe fallback a truthful, routed protocol response
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1048]
---

# TODO-1080: Reality probe fallback correctness

## Why and evidence

TODO-1048 is marked DONE, but its local UDP test sends canned bytes beginning
with a TLS record prefix, not a live TLS or QUIC handshake
(`crates/qf-reality/src/lib.rs`, `probe_relay_returns_cover_listener_bytes_verbatim`).
`src/stealth/manager.rs::handle_fallback` prefers cached TCP TLS flight bytes
over the relay and sends them as one UDP response. A TCP TLS flight is not a
valid QUIC response. `src/core/connection/send.rs` polls a `FallbackResponse`
but sends it to `self.peer_addr`, ignoring its `target`; when the caller's
buffer is short, polling already consumed the response. In
`src/core/connection.rs`, every non-TLS `conn.recv` error is labeled a possible
probe and converted to success. These paths do not establish the claimed
scanner-visible, protocol-valid fallback or multi-scanner isolation.
`StealthConfig::stealth()` sets an empty `reality_cover_targets` list and
`dynamic_enabled=false`; `StealthManager` consequently creates no
`RealityProxy` for the ordinary stealth preset. If a cover cache is enabled
separately but the proxy is absent, `handle_fallback` enters its cached
branch and returns without sending any bytes. Thus probe behavior depends
on mode and configuration in a way the current "Reality fallback" claim
does not disclose.

## Target contract

- Implement the unauthenticated-ingress branch of TODO-1075's single entry
  policy. The decision occurs before a tunnel-specific response and never
  treats an authenticated tunnel failure as a cover probe. Its cover origin,
  protocol, and response destination come from one validated entry binding.
  TODO-1094 must prove whether a stealth-compatible early admission signal
  exists for direct QUIC; absence of such proof limits the supported claim.
- Define the supported ingress protocol and authentication boundary first.
  A UDP/QUIC probe must receive a valid QUIC response from a real, compatible
  cover endpoint, or an explicit no-response policy. Never transmit cached
  TCP TLS records as UDP/QUIC. A TCP listener, if supported, needs its own
  byte-preserving bidirectional TCP relay; it cannot share the UDP packet path.
- Derive cover/probe readiness from the one validated entry binding, not
  `dynamic_enabled` or a nonempty string list. Each declared supported
  stealth mode must either instantiate the complete compatible response
  route or choose the explicit no-response policy. A cache cannot claim a
  response without an actual sender/dispatcher.
- Preserve `(probe source, target, response bytes, protocol, lifetime)` as one
  session identity. Route each response to its recorded source, including
  simultaneous probes, NAT source-port reuse, target rotation, and expiry.
  Authentication failures must not acquire an authenticated connection's
  address or leak another scanner's bytes.
- Do not dequeue a response until a send buffer can hold it. State the
  oversize policy against the maximum UDP payload and path MTU: bounded
  retry or explicit drop with telemetry, never silent loss after
  `BufferTooShort` and never truncation.
- Replace the broad `Err(_) => Ok(())` receive branch with an explicit,
  tested probe classification. Internal, malformed-state, resource, and
  transport errors remain visible errors; only designated unauthenticated
  probe input may enter fallback. Keep the original error for diagnostics.
- If no live cover endpoint can produce a protocol-valid response, document
  that limitation and use the explicit no-response behavior. Do not claim
  Xray/REALITY equivalence until the actual wire contract is proven.

## Implementation and proof

- [ ] Map call signatures and ownership from `RealityProxy::forward_probe`
      through `FallbackResponse`, `StealthManager::poll_fallback`, core send,
      and the socket dispatcher. Choose one owner for per-scanner routing.
- [ ] Remove the cached TLS-flight UDP branch or place it behind a truly
      matching TCP listener. Make the relay protocol and cover origin agree.
- [ ] Test ordinary stealth, Stealth MAX, dynamic, explicit targets, and an
      independently enabled cache with no proxy. Verify the emitted outcome
      and diagnostic for each; never count a consumed but unsent cache hit.
- [ ] Preserve target and response on the core send path; bound queues,
      lifetime, output size, and teardown without cross-session reuse.
- [ ] Narrow receive-error classification and expose non-probe failures.
- [ ] Test a local, real protocol endpoint and a complete scanner handshake.
      Test two concurrent scanners, buffer-too-short retry, malformed input,
      origin timeout, origin error, and authenticated traffic isolation.
- [ ] Correct TODO-1048 and `docs/DOCUMENTATION.md` claims against measured
      packet transcripts. Preserve the historical DONE record while linking
      this follow-up and its actual proof boundary.

## Acceptance

- Zero TCP TLS records emitted on the UDP fallback path; zero canned
  TLS-looking fixture bytes used as handshake proof.
- 100% of delivered fallback responses go to their recorded scanner address;
  no response is lost solely because the first caller buffer was short.
- A packet capture and local endpoint transcript demonstrate one complete
  supported probe exchange; unsupported ingress has an accurate documented
  outcome. Authenticated tunnel and fallback traffic remain isolated. Zero
  configured supported modes silently swallow a probe because the fallback
  sender was not constructed.
- Every receive-error variant has an explicit disposition test, including a
  test that fails if a real transport error is swallowed as a probe.

## Boundaries

No public cover origin is required by tests. This task does not invent QUIC
server behavior for a cover site or alter the tunnel's authenticated wire
protocol to make a probe test pass.
