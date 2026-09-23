---
id: TODO-1081
title: Make shared-hop ECH automatic, service-bound, and freshness-safe
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1064]
---

# TODO-1081: ECH service binding and default policy

## Why and evidence

The current `qf_dns::https_record::extract_ech_config_list` returns the first
key-5 value in any HTTPS answer. It does not check answer owner/class, follow
the CNAME/SVCB AliasMode chain, choose the lowest usable ServiceMode
priority, validate mandatory keys, or bind TargetName/port/ALPN to the dial.
An AliasMode record may carry an ignored key-5 parameter, yet the parser can
select it. `resolve_outer_hop_ech` returns `()` and silently dials without ECH
after persistent DoH failure; it attaches bytes only once before `Engine::new`
with no DNS TTL refresh. The current persona gate suppresses ECH for
Firefox/Safari/Brave even when an HTTPS record advertises it, while the
startup log says "ECH enabled" as soon as bytes are attached. A random
persona can therefore disable ECH unintentionally. TODO-1064's claim that
in-band retry configs remove any need to refresh DNS is too strong. The
in-tree VPN listener does not terminate ECH, so a shared outer deployment
needs an actual ECH-capable TLS/MASQUE terminator; a DNS key learned for an
unrelated CDN endpoint cannot make the in-tree listener ECH-capable.
The parser also iterates `qdcount.min(64)` and `ancount.min(64)` without
rejecting a larger declared count; unconsumed questions can then be
interpreted as answers. It returns as soon as the first key-5 SvcParam is
seen, without validating remaining parameter order, duplicates or trailing
RDATA. Its public doc refers to nonexistent `want_qtype`/`want_name`
arguments. Reject over-limit counts before parsing and validate a complete
record before selecting its ECH bytes; correct the API documentation.
The only production call of `resolve_outer_hop_ech` is
`src/main/runtime/client.rs::run_circuit_client`, before `Engine::new` and
`Engine::start`. A client constructed through the public Engine API does not
perform that discovery at all, while a prepopulated `HopConfig` can still
carry bytes. The CLI circuit path performs discovery before its kill switch
exists; TODO-1107 owns the protected DoH bootstrap needed for that lookup.
`resolve_outer_hop_ech` calls the synchronous
`ClientDnsRuntime::prepare` inside an async function before its
`spawn_blocking` block, so hostname bootstrap can block the Tokio executor;
its subsequent `proxy.doh_client()` merely clones the already prepared
client. This is a separate startup/runtime issue from ECH service selection.

Standards: RFC 9460 (SVCB/HTTPS alias, service priority, mandatory, endpoint
selection), RFC 9848 (ECH deployment and SVCB-reliant behavior), and RFC 9849
(ECH handshake and retry configuration). Source URLs:
https://www.rfc-editor.org/rfc/rfc9460.html,
https://www.rfc-editor.org/rfc/rfc9848.html,
https://www.rfc-editor.org/rfc/rfc9849.html.

## Target contract

- Use TODO-1075's validated entry binding as the source of the outer service,
  certificate identity, ECH names, and dial endpoint. ECH is a capability of
  that shared service, not a second independently configured entry identity.
- For a shared outer hop with a usable, advertised ECH-capable HTTPS service,
  offer ECH on every eligible new TLS connection, including fallback and
  reconnection, whether started by the CLI or the public Engine API. Resolve
  before the first ClientHello through TODO-1107's pinned, authenticated
  pre-dial bootstrap path. It cannot use the tunnel it is about to establish.
  An inner dedicated-IP listener remains outside this ECH policy.
- Parse the DNS response into a typed result: validated question and response
  metadata, bounded CNAME and AliasMode traversal, owner/class checks,
  ServiceMode priority, TargetName, port, ALPN, mandatory keys, ECHConfigList,
  TTL and DNSSEC status if available. Reject loops, malformed names, unknown
  mandatory keys, out-of-bailiwick unrelated answers, conflicting parameters,
  and unsupported service choices without selecting arbitrary key-5 bytes.
- Select the actual connection endpoint from the chosen HTTPS service and
  bind its ECH configuration to that endpoint and origin name. Do not send a
  config learned for one service while dialing another. Preserve HTTPS/SVCB
  endpoint and certificate authentication semantics across circuit entry,
  fallback, standby, and reconnect paths.
- Define the deployment topology that terminates ECH and forwards the
  authenticated MASQUE tunnel. Reject ECH configuration for an in-tree
  listener that cannot decrypt it; do not advertise ECH as deployable merely
  because the client can emit an encrypted ClientHello.
- Decide persona before the dial. Automatic persona choice selects a captured
  ECH-capable profile when ECH is available. A fixed, operator-selected
  persona that cannot produce a faithful ECH ClientHello returns a named
  incompatibility or follows an explicit documented operator policy; never
  silently downgrade while reporting ECH active. Keep profile fidelity
  evidence coupled to the selected persona.
- Distinguish definitive no-ECH, temporary resolution failure, malformed
  response, unsupported config, ECH offered, and ECH accepted/rejected in
  typed outcomes and telemetry. When the resolved service requires ECH,
  failed resolution or unusable config must not silently emit a plaintext
  ClientHello. Explicitly define behavior when no HTTPS record advertises
  ECH, including whether persona-faithful GREASE is appropriate; GREASE never
  counts as encryption.
- Honor DNS TTL, bounded retry-config recovery, and config expiry on new
  connections. In-band retry configs can recover a rejected handshake; they
  do not replace endpoint/TTL refresh. Reconnects must not reuse an expired
  or mismatched ECHConfigList.

## Implementation and proof

- [ ] Map the DoH parser and `ClientDnsRuntime::prepare` contracts, preserving
      existing DoH response ID/question validation in `forwarding.rs`.
- [ ] Replace the lossy `Option<Vec<u8>>` extraction with typed HTTPS service
      selection and bounded DNS chain handling; test AliasMode, CNAME,
      priority, mandatory, TargetName, port, ALPN, TTL, malformed input,
      answer-owner mismatch, and unrelated key-5 injection. Explicitly test
      QDCOUNT/ANCOUNT over the bound, a valid key-5 followed by malformed or
      duplicate SvcParams, and trailing RDATA; no partial-count or
      early-return record may supply a selected config.
- [ ] Carry a validated service binding and expiry through `HopConfig`, the
      outer-hop dial, TLS provider, fallback topology, and reconnect logic.
- [ ] Make ECH/persona selection explicit before the first dial and return a
      typed outcome to the common Engine/client dial owner instead of
      ignoring `()` in `src/main/runtime/client.rs`. Remove the redundant
      eager/repeated DoH client preparation and keep any blocking endpoint
      resolution off the async executor.
- [ ] Prove an actual local ECH-capable endpoint can decrypt and complete the
      handshake and carry a MASQUE association, or label a decryptable
      ClientHello test as offer-only until a real terminator is available.
      Test no plaintext fallback after an
      all-ECH HTTPS response and test accepted/rejected/retry states.
- [ ] Update TODO-1064, `docs/DOCUMENTATION.md`, config text, and logs to
      match tested ECH policy and actual persona support.

## Acceptance

- All valid eligible shared-hop attempts offer ECH; zero plaintext
  ClientHellos after a validated all-ECH service response except an explicit
  operator override with a recorded reason. No ECH claim for a direct
  dedicated-IP hop or GREASE-only offer.
- Parser tests cover every selection and rejection case above; a selected
  config's owner, endpoint, name and TTL match the actual dial.
- A cold start, TTL expiry, reconnect, fallback, fixed incompatible persona,
  public Engine API start, and transient/terminal DoH failure each yield a
  deterministic, visible result. The initial ClientHello never precedes
  required service discovery. An ECH lookup never blocks the Tokio worker or
  bypasses the protected bootstrap policy.

## Boundaries

ECH is useful for a shared address whose service binding supports it. This
task does not claim that ECH hides a dedicated VPN IP or require a custom
server ECH implementation. Performance and wire-image effects require
measurement before changing a default persona.
