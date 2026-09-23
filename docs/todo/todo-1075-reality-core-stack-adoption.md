---
id: TODO-1075
title: Unified Reality, shared-front, and stealth entry architecture
severity: LOW
phase: S
priority: P2
status: OPEN
created: 2026-09-22
depends_on: []
---

# TODO-1075: Unified Reality, shared-front, and stealth entry architecture

## Why

The product target is one authenticated tunnel and entry policy, combining
REALITY-grade probe handling with the useful property of domain fronting:
shared-edge reachability that does not reveal a dedicated tunnel IP. The
existing `RealityProxy` and retired `enable_domain_fronting` do not jointly
deliver that property. Xray REALITY's documented example uses raw/TCP TLS and
forwards rejected ClientHellos to a real target; our UDP/QUIC ingress needs
its own protocol-valid design. Copying features blindly adds detection
surface, so each candidate needs a wire-level verdict, not a port.

## Unified entry decision and boundaries

- One logical session, authenticated identity, route-selection state machine,
  and inner tunnel protocol. Direct QUIC, an authorized shared-edge HTTP
  tunnel (including MASQUE CONNECT-UDP where supported), and any justified
  TCP-capable carrier are adapters selected by typed reachability outcomes,
  not independently configured VPN implementations. Never duplicate QKey,
  tunnel authentication, replay protection, policy, or application framing
  across carriers. A path may fail explicitly; no deployment can promise
  reachability under every censor or outage.
- Expose one product entry profile. When that binding has a validated,
  authorized shared ingress, prefer it for the first dial so its shared-IP
  property and REALITY-grade probe contract apply to the same session.
  Direct QUIC is the first dial only for a deployment without that ingress
  or an explicit operator policy. A fallback must stay within the binding's
  declared anonymity and ECH floor; never switch from a required shared
  route to a dedicated-IP direct dial merely to report availability.
- Define one validated entry binding before QKey issuance and before the
  first client dial: deployment/route identifier, dial endpoint, authenticated
  TLS name and certificate authority, ECH public/inner names and selected
  HTTPS/SVCB service when applicable, ALPN, HTTP authority and CONNECT target
  when a real shared edge supports them, cover origin and its protocol, and
  allowed carrier set. Keep probe cover origin distinct from authenticated
  tunnel identity. Reject unsupported combinations before emitting a
  ClientHello; desktop and standalone clients derive identical effective
  values. TODO-1092 owns QKey/certificate parity; TODO-1081 owns ECH service
  and endpoint freshness; TODO-1093 owns UI/config serialization.
- Preserve the domain-fronting benefit only with proven, authorized HTTP
  co-tenancy or an owned/shared ingress that actually routes the requested
  authority. TLS authenticates the visible front; the inner tunnel
  authenticates QuicFuscate. ECH can protect the inner name when the selected
  shared service terminates ECH. A mismatched SNI/Host pair on an arbitrary
  CDN, a third-party certificate assumed from an allowlist, and ECH bytes
  sent to a listener without ECH keys are invalid deployment designs.
- Classify unauthenticated input before any tunnel-specific response. A
  supported UDP/QUIC scanner must see a complete protocol-valid exchange
  from the bound cover endpoint, with per-scanner routing and isolation; a
  supported TCP ingress needs a separate bidirectional TCP relay. If neither
  protocol-valid path exists, record the explicit no-response policy. No
  cached TCP TLS flight may be sent on UDP. The current stable ASCII QKey ID
  in the clear QUIC Initial cannot be the stealth admission design; verify a
  protocol-valid early-routing mechanism before promising REALITY-grade
  handling. TODO-1080 owns relay correctness; TODO-1094 owns Initial-token
  privacy and early-admission feasibility.
- Select the carrier with one bounded state machine that covers synchronous
  dial errors and handshake-timeout reachability, never authentication
  rejection. The selected primary and optional one fallback both carry the
  same authenticated inner session and obey the binding's privacy floor and
  firewall/no-leak policy. TODO-1083 owns the decision and end-to-end proof;
  TODO-1076 owns churn/lifecycle resilience.
- Browser persona, QUIC Initial/transport parameters, H3 cover behavior,
  outer IP/UDP headers, shaping budget, and ECH offer must describe one
  coherent wire image per session. Existing TODO-1082/1085/1087 and
  TODO-1074 own fidelity and cost measurements; optimization may not add a
  second uncoordinated packet-shaping authority. TODO-1095 first restores
  mandatory RFC long-header Length framing before any browser-like QUIC or
  REALITY-grade wire claim.
- QUIC v1/v2 is a wire-version policy within that same tunnel, not a second
  product variant. The current Engine/CLI defaults prefer v2, but RFC 9369
  gives v2 no new application capability or security/privacy property; its
  changes exercise version negotiation and resist ossification. Choose the
  first version from measured endpoint support, reachability and
  persona-matched captures, then use authenticated version negotiation
  within the binding. Do not claim that v2 alone improves stealth or
  switch versions to bypass a required shared/ECH policy. TODO-1082 owns
  version-specific wire-image proof.

## Superiority gate

- Compare against a pinned upstream Xray REALITY build and the current
  QuicFuscate baseline under the same network, cover, and hardware
  conditions. Record versions/configs and distinguish Xray's documented
  raw/TCP route from our UDP/QUIC and shared-edge routes.
- Require full active-probe transcripts, certificate/authentication/replay
  outcomes, scanner isolation, passive fingerprint and traffic-classifier
  results, UDP-blocked reachability, latency, throughput, and byte/CPU
  overhead with repeat counts and uncertainty. Gate values: zero invalid
  scanner responses, cross-scanner deliveries, certificate bypasses, replay
  acceptances, plaintext ECH downgrades on an all-ECH service, and direct
  leaks after shared-edge selection; complete successful authenticated
  exchange on each declared supported carrier. Before benchmarking, fix and
  publish the classifier corpus, network impairments, comparison workloads,
  and non-inferiority margins for latency/throughput/overhead. At least one
  demonstrated security or reachability improvement and no breach of those
  predeclared margins are required before calling the product better. Until
  then, superiority and universal availability are unproven goals.

## Candidates (initial, extend during research)

- Xray Vision / XTLS flow control (splice-style early-data cut-through).
- REALITY-style destination camouflage (authenticated temporary certificate
  for clients; real target handshake for rejected probes) versus our current
  persona emulation and UDP relay.
- ShadowTLS v3 (relay a genuine TLS session as cover for a second channel).
- MASQUE CONNECT-IP / CONNECT-UDP hop composition patterns.
- uTLS/browser-fingerprint research beyond our current persona tables.
- Website-fingerprinting defenses (FRONT-style, WTF-PAD successors).
- GFW QUIC-blocking behavior research — confirm or update the current
  "residual/compute-limited" classification with fresh evidence.

## Per-candidate verdict template

- Threat model addressed (active probe, passive DPI, fingerprint DB, traffic
  analysis).
- Wire effect (what changes on the wire, byte and timing level).
- Detection surface added or removed.
- Implementation cost and ownership boundary.
- Measurement plan (how we'd prove it helps).
- Verdict: adopt / evolve (build our variant) / reject — with rationale.

## Non-goals

- No blind feature copying.
- Arbitrary CDN SNI/Host mismatch stays rejected. Authorized shared-front
  routing and ECH-capable co-tenancy are within the unified target.
- No claim that any defense is "undetectable" — only measured properties.

## Output

- Ranked candidate table committed to this file.
- Follow-up TODOs created only for adopt/evolve verdicts.
- TODO-1096 owns the integrated runtime rollout and proof once this entry
  contract is settled; it must use one authenticated tunnel, not fork the
  product into independent Reality and domain-fronting implementations.

## Acceptance

- [ ] Every candidate above has a filled verdict row.
- [ ] At least the top-2 candidates get a wire-level feasibility sketch.
- [ ] Rejected candidates record the reason, not just "no".
- [ ] One entry-binding schema, carrier state machine, and packet-level flow
      sketch connect TODO-1080/1081/1083/1092/1094/1095 without parallel tunnel
      authentication or a stable cleartext client identifier.
- [ ] A real shared-edge route and a direct route use the same inner tunnel;
      unsupported fronting/ECH topologies fail before dial with a named cause.
- [ ] Superiority claims are withheld until the comparator gate above passes.

## Source boundaries

- Xray REALITY documented config and reject-to-target behavior:
  https://github.com/XTLS/REALITY/blob/main/README.en.md
- HTTP co-tenancy fronting model: https://www.rfc-editor.org/rfc/rfc8744.html
- CONNECT-UDP carrier: https://www.rfc-editor.org/rfc/rfc9298.html
- ECH service binding: https://www.rfc-editor.org/rfc/rfc9848.html
- QUIC v2 capabilities and privacy boundary:
  https://www.rfc-editor.org/rfc/rfc9369.html#section-7
- Examples of provider SNI/Host enforcement:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html
  and https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1013/
