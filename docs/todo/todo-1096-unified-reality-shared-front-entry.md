---
id: TODO-1096
title: Execute one validated Reality and shared-front entry
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1075, TODO-1080, TODO-1081, TODO-1083, TODO-1092, TODO-1093, TODO-1094, TODO-1095, TODO-1107]
---

# TODO-1096: Unified Reality and shared-front entry

## Why and evidence

The desired product is one tunnel that gains REALITY-grade probe resistance
and, where infrastructure genuinely permits it, the shared-address benefit
of domain fronting. The current paths do not compose into that product.
`src/stealth/manager.rs::masque_proxy` picks the first
`stealth.reality_cover_targets` entry as a MASQUE proxy authority;
`src/core/connection.rs::ensure_masque_tunnel_with_requirement` sends that
name as H3 `:authority` over the already established QUIC connection. It does
not dial a shared edge at that point. The H3 CONNECT-IP validator in
`src/transport/h3/connection/masque_and_webtransport.rs` checks only that
`:authority` is nonempty. Thus an arbitrary cover host can be advertised as
proxy authority without being the authenticated endpoint or a routing
participant. Separately, TODO-1080 shows the present UDP fallback cannot
complete a valid TCP TLS cover handshake, and TODO-1083 shows the declared
UDP-blocked fallback has no demonstrated timeout-driven application path.
The open tasks listed in `depends_on` own those local defects. This task owns
their single deployed contract, migration and comparative acceptance.
`qf_reality::RealityProxy::new_with_targets` silently retains the
environment/built-in 1.1.1.1, 8.8.8.8 and 9.9.9.9 relay set when an explicitly
configured cover list has no valid entry. A typo in the operator's intended
origin can therefore select a different external endpoint. Treat an absent
optional list separately from a present-but-invalid binding, and never use
an undeclared fallback target for an explicit profile.
`StealthManager::new_with_clock` also gives the cover scheduler an implicit
`cdn.cloudflare.com` target when no cover list exists, and
`webtransport_cover_plan` uses the same implicit authority. Those names are
sent as H3 authorities to the existing peer; there is no evidence that the
peer is authorized to serve them. The fallback is another untyped
cover-origin-to-service conversion and must be removed with the explicit
first-target shortcut.
`src/engine/engine/config_projection.rs::resolve_client_entry` calls the
system resolver for a hostname entry inside `Engine::connect`, after
`Engine::start` has enabled a blocking kill switch. A cold resolver can
therefore prevent the first dial; resolving before that firewall policy
without a protected bootstrap can leak ordinary underlay DNS. The new
entry binding must solve this same pre-dial identity/address problem as
TODO-1107's ECH DoH bootstrap, not merely relabel an unprotected lookup.
`src/core/connection/request_headers.rs::build_masque_request_headers`
injects the QKey `x-qf-auth` token into H3 requests, and
`src/core/connection/h3_runtime.rs::build_http3_request_headers` does the
same even for `outer_hop=true`. That is appropriate only when the H3 TLS
terminator is trusted to see that credential. A future cooperating or
third-party shared edge would terminate outer TLS and read these headers;
the current design has no explicit edge trust role or separate relay
credential. This is a deployment-design gap, not proof that the current
direct QuicFuscate listener leaked a token to a third party.

## Target contract

- One versioned, typed `EntryBinding` is validated before QKey issuance and
  dial. It identifies an authenticated tunnel service, allowed carriers,
  route identifier, dial endpoint, TLS authority and certificate trust,
  optional ECH service binding and public/inner names, HTTP authority and
  CONNECT target only for a real authorized shared edge, and a separate
  protocol-typed probe cover origin. A plain host list is never promoted
  implicitly into a MASQUE proxy, certificate identity, or front route.
- Resolve a hostname dial endpoint through a pinned, certificate-authenticated
  pre-dial discovery path or an explicit validated address. The kill switch
  admits only the exact bootstrap service and selected entry endpoints,
  with a bounded transition between them. A cold cache cannot silently
  force an underlay DNS exception or a dedicated-IP fallback.
- One QKey/authentication/replay policy, inner packet framing, application
  stream semantics, error model and firewall/leak policy are shared by the
  direct and shared-edge carriers. Carriers adapt encapsulation and outer
  handshake only. This is one user-visible entry profile, not two selectable
  VPN implementations. A validated shared ingress is primary when the
  binding requires or prefers its shared-IP property. Direct QUIC is primary
  for direct-only deployments or explicit operator policy. A route selected
  after a classified reachability failure cannot silently downgrade shared-
  address anonymity, identity, ECH policy, or anti-replay.
- Declare the outer TLS terminator's trust role in `EntryBinding`. An
  untrusted shared edge receives only the routing information and a
  narrowly scoped relay credential it must verify; the inner QKey secret,
  exit authentication, replay material and application identity remain
  inside the encrypted inner tunnel. A trusted owned relay may receive
  the current `x-qf-auth` form only under an explicit, testable deployment
  policy. The default shared-edge path never assumes that outer TLS hides
  H3 headers from its terminator.
- Direct carrier: standards-compliant QUIC v1/v2 first flight and explicit
  probe outcome. Shared carrier: real controlled/cooperating H3 endpoint
  that accepts CONNECT-UDP or CONNECT-IP and routes the inner tunnel to the
  authenticated service. The outer TLS SNI, certificate, ECH public name and
  H3 authority must match that actual service's advertised routing rules.
  HTTP `Host` variation is permitted only where the named shared service
  explicitly supports and authorizes it. No arbitrary third-party CDN name
  is accepted as proof of fronting.
- One entry state machine handles binding-based primary selection, bounded
  reachability classification, at most one policy-permitted alternate
  carrier, success, rejection, and teardown. A shared-required binding
  never falls back to the dedicated IP. Authentication/certificate failures
  are terminal.
  Each outcome has a stable diagnostic. Supported protocol-valid probes
  reach the bound cover origin without scanner cross-talk; unsupported
  protocols have an explicit no-response policy.
- Remove `masque_proxy()`'s first-cover-target fallback and any other path
  that treats a cover origin as an authenticated proxy by string reuse.
  Remove the implicit `cdn.cloudflare.com` H3 cover/WebTransport authority
  too; absent a validated cover service, emit no such request. Preserve a
  cover target only for its declared probe/cover purpose. A configured but
  entirely invalid probe origin list fails profile validation; it must not
  fall back to an environment or built-in third-party relay. Migrate
  CLI, TOML, QKey issuance, desktop IPC/UI and docs atomically to the typed
  roles; reject ambiguous legacy configs with a precise migration error.
  Keep at most a bounded, explicit wire-transition plan if old peers must
  interoperate. No permanent second implementation or shadow config.
- ECH runs when the selected shared service advertises a valid, fresh HTTPS
  service binding and the configured policy requires/offers it. Never send
  ECH to a listener without the corresponding key/config; never silently
  fall back to a clear outer name when the selected binding requires ECH.
  Browser persona, QUIC framing, transport parameters, H3 and outer socket
  behavior are verified as one wire image per carrier.

## Implementation and proof

- [ ] Close TODO-1075's threat model and entry-binding schema using primary
      Xray REALITY, RFC QUIC/ECH/MASQUE and actual edge-provider contracts.
      Pin an Xray baseline and declare measurable comparison workloads and
      non-inferiority margins before comparing.
- [ ] Trace and enumerate every consumer of `reality_cover_targets`,
      `masque_proxy`, H3 `:authority`, QKey `df_sni_*`, `outer_hop`, ECH config,
      `x-qf-auth`, implicit `cdn.cloudflare.com`, and TLS name in server,
      client, engine, core, Tauri,
      admin UI, tests and docs. Record which name and endpoint is
      authenticated on each hop and exactly which terminator sees each
      credential. Include `resolve_client_entry`, standalone target
      resolution, kill-switch enable/connecting order, and DoH/ECH pre-dial
      bootstrap from TODO-1107.
- [ ] Distinguish no configured cover-origin policy from an explicitly
      configured but invalid policy at `RealityProxy::new_with_targets` and
      all config entrypoints. Reject invalid entries with an actionable
      diagnostic before runtime selection; test all-invalid, mixed-valid,
      absent, and environment-supplied cases, with zero undeclared target
      selection under an explicit profile.
- [ ] Introduce one validated binding and route planner at the existing
      config/engine boundary; compile it to carrier-specific immutable dial
      inputs. Remove implicit role conversion. Do not add a new abstraction
      until the consumer map proves its ownership boundary.
- [ ] Wire direct and controlled shared-edge carriers to the same inner
      tunnel and authentication. Reuse the existing H3/MASQUE implementation
      only where a real accepting edge and correct CONNECT semantics are
      demonstrated. Add TCP-capable carrier only when UDP reachability data
      and a real endpoint justify it; never synthesize a TLS-looking reply.
- [ ] Integrate TODO-1080/1081/1083/1092/1093/1094/1095 corrections in one
      rollout. Test active probes, two scanners, QUIC framing, Retry, ECH
      acceptance/rejection, certificate mismatch, revocation, replay,
      timeout/unreachable retry, forbidden downgrade, route teardown and
      leak protection with actual endpoints and packet captures. On a
      cooperating edge, inspect decrypted outer H3 and decrypted inner
      tunnel separately; prove inner QKey bytes and exit identity are
      absent from the edge-visible header/body transcript.
- [ ] Compare pinned Xray REALITY and the previous QuicFuscate route under
      the same hardware, network and probe corpus. Report reachability,
      scanner response validity, passive fingerprint/classifier outcomes,
      latency, throughput, CPU and byte overhead with repeat counts and
      uncertainty. Update product docs and remove obsolete aliases only
      after clients and server move together.

## Acceptance

- Direct and at least one authorized shared-edge route complete the same
  authenticated application exchange with one inner tunnel implementation;
  zero implicit cover-origin to proxy-authority conversions remain.
- 100% of emitted SNI/certificate/ECH/authority/CONNECT tuples match the
  selected binding and edge routing contract; unsupported combinations fail
  before dial with a named error. No certificate bypass, replay acceptance,
  scanner cross-delivery, inner-QKey exposure to an untrusted edge, or
  direct leak after shared-edge selection occurs in the declared test matrix.
- Protocol-valid probe transcripts and independent packet parsing cover every
  supported ingress; unsupported ingress behavior is documented accurately.
  The QUIC first flight meets TODO-1095 before any browser-persona claim.
- Any claim of being better than Xray REALITY is backed by TODO-1075's
  predeclared comparison gate. If measurements do not beat the comparator,
  report the measured limits and retain the best verified deployment policy.

## Boundary

No system can guarantee reachability under every outage or censor. This
task targets one reliably reasoned product path and explicit failure modes,
not an unconditional "always works" marketing claim.
