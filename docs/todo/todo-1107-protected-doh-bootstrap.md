---
id: TODO-1107
title: Resolve DoH bootstrap only through an explicit protected path
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1058, TODO-1075]
---

# TODO-1107: Protected DoH endpoint bootstrap

## Why and evidence

`crates/qf-dns/src/forwarding.rs::build_doh_client_for_endpoints` calls
`(host, port).to_socket_addrs()` for each hostname endpoint and pins the
result in reqwest. `DnsProxyConfig::for_client_endpoints_with_policy`
immediately calls `prepare_doh_client`. `ClientDnsRuntime::prepare` therefore
resolves before the Engine enters its connecting firewall policy, but after
`Engine::start` enabled a blocking kill switch. The standalone runtime
enables and arms its endpoint-only connecting policy before it calls
`prepare_endpoint_with_policy`. Both clients activate the DoH proxy only
after tunnel/data-plane readiness. A DoH hostname not already served from
an OS cache can thus fail bootstrap under a strict kill switch. With the
kill switch disabled, the same code may resolve over ordinary underlay DNS
even when the stealth DoH policy forbids cleartext UDP/53 fallback. The
existing zero-UDP fallback test observes qf-dns forwarding, not this OS
bootstrap call. No packet-capture claim is made without a native run.
The ECH discovery path calls `ClientDnsRuntime::prepare` before
`Engine::start` in `run_circuit_client`, then calls `doh_client()` again even
though preparation already built and cached it. That early ECH lookup also
needs the same protected bootstrap contract and must not be treated as an
exception for an optional feature.

The HTTPS endpoint's hostname remains the certificate/SNI identity even
when its socket address is pinned. The current pre-pin design solves local
proxy recursion but does not define a protected bootstrap transport.
TODO-1075 establishes the typed entry identity. This bounded bootstrap
contract precedes TODO-1081's ECH service selection and TODO-1096's common
runtime rollout; waiting for TODO-1096 would leave its mandatory pre-dial
discovery without an implemented protected path.

## Target contract

- A stealth client never resolves a DoH endpoint hostname through an
  implicit system resolver on the physical underlay. It obtains a bounded
  A/AAAA set through an authenticated tunnel resolver before local DNS
  redirection, or uses explicitly configured bootstrap IPs bound to the
  original HTTPS hostname for SNI and certificate verification. No
  unrestricted DNS firewall exception or hardcoded public resolver.
- ECH service discovery occurs before the first outer-hop ClientHello and
  therefore cannot depend on that tunnel. It requires an explicitly pinned
  DoH bootstrap IP with certificate-verified HTTPS and a narrowly scoped,
  temporary firewall allowance for that exact IP:port, or an equally
  authenticated pre-dial channel. Close the allowance after lookup. If the
  configured policy requires ECH but no protected pre-dial lookup exists,
  fail before dialing instead of attempting an impossible tunnel bootstrap
  or silently falling back to a plaintext ClientHello. The later local DNS
  proxy may use authenticated tunnel DNS or the validated pin.
- Complete tunnel authentication and the required DNS/data-plane readiness
  before tunnel resolver lookup. If that path is unavailable and no explicit
  bootstrap address exists, fail with an actionable typed configuration/
  bootstrap error while keeping the kill switch closed. Do not deadlock by
  resolving through the local proxy being initialized.
- Pin addresses per endpoint, preserve IPv4/IPv6 and existing endpoint
  count/deadline bounds, and define TTL/reconnect refresh through the same
  protected path. Validate configured bootstrap address syntax and reject
  empty sets. A certificate mismatch or hostname change never inherits a
  previous pin silently.
- `off`/`performance` may retain an explicitly declared underlay-bootstrap
  policy if product configuration permits it; stealth modes have zero
  underlay UDP/53 and TCP/53 requests, including startup and reconnect.
  The Engine and standalone clients use one bootstrap contract.

## Implementation and proof

- [ ] Trace `Engine::start/connect`, standalone `run_client`, kill-switch
      policy, assigned DNS, TUN/data-plane readiness, qf-dns constructor,
      reqwest address override and resolver restoration on failure. Record
      existing hostname and IP-literal behavior and required config schema.
- [ ] Move hostname bootstrap out of the eager qf-dns constructor into one
      explicit resolver input. At pre-dial ECH discovery, use an authenticated
      pinned bootstrap path with exact temporary firewall ownership; at the
      post-authentication/pre-local-proxy boundary, select authenticated
      tunnel DNS or the validated pin. Retain HTTPS host verification and a
      bounded address set. Make startup and reconnect failures fail closed
      with exact error propagation.
- [ ] Add failable Engine and standalone tests with a cold resolver, blocked
      underlay, pre-dial ECH DoH over an exact pinned HTTPS allowance,
      successful post-auth tunnel DNS, missing bootstrap, IPv4/IPv6, stale
      pin/TTL, certificate mismatch, allowance revocation, and rollback.
      Assert no OS resolver call from the stealth path using a real injected
      resolver boundary, not a mocked success-only proxy.
- [ ] Run native packet capture with kill switch on and off: count all
      underlay port-53 packets from process start through DoH activation and
      reconnect; require zero for stealth. Confirm DoH HTTPS reaches the
      pinned address and verifies the configured hostname. Update
      `docs/DOCUMENTATION.md` and TODO-1058 proof language.

## Acceptance

- A cold-cache hostname DoH endpoint starts in both client runtimes under
  a strict kill switch through a protected bootstrap path, or fails closed
  with an explicit missing-bootstrap error; it never succeeds by opening a
  cleartext underlay exception.
- Native startup and reconnect captures show zero stealth underlay DNS
  requests; IP literal and pinned-hostname cases preserve certificate
  verification, bounds and resolver rollback. The documented policy matches
  measured behavior.
