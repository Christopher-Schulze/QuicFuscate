---
id: TODO-1101
title: Prove and repair the DoH TCP persona claim
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1058, TODO-1082]
---

# TODO-1101: DoH TCP persona fidelity

## Why and evidence

TODO-1058 is marked DONE with a claim that the DoH connection uses the
same persona as the tunnel. In fact,
`src/implementations/client/dns_runtime.rs::stealth_dns_policy` passes only
`TlsProfile.cipher_suites` to qf-dns; `crates/qf-dns/src/forwarding.rs`
builds a separate reqwest/rustls TCP client with fixed `h2` ALPN and
`quicfuscate-doh/1.0` user agent. No captured TCP ClientHello, extension
order, supported groups, key-share, signature algorithms, HTTP/2 SETTINGS,
or request-header comparison proves a browser-equivalent DoH flow. Sharing
three TLS 1.3 cipher IDs is narrower than sharing a browser persona.

The `persona_rustls_config` comment and TODO-1058 result specifically state
that TLS 1.2 suites keep rustls defaults. The code sets
`provider.cipher_suites = mapped`, where `mapped` contains only TLS 1.3
suites, so TLS 1.2 suites are removed. The existing unit test asserts only
the three mapped suites and therefore would pass with this discrepancy.

## Target contract

- Keep stealth modes' zero-UDP/53 fallback guarantee. Define a protocol-
  specific persona contract: QUIC/h3 and DoH TCP/h2 can share browser and OS
  selection, but their actual TLS/HTTP wire fields must each be compared to
  a capture for that protocol. No documentation says "same persona" solely
  from cipher-list equality.
- Decide TLS 1.2 support explicitly from captured browser behavior and DoH
  endpoint compatibility. If supported, preserve the provider's TLS 1.2
  suites after the ordered TLS 1.3 mapping; if intentionally TLS 1.3-only,
  configure protocol versions accordingly and state the compatibility
  boundary. Keep one provider config and no parallel TLS implementation.
- For an enabled claimed browser persona, emitted DoH ClientHello and h2
  request match its captured TCP policy across cipher ordering, extensions,
  supported versions/groups/key shares, ALPN, SNI/ECH where applicable,
  HTTP/2 SETTINGS and request headers. If reqwest/rustls cannot realize a
  field, document the measured delta and describe the client honestly; do
  not add a new TLS stack just for an unmeasured cosmetic claim.
- DoH endpoint pinning, certificate verification, timeout, failure and
  resolver-restoration behavior remain functional. The DoH user agent must
  not claim browser likeness while advertising `quicfuscate-doh/1.0` unless
  this explicit deviation is accepted in the product fingerprint contract.

## Implementation and proof

- [ ] Inventory DoH constructor call sites, selected personas, actual
      reqwest/rustls version/ALPN behavior, and the existing browser TCP/h2
      captures or collect targeted new captures. Measure wire fields on the
      configured DoH request, not only `crypto_provider().cipher_suites`.
- [ ] Fix the TLS 1.2 cipher/version contradiction in the existing provider
      builder. Add a real local TLS 1.2-only DoH endpoint test if 1.2 remains
      supported, plus a TLS 1.3 endpoint test and rejection/diagnostic case.
- [ ] Establish a small capture-backed comparison gate for each claimed DoH
      persona, including ClientHello and HTTP/2 metadata; feed its disposition
      into TODO-1082's support matrix. Preserve strict zero-UDP fallback tests.
- [ ] Correct TODO-1058, `docs/DOCUMENTATION.md`, and config/telemetry claims
      to the verified DoH fingerprint level. State any measured deviation,
      including user agent, without hiding it as a browser match.

## Acceptance

- The TLS 1.2 behavior matches the code, tests and documentation; a 1.2-only
  endpoint either completes with verified identity or fails for an explicit
  documented TLS 1.3-only policy.
- Every marketed DoH browser persona has a failable capture comparison with
  named deviations; zero unsupported "same persona" claims remain. The
  stealth DoH failure path still emits zero UDP/53 sends.
