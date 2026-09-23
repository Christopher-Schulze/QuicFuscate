---
id: TODO-1087
title: Prove H3 masquerade stays on the outer hop
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1055]
---

# TODO-1087: H3 inner-flow wire proof

## Why and evidence

TODO-1055's acceptance requires a captured inner `/tun` flow without extra
masquerade datagrams or server-push signals. The listed closeout evidence is
unit tests and source deletion, not that capture. It is plausible that the
implementation is correct, but the stated wire acceptance is unproven.

## Target contract

- Inner `/tun` streams emit only functional headers and tunnel application
  data. Persona User-Agent, QPACK dynamic-table training, WebTransport cover,
  and any other masquerade bytes are owned by the outer hop only.
- Server push stays disabled at the HTTP/3 protocol boundary: no outgoing
  MAX_PUSH_ID, PUSH_PROMISE or push streams; incoming unsolicited push follows
  RFC 9114 error handling. Do not infer this from absence of a generator.
- Attribute every observed extra datagram to a legitimate QUIC control,
  FEC, padding, cover, or application owner before declaring the inner path
  clean. Keep the TODO-1052 shared wire budget observable.

## Implementation and proof

- [ ] Run a local inner-only control and an outer-hop MASQUE scenario with
      equivalent application payload and full packet/decrypted H3 traces.
- [ ] Compare request headers, QPACK table instructions, H3 frames and
      datagram/byte counts; inspect every difference and document ownership.
- [ ] Exercise unsolicited server push with a local peer and assert the
      protocol error required by RFC 9114.
- [ ] Attach raw artifact hashes and command/commit metadata to TODO-1055;
      correct `docs/DOCUMENTATION.md` if the capture contradicts it.

## Acceptance

- Zero outer-persona headers, QPACK training or push frames in captured inner
  streams; all additional wire datagrams have a classified owner.
- The positive outer-hop capture contains the intended persona behavior, and
  negative inner-only capture fails if that behavior leaks inward.
