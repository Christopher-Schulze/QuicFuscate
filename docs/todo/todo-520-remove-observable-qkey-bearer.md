---
id: TODO-520
title: Remove observable QKey bearer from QUIC Initial packets
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-21
depends_on: [TODO-415]
supersedes: []
---

# TODO-520: Remove observable QKey bearer from QUIC Initial packets

## Why

The client injects the reusable QKey bearer into its QUIC transport parameters. RFC 9001 carries client transport parameters in ClientHello, and QUIC Initial protection keys are derived from public connection data. RFC 9000 therefore treats client transport parameters as observable by an on-path device. The current claim that this client token is carried in encrypted `EncryptedExtensions` is false and exposes a credential-derived authentication secret before handshake confidentiality exists.

The existing `x-qf-auth` HTTP/3 header already carries the same bearer after 1-RTT encryption. The server's authentication gate blocks MASQUE, TUN, and application forwarding until that header validates, so the observable early channel is unnecessary.

## Acceptance

- Client Initial and ClientHello bytes contain no QKey bearer or credential-derived equivalent.
- QKey authentication succeeds only through a handshake-confidential channel.
- Missing or invalid authentication cannot forward MASQUE, TUN, or application payloads.
- The QKey transport-parameter API, storage, parser, tests, and false confidentiality claims are removed atomically.
- A regression test inspects emitted pre-handshake datagrams for a unique bearer sentinel and proves absence while an end-to-end test proves encrypted authentication still succeeds.
- Full native test, Clippy, cross-target, documentation, and live Omega authentication gates pass.
- Protected Svelte/Tauri UI surfaces remain byte-unchanged.

## Sub-Tasks

- [ ] Map every QKey transport-parameter producer, consumer, fallback, and authorization gate.
- [ ] Add a failing pre-handshake credential-confidentiality regression.
- [ ] Remove the client transport-parameter bearer path and retain encrypted HTTP/3 authentication.
- [ ] Prove invalid and missing credentials fail closed before protected data forwarding.
- [ ] Reconcile TODO-415 and current architecture/security documentation with protocol truth.
- [ ] Run local, cross-target, CI, and Omega authentication proof.

## Notes

- RFC 9001 Section 8.2 places `quic_transport_parameters` in client `ClientHello` and server `EncryptedExtensions`.
- RFC 9001 Section 5.2 derives Initial secrets from the client's initial Destination Connection ID; RFC 9000 explicitly states that an attacker can observe client transport parameters.
- Source evidence: `src/core.rs` sets the QKey token before handshake; `src/qftls.rs` injects it into local transport parameters; `src/implementations/server/mod.rs` accepts the extracted bearer but already supports encrypted HTTP/3-header fallback and blocks protected forwarding until authentication.
- No UI change is required or allowed.

## Deviations

None.
