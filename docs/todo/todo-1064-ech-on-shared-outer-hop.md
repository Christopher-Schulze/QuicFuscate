---
id: TODO-1064
title: ECH only on a shared outer hop
severity: LOW
phase: S
priority: P3
status: DONE
created: 2026-09-21
depends_on: [TODO-1058, TODO-1063]
---

# TODO-1064: ECH only on a shared outer hop

## Why

RFC 9849 (2026-03) encrypts the inner ClientHello, including SNI. QUIC can carry it because the ClientHello sits in Initial. rustls 0.23 can do ECH as a client (`EchConfig`). Server-side rustls is still an open issue (rustls 1980). As of 2026-08, Cloudflare serves millions of ECH-capable domains over TCP and QUIC. On a dedicated VPN IP, ECH hides almost nothing: the IP is the name. RFC 9849 says the same.

## Current code

- rustls 0.23 is the TLS stack (`Cargo.toml`).
- Nothing constructs `EchConfig`.
- A grease ECH extension inside the synthetic hello does not count. TODO-1062 deletes that hello.

## Target

- Client ECH only on the outer hop from TODO-1063, and only when that hop's HTTPS/SVCB record contains an `ech` parameter.
- Fetch the record with DoH (TODO-1058), not cleartext DNS.
- If the record has no ECH config, connect without ECH. Do not invent a config.
- Do not implement server ECH while rustls server support is missing. The VPN listener does not pretend to speak ECH.

## Non-goals

- No custom HPKE.
- No frontend visual change.
- No ECH on the inner dedicated-IP listener.

## Design

1. After DoH, parse the HTTPS record. If `ech` is present, build `rustls::client::EchConfig` with the rustls HPKE provider and set it on the outer `ClientConfig`.
2. The direct UDP path to a dedicated IP does not set ECH.
3. Tests use a fixture record. Assert the client offers ECH when the fixture is present and does not when it is absent. Use the rustls API. Do not hand-roll the extension. A local server does not need to accept ECH if rustls still cannot be an ECH server.

## Sub-Tasks

- [x] Confirm the pinned rustls 0.23 exposes `EchConfig`. If the lock is older, bump only within 0.23 and record the version. Do not fork and do not write a private ECH stack.
- [x] Parse the HTTPS `ech` parameter from DoH.
- [x] Outer client sets ECH only when the parameter exists.
- [x] Tests: fixture present vs absent.
- [x] Config comment: a dedicated IP gains nothing from ECH.

## Acceptance

- Outer hop with an ECH fixture offers ECH.
- Outer hop without a fixture does not.
- The inner listener has no ECH state.
- No hand-rolled ECH extension bytes.

## Result (2026-10-14)

- **rustls 0.23.45 already carries client ECH** (`rustls::client::EchConfig`,
  `EchMode::Enable`, `ConfigBuilder::with_ech`). No bump needed, no fork, no
  hand-rolled extension bytes. HPKE suites come from `qf-hpke`
  (`crates/qf-hpke`), a pure-Rust `rustls::crypto::hpke::Hpke` provider
  built on `hpke-rs` with the `rustcrypto` backend — the ring provider ships
  no HPKE and aws-lc-sys was dropped from the default tree after review.
  The provider is always compiled in; the `rustls-aws-lc` feature stays
  declared for bakeoff comparisons only. Coverage: X25519/P-256/P-384 KEMs
  x AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305; a list offering only P-521
  suites fails closed at `EchConfig::new` (the rustcrypto backend has no
  P-521 — implementing DHKEM-P521 inside qf-hpke would be hand-rolled KEM
  internals, which the standard-library policy deliberately rejects).
- **Always-on at the right time**: the lookup runs before the engine dials,
  its result lives on the `HopConfig`, and every engine-internal reconnect,
  standby promotion, or `outer_hop` fallback retry reuses it automatically.
  A transient DoH failure at startup no longer leaves ECH off for the whole
  session — the HTTPS-record lookup retries up to 3 times at 250 ms spacing
  (still fail-soft: a clean "no ech" answer is not retried, a persistent
  outage still dials a normal ClientHello). Key rotation server-side is
  handled by rustls' in-band ECH retry-config mechanism, so no periodic
  re-resolution is needed.
- **DoH path**: `qf_dns::https_record` builds the type-65 query and extracts
  the `ech` SvcParam (key 5) from the answer section — bounded parse,
  compression-aware names, fail-closed on malformed RDATA. The wire value is
  already the binary ECHConfigList; no base64 step applies.
- **Orchestration**: `resolve_outer_hop_ech` (client lib) runs inside
  `run_circuit_client` before `QuicFuscateEngine::new` — while the system
  resolver is still untouched. It uses `ClientDnsRuntime::prepare`, so the
  lookup rides the same DoH endpoint and TLS persona as the TODO-1058 proxy.
  The resolved bytes land on `HopConfig::ech_config_list` (`#[serde(skip)]`,
  runtime-injected, never operator config) — only on the outer hop / circuit
  entry hop. `outer_hop_fallback_config` clones carry it into the synthesized
  two-hop circuit automatically.
- **TLS provider**: `transport::Config.ech_config_list` flows through the
  existing provider constructor chain into `rustls_provider`. Both client
  config builders (`create_client_connection` and the persona rebuild) call
  `with_ech(EchMode::Enable)` when a list is present. `EchConfig::new`
  validates the list — a corrupt or invented one is a dial error, never a
  silent downgrade. The persona gate applies too: a profile whose captured
  fingerprint never sends ECH (e.g. Brave) emits a plain ClientHello even
  with a record present.
- **Boundaries kept**: the direct UDP dial and every inner hop pass `None`
  explicitly; server-side ECH is not implemented (rustls lacks it); no GREASE
  is invented when the record is absent.

## Tests

- `qf-dns`: 6 `https_record` tests — query wire shape, `ech` present/absent,
  non-HTTPS answers ignored, malformed RDATA → `None`.
- `qftls::tests::ech_tests` (always compiled; qf-hpke needs no feature):
  `EchConfig` construction
  accept/reject paths plus **real wire assertions** — the emitted ClientHello
  carries extension `0xfe0d` and the outer SNI becomes the ECH `public_name`
  for an ECH persona; a Brave persona and an absent list both emit no `0xfe0d`.
  The strongest proof is `ech_payload_decrypts_to_inner_hello_with_real_sni`:
  the fixture list carries a real X25519 public key, the emitted outer hello's
  ECH payload is decrypted with the matching private key under the exact
  draft-ietf-tls-esni-17 construction (`info = "tls ech"‖0x00‖ECHConfig`,
  AAD = serialized outer hello with the payload field zeroed), and the
  recovered `EncodedClientHelloInner` carries the true service SNI. So the
  wire bytes are not merely shaped right — a real ECH terminator could
  decrypt them.
- `engine::engine::tests`: the synthesized fallback circuit carries
  `ech_config_list` on the entry hop only, and the field never serializes.
- `implementations::client::ech`: hostname selection (SNI > endpoint host,
  IP literals excluded), entry-hop targeting, no target on direct dials.

## Risks

- The locked rustls 0.23 might predate client ECH. The version check is the first step. If the API is missing, this task stays blocked on a rustls bump.
  - Resolved: rustls 0.23.45 exposes the full client ECH API.
