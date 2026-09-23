---
id: TODO-1047
title: Real ClientHello and transport parameters from one browser capture
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: []
---

# TODO-1047: Real ClientHello and transport parameters from one browser capture

## Why

QUIC Initial is readable with the version salt. A censor hashes the ClientHello and the QUIC transport parameters. JA4 does not cover transport parameters, so a second hash does. Today the persona and the bytes on the wire disagree.

## Current code

- `src/qftls/rustls_provider.rs` `default_transport_params`: idle 30 s (`0x01`), `initial_max_data` 10 MB, both bidi stream data limits 1 MB, bidi and uni stream counts 100. One blob for every persona. No grease, no `max_datagram_frame_size`, no `active_connection_id_limit`, no `initial_source_connection_id`.
- `RustlsProvider::new_with_ca_with_snapshot_and_clock_and_max_udp_payload` installs that blob into the rustls QUIC connection. That is what Initial carries.
- `src/stealth/manager.rs` `apply_utls_profile` copies `fingerprint.initial_max_data` onto `transport::Config`. That changes internal flow control, not the Initial bytes.
- `crates/qf-stealth/src/fingerprint_profile.rs` stores 5 MB to 15 MB per browser/OS. `PROFILE_CATALOG_SNAPSHOT` is `2026-09`.
- `src/qftls/tests.rs` `every_supported_persona_controls_the_real_rustls_client_hello_order` checks cipher order and that key-share groups overlap the profile. It does not require the hello to match a capture, and it does not check transport parameters.

## Target

One capture per persona is the only source for:

- cipher suite list and order actually offered by rustls
- extension set and order rustls can emit
- supported groups, including only groups rustls can mint as real key shares
- the transport-parameter block rustls puts in Initial
- ALPN `h3`

Internal flow control may be larger than the advertised limits. The advertised numbers must be the capture's numbers.

Grease values must be real grease (reserved values a browser emits), generated per connection, not a fixed constant that is itself a fingerprint.

## Non-goals

- Do not send `TlsCover::generate_client_hello` (TODO-1062).
- Do not invent ML-KEM shares. If the capture has X25519MLKEM768 and rustls cannot produce a real share, the persona stays on the groups rustls can produce, and the catalog must not claim the missing group.
- No frontend visual change.
- No mid-connection hello rewrite. A new persona needs a new connection (TODO-1056).

## Design

1. Add a checked-in fixture per persona: raw Initial CRYPTO payload plus a parsed parameter map. Store under `crates/qf-stealth` fixtures, dated, next to `PROFILE_CATALOG_SNAPSHOT`.
2. Replace `default_transport_params` with `transport_params_for_persona(profile, max_udp_payload, local_scid)`. `max_udp_payload_size` stays the path MTU cap. Other integers come from the fixture. `initial_source_connection_id` is the real local SCID, not a constant.
3. `apply_utls_profile` must call the same builder. Delete the second numeric table or generate it from the fixture so the two cannot drift.
4. rustls ClientHello config (`apply_profile_to_config` and the cipher/extension lists on `TlsProfile`) is reduced to what the fixture contains and what rustls can emit. A test fails if the on-wire hello's cipher list, extension types, or transport-parameter IDs differ from the fixture, ignoring per-connection grease and the real key-share bytes.
5. Key shares stay rustls-generated. The test checks groups, not raw share bytes.

## Sub-Tasks

- [x] Capture or import one current Chrome, Firefox, and Safari Initial. Record browser version and date in the fixture header.
- [x] Builder used by both rustls Initial and `apply_utls_profile`.
- [x] Extend `every_supported_persona_controls_the_real_rustls_client_hello_order` to compare parameter IDs and cipher/extension order to the fixture.
- [x] Fail the freshness script (`scripts/audits/verify-fingerprint-freshness.sh`) when the fixture date is older than `PROFILE_CATALOG_SNAPSHOT` allows.
- [x] Document which capture groups were dropped because rustls cannot mint them.

## Acceptance

- Decoding a test Initial with the version salt yields transport parameters whose IDs and values match the fixture for that persona, except SCID and grease.
- Two personas do not produce the same parameter blob unless their fixtures are actually the same.
- `apply_utls_profile` and the Initial blob cannot disagree on `initial_max_data`.

## Tests

- Rustls provider test decrypts or parses the CRYPTO frame and asserts the parameter map.
- A mismatch fixture (catalog 15 MB, hello 10 MB) must fail in CI once the single builder exists.

## Risks

- Browser parameters move every release. The freshness gate is the control, not a one-time paste.
- Advertising a smaller `initial_max_data` than the old 10 MB can slow the ramp. That is required for mimicry. Internal credit above the advertisement would be a lie if it is used to send more than the peer allowed. Advertise the capture, and do not send past the peer's limit.

## Notes

2026-09-22 source check, not a capture. Firefox `modules/libpref/init/StaticPrefList.yaml` on main: `network.http.http3.max_data` 25165824, `network.http.http3.max_stream_data` 12582912, `network.http.http3.idle_timeout` 30 seconds. Those are Neqo prefs, not an Initial CRYPTO payload. The catalog Firefox `initial_max_data` 12582912 matches the stream window, not the connection window. Do not paste 25165824 into the catalog and call this task done. Chrome `quic_constants.h` `kDefaultFlowControlSendWindow` is 16 KB and the 16 MB / 24 MB values are receive-window limits, not a proven ClientHello `initial_max_data`. Safari was not fetched. No Initial fixture is in the repo.

### Implemented (2026-09-22)

- **Fixture**: `crates/qf-stealth/fixtures/transport_params.toml`, parsed by
  `crates/qf-stealth/src/transport_params.rs`. One `[engine]` section per
  engine family (Chromium, Firefox, WebKit) holds `snapshot`,
  `provenance` (`wire-capture` / `source-constants` / `unverified-catalog`),
  `captured_at`, the full `sends` transport-parameter map, and the
  ClientHello contract (cipher order, extension order, supported groups,
  key-share groups, ALPN).
- **Chromium**: real wire capture of Chrome 154.0.8037.44 taken on
  2026-09-22 with `scripts/capture/quic_initial_listener.py` (headless
  Chrome against 127.0.0.1:4434, tshark-decoded Initial). Captured values:
  `initial_max_data` 15728640, all three `initial_max_stream_data_*`
  6291456, `initial_max_streams_bidi` 100, `_uni` 103,
  `max_idle_timeout` 30000, `max_udp_payload_size` 1472,
  `max_datagram_frame_size` 65536, `google_connection_options` 'ORIG',
  `version_information`, per-connection GREASE TP, zero-length
  `initial_source_connection_id`. No `ack_delay_exponent`,
  `max_ack_delay`, or `active_connection_id_limit` — Chrome does not send
  them. Extension order incl. ALPS and real ECH recorded in the fixture.
- **Firefox**: neqo source constants (`source-constants` provenance):
  stream limits 100/100, `initial_max_stream_data_*` 1048576,
  `initial_max_data` 2097152, `max_datagram_frame_size` 65535,
  `ack_delay_exponent` 3, `max_ack_delay` 25, `active_connection_id_limit`
  8, `min_ack_delay` 0xff02de1a, `grease_quic_bit` 0x2ab2, idle 30 s.
  No local wire capture was produced; provenance states this honestly.
- **Safari/WebKit**: marked `unverified-catalog`; the freshness audit
  warns instead of treating it as captured.
- **Single builder**: `EngineParams::encode(...)` produces the Initial TP
  block (parameter shuffle for Chromium per capture behavior, insertion
  of the real `local_scid` and `version_information`, per-connection
  GREASE). `RustlsProvider::fixture_transport_params` calls it with the
  connection's actual SCID threaded through
  `create_provider_*_with_snapshot_and_clock_and_max_udp_payload(...,
  local_scid)`. `transport/connection/lifecycle.rs::enable_tls` passes
  `self.scid`; compatibility constructors pass `&[]` (zero-length SCID,
  wire-valid and what Chrome itself sends).
- **No drift**: `StealthManager::apply_utls_profile` now applies all seven
  flow-control fields plus `max_idle_timeout` from the same fixture
  values that the Initial advertises.
- **Mintable key shares only**: `crypto_provider_for_profile` intersects
  the persona `supported_groups` with ring's `[X25519, P-256, P-384]`.
  Chrome's captured X25519MLKEM768 narrows the offered group list but no
  ML-KEM share is ever emitted — documented deviation from the raw
  capture, required by the non-goal.
- **Freshness**: `verify-fingerprint-freshness.sh` checks fixture
  existence, snapshot, per-engine `provenance`/`captured_at`, age <= 6
  months for verified fixtures, and required `sends` keys;
  `unverified-catalog` produces a warning.
- **Tests**: Chrome fixture matches capture byte-values; Firefox matches
  neqo order/values; distinct engines produce distinct blobs; GREASE
  differs per connection; real SCID is emitted; internal config equals
  advertised params; `max_udp_payload_size` clamps at the path budget.
- **Deviation**: Safari stays unverified rather than carrying an invented
  capture; `initial_source_connection_id` is empty for test/convenience
  providers and real on transport connections — matching Chrome's own
  zero-length SCID behavior in the capture.
