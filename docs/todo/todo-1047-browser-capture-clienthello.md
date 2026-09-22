---
id: TODO-1047
title: Real ClientHello and transport parameters from one browser capture
severity: HIGH
phase: S
priority: P1
status: OPEN
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

- [ ] Capture or import one current Chrome, Firefox, and Safari Initial. Record browser version and date in the fixture header.
- [ ] Builder used by both rustls Initial and `apply_utls_profile`.
- [ ] Extend `every_supported_persona_controls_the_real_rustls_client_hello_order` to compare parameter IDs and cipher/extension order to the fixture.
- [ ] Fail the freshness script (`scripts/audits/verify-fingerprint-freshness.sh`) when the fixture date is older than `PROFILE_CATALOG_SNAPSHOT` allows.
- [ ] Document which capture groups were dropped because rustls cannot mint them.

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
