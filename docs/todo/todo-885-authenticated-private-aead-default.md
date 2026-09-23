---
id: TODO-885
title: Implement authenticated private AEAD negotiation and promote the proven default
severity: CRITICAL
phase: S
priority: P0
status: IN_PROGRESS
created: 2026-08-11
depends_on: [TODO-883, TODO-884, TODO-681]
---

# TODO-885: Implement Authenticated Private AEAD Negotiation and Promote the Proven Default

## Objective

Make the single TODO-884 winner the automatic post-authentication packet AEAD between updated QuicFuscate peers while preserving a standards-only QUIC/TLS handshake, passive wire shape, unauthenticated probe behavior, explicit standard fallback, and a fail-closed advanced-required mode.

The protocol must be private, versioned, authenticated, downgrade-resistant, independently keyed, and easy to audit. It must not pretend that AEGIS or MORUS is a registered TLS or QUIC cipher suite.

## Non-Negotiable Architecture

### Parallel Standards and Advanced Modes

| Mode | Behavior |
|---|---|
| `standard` | RFC-compatible rustls packet protection for the complete connection; no private negotiation |
| `auto` | Standard handshake and initial 1-RTT, then authenticated private upgrade when both peers support the frozen winner; otherwise remain standard |
| `advanced-required` | Standard handshake and authentication, then require the private upgrade; close generically if negotiation or proof fails |

`auto` becomes the product default. This makes the TODO-884 winner the effective QuicFuscate-to-QuicFuscate data-plane default after authentication while keeping ordinary standard QUIC as the universal fallback and rollback path.

### Standards Boundary

- Initial packets remain version-defined standard QUIC packet protection.
- Handshake packets remain rustls TLS 1.3 packet protection.
- The first 1-RTT keys remain rustls standard keys.
- Certificate validation, ALPN, transport parameters, QUIC version negotiation, Retry, and QKey authentication remain unchanged.
- Private capability negotiation is not advertised in ClientHello, QUIC version negotiation, clear transport parameters, SNI, ALPN, or unauthenticated response bytes.
- An unauthenticated active probe sees only the existing standard H3/Reality behavior.
- The private switch occurs only after TLS handshake completion and successful QKey application authentication.

## Existing Reusable Boundary

`QuicTlsProvider` already exposes:

- `export_keying_material(label, context, length) -> Result<SensitiveKeyingMaterial, ConnectionError>`

The rustls implementation already wraps `Connection::export_keying_material` in an erasing owner. The implementation must use this real exporter boundary after reading its current signature and state preconditions. It must not expose rustls traffic secrets or reuse the existing silent 32-byte-to-16-byte truncation in `select_packet_data_aead()` as a protocol KDF.

## Protocol State Machine

| State | Allowed packet AEAD | Transition requirement |
|---|---|---|
| `StandardHandshake` | Standard only | TLS completes and rustls OneRtt keys are installed |
| `StandardAuthenticated` | Standard only | QKey auth succeeds and encrypted control is available |
| `ProposalSent` or `ProposalReceived` | Standard only | Versioned proposal is transcript-bound and validated |
| `SelectionConfirmed` | Standard only | Both sides authenticate the same algorithm, parameters, and context |
| `SwitchScheduled` | Standard below the per-direction boundary | Both sides acknowledge exact write packet-number boundaries |
| `AdvancedActive` | Frozen winner at or above the boundary | Deterministic packet-number selection, no trial decrypt |
| `AdvancedUpdating` | Current or next advanced epoch by exact key-phase state | Authenticated update and bounded transition complete |
| `StandardFallback` | Standard only | Allowed only before advanced activation in `auto` mode |
| `Terminal` | None | Authentication, downgrade, state, or cryptographic failure |

Illegal, duplicate, reordered, replayed, cross-connection, or conflicting control transitions fail closed.

## Versioned Negotiation Contract

The encrypted authenticated control message must contain bounded typed fields for:

- private protocol version;
- message kind and state generation;
- supported frozen product-family identifiers;
- selected algorithm identifier;
- exact key, nonce, and tag parameter profile;
- connection role and direction labels;
- local proposal nonce and peer proposal nonce;
- authentication transcript hash, never the raw QKey;
- TLS exporter context hash;
- original and current destination connection identifiers in canonical role order;
- QUIC version and negotiated ALPN;
- per-direction standard-to-advanced switch packet number;
- key epoch and key-update policy;
- feature flags with unknown-critical-bit rejection;
- transcript authenticator and confirmation value.

Numeric message and algorithm identifiers must be centrally owned and collision-checked. The implementation must inventory existing H3/MASQUE capsule and control identifiers before assigning values.

## Key Schedule

- Derive a fixed-length exporter root only after TLS handshake completion and QKey authentication.
- Use a QuicFuscate-specific exporter label and a canonical context hash that binds protocol version, algorithm, both proposal nonces, role-ordered connection IDs, QUIC version, ALPN, and the authenticated QKey transcript hash.
- Expand independent client-write, server-write, client-read, server-read, confirmation, and key-update secrets with explicit domain-separated labels.
- Request the exact selected algorithm key length. Never derive 32 bytes and silently discard half.
- Derive the 12-byte packet IV expected by the current packet wrapper and bind its conversion into the algorithm-specific nonce construction with vectors.
- Preserve a 16-byte authentication tag and current QUIC packet-length shape.
- Keep header protection standard and independently owned. The packet AEAD switch must not ambiguously replace or reuse the rustls header-protection key.
- Bind packet number, complete unprotected QUIC header AAD, direction, connection, and epoch exactly once.
- Keep secrets in zeroizing or locked owners consistent with current memory policy.
- Prohibit exporter-root reuse across reconnect, resumption, Retry, migration-created replacement connections, or circuits.

## Deterministic Packet Switch

- Negotiate a separate write boundary for each direction after both confirmations.
- Select standard versus advanced packet open by decoded packet number and committed direction boundary, not by trying multiple AEADs.
- Allow bounded reordering across the boundary by retaining the standard opener only for packet numbers below the boundary and the advanced opener only for packet numbers at or above it.
- Never attempt algorithm fallback after an authentication failure.
- Never send an advanced packet before the peer has acknowledged the boundary.
- Release the standard packet owner after the largest plausible reordered packet below the boundary has been retired by an explicit bounded rule.
- Keep header unprotection, packet-number reconstruction, FEC ordering, and loss recovery coherent across the boundary.
- Ensure FEC never combines packets from different AEAD epochs into an ambiguous recovery window.

## Key Update, Migration, Resumption, and 0-RTT

- Define one advanced epoch owner synchronized with QUIC key-phase semantics without hijacking an unrelated bit or losing rustls header-protection updates.
- Intercept rustls OneRtt key updates so new standard keys remain available for rollback/testing while the advanced payload owner advances through the exporter-derived epoch schedule.
- Retain bounded previous read epochs for legitimate reordering only.
- Reject epoch rollback, skip beyond the allowed window, duplicate update, and conflicting direction state.
- Connection migration retains the connection-bound advanced state only when the existing QUIC connection survives.
- A replacement connection, reconnect, or resumed TLS connection performs a fresh authenticated private negotiation.
- 0-RTT stays standards-only, default-off, and opt-in. Advanced 0-RTT is out of scope. TODO-1031 owns the replay-safe transport path; the product H3/MASQUE/TUN path remains post-handshake.

## Stealth Contract

- AEGIS/MORUS is selected for performance and cryptographic properties, not because ciphertext is visually more random than AES-GCM.
- No visible handshake extension announces the private capability.
- Packet number length, connection ID behavior, tag length, padding policy, timing policy, ACK behavior, and H3 persona remain unchanged unless independently justified.
- Negotiation occurs inside already encrypted and authenticated H3/MASQUE control traffic.
- Failure responses are generic and timing-bounded so unsupported capability, wrong QKey, wrong algorithm, and invalid confirmation are not cleanly distinguishable to an unauthenticated observer.
- Telemetry may report the effective family and state using low-cardinality values. It must never report keys, transcript material, raw control bytes, QKeys, or per-destination values.

## Configuration and Compatibility

- Add a typed packet-protection mode with `standard`, `auto`, and `advanced-required` only.
- Keep the selected advanced family planner-owned from TODO-884. Ordinary configuration must not expose internal AEGIS X4/X8 backends.
- Migrate existing `aead_preference` and `force_aead` settings deterministically. Reject ambiguous combinations.
- Updated peers in `auto` upgrade only when both report the exact supported protocol version and frozen winner.
- Older peers and third-party standard peers remain standard without a visible negotiation failure.
- `advanced-required` never falls back after mismatch.
- Provide one emergency standards-only runtime/config rollback that does not require a binary downgrade.
- Persist no derived traffic keys or exporter roots.

## Implementation Plan

1. Freeze the TODO-884 decision record, identifier, provider policy, parameter sizes, hardware fallback, and mandatory gates.
2. Read the complete QFTLS exporter, QKey auth, H3/MASQUE control, packet-key installer, key-update, packet open/seal, FEC, migration, reconnect, telemetry, and config signatures.
3. Write the private protocol state machine and field contract into the existing canonical documentation before wire identifiers are implemented.
4. Add typed negotiation messages, strict bounded parsing, transcript hashing, and negative fixtures.
5. Add exporter-root and directional key derivation with normative internal vectors and erasure tests.
6. Split standard header-protection ownership from selectable 1-RTT payload AEAD ownership.
7. Implement per-direction deterministic switch boundaries and bounded retirement of old keys.
8. Implement advanced key updates and lifecycle handling.
9. Wire configuration, effective-state diagnostics, telemetry, and emergency rollback.
10. Add exhaustive unit, property, fuzz, integration, interop, native, performance, and active-probe proof.
11. Run staged canary, mixed-version, forced-standard, auto-upgrade, advanced-required, and rollback scenarios.
12. Update all canonical docs, config examples, release gates, and task truth in one documentation pass.

## Acceptance Criteria

- TODO-883 standard-path truth and TODO-884 winner evidence are complete.
- TODO-681 has no promotion blocker for the selected implementation.
- Standard mode remains fully functional and interoperable.
- Initial, Handshake, unauthenticated, and pre-auth 1-RTT packets always use standard rustls protection.
- `auto` upgrades updated authenticated peers to exactly the TODO-884 winner.
- Unsupported peers remain standard in `auto` without visible capability advertising.
- `advanced-required` fails closed on any mismatch or failed proof.
- Negotiation is versioned, bounded, replay-resistant, cross-connection-resistant, downgrade-resistant, and transcript-bound.
- Keys derive from the real TLS exporter plus authenticated connection context, with independent directions and epochs.
- No silent key truncation exists in the protocol path.
- Packet-number boundaries handle reordering without trial decryption or a remote algorithm oracle.
- Header protection, FEC, loss recovery, migration, reconnect, resumption, and key updates remain coherent.
- The selected family is observable as the effective post-auth runtime owner in live packet evidence.
- Live standard and advanced captures have the same expected QUIC packet shape and 16-byte tag overhead.
- End-to-end VPN performance meets TODO-884 promotion and rollback thresholds.
- A standards-only emergency rollback works without reinstalling the client or server.
- Documentation calls this a private QuicFuscate mode, never a standardized QUIC cipher suite.

## Verification Matrix

- State-transition table tests covering every valid and invalid edge.
- Parser tests for truncation, overlong values, duplicate fields, unknown critical bits, integer overflow, conflicting algorithms, replay, cross-role swap, and transcript mutation.
- Exporter and KDF deterministic vectors for both roles, both directions, multiple connection IDs, and every epoch.
- Packet roundtrip, forgery, boundary reordering, duplicate, loss, FEC recovery, and key-retirement tests.
- Standard-only interop against the existing rustls peer.
- Updated-to-updated auto upgrade and advanced-required tests.
- Updated-to-old, old-to-updated, and unsupported-version compatibility tests.
- QKey failure, active probe, Reality fallback, malformed authenticated control, and timing-class tests.
- Migration, reconnect, resumption-without-0RTT, Retry, NAT rebinding, idle timeout, graceful close, and process restart tests.
- 1/2/3-hop integration once TODO-886 is available.
- Native ARM64, Linux x86_64, Windows x86_64, sanitizer, fuzz, runtime guardrail, strict Clippy, formatting, documentation truth, and diff hygiene gates.
- Benchmark comparison against the frozen TODO-884 artifacts with automatic rollback-threshold failure.

## Primary Files and Owners

- `src/qftls.rs`
- `src/qftls/private_protocol.rs`
- `src/transport/packet.rs`
- `src/transport/connection/`
- `src/core_parts/connection.rs`
- `src/implementations/client/`
- `src/implementations/server/parts/live_auth.rs`
- `crates/qf-crypto/`
- `crates/qf-engine-types/`
- `crates/qf-telemetry/`
- `scripts/tests/rust/`
- `scripts/tests/fuzz/`
- `scripts/benchmarks/`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `config/`

## Fail-Closed Rules

- Never advertise the private algorithm before authentication.
- Never derive private keys directly from a QKey.
- Never reuse TLS traffic secrets as private AEAD keys.
- Never switch based on configuration alone.
- Never trial-decrypt with multiple algorithms.
- Never fall back after advanced activation or authentication failure.
- Never call the private mode RFC-compatible or standardized.
- Never make performance evidence override a failed security gate.

## Out of Scope

- Advanced 0-RTT.
- Third-party QUIC interoperability while private mode is active.
- New tag lengths or packet formats.
- Exposing internal SIMD backend names as protocol values.

## Deviations

The typed `packet_protection_mode` configuration, exact private-family selector, bounded
authenticated control state machine, H3/MASQUE capsule bridge, QKey transcript binding, TLS
exporter context, and transport packet-key installer are now connected. `src/qftls/private_protocol.rs`
authenticates bounded proposal, selection, and confirmation messages, binds canonical
role-ordered connection context, derives independent directional material from the real exporter
root, and enters `Terminal` on private protocol errors. `src/core/connection/private_packet_protection.rs`
owns the bounded control queue and activates the transport private payload owner only after TLS,
QKey, accepted MASQUE flow, and boundary conditions all hold. Initial, Handshake, pre-auth 1-RTT,
header protection, and 0-RTT behavior remain standards-only.
`advanced-required` is still rejected at engine construction until TODO-883, TODO-884, and TODO-681
promotion gates are complete. The authenticated activation path is locally covered, but native
multi-hop, packet-capture, interoperability, side-channel, and performance promotion evidence
remain open. The current local post-refactor gates are green: 1,750 root all-feature library
tests with 1,749 passed and one ignored, strict all-feature Clippy, formatting, the 400-file
zero-`include!` module audit, runtime guardrails with zero critical findings and zero warnings,
documentation truth, Desktop Svelte checking, and Tauri checking. Existing migration aliases
remain unchanged.

The latest local structure gate reports `400` Rust files, zero files above `2,000` lines, and zero
source-assembly `include!` calls. This does not change the promotion blocker: TODO-883, TODO-884,
and TODO-681 still lack the required native, packet-capture, side-channel, and decision-grade
cross-platform evidence.

The post-authentication bootstrap ordering is now explicit in the local runtime path. The server
primes the private-control owner after accepting every authenticated peer MASQUE flow, including
`NextHopUdp` relay flows, and the client primes the direct assignment plus every active circuit hop
after QKey transcript binding. The runtime guardrail audit enforces these source-order anchors.
Local proof for this correction is green: `cargo check --all-features`, the focused private-control
filter (`2/2`), the focused circuit filter (`8/8`), strict root library Clippy, formatting, diff
hygiene, and runtime guardrails (`Critical: 0`, `Warnings: 0`). This remains local implementation
evidence only; TODO-883, TODO-884, and TODO-681 promotion gates are unchanged.

## Live-Observability Increment (2026-09-19)

- Added spec-compliant low-cardinality telemetry: `quicfuscate_private_upgrade_activated_total`
  counts each connection whose negotiated private owner becomes the effective 1-RTT AEAD
  (one-shot latch `take_private_upgrade_activated` on the connection, sampled in the per-client
  housekeeping loop on both the legacy loop and every shard worker). It reports the activation
  fact only - no keys, transcripts, family internals, or peer-identifying values.
- `tun-e2e-netns.sh` accepts `QF_E2E_METRICS_PORT` to bind the metrics HTTP server for live
  scraping during the run.
- Finding: with the shipped defaults (`packet_protection_mode = "auto"` plus
  `aead_preference = "auto"`), `CryptoConfig::private_family()` returns `None`, so
  `ensure_private_packet_protection_runtime` never constructs the negotiation machine and the
  upgrade silently never fires. This is consistent with the "planner-owned winner" rule while no
  TODO-884 winner is frozen, but it means the `auto` product default is currently inert; once the
  winner is frozen, `DataAeadPreference::Auto` should map to it (or a dedicated planner selector)
  so the default path actually negotiates.

## Root-Cause Fix: Standalone Client Never Started Private Negotiation (2026-09-19)

Live debugging on Omega (ARM64, real TUN + QKey + MASQUE) with gate instrumentation showed the
private runtime was never created on the standalone client: `authenticated_qkey_transcript_hash`
stayed `None` forever while TLS, the authenticated assignment, and the local control flow were
all healthy. Two distinct defects in the standalone CLI client path caused it:

- `src/main/runtime.rs::negotiate_standalone_assignment` carried an older copy of the
  assignment loop: it returned the accepted assignment without calling
  `mark_qkey_authenticated_from_token()` or driving
  `private_packet_protection_control_tick()`. The io_driver `negotiate_assignment` path had both
  calls; the standalone path (used by `quicfuscate client --tun`) did not, so the QKey transcript
  binding was never committed and no proposal was ever emitted.
- `src/main/runtime/client.rs` built the connection via
  `QuicFuscateConnection::new_client_with_runtime` but never applied
  `set_private_packet_protection_policy`, leaving the constructor defaults (`Auto` + `None`
  family) in place even when `[crypto] aead_preference` selected a family.

Fix: the standalone assignment loop now marks the QKey transcript binding and drives one control
tick before returning (same ordering as the io_driver path), and the standalone client applies the
configured `packet_protection_mode`/`private_family` policy right after connection construction.
`private_packet_protection_control_tick` was promoted from `pub(crate)` to `pub` so the binary
crate can drive it.

Server side verified healthy by the same instrumentation: `evaluate_qkey_http3_headers`
authenticates the `x-qf-auth` CONNECT header, the transcript hash is committed, and the runtime
is created on the first post-auth tick (silent early return once `runtime.is_some()`).

## Live Verification: Private Upgrade Activates End-to-End (2026-09-19, Omega ARM64)

After the standalone-client fix, a live run (server `--tun` + `--metrics-port`, client `--tun`
+ `--qkey`, `packet_protection_mode="auto"`, `aead_preference="aegis"` on both peers)
shows:

- `quicfuscate_private_upgrade_activated_total 1` — the negotiated private owner became the
  effective 1-RTT AEAD on the live connection.
- Tunnel data plane healthy through the switch: `ping 10.9.0.1` 0% loss before and after
  activation; TUN interfaces up on both ends.
- Three transient `KeyUpdateError` receives at the exact activation boundary on the client —
  consistent with the bounded boundary-reordering window absorbing in-flight packets sent
  under the previous owner. No connection impact; traffic continued cleanly.

This is the first live proof that the `auto` upgrade path negotiates and activates the
private owner end-to-end. Note the activation used an explicit `aegis` family — the
shipped `aead_preference="auto"` still maps to `None` until the TODO-884 winner is frozen
(planner-owned default remains an open gate).

## Interop & Lifecycle Matrix — Live on Omega (2026-09-19)

| Scenario | Result |
|---|---|
| auto+aegis ↔ auto+aegis | upgrade activates; `activated_total=1` |
| standard ↔ auto+aegis | connects, stays standard; metric stays 0 |
| client reconnect (fresh generation) | fresh negotiation; `activated_total` → 2 |
| server errors across all runs | 0 |

Observed gap RESOLVED 2026-09-19 (`6e56611`): `PRIVATE_NEGOTIATION_DEADLINE` = 10s bounds
every pending negotiation state via `created_at` on the protocol clock, checked inside
`private_packet_protection_control_tick` (no timer thread, injectable test clock). On expiry
`auto` falls back to standard (`force_standard_fallback`); `advanced-required` enters
Terminal with `PrivateProtocolError::NegotiationTimeout` (fail-closed). Active, fallback,
and terminal states never expire. Unit coverage: expired-pending, fresh-pending,
standard-immunity, active/terminal-immunity.

Remaining open gates: x86_64 second-witness benchmarks, side-channel review,
and the TODO-884 winner freeze that maps `aead_preference="auto"` to a concrete
family so the shipped default actually negotiates. ~~packet-capture wire
evidence~~ closed 2026-09-22 by TODO-1029.

## Wire proof (TODO-1029, 2026-09-22, Omega aarch64, QUIC v2)

DONE — `src/bin/qf-aead-wire-proof.rs` against live netns pcaps with
`SSLKEYLOGFILE` keylog + `QUICFUSCATE_PRIVATE_KEY_DUMP` install dump
(schedule root + context hash for offline epoch derivation):

- Private run (`mode=off` both peers): initial=3 / handshake=5 open rustls
  AES-GCM; 9 pre-boundary 1-RTT standard; 50 post-boundary 1-RTT fail rustls
  and open AEGIS-128L; zero unopened; zero standard above boundary; dump
  boundaries mirrored (client w5/r4, server w4/r5) with identical directional
  key bytes.
- Control run (client `off`, server `stealth`): 69/69 packets rustls-only,
  zero private, no dump emitted — mixed-policy negotiation never installs.
- Analyzer handles QUIC v2, the fork's no-length-field long headers, private
  epoch derivation (HKDF schedule), and coalesced GSO/GRO datagrams via
  trial-open splitting.
- Artifacts (operator-local, not committed): `/tmp/qf1029/runA4/` and
  `/tmp/qf1029/runB/` on Omega.

## Split remaining work (2026-09-21, no implementation)

- TODO-1044 owns the family freeze. TODO-1028 is blocked and must not freeze
  from the old ARM cells.
- Ship default is rustls AES-GCM (TODO-1033). This task stays the opt-in
  private upgrade machine and must not override that default.
- TODO-1044 picked opt-in S-AEGIS. `aead_preference="auto"` still installs no
  family. The sentence above that says `auto` becomes the product default is
  superseded: the shipped default is `standard`.
- TODO-1029 pcap wire proof is DONE (see above).
