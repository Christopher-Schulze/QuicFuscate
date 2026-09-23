---
id: TODO-883
title: Prove and reconcile the live standard QUIC packet-protection baseline
severity: CRITICAL
phase: S
priority: P0
status: BLOCKED
created: 2026-08-11
depends_on: [TODO-1095]
---

# TODO-883: Prove and Reconcile the Live Standard QUIC Packet-Protection Baseline

## Current execution gate (2026-09-23)

This detail contains an August baseline and several now-superseded status
claims. The current `CryptoConfig::default()` ships standard packet protection;
TODO-885 already has an opt-in authenticated private AEGIS path with TODO-1029
ARM64 packet-capture evidence. Rustls-standard 0-RTT has since gained an
explicit, default-off opt-in with directional keys and server anti-replay
validation; it is not universally disabled. Do not reimplement those paths or
describe the old custom MORUS owner as live. TODO-1095 must first restore
RFC long-header Length framing before this task can claim a fully standard
wire baseline.

The remaining task is to rerun the standard-only capture and effective-owner
proof on the corrected framing, then execute the native x86_64 and Windows
provider/persona/0-RTT-disabled-default matrix at the **same source revision**.
Record exact ClientHello suite order, negotiated suite, Initial/Handshake/
1-RTT packet and header owners, zero private upgrade, standard-only peer
interop, packet-number/key-update behavior, and artifact/command identities.
Where opt-in 0-RTT is exercised, verify its standard rustls keys and replay
policy separately from the default-off baseline. A prior ARM64 or malformed
long-header capture cannot close these gates. Preserve the measured ring
baseline and keep aws-lc-rs evaluation in TODO-1036.

## Objective

Produce one exact, runtime-proven answer for which algorithms and key owners protect every normal QUIC encryption level before QuicFuscate adds a private post-authentication packet-protection mode. Make the standards path fast, persona-coherent, directly observable, and permanently available as the interoperability and rollback baseline.

This task must remove the current ambiguity between the configured retained data-plane AEAD preference and the packet keys that rustls actually installs. It must not activate AEGIS or MORUS in production.

## Current Status

The local historical standard-path implementation is complete. Current closure remains blocked by TODO-1095 plus native x86_64/Windows execution and standard-only packet-capture evidence at the corrected source revision. The shipped default is standard AES-GCM; opt-in AEGIS activation is separately owned by TODO-885.

## Verified Current State

- `src/qftls.rs::crypto_provider_without_chacha()` starts from `rustls::crypto::ring::default_provider()` and removes the TLS 1.3 and TLS 1.2 ChaCha20-Poly1305 suites.
- QFTLS builds client and server connections with TLS 1.3 only.
- rustls reports Handshake and OneRtt `KeyChange` values. `RustlsProviderImpl::one_rtt_keys()` wraps the rustls packet and header-protection keys, and `poll_secrets_and_install()` installs them through `QuicTlsKeyInstaller`.
- `src/transport/packet.rs::install_one_rtt_keys()` replaces the active packet seal/open and header-protection owners with the rustls-provided objects and clears the private read/write secrets.
- `crates/qf-crypto::select_packet_data_aead()` can build AEGIS or MORUS packet owners, but its normal production effect is not established after rustls installs OneRtt keys.
- `src/engine/engine.rs` applies `[crypto] aead_preference` through `install_data_aead_config()`. The source currently does not prove that this setting changes the normal rustls-backed 1-RTT owner.
- `qf-stealth::TlsProfile` contains an ordered `cipher_suites` list, but `RustlsProviderImpl::rebuild_client_connection()` currently applies ALPN, early-data, SNI, roots, and certificate policy without projecting that list into the real rustls provider.
- The effective negotiated TLS 1.3 suite is not currently captured as durable runtime evidence. Source order makes AES-GCM the only family, but source inference is not packet-capture proof.
- 0-RTT is already disabled and rejected by configuration until real packet-key installation exists. This task must preserve that fail-closed boundary.

## Required Truth Model

| Encryption level | Required owner | Required algorithm truth |
|---|---|---|
| Initial | RFC-defined QUIC key derivation and packet protection | Version-specific standard suite only |
| Handshake | rustls QUIC TLS keys | Negotiated TLS 1.3 standard suite only |
| 0-RTT | Disabled until separately implemented and replay-reviewed | No implied or synthetic support |
| 1-RTT standard mode | rustls QUIC packet and header-protection keys | Exact negotiated standard suite exposed and tested |
| 1-RTT advanced mode | Out of scope for this task, owned by TODO-885 | Must begin only after this baseline is complete |

## Scope

### Runtime Observability

- Add a typed, low-cardinality packet-protection snapshot owned by the connection, not inferred from configuration.
- Record the negotiated TLS cipher suite from the real rustls connection after handshake completion.
- Record separate owners for packet AEAD and header protection at Initial, Handshake, and 1-RTT.
- Distinguish `rustls-standard`, `private-advanced`, and transitional states without logging keys, nonces, raw QKeys, exporter material, packet payloads, or high-cardinality peer data.
- Expose the snapshot to structured logs, internal diagnostics, metrics, and the developer harness.
- Add a test-only observer that proves which concrete owner sealed and opened a packet without changing dispatch or timing in release builds.
- Ensure configuration displays requested policy and effective runtime state separately.

### Real ClientHello and Persona Coherence

- Inventory the exact rustls 0.23 cipher-provider and negotiated-suite APIs before calling them.
- Map only supported TLS 1.3 suites from `TlsProfile.cipher_suites` into the real rustls provider order.
- Preserve the explicit project policy that excludes ChaCha unless a separately approved policy change is made. Do not silently re-add it to imitate a persona.
- Fail closed when a profile projects no supported suite instead of silently falling back to an unrelated provider order.
- Keep client and server overlap valid for every supported persona.
- Capture and parse real ClientHello bytes from the live rustls path. Synthetic TLS Cover metadata does not count as proof.
- Verify that cipher ordering, ALPN, SNI, supported versions, key shares, and visible extensions remain internally coherent enough that the cipher fix does not create a worse fingerprint.

### Configuration Truth

- Trace every caller and storage owner of `CryptoConfig`, `DataAeadPreference`, `force_aead`, and the packet data selector.
- Until TODO-885 is implemented, reject or explicitly report any configuration that claims to select the normal live 1-RTT algorithm but cannot affect the rustls key owner.
- Do not keep a setting that silently does nothing.
- Preserve parse compatibility only when the runtime reports the setting as inactive and migration is deterministic.
- Define the exact standard baseline configuration consumed by TODO-884 and TODO-885.

### Standard Provider Evaluation

- Measure the current ring provider through both the rustls `PacketKey` path and the complete connection send/receive path.
- Evaluate `aws-lc-rs` only as an evidence candidate after reading its current rustls provider contract, target support, license, dependency footprint, binary-size impact, FIPS implications, and native build requirements.
- Do not add or switch a crypto provider on primitive-only throughput evidence.
- Keep the provider with the best end-to-end standards-path result unless another provider is measurably faster, equally portable, and no harder to audit or ship.
- Preserve a dependency-minimal rollback path.

## Implementation Plan

1. Read the complete QFTLS provider, packet-key installer, packet protection, profile mapping, engine crypto config, relevant tests, and standard-provider call graph on the implementation revision.
2. Capture a before-change live handshake and encrypted data exchange with secrets disabled in logs. Record ClientHello suite order, server selection, QUIC version, encryption-level transitions, and the active 1-RTT owner.
3. Add typed effective-state reporting at the QFTLS to transport installation boundary.
4. Project the supported persona cipher order into the actual rustls provider and add fail-closed validation.
5. Reconcile inert or misleading data-AEAD configuration behavior without activating custom packet protection.
6. Add standard provider microbenchmarks and production-path benchmarks required as TODO-884 baselines.
7. Re-run packet capture and prove that source, runtime state, and wire evidence agree.
8. Update `docs/DOCUMENTATION.md`, `docs/MAP.md`, configuration examples, CLI help, telemetry documentation, and task truth in one documentation pass.

## Acceptance Criteria

- A live client/server exchange reports the exact negotiated TLS 1.3 suite and the concrete packet/header owner for each installed encryption level.
- Packet capture independently confirms the real ClientHello suite order and negotiated standard suite.
- Initial and Handshake remain standards-only.
- 0-RTT remains disabled and fail-closed.
- The default 1-RTT path is proved to use rustls standard packet and header-protection keys until TODO-885 performs an authenticated switch.
- Every supported `TlsProfile` produces a non-empty, supported, deterministic real provider order.
- A profile/provider mismatch fails closed with an actionable error.
- `aead_preference` and `force_aead` never appear effective when rustls owns the active packet key.
- No secrets or peer-identifying high-cardinality values are emitted.
- Standard-path throughput, latency, allocation, CPU, and packet-size baselines exist for TODO-884.
- Documentation no longer implies that retained AEGIS/MORUS config automatically controls normal live 1-RTT traffic.
- No private AEAD is activated by this task.

## Verification Matrix

- QFTLS unit tests for provider ordering, suite projection, empty-overlap refusal, and effective-state transitions.
- Packet-key installer tests proving rustls ownership replacement and no private-owner leakage.
- Real client/server handshake tests for every supported browser persona.
- Live ClientHello and server-selection parser assertions.
- Standard AES-128-GCM and AES-256-GCM interop cases where the provider permits each suite.
- Negative tests for unsupported profile suites, no suite overlap, invalid configuration, and attempted 0-RTT enablement.
- Connection send/receive, key-update, migration, resumption-without-0RTT, loss, and reordering tests.
- Current workspace format, strict Clippy, relevant unit/integration suites, runtime guardrails, documentation truth, and diff hygiene.
- Native ARM64 macOS plus hosted Linux x86_64 and Windows provider execution. A cross-compile alone is not native crypto evidence.

## Primary Files and Owners

- `src/qftls.rs`
- `src/transport/packet.rs`
- `src/transport/connection/`
- `crates/qf-crypto/src/lib.rs`
- `crates/qf-stealth/src/tls_profile.rs`
- `crates/qf-engine-types/src/lib.rs`
- `crates/qf-engine-types/src/config.rs`
- `src/engine/engine.rs`
- `src/engine/config.rs`
- `scripts/benchmarks/ci_regression.rs`
- `scripts/tests/rust/`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `config/quicfuscate.toml`
- `config/server-linux.default.toml`

## Fail-Closed Rules

- Never infer a negotiated suite from provider order.
- Never label a configured algorithm as effective without observing the installed packet-key owner.
- Never expose secret key material to make the evidence easier.
- Never weaken certificate verification, QKey authentication, QUIC version checks, or 0-RTT policy for a test.
- Never call synthetic TLS Cover output proof of the real rustls ClientHello.
- Never promote a provider from one primitive benchmark.

## Out of Scope

- Activating AEGIS or MORUS for live traffic.
- Selecting the advanced default winner.
- Defining a private wire protocol.
- Multi-hop circuit implementation.
- Re-enabling 0-RTT.

## Deviations

None.

## Current Implementation Evidence

- `PacketProtectionSnapshot` records packet-AEAD and header-protection ownership independently for Initial, Handshake, 0-RTT, and 1-RTT. The actual negotiated rustls TLS 1.3 suite is captured from the connection, never inferred from provider order.
- The real rustls provider follows each browser persona's supported AES-GCM order, deduplicates it, and fails closed on an empty overlap. Live ClientHello parsing verifies suite order, SNI, ALPN, TLS 1.3, key shares, and extension uniqueness for all six personas. Twelve real client/server handshakes cover both retained AES suites.
- Initial stays standard, Handshake and normal 1-RTT are installed as `rustls-standard`, and 0-RTT is disabled. Every attempted early-data enablement returns an error. Retained `aead_preference` and `force_aead` values remain parse-compatible but are reported inactive until TODO-885 owns an authenticated transition.
- Telemetry exports one bounded metric family, `quicfuscate_quic_packet_key_installs_total`, with only `level`, `owner`, and `suite` labels. Developer diagnostics render the same secret-free connection snapshot.
- Current ring microbenchmarks on ARM64 macOS cover real rustls packet keys at 64, 1024, 1400, and 8192 bytes. Median AES-128-GCM seal/open results are 135.61/99.02 ns, 326.45/341.78 ns, 458.02/422.88 ns, and 1.7535/1.9889 us. Median AES-256-GCM results are 126.06/90.48 ns, 372.22/381.35 ns, 549.23/478.67 ns, and 2.4164/2.2544 us.
- The complete paired-connection send/receive baseline uses real rustls 1-RTT key bundles. Median AES-128-GCM results are 38.57 us at 256 B, 41.87 us at 1024 B, and 47.13 us at 1400 B. Median AES-256-GCM results are 45.55 us, 47.10 us, and 49.76 us respectively. These short Criterion runs use ten samples and are comparison baselines, not release-threshold claims.
- `aws-lc-rs` remains an evaluated candidate, not a dependency: its broader native build surface and absent QuicFuscate end-to-end or binary-size evidence do not satisfy the promotion bar. ring remains the dependency-minimal standard baseline.
- Rustls TLS 1.3 resumption is now real rather than inferred: a shared bounded client session store and shared server ticket key produce a second in-memory handshake reported as `HandshakeKind::Resumed` on both endpoints. 0-RTT remains disabled, no early-data keys are installed, and `session_ticket()` no longer returns a synthetic digest.
- **Omega (aarch64 Linux) native verification (2026-08-23):** `cargo test --all-features --lib` passes 1793/1793 on Omega (aarch64, Rust 1.97.1). Strict Clippy (`-D warnings`) passes under both `--features rust-tests` and `--all-features`. `cargo fmt --all -- --check` passes. Fuzz contract and 7/7 fuzz targets pass. qf-crypto Miri passes 151/151 (after the MORUS scalar fix in commit `39e0578`). Sudo is available for `ip netns`/`nft`/`tcpdump` packet-capture evidence. The remaining external gate is x86_64 native execution and packet capture on that ISA; the aarch64 Linux gate is now proven green.
