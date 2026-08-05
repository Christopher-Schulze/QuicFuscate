# QuicFuscate Technical Documentation

**Status**: This document is the canonical technical reference and reflects the current runtime behavior.

## Documentation Transparency and Feature Contract

- Runtime correctness is defined by checked-in code, targeted tests, and audit scripts, not by aspirational feature wording.
- Security-sensitive changes are reconciled against runtime behavior, fail-closed policy, and this document before being treated as current truth.
- Public/runtime feature claims use this state vocabulary only:

| State | Meaning |
|---|---|
| `active` | production runtime path |
| `compat-only` | available for compatibility, not the primary runtime path |
| `experimental/internal` | gated behind internal features, probes, or explicit test-only surfaces |
| `deprecated` | kept only as a migration contract away from older behavior |

### Feature State Matrix

| Feature Surface | State | Notes |
|---|---|---|
| UDP/io_uring fast path | `active` | canonical retained fastpath |
| AF_XDP socket code (`internal_af_xdp_experimental`) | `experimental/internal` | not part of default runtime |
| Core H3/MASQUE carrier | `active` | production CONNECT-UDP/capsule carrier for authenticated TUN traffic |
| XOR obfuscation | `compat-only` | not part of canonical product path |
| `transport::batch` | `experimental/internal` | rust-parity/test-only transport surface |
| `accelerate::*` parity helpers | `compat-only` | internal runtime owner plus explicit `rust-tests` parity surface |
| `accelerate::random` helpers | `compat-only` | heuristic/perf helper surface only |
| Packet-number decode dispatch | `active` | `transport::packet` calls `optimize::transport::decode_packet_number()` after header protection removal; BMI2/SVE2/NEON/scalar dispatch preserves QUIC reconstruction semantics |
| Server egress network-stack normalization | `active` | one frozen TLS/network persona per server-side connection; decoded IPv4 TUN/MASQUE uplink only; explicit disabled passthrough |

## Runtime Complexity Layer Model

The retained complexity in this repository is intentional and should be read through four explicit layers. This is the canonical architectural interpretation after the owner-reduction programs.

| Layer | Purpose | Canonical examples |
|---|---|---|
| `canonical runtime/product path` | user-visible retained runtime behavior and stable product contract | `src/core.rs` (+ `src/core_parts/`), `src/transport/connection/`, `src/crypto/` product contract, `src/fec/` public `auto` / `off` contract |
| `adaptive policy/control` | runtime policy loops that tune retained capability without changing the product contract | `src/brain.rs`, `src/stealth/`, `src/fec/` target/family auto-controller |
| `platform acceleration` | hardware detection, SIMD dispatch, Linux fast paths, and owner-local hot-path helpers | `src/optimize/`, `src/simd/`, `src/optimize/udp.rs`, `src/optimize/uring_batch.rs` |
| `compat/test/experimental` | retained compatibility machinery, parity hooks, archived sources, and explicitly gated internal surfaces | archived legacy sources, `internal_af_xdp_experimental`, `rust-tests`, `benches` |

### Layer Ownership Rules

- A visible runtime behavior belongs either to the `canonical runtime/product path` or to `adaptive policy/control`, never both.
- Hardware-specific code belongs to `platform acceleration` and should stay behind owner-local selectors or helpers.
- Compatibility aliases, explicit parity hooks, and internal feature-gated paths belong to `compat/test/experimental` and must not be described as canonical runtime behavior.
- Documentation, tests, and audit scripts should describe every retained surface through exactly one of these four layers.

### Drift Prevention

- `scripts/tests/audits/audit-runtime-guardrails.sh` is the current fail-fast drift check for top-level feature-claim mismatches and runtime/docs contract regressions.
- Feature-claim changes are expected to update both code truth and documentation truth in the same change set.

## Security Review Boundary Map

This section is the fast path for skeptical review. It is not a marketing summary. It points directly at the sensitive boundaries, their owners, and their strongest proof surfaces.

### Reviewer Trust Snapshot

- Runtime correctness is defined by checked-in code, targeted tests, and audit scripts.
- AI-assisted development is part of the repository workflow; code truth is defined by checked-in code and gates, not by assistant claims.
- Custom data-plane crypto with in-tree implementations:
  - product contract: `Aegis128L`, `Morus1280_128`
  - internal backend machine room: `Aegis128X4`, `Aegis128X8`
- The Linux high-performance send path is `io_uring` with automatic SQPOLL (kernel >= 5.12
  or `CAP_SYS_ADMIN`) and batched `SendMsg` as the production send default.
  Experimental `SendMsgZc` zero-copy (kernel >= 6.0) is probed at startup but only enabled
  when `QUICFUSCATE_IO_URING_ZC=1` is set.
- The io_uring server send path batches all outgoing packets from a connection through one
  runtime-owned `UringBatchWorker`; client outbound dispatch uses the same bounded worker
  boundary. Direct `UringBatchSender` calls remain synchronous compatibility primitives.
- The client inbound path uses a dedicated `UringRecvBatch` ring with pre-posted `RecvMsg` SQEs
  and an **eventfd bridge** to Tokio: `register_eventfd_async(eventfd)` wakes a
  `tokio::io::unix::AsyncFd` on CQ completions. In pool-backed mode those RecvMsg slots point
  directly at shared `MemoryPool` blocks; completions transfer the filled block into
  `core::recv_pooled_block()` while immediately arming the ring slot with a replacement block.
  This removes the io_uring-to-FEC memcpy on the Linux client fast path. Fallback to Tokio
  `recv()` + `try_recv()` when io_uring is unavailable.
- MSG_ZEROCOPY is not part of the final runtime story.
- Packet-number decode on packet open is centralized in `src/optimize/transport.rs`:
  `src/transport/packet.rs` removes header protection, rebuilds the encoded packet-number field,
  then dispatches through BMI2 on x86_64, SVE2/NEON on aarch64, or the scalar fallback.
- busy-poll socket tuning is not used.
- busy-poll socket tuning is not part of the final runtime story.
- The repository is not reducible to `quinn-udp` plus trivial glue.

### Shortest Audit Path

For a skeptical review, the shortest useful read order is:

1. `Reviewer Trust Snapshot`
2. `Runtime Complexity Layer Model`
3. The boundary row relevant to the subsystem under review
4. The strongest proof surfaces for that row

If a claim is not backed by one of the proof surfaces below, treat it as untrusted until verified directly in code.

| Boundary | Canonical owner | Constraint | Strongest proof surfaces |
|---|---|---|---|
| Data-plane AEAD posture | `src/crypto/`, `src/simd/` | Product contract is `Aegis128L` or `Morus1280_128`; internal width variants remain backend machine room only | `scripts/tests/rust/rt-security-suite.rs`, `scripts/tests/rust/rt-property-suite.rs`, `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs` |
| TLS-visible handshake boundary | `src/qftls.rs` | rustls owns real TLS protocol semantics; TLS Cover is overlay/cover only | `docs/todo/done/todo-85-tls-cover-and-rustls-boundary-clarification.md`, `scripts/tests/audits/audit-runtime-guardrails.sh` |
| Packet protection ownership | `src/transport/packet.rs`, `src/transport/connection/` | Packet protection and data-plane AEAD are fork-specific transport decisions, not TLS cipher-suite claims | `docs/todo/done/todo-76-forked-aead-protocol-posture-clarification.md`, targeted transport rust-tests, `audit-runtime-guardrails.sh` |
| Unsafe SIMD / crypto machine room | `src/crypto/`, `src/simd/`, `src/optimize/` | Unsafe and SIMD stay internal or parity-scoped; product/runtime claims stay at owner boundaries only | `cargo clippy --all-targets --all-features -- -W clippy::all`, `scripts/tests/audits/audit-all-comprehensive.sh`, `scripts/tests/audits/audit-runtime-guardrails.sh` |
| Stealth/TLS-cover boundary | `src/stealth/`, `src/qftls.rs` | Stealth owns persona and cover policy; rustls still owns real TLS protocol semantics | `docs/todo/done/todo-81-stealth-capability-preservation-and-simplification.md`, `docs/todo/done/todo-85-tls-cover-and-rustls-boundary-clarification.md` |
| Raw-IP fingerprint boundary | `src/stealth/fingerprint.rs`, `src/core_parts/connection.rs`, `src/implementations/server/parts/` | normalize decoded client-to-server raw-IP ingress exactly once; apply the frozen profile to server-generated control ICMP; never mutate sealed QUIC or ordinary server-to-client downlink; preserve fragments and PMTUD | fingerprint units, routing ICMP tests, `rt-core-connection-basics`, `rt-stealth-config-toml`, `fingerprint_normalizer` benchmark |

## Transport Overlap and Divergence vs quinn-udp

QuicFuscate is not a `quinn-udp` wrapper. It overlaps with standard UDP/QUIC transport concerns, but the runtime contract adds fork-owned packet protection, FEC integration, stealth shaping, MASQUE/TUN ownership, Brain feedback loops, and platform fastpath dispatch. Reviewer-facing conclusion: compare packet I/O mechanics where useful, but do not reduce repository scope to `quinn-udp` plus trivial glue.

### Reviewer Checklist

- Verify that every retained sensitive boundary above maps to exactly one owner set.
- Verify that product-facing claims stay at the owner boundary and do not leak backend-machine-room details.
- Verify that the proof surfaces listed above are green before trusting broader claims.
- Treat `compat-only` and `experimental/internal` surfaces as non-canonical unless a proof surface says otherwise.
- Prefer this evidence order for retained runtime claims:
  - targeted rust-tests and property tests
  - fuzz targets
  - benchmark/evidence suites
  - guardrail audit

### Consolidated Quality Evidence Bundle

Use this section as the shortest non-marketing answer to "what evidence exists right now?".

| Evidence class | Primary surfaces | What it supports |
|---|---|---|
| Targeted runtime and contract tests | `scripts/tests/rust/rt-security-suite.rs`, `scripts/tests/rust/rt-property-suite.rs`, targeted `cargo test --features rust-tests` runs | retained runtime contract, backend parity, regression resistance |
| Fuzzing | `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`, `scripts/tests/suites/test-security-fuzzing.sh` | malformed input handling and retained crypto/runtime stress coverage |
| Guardrail audit | `scripts/tests/audits/audit-runtime-guardrails.sh` | runtime/docs/contract drift detection |
| Runtime soak and chaos | `scripts/tests/suites/test-runtime-soak-chaos.sh` | control-plane, integration, and runtime stability evidence |
| DDoS admission | `scripts/tests/suites/test-ddos-admission.sh` | sustained activation/clear hysteresis, established-client bidirectional continuity, real Retry handshake, real MaxMind decisions, strict-HTTPS blacklist refresh, cache restart, failed-refresh last-known-good preservation, and bounded resource evidence |
| FEC empirical proof | `scripts/tests/suites/test-fec-auto-controller-proof.sh`, `scripts/tests/suites/test-fec-auto-controller-scenarios.sh` | clean-path efficiency, escalation, cadence, recovery, and backend-family evidence |
| Retained crypto performance evidence | `scripts/benchmarks/suites/bench-retained-crypto-backends.sh` | whether retained `Aegis128L` / `Aegis128X4` / `Aegis128X8` / `Morus1280_128` machine room earns its complexity |

### Evidence Limits

- The current evidence proves active regression resistance, retained-contract consistency, and meaningful runtime/benchmark coverage.
- It does not claim formal verification.
- It does not replace external security review of the retained custom data-plane crypto and SIMD machine room.

### Release Scope
- Distribution model: source-first release (open-source code distribution) plus CI-built binary artifacts published to GitHub Releases.
- `.github/workflows/release.yml` builds native x86_64 and ARM64 Linux server bundles plus Tauri ed25519-signed desktop artifacts for macOS (DMG plus `.app.tar.gz` updater), Linux (deb plus directly signed `.AppImage`), and Windows (directly signed MSI). Both server architectures and Windows are required dependencies of tagged release publication; macOS and Linux desktop jobs remain non-blocking.
- Updater integration is configured in `tauri.conf.json` with `bundle.createUpdaterArtifacts: true`, a GitHub Releases endpoint, and an embedded ed25519 pubkey. The `latest.json` manifest is generated in CI with real minisign signatures from the Tauri build output, including only platforms whose signed updater bundles are present.
- TODO-519 is complete: native parallel MSVC check, all 1,673 tests, and Clippy passed; releases `v0.4.3` and `v0.4.4` publish a signed Windows MSI and a matching `latest.json` `windows-x86_64` entry.
- Release `v0.4.4` is the smallest patch increment from `v0.4.3`. `Cargo.toml`, the root and dependent lockfiles, and `apps/tauri/src-tauri/tauri.conf.json` carry `0.4.4`.

### Current Release Checkpoint

- **First GitHub Release published: `v0.4.0`** - https://github.com/Christopher-Schulze/QuicFuscate/releases/tag/v0.4.0
- **Current public GitHub release: `v0.4.4`** - https://github.com/Christopher-Schulze/QuicFuscate/releases/tag/v0.4.4
- Release Build run `30612996058` published version-coherent native x86_64 and ARM64 Linux server bundles, macOS DMG and signed updater archive, Linux deb and signed AppImage, signed Windows MSI, checksums, provenance, and a signed three-platform `latest.json` updater manifest.
- Server release artifacts include separate native x86_64 and ARM64 bundles. The ARM64 artifact is architecture-named and carries an adjacent SHA-256 file so an operator cannot mistake the x86_64 bundle for an AArch64 deployment.
- Last fully verified release checkpoint: `bf929bfddd1ca129c21d480f2ece31fb03a37c42` (`v0.4.4` tag).
- GitHub `CI` run `30611849921`, `Clippy Matrix` run `30611849920`, and Release Build run `30612996058` are green on `bf929bfddd1ca129c21d480f2ece31fb03a37c42`.
- `cargo audit` clean: 0 vulnerabilities, 0 warnings (crossbeam-epoch RUSTSEC-2026-0204 patched: 0.9.18 → 0.9.20).
- The repository owns its release and CI Rust toolchain through `rust-toolchain.toml`, pinned to `1.97.1`; nightly is used only by the explicit fuzz lane. This is a pinned stable baseline, not an MSRV promise; no older Rust compatibility is currently supported or claimed.
- The CI workflow now includes an `app-backend-checks` job that builds the desktop Svelte bundle for Tauri context, then runs locked metadata, check, Clippy, and test gates in `apps/tauri/src-tauri` on macOS.
- The Linux fastpath evidence job is green in the current CI checkpoint. This proves the current non-privileged CI fastpath suite, not a replacement for a privileged production deployment soak.
- **TODO-412 DONE**: Real-world QUIC connection over the internet verified: Mac (ARM64) → Broderick (Oracle Cloud, ARM64, 92.5.226.155:4433). TLS handshake successful, RTT 0ms, Loss 0.00%, FEC NEON SIMD active, stealth uTLS+TLS Cover active. Oracle Cloud Security List is now open for UDP 4433. Server RSS 3.1 MB at idle.
- **TODO-512 DONE**: Full soak matrix on Broderick (ARM64, Ubuntu 24.04, release build): 25/25 scenarios PASS, 0 failures. 10 steady_integration + 10 fec_loss_chaos + 5 admin_qkey iterations.
- **TODO-513 DONE**: Full install/upgrade/rollback/uninstall lifecycle on Broderick (ARM64, Ubuntu 24.04): all steps PASS. Config and QKey registry preserved across upgrade. State preserved after uninstall. `/api/health` endpoint used as liveness signal.
- **TODO-517 DONE**: Historical `HintChannel<A>` abstraction for brain.rs hint atomics. TODO-584 replaced those process-global channels with connection-local `BrainFecHints` and `IntelligentLevelHints`.
- **TODO-518 DONE**: Historical global atomic count reconciliation; the current source inventory is maintained in the Global Atomic State Audit section below.
- TODO-508 through TODO-520, TODO-412, and TODO-448 retain their individual completion evidence. The exhaustive acceptance reconciliation is complete and its genuine gaps are now represented directly by the ordered open production TASKs in `docs/todo.md`; production readiness remains open until that register reaches zero without unresolved blockers. The current graceful-drain source checkpoint `bef00fe6501baa1d5fc99ad25f5e8e89c9b6d4a3` remains independently proven by local full Rust gates, GitHub CI `29880712890`, Clippy Matrix `29880712914`, native ARM64 release job `88800780673`, and the exact two-client lifecycle proof on Omega in 5118 ms.
- TODO-558 is closed on implementation commit `b7db20443bb070d97686975034ebd9656ca3f98e`: local full Rust/Clippy/script gates, eight repeated Omega Off/Auto moderate/severe matrices, CI `30155084370`, Clippy Matrix `30155084377`, and Release Build `30155084369` pass. The GitHub source archive SHA-256 is `64a8fae24a1143ab9715b78c0075dfcf570c51432682f5c1383077d5309be678`; native ARM64 release artifact `8618776310` has bundle SHA-256 `0fb66cb66b48475cb578eccadeb1d9f8da17273f98939ab60931b0dd8ebdeecb` and binary SHA-256 `ea93bc10af7fc205da41b2acf02b5b6a0b25702113c7d8900390c12e99e516fb`.
- TODO-556 is closed on exact commit `06e60435604678bc0f7c47c633d557496654a4d8`: CI `30156460437`, Clippy Matrix `30156460410`, and Release Build `30156460404` pass; all 29 check runs report zero annotations. Retained first-party workflows use `actions/checkout@v7`, `actions/cache@v6`, `actions/upload-artifact@v7`, and `actions/download-artifact@v8`. Verified SHA-256 values include x86_64 server bundle `b9748c28be49f2621c3a5b67d19912710c69165b40b64a4f505f722c4ebba206`, ARM64 server bundle `31a966a6ce42be3adbb8e31d8f5bb9c16100a5d23be9b2dd8f6177f79cf2c727`, Linux binary `b2c93bb33970c4b61e285d635cc5e20a7dd027ff96f3eef9799b788d36f3af2c`, and signed Windows MSI `a6b7c4cca7aec9ea56175997b9f9c76b5e2ba8cc784061f62aa031a873d17d5c`.
- **Release pipeline**: `release.yml` first rejects any mismatch between the release tag, root product version, and Tauri bundle version through `scripts/audits/verify-release-version.sh`, then builds required native x86_64 and ARM64 Linux server bundles, optional macOS/Linux desktop bundles, and a required Windows MSI bundle. `publish-release` cannot publish a `v*` tag unless both server-architecture jobs and the Windows job succeed; it then creates the GitHub Release with checksums, available desktop artifacts, and `latest.json`. GPG signing key: `07484E2F6ED688BC` (ed25519, expires 2028-07-06). Tauri updater signing uses the `TAURI_SIGNING_PRIVATE_KEY` secret.
- **Tauri updater**: `bundle.createUpdaterArtifacts: true` produces platform-specific updater artifacts: macOS `.app.tar.gz` plus `.sig`, Linux `.AppImage` plus `.sig`, and Windows `.msi` plus `.sig`. The workflow reads those signature files directly into `latest.json`, with release URLs for `darwin-aarch64`, `linux-x86_64`, and `windows-x86_64` when the corresponding pair exists. macOS/Linux may be omitted after optional job failure; Windows is required for tagged publication. Release `v0.4.4` proves all three signed updater entries.
- **Desktop platforms**: macOS and Linux remain optional release jobs. Windows is required and proven by native parallel MSVC CI plus the signed `v0.4.4` MSI and updater-manifest evidence.
- **Current native Windows evidence**: CI run `30611849921`, job `91096669655`, compiles 2,010 tests, passes 2,005 normal tests with 5 explicitly privileged tests ignored, then passes the privileged Wintun lifecycle, WFP policy, process-exit retention, stale-cleanup, and zero-residue suites plus Clippy with warnings denied.
- **TODO-519 local regression evidence**: macOS root check/Clippy, 1,664 `rust-tests` library tests, `cargo test --workspace --all-targets --features rust-tests` including the integration harnesses, and `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` pass. TODO consistency passes across 165 detail files with zero violations, and runtime guardrails pass with zero critical findings and zero warnings. The native Tauri host passes check, 29/29 tests, and all-target Clippy through a temporary `TAURI_CONFIG` `frontendDist` URL override, which avoids generating or modifying the protected Svelte bundle and does not count as Windows packaging proof.
- **TODO-520 post-fix local evidence**: 1,673/1,673 library tests and every workspace target pass with `rust-tests`; workspace all-target Clippy passes with warnings denied; TODO consistency passes across 166 detail files; runtime guardrails report zero critical findings and zero warnings. Real UDP CLI proof records `client_authenticated` only after a CA-verified TLS handshake and exits immediately with `UnknownIssuer` when the same CA is omitted.
- UI changes remain protected by the `AGENTS.md` UI Change Boundary: no UI component, view, style, asset, text, or adjacent UI cleanup is allowed without an explicit current-task request for that exact UI change.

### Release Security Audit Baseline

Audit command evidence:
- `cargo clippy --workspace --all-targets -- -D warnings` -> pass.
- `cargo test --workspace --all-targets` -> pass.
- `cd apps/svelte-admin && bun run test:unit && bun run check` -> pass.
- `cd apps/svelte-desktop && bun run test:unit && bun run check` -> pass.
- `bash scripts/tests/smoke/smoke-ui-frontends.sh` -> pass.
- `bash scripts/build/build-web-admin.sh` -> pass.
- `cargo audit --json > scripts/out/tests/cargo-audit.json` -> pass (`vuln_count=0`, `warnings_count=0`).
- `cd apps/tauri/src-tauri && cargo check && cargo clippy --all-targets && cargo audit --json` -> `check`/`clippy` pass; audit reports 18 informational transitive advisories (`17 unmaintained`, `1 unsound`) in the Tauri desktop dependency chain with `vulnerabilities.found=false` (`count=0`).
- `./scripts/tests/audits/audit-all-comprehensive.sh` -> executed; policy report flags high unsafe and unwrap counts and exits non-zero by design when findings exist.

Attack surface and control mapping:
- Admin authentication and session surface:
  - controls: Argon2 hashes, `HttpOnly` cookies, `SameSite=Strict`, secure-cookie behavior tied to HTTPS forwarding, poison-free `parking_lot` ownership for auth/session/rate state, a 10,000-key LRU login limiter that counts every login/auth request attempt and clears successful keys, password-change lock (`423`) paths, same-origin POST validation (`Origin` host+port must match `Host` header when present; dev proxies must not rewrite `Host` via `changeOrigin`), and per-session CSRF token checks on authenticated POST routes.
  - bounded state: session replay fingerprints use a `HashSet` for constant-time membership beside a timestamped `VecDeque`. Entries are pruned in insertion order after the explicit five-minute replay window and one oldest entry is evicted on each insertion beyond the 4,096-entry ceiling. Duplicates are rejected while retained; after five minutes or history-cap eviction, reuse is accepted while the sliding session remains valid. The outer live-session map admits at most 256 sessions, rejects new successful logins with an explicit 429 at capacity without evicting active sessions, prunes expired records before admission, exposes counters through `AdminHttpServer::session_snapshot()`, and clears on server shutdown. Login keys are pruned by lockout age and evicted least-recently-used at the hard cap.
  - verification: `implementations::server::admin_http` tests for lockout, throttling, cookie flags, lock removal, and cross-origin POST rejection.
- QKey issuance and revocation surface:
  - controls: strict QKey parsing and canonicalization, stable token IDs, zeroizing raw-token and decoded-token owners from issuance/import through hashing and live authentication, a versioned authenticated registry envelope, protected raw-key files, fail-closed startup and mutation errors, atomic plaintext migration and current/previous-key rotation, TTL normalization, revoke path validation, persisted registry constraints, revoked-key rejection during initial auth, SessionId-to-QKey runtime tracking, active-session close on admin revoke, pending-auth revocation race prevention, configurable revoked-record retention with bounded housekeeping pruning and Prometheus accounting, explicit revocation state with no inert automatic-rotation scheduler, and runtime auth-state rebind on source-address churn by DCID/source-id matching.
  - verification: `implementations::server::qkey_registry` and `qkey_registry_storage` tests cover registry transactions, envelope authentication, corruption, key mismatch, migration, rotation, permissions, and zeroization; `scripts/tests/suites/test-qkey-registry-encryption.sh` proves real-process migration, restart, plaintext-downgrade rejection, wrong-key rejection, tamper rejection, rotation, permissions, leak absence, and cleanup against an exact binary; admin HTTP QKey API tests, runtime revocation tests, and `qkey_auth_tests::engine_qkey_id_matches_registry_qkey_id` cover the surrounding runtime contract.
- Engine connect-state surface:
  - controls: `engine.connect()` is handshake-aware and only sets `Connected` after runtime handshake establishment within a bounded timeout.
  - verification: `engine::engine::tests::test_engine_connect_disconnect`.
- Static admin asset serving:
  - controls: traversal rejection and SPA-safe fallback routing.
  - verification: `static_assets_rejects_path_traversal_with_403`, `static_assets_serves_index_for_spa_routes`.
- Desktop IPC command surface:
  - controls: typed command payload validation, failure-path tests for connect and state persistence, keychain-backed secret storage path.
  - verification: desktop unit tests in `scripts/tests/frontend/desktop/unit/` (30 files, 368 tests covering components, views, dialogs, and utility modules).

Probe detection telemetry review:
- Counters are emitted in telemetry export and wired to runtime paths:
  - `quicfuscate_stealth_probe_detected_total`
  - `quicfuscate_stealth_probe_switch_total`
  - `quicfuscate_stealth_probe_fake_total`
  - `quicfuscate_stealth_probe_block_total`
  - `quicfuscate_stealth_mode_escalated_total`
- Validation coverage:
  - deterministic probe suite: `cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture`
  - suite wrapper with optional soak loop: `./scripts/tests/suites/test-probe-detection.sh --fast --soak-iters 2`
- Operational alert guideline (initial release baseline):
  - investigate if `quicfuscate_stealth_mode_escalated_total` increases repeatedly in short windows.
  - investigate if `quicfuscate_stealth_probe_detected_total` rises without matching network pressure events.

Security findings table:
| Severity | Finding | Impact | Status | Owner |
|---|---|---|---|---|
| medium | Comprehensive audit script reports many `unsafe` blocks | higher review burden for memory-sensitive paths | accepted with controls | core runtime |
| medium | Comprehensive audit script reports many `unwrap` call sites | potential panic if assumptions are broken | accepted with controls | core runtime |
| low | Signed updater availability is platform-dependent | macOS/Linux may be omitted if their non-blocking release jobs fail; Windows remains a required tagged-release dependency | controlled by release workflow | desktop release |

Current release constraints:
- Releases `v0.4.1` and `v0.4.2` retained mismatched `0.4.0` artifact versions. Releases `v0.4.3` and `v0.4.4` are coherent across server, desktop, MSI, signature, and updater-manifest versions.
- The `v0.4.4` tag matches both root Cargo and Tauri bundle versions; publication succeeded only after the required x86_64 server, ARM64 server, and signed Windows MSI jobs passed.

### Threat Model

Assets:
- Server private key and runtime secret material.
- Admin credentials, cookies, and lockout state.
- QKey token registry and revocation state.
- Desktop local tunnel state and keychain-backed secrets.
- Build and release metadata for the current source-first distribution path.

Trust boundaries:
- Public QUIC ingress boundary.
- Admin HTTP/API boundary.
- Desktop local process and IPC boundary.
- Local filesystem persistence boundary.

Primary threat scenarios:
- Brute-force and credential stuffing on admin login.
- Session theft and cookie misuse behind misconfigured proxies.
- QKey abuse, replay attempts, or unauthorized issuance.
- Config tampering through malformed admin API payloads.
- Active-probe pressure and stealth-profile misclassification.
- Desktop local misuse through invalid tunnel or secret inputs.

Threat to mitigation mapping:
- Brute-force and stuffing -> per-IP failed-login limits and 429 lock paths.
- Session misuse -> secure cookie flags, strict SameSite, explicit forwarded-proto checks.
- QKey abuse -> strict parser, canonical IDs, revoke support, disk persistence constraints.
- Config tampering -> schema and payload validation plus explicit rejection status codes.
- Probe pressure -> adaptive stealth/FEC controls plus deterministic test suites.
- Desktop misuse -> typed validators, migration sanitization, and failure-path tests.

Residual threat profile:
- False positives in probe-detection paths under extreme jitter/loss remain part of the validation stream.
- Signed Windows update-channel threats remain partially open until native MSI/signature and tagged manifest verification completes.

### Deployment Hardening Guide

Server hardening baseline:
- Bind admin HTTP only to trusted interfaces or localhost.
- Enforce firewall rules for QUIC and admin ports; deny all unused inbound paths.
- Run service under dedicated non-root user with minimal filesystem permissions.
- Restrict `config/` and persistent state paths to owner-only access.
- Configure log rotation and retention; avoid logging sensitive token material.
- Back up config and QKey registry on controlled intervals with encrypted storage.
- Enable memory locking (`[security] lock_memory = true`, `lock_blocks = true`) to prevent key material and crypto buffers from being swapped to disk. The TLS private-key allocation and MemoryPool blocks are locked during privileged initialization. When Linux privilege reduction is configured, process-wide locking runs after setxid so glibc never broadcasts the transition across pre-locked runtime stacks. `LimitMEMLOCK=infinity` in systemd enables current-and-future process locking; finite limits retain the individually locked boundary and attempt current-page locking with explicit failure reporting.
- Enable tamper-evident audit logging via `--audit-log <path>` to record security-relevant authentication, connection, QKey, admin, privilege, configuration, firewall, and lifecycle events in a hash-chained NDJSON file with mode `0o600`.
- Verify the complete persisted chain with `quicfuscate verify-audit-log <path>` before trusting or archiving an audit file.

Admin UI hardening baseline:
- Put admin UI behind HTTPS termination in production.
- Ensure forwarded-proto headers are set correctly by the trusted proxy.
- Rotate default admin credentials on first bootstrap.
- Operate IP blocklist with explicit review and rollback procedure.

Desktop hardening baseline:
- Keep updater disabled for source-first or unsigned builds; enable delivery only for artifacts covered by the signed updater manifest.
- Store secrets in OS keychain path where available.
- Keep local state sanitized on load and persist only normalized structures.
- Prefer fixed window constraints and explicit close behavior for predictable UX.

Operational hardening:
- Pre-release smoke: run clippy/tests/UI checks and record outputs in `scripts/out/tests/`.
- Incident response: immediate revoke of affected QKeys, rotate admin password, restart service, verify telemetry counters.
- Rollback: restore previous config and QKey registry backup, restart, re-run smoke checks.

Verification commands:
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cd apps/svelte-admin && bun run test:unit && bun run check`
- `cd apps/svelte-desktop && bun run test:unit && bun run check`
- `bash scripts/tests/smoke/smoke-ui-frontends.sh`
- `bash scripts/build/build-web-admin.sh`
- `cargo audit --json > scripts/out/tests/cargo-audit.json`

### Audit Logging (TODO-515, TODO-525)

The server runtime emits tamper-evident audit events to a hash-chained NDJSON segment set when `--audit-log <path>` is provided. One global `OnceLock<Arc<AuditLog>>` owner is initialized before privilege dropping. Producers validate JSON-encoded UTF-8 bounds before cloning dynamic fields, then submit fully owned events through non-blocking `try_send`; the single `qf-audit-writer` assigns sequence and timestamp, serializes, hashes, rotates, checkpoints, and performs all file I/O. Queue saturation, lifecycle closing, or disconnection rejects the newest event and increments `quicfuscate_audit_dropped_events_total`; oversized source IP, client ID, reason, message, or combined dynamic payload is rejected before queue admission and increments `quicfuscate_audit_payload_rejections_total`; sink or checkpoint failures increment `quicfuscate_audit_persistence_errors_total`. If the system clock is before the Unix epoch, the writer rejects the event and enters its terminal persistence-error state instead of silently recording timestamp zero. TODO-813 centralizes queue, segment, retention, and lifecycle timeout bounds before any audit resource is acquired. The producer-terminal admission contract remains open under TODO-726; synchronous durability cancellation and failure classification remain TODO-675.

**File security:** The active log, immutable segments, and checkpoint are regular files created with mode `0o600` (owner read/write only) on the global startup path. Direct public reopen also reasserts `0o600` on the opened active-file handle before the writer can append. Symlinks and special files are rejected before reading. When running as root, the audit set is chowned to the resolved runtime user/group so logging survives privilege reduction. The parent directory is chowned only if the server created it; pre-existing system directories are never re-owned. Pathname binding remains TODO-728.

**Hash chaining and schema:** Schema v2 hashes `version|seq|timestamp|event_type|severity|source_ip|client_id|actor|target|outcome|reason|message|prev_hash`. Every v2 record carries typed actor, target, and outcome fields plus an optional stable reason. The verifier retains schema v1 compatibility for existing single-file logs.

**Rotation and retained proof:** `[audit] max_segment_bytes` rotates the active file to an immutable `<base>.<start>-<end>.segment`; `max_segments` bounds the complete retained set including the active file after validation. `AuditOptions::validate()` applies the shared bounds `queue_capacity = 1..=65,536`, `max_segment_bytes = 1..=134,217,728` bytes (128 MiB), `max_segments = 1..=64`, and `flush_timeout_ms = 1..=60,000`. Dynamic event strings are bounded by their JSON-encoded UTF-8 byte length: source IP `128`, client ID `512`, reason `512`, message `8,192`, and the combined dynamic payload `8,192` bytes, including JSON string quotes and escapes. The resulting nominal retained-segment budget is at most 8,589,934,592 bytes (8 GiB), calculated as `max_segment_bytes * max_segments`. Before retention removes an oldest segment, a mode-`0600` atomic checkpoint advances the retained anchor and records the ordered segment identities plus tail sequence/hash. Checkpoint replacement is durable on Unix and Windows. Restart verifies the retained set, resumes at `tail_seq + 1`, and recovers a fully valid active tail left by an interrupted rotation; whole-file startup reads remain TODO-727.

**Verification and lifecycle:** `AuditLog::verify_chain()` and `quicfuscate verify-audit-log <path>` validate ordered segment identity, sequence and hash continuity, checkpoint anchor/tail, and detect mutation, interior deletion, reordering, truncation, and tail loss. `flush()` is a bounded acknowledged barrier for commands before the barrier, but the underlying file operations remain synchronous under TODO-675. Shutdown atomically changes admission from `Open` to `Closing`, waits for already-admitted producers, then sends the final flush barrier and joins the writer; producers racing after that linearization point receive typed `WorkerClosing` or `WorkerDisconnected` errors and are counted as dropped. Clean shutdown normally flushes, stops, and joins the worker; sticky failure reporting and drop-time error visibility remain TODO-675.

**Event types emitted at runtime:**
- `ServerStarted` / `ServerStopped` - server lifecycle
- `PrivilegesDropped` / `PrivilegeDropFailed` - privilege drop outcome
- `ClientAuthenticated` / `AuthFailed` / `AuthTimeout` - QKey authentication result or deadline expiry
- `QkeyIssued` - QKey issued in `QKeyRegistry::insert_with_ttl`
- `QkeyRevoked` - admin revoked a QKey
- `AdminAction` - admin kick, failed config reload
- `ConfigReloaded` - successful config reload
- `ConnectionEstablished` / `ConnectionClosed` / `ConnectionRejected` - live and standalone session acceptance, rejection, removal, and expiry reconciliation
- `FirewallRuleAdded` / `FirewallRuleRemoved` - platform routing/firewall setup and idempotent teardown boundaries

**Runtime proof:** `scripts/tests/suites/test-graceful-shutdown.sh` starts a real server with `--audit-log`, authenticates two real clients, performs authenticated admin drain and config reload operations, observes connection closure, enforces minimum event counts, and validates the persisted chain through `verify-audit-log`. `qf-audit-probe` refuses existing evidence, drives concurrent producers, enforces at least 10,000 durably accepted events per second with zero drops/errors, restarts the writer, re-verifies the chain, and emits machine-readable JSON. RFC 5424 and CEF conversion remain external collector responsibilities; collectors consume the canonical NDJSON segment set.

**Memory locking (TODO-516):** When `[security] lock_memory = true` (default), an unlimited `RLIMIT_MEMLOCK` uses `mlockall(MCL_CURRENT | MCL_FUTURE)`; a finite or unreadable budget uses `MCL_CURRENT` so a successful call cannot make later allocations fail with `ENOMEM`. With Linux privilege reduction, `mlockall` runs after the verified setxid transition because native ARM64 proof showed that carrying pre-locked runtime and signal stacks through glibc's multi-threaded setxid broadcast can fault. The TLS private-key allocation is parsed and individually locked before the drop, and `lock_blocks = true` individually locks each `MemoryPool` block on allocation. `BlockLockLedger` records only successful block locks per pool. `MemoryPool::free()` is the caller-owned return boundary; queue shrink, full-queue disposal, pool `Drop`, and thread-local cache `Drop` all zeroize blocks, call `munlock(2)` through the ledger, and only then release the `AlignedBox` allocation. Direct `AlignedBox` drops still bypass pool ownership and remain separate pooled-buffer cleanup boundaries. `LimitMEMLOCK=infinity` in the systemd unit survives the UID/GID transition and enables full current-and-future protection. The process caller currently logs and continues after `mlockall` failure, and the embedded engine does not apply the same lock settings before TLS identity loading; readiness and entry-point propagation remain TODO-851 and TODO-852. Finite-limit failures remain explicit warnings while the individual key and pool locks stay active. A fresh native proof of this post-change source remains outstanding because the configured Omega SSH path is unavailable. Preloaded qftls-key lock ownership is tracked separately in TODO-643 and TODO-853.

**Retained-secret erasure:** `src/secret.rs` owns heap-backed secret byte and UTF-8 representations and overwrites the live range before clearing and deallocation. QKey generation, parsing, configuration, profile, connection, registry insertion, and binary-token hashing use these owners; persisted registry state contains only the non-secret QKey identifier and SHA-256 verifier. QuicFuscate's copied 1-RTT traffic secrets, session-cache ticket material, test-bound ticket keys/sessions, returned session-ticket copies, private-key PEM read buffers, and AES header-protection key use zeroizing owners. AEGIS L/X4/X8 wrappers retain only their copied key and IV, wipe both on wrapper drop, and create local derived cipher state for each packet or batch; the local state is zeroized on scope exit and is never shared behind a mutex. Test-only pre-deallocation observers make normal, error, eviction, replacement, and partial-initialization erasure assertions failable without reading freed memory. TODO-681's completed crypto unsafe audit leaves separate proof work for `Aes128Ctx` round-key storage, temporary AES schedules, ChaCha nonce/clone copies, AEGIS `Copy` state values, and the exact compiler-level erasure boundary.

## Introduction & Purpose
QuicFuscate is a forked stealth transport and VPN runtime built around a custom QUIC-like transport/data-plane posture, hybrid adaptive FEC, and a cohesive stealth stack. The canonical runtime is designed for strong censorship resilience and high-throughput operation under this forked protocol contract. It is not a drop-in upstream QUIC implementation.

This document provides comprehensive technical documentation for the system architecture, modules, and implementation details in Rust.

### Quick Index (Fast Paths)
- Runtime architecture and module map: [Architecture at a Glance](#architecture-at-a-glance)
- QUIC version policy and downgrade protection: [QUIC v1/v2 Version Negotiation](#quic-v1v2-version-negotiation)
- Stealth behavior and mode matrix: [Obfuscation-Modes Overview](#obfuscation-modes-overview)
- TLS boundary and controls: [TLS Boundary: rustls protocol with optional cover overlay](#tls-boundary-rustls-protocol-with-optional-cover-overlay)
- FEC runtime controls and tuning: [FEC Operations Guide](#fec-operations-guide)
- CLI operation and server/client flows: [Usage](#usage)
- Profiling runners and evidence semantics: [Profiling Evidence Contract](#profiling-evidence-contract)
- Full config schema and env overrides: [Configuration Reference (Full)](#configuration-reference-full)
- Embedded API contracts: [Engine Control Plane (embedded orchestration)](#engine-control-plane-embedded-orchestration)
- Script entrypoints and suites: [Scripts Reference (Authoritative)](#scripts-reference-authoritative)

### Architecture at a Glance
- Modular Rust crate with focused modules:
  - `src/core.rs` (+ `src/core_parts/`): QUIC I/O and session management; maintains rolling `ConnectionStats` including VNNI-accelerated congestion aggregation (`aggregate_congestion`) for cwnd, bytes-in-flight and loss score.
  - `src/crypto/`: AEAD and handshake glue
  - `src/fec/`: Encoder/decoder/adaptive/GF tables
  - `src/stealth/`: HTTP/3 masquerading, TLS Cover, domain fronting, QPACK helpers, active probe detection, runtime Server Push cover coordination
  - `src/dns/`: canonical DNS packet parsing, upstream forwarding, cached DoH client, endpoint fallback, and DNS response construction
  - `src/implementations/client/dns_runtime.rs`: client-owned localhost UDP/53 proxy, pre-pinned DoH endpoint lifecycle, platform resolver mutation, and fail-closed restoration
  - `src/reality.rs`: Reality Fallback (Xray-style reverse proxy for active probe mitigation)
  - `src/interface.rs`: Cross-platform TUN interface
  - `src/interface/wintun.rs`: Feature-gated native Windows Wintun adapter, packet I/O, MTU, and shutdown lifecycle
  - `src/transport.rs`: Transport module root with focused submodules in `src/transport/` (packet, version, recovery, frames, h3, xdp, udpfast, connection)
  - HTTP/3 streams: `fin_received` flag tracks stream completion for deterministic GC in `poll()`
  - UDP fast paths: runtime-owned sendmmsg/recvmmsg batching in `src/optimize/udp.rs`, narrowed `udpfast` compatibility coverage, and sendmsg_x batching (macOS)
- `src/brain.rs`: StealthBrain adaptive policy engine (ACK/FEC hints plus Core H3/MASQUE hint channel), lock-free packet-observer telemetry accumulators drained by `apply_policy` (packet size/count/reordering are complete; inter-arrival bins use every-eighth-packet sampling), sensor-fusion logic, and Intelligent-mode runtime-policy delta emitter

- `src/profile.rs`: test/compat-only `Aegis128Profile` adapter mapped to `simd::CryptoAeadPlan`
- `src/engine/`: Embedded control plane (`QuicFuscateEngine`, `EngineConfig`, `EngineCommand`, `EngineEvent`, `EngineStats`) for programmatic runtime orchestration
- `src/compress.rs`: Compression manager (zstd-only) with adaptive policy, telemetry-backed decisions, and optional dictionaries
- `src/qftls.rs`: Boundary split between rustls real TLS protocol and optional TLS Cover overlay
  - `src/instrumentation.rs`: Global runtime metrics and health export surfaces (`/metrics`, `/health`); Prometheus export writes directly into one pre-sized output string without per-metric temporary `String` values.
  - `src/implementations/server/metrics.rs`: Server metrics runtime and HTTP endpoint wiring; the Prometheus exporter uses direct `write!` formatting into a pre-sized buffer.
  - `src/optimize/`: Optimization submodules now live under `src/optimize/*` and are re-exported through `src/accelerate.rs` to keep the public `accelerate::*` API stable.
  - TLS fingerprint sourcing follows the canonical "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".
  - Unified configuration via `config/quicfuscate.toml`; environment overrides through `QUICFUSCATE_*`
  - Modular script-based architecture with dedicated scripts for each functionality
- `src/pki/mod.rs`: Production CA hierarchy generation and validated reuse of the server leaf, including Rustls/WebPKI chain, hostname, expiry, and private-key matching checks; invalid or incomplete material is quarantined before regeneration.
- Organized script directories: `scripts/build/`, `scripts/install/`, `scripts/utils/`, `scripts/benchmarks/`, `scripts/tests/build/`, `scripts/tests/analysis/`, `scripts/tests/audits/`, `scripts/tests/frontend/`, `scripts/tests/fuzz/`, `scripts/tests/lib/`, `scripts/tests/rust/`, `scripts/tests/smoke/`, `scripts/tests/suites/`, and `scripts/tests/utils/`
- Individual scripts for specific tasks: build management, benchmarking, testing, auditing, and utilities

- Developer Harness: `src/harness.rs` provides a central CLI used by scripts. Unit tests still exist in the codebase, but the harness is the main entry point for scripted internal tooling.
- Desktop App: `apps/svelte-desktop` (SvelteKit + Svelte 5 + bits-ui + Tailwind v4, packaged through Tauri) is the canonical native desktop client with tunnel management, settings, logs, and hardware detection. State is persisted via Tauri `invoke` commands with debounced writes. The selected tunnel surface supports direct `Set QKey` / `Change QKey`, exposes compact live diagnostics (token, loss, recovered packets, policy source), and the shell restores keyboard shortcuts for navigation/tunnel actions plus a fatal-error recovery screen for true hard UI faults.
- Web admin: `apps/svelte-admin` (SvelteKit + Svelte 5 + bits-ui + Tailwind v4) is the canonical admin/control surface. Its static publish output is generated into the ignored `assets/web-admin/` path by `scripts/build/build-web-admin.sh`; a fresh checkout must run that step before serving or bundling the admin root. It provides dashboard, configuration, QKey management, logging views, and an explicit route-level crash fallback for render/load failures.
- Shared UI packages: `packages/ui` (shared Svelte 5 components: Switch, Select, Toast, ConfirmDialog, Skeleton, GlassCard, ErrorBoundary, SettingRow, AboutContent; plus ripple action, cn utility, toast store, and `createCopyFeedback` hook for clipboard-write + timed visual feedback). `ErrorBoundary` is a real Svelte boundary wrapper that can catch child render failures and render a supplied fallback. `packages/ui` has its own vitest config with 82 unit tests (9 files) under `scripts/tests/frontend/shared-ui/unit/`. `packages/theme` provides the shared CSS layer (glass morphism, layout, tokens, buttons, animations, login, scrollbar).
- QKey: server-issued connection key string (`QKey-...`) that embeds connection parameters (remote, SNI), optional policy presets (stealth/FEC), and a bearer token. QKeys are generated in the Web Admin UI and must be treated like passwords.
- Raw QKeys are one-time reveal credentials: the server returns the full credential at issuance time, but registry/list surfaces remain metadata-only and do not reconstruct raw QKey material later.
- Admin control plane: `src/implementations/server/admin_http.rs`, `src/implementations/server/qkey_registry.rs`, and `src/implementations/server/qkey_registry_storage.rs` provide server-authoritative QKey issuance/revocation, fail-closed encrypted persistence, and runtime policy enforcement surfaces.
- Replay-window maintenance: `QKeyRegistry::prune_replay_window()` supplies the current Unix-epoch timestamp to `ReplayWindow::prune(now)`. Standalone housekeeping invokes it every tick, removing stale nonce slots and advancing an empty quiet window so out-of-window frames cannot become accepted solely because no new traffic arrived.
- Standalone CLI server runtime: `src/implementations/server/mod.rs::ServerRuntime::new_standalone(...)` owns standalone UDP socket bootstrap, live-state bootstrap, accept-loop ownership, optional standalone TUN setup, and auxiliary shutdown/control-plane signal registration for metrics, Unix admin, and admin-web services.
- Graceful server lifecycle: SIGINT, SIGTERM, admin shutdown, and authenticated `POST /api/drain` enter the same `Running -> Draining -> Stopped` state machine. Draining rejects new clients immediately, preserves established sessions until they close or `[engine] shutdown_timeout_ms` expires, flushes final QUIC CONNECTION_CLOSE packets, then tears down auxiliary services and host resources. `GET /api/drain/status` reports lifecycle, active connections, grace, and elapsed time. SIGHUP validates and applies supported runtime config changes without restarting, then independently reopens the operational file sink through its writer owner. systemd receives READY, RELOADING, STOPPING, STATUS, and configured watchdog notifications.
- Standalone runtime config reload: the server module owns runtime reload normalization for stealth overrides, optimize normalization, and `transport.*` TOML overrides. Reload is explicitly `NextConnectionOnly`: the single live server loop serializes profile replacement with connection construction, while every existing session remains immutable. Admin acknowledgement, runtime logs, and audit records state this scope and the unchanged active-session count. `main.rs` only forwards reload intent and transport state into that server-owned path.
- Server listen-address normalization: standalone CLI and embedded `EngineMode::Server` now derive `ServerConfig.listen` through the same server-owned resolver, so both entry surfaces share one canonical listen-address interpretation for runtime ownership.
- Desktop: imports QKeys (paste/import), persists them per tunnel locally, and uses them for connect/disconnect. Existing tunnel shells can be upgraded in-place through `Set QKey` / `Change QKey`. The desktop UI does not generate server-issued QKeys and does not render them after import.

### QUIC v1/v2 Version Negotiation

The canonical Engine and standalone CLI runtimes support only standardized QUIC v2 (`0x6b3343cf`) and v1 (`0x00000001`), ordered by `[transport].quic_versions`; the default is `["v2", "v1"]`. `src/transport/version.rs` owns the usable-version state, v1/v2 long-header type mapping, reserved-version greasing, and RFC 9368 Version Information transport parameter. Grease values are advertised only on the wire and never become selectable runtime versions.

`src/transport/packet.rs` owns version-specific Initial key labels and salts, Retry integrity material, invariant Version Negotiation parsing, and stateless server VN replies before connection allocation. A client accepts a VN packet only before any other server packet, with DCID equal to its current SCID, SCID equal to its original DCID, and without its original version in the offered list. At most one restart is allowed; the restart chooses the first locally preferred common version, generates fresh connection IDs, and resets packet-number, recovery, crypto, TLS, H3, flow-control, and retained-stream transmission state.

Both peers authenticate the result through `version_information` during the rustls handshake. Malformed or duplicate parameters fail with `TRANSPORT_PARAMETER_ERROR`; inconsistent choices, missing required v2 information, and downgrade attempts fail with `VERSION_NEGOTIATION_ERROR`. A server may accept a legacy peer without Version Information, and a client that explicitly falls back to v1 after VN applies RFC 9368's synthetic v1 compatibility rule. QUIC v2 uses the RFC 9369 packet type bits, Initial salt, `quicv2 key`/`iv`/`hp`/`ku` labels, and Retry key/nonce.

#### Engine Control Plane (embedded orchestration)
`quicfuscate::engine::QuicFuscateEngine` is the canonical embedding entrypoint for non-CLI integrations. It owns the canonical aggregated `EngineConfig`, selects `ClientRuntime` or `ServerRuntime` via `engine.mode`, tracks lifecycle in `EngineState`, and emits `EngineStats` snapshots for host applications. `reload_config_from_file()` parses and validates a complete TOML candidate before publication. A created/stopped engine replaces the full configuration; a running client updates only the next-connection projection while preserving immutable active sessions except for the typed FEC control path. A running generic server rejects these mutations because the standalone server reload owner is separate.

Embedded server startup constructs `ServerRuntime`, its Tokio UDP socket, and all runtime-bound channels inside the dedicated Tokio thread. The synchronous Engine start boundary waits up to the larger of 30 seconds or the configured shutdown timeout for a typed readiness acknowledgement containing shutdown control and metrics ownership. Runtime construction, thread-creation, firewall-preflight, and kill-switch setup failures are returned as `EngineError` and transition the engine from `Starting` to `Error`; no failed start remains in `Starting`. No Tokio resource is created outside an active reactor. A startup timeout retains the thread join handle under Engine lifecycle ownership so `stop()` can complete bounded cleanup.

Control and observability are explicit through typed channels:

- `EngineCommand`: `Start`, `Stop`, `Connect`, `Disconnect`, `Reconnect`, runtime overrides (`SetStealthMode`, `SetFecMode`, `SetCongestionControl`, `SetTrafficPadding`, `SetTimingObfuscation`, `SetZeroRtt`), and diagnostics/state queries (`GetTunCapabilities`, `GetState`, `GetStats`).
- `EngineEvent`: `StateChanged`, `Connected`, `Disconnected`, `Error`, `StatsUpdated`, `StealthEscalated`.

This keeps CLI and embedded control planes aligned on one runtime mutation path.

#### Authenticated Client Assignment and Carrier

`src/control_plane.rs` owns the versioned, bounded client-assignment capsule carried on the
authenticated Core MASQUE CONNECT-UDP flow. The capsule binds the server session identity to
the client reconnect generation and carries explicit IPv4/IPv6 family order, prefixes, DNS, MTU,
and an explicit disabled state. The receiver rejects unsupported versions, unknown flags,
malformed or oversized payloads, stale generations, and conflicting assignments before any
native TUN state is changed; an identical retransmission is harmless.

`ClientRuntime` and the standalone CLI client both set the generation before opening the local
MASQUE control flow, wait for the authenticated assignment and confirmed CONNECT-UDP response,
then project the accepted addresses and MTU into the native TUN open contract. A failed
negotiation or projection rolls back the connection without opening or retaining a stale TUN.
The server emits one assignment only after the QKey/authenticated peer MASQUE flow is accepted
and derives the payload from that session's allocated `AssignedClientIps` and server assignment
settings. Generic client ingress and standalone/live ingress use the same Core H3/MASQUE carrier;
generic downlink handoff is bounded before the native TUN write.

The carrier contract has one active CONNECT-UDP Flow-ID per QUIC connection. Core decodes the
MASQUE Flow-ID varint, accepts it only when it matches the Flow-ID registered for the active
CONNECT-UDP stream, then applies the shared tunnel normalizer before dispatch. The canonical
production Flow-ID is `0`; unbound or missing-flow datagrams are drained and dropped. Data
capsule type `0x00` is the decoded raw-IP path, assignment capsule type `0x40` is control-only,
and H3 stream fallback uses the `QFT1` magic plus a bounded big-endian 16-bit packet length.
The framed fallback is decoded before any TUN callback, so a MASQUE flow-id, control capsule,
raw IP payload, and malformed stream bytes cannot be confused by a native boundary.

The standalone client does not negotiate an assignment when TUN bridging is disabled. Its
legacy local `--tun-*` address and MTU overrides are rejected when TUN is enabled so the server
assignment remains the sole address/configuration source. Native privileged Linux/macOS/Windows
proof and authenticated live client/server evidence remain separate gates owned by TODO-866 and
TODO-867.

### Cohesive Stealth Stack (Hard to Classify)
The stealth design is one coherent browser-like H3/MASQUE flow, not a pile of unrelated
stealth toggles. TODO-464 through TODO-471 are complete and define the production policy.

- Persona: one browser/OS/TLS/H3/QPACK persona is selected per connection and remains immutable for that connection. Profile sequences and interval rotation are next-connection/reconnect policies, not mid-session identity mutation.
- TLS: RealTLS via rustls with optional TLS Cover that emits synthetic encrypted QUIC cover records from the active profile (no external uTLS/FFI in the cover layer). TLS Cover does not own or synthesize the real ClientHello. The Engine client path now passes the uTLS/persona decision instead of hardcoding it off; a shared filtered rustls provider removes ChaCha suites from real client offers and server-accepted suites.
- HTTP/3/QPACK: ALPN, header sets, QPACK policy, and framing must align with the selected persona snapshot.
- Core H3/MASQUE: production VPN/TUN payloads use the Core H3/MASQUE data plane. It is the sole active CONNECT-UDP/capsule carrier; the retired `stealth::MasqueManager` and stealth-local DoH resolver are preserved only under `archive/`.
- Domain Fronting: useful only with explicit, vetted fronting configuration. Blind fronting defaults are disabled for Performance, Stealth, and clean Intelligent mode.
- DoH: DNS resolution stays inside the tunnel path and keeps the canonical stealth runtime free of payload-side XOR obfuscation.
- Active Probe Detection + Reality Fallback: probe-like traffic is detected and, when required, relayed via `RealityProxy` to preserve realistic upstream behavior under active scanning.
- Cover Traffic: Cover PING, H3-framed cover requests, randomized bounded Server Push cover, and escalated WebTransport cover are valid layers.
- StealthBrain Coordination: telemetry-driven policy updates may tune ACK strategy, pacing, timing, padding, cover intensity, and FEC hints. Brain may steer actuators, but does not mutate active persona identity.

The intended result is a homogeneous, believable fingerprint: normal QUIC cryptography, normal H3/MASQUE semantics, stable browser identity per connection, and adaptive size/timing/FEC behavior under pressure.

#### Stealth Padding & Timing Obfuscation
- Padding is applied just before AEAD sealing in `transport::Connection::send()` to ensure full authentication and confidentiality.
- Strategies (configurable via `StealthConfig` -> wired into `transport::Config.set_stealth_padding`):
  - Random (0..=max), Fixed (up to `max`), Adaptive (to next 64-byte boundary), BrowserMimic (small skew up to ~`max/4`), PacketNormalize (pads all 1-RTT packets to `normalize_target_size` bytes).
- Mode defaults:
  - Stealth: Adaptive with a small cap (`max_padding_size = 86`) - low overhead, smooths packet sizes.
  - Anti-DPI: BrowserMimic with larger cap (`max_padding_size = 256`).
- Timing obfuscation (Anti-DPI default): per-packet random jitter (us) gated in `transport::Config.set_stealth_timing`; enforced as a send gate in `Connection::send()`.
- Hot-path randomness: padding-rate rolls, Random/BrowserMimic padding samples, and jitter samples use `transport::rand::fast_rand_u64_uniform`, a secure-seeded non-cryptographic per-thread SplitMix64 helper. This is intentionally limited to cover heuristics; connection IDs, path challenges, keys, nonces, tokens, and authentication material stay on secure RNG APIs.
- Hardware integration: On GFNI-capable x86 policies, `accelerate::stealth::add_tls_padding` activates a GFNI-based padding generator that also feeds `StealthManager::apply_padding`; fallbacks (AVX2/SSE2/Scalar) remain unchanged and telemetry (`STEALTH_PADDING_GFNI_OPS`) counts the generated bytes.

#### HTTP/3 Client Hints & sec-fetch
- `stealth::Http3Masquerade` emits `sec-ch-ua`, `sec-ch-ua-platform`, and `sec-ch-ua-mobile` only for Chromium personas (Chrome/Edge).
- Chromium personas emit navigation headers `sec-fetch-{dest,mode,site,user}`; Firefox retains the title-case navigation template, while Safari uses a separate generic navigation template with no `sec-fetch-*`, `upgrade-insecure-requests`, or `cache-control` fields.
- `sec-ch-ua` major versions are derived from the active `User-Agent` to maintain internal consistency per browser/OS profile.

### TLS Boundary: rustls protocol with optional cover overlay
- Real TLS: implemented via rustls in `src/qftls.rs` with `CombinedProvider` orchestrating a rustls protocol stack plus optional TLS Cover overlay. Client certificate verification is enabled by default and mandatory in release builds; `--verify-peer` is retained as a compatibility flag, `--ca-file` adds a private trust anchor, and negotiated HTTP/3 is unavailable until rustls completes.
- Client CA ownership: `transport::Config::load_verify_locations_from_file()` reads, PEM-parses, and Rustls-validates every configured certificate before retaining the path on that transport configuration. `enable_tls()` passes the path into the connection-local provider, including version-negotiation and profile/SNI rebuilds; no process-global client CA state exists. Missing, unreadable, empty, malformed, or invalid-DER bundles fail before standalone kill-switch publication, and error messages expose the path without certificate contents.
- TLS Cover: cover provider in `qftls::CombinedProvider` is enabled by default and can be disabled with `QUICFUSCATE_TLS_COVER=0`. Generates synthetic QUIC `CRYPTO` frames during the TLS handshake phase only (correct QUIC behavior per RFC 9001 - CRYPTO frames do not appear post-handshake in real QUIC). Post-handshake cover is provided by QUIC Cover PINGs, H3-framed cover requests and Server Push/WebTransport, plus transport TrafficPadding. Raw random bytes are never injected into an H3 stream. The canonical runtime cover mode now comes from the active `StealthManager::runtime_tls_profile(...)`: `off`, `performance`, and `intelligent` drive the cover layer into performance mode, while stealth-heavy modes keep timing/jitter enabled. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) enables TLS Cover extras in the stealth manager (ticket manager and cert chain emulator) but does not control the cover provider itself. Cipher selection is automatic (`auto`) and prefers AES-128-GCM when hardware AES (AESNI/VAES/SVE AES) is available, otherwise falls back to ChaCha20-Poly1305. Each provider obtains fresh OS entropy and derives connection-local key/IV material through domain-separated HKDF. `CryptoContext::install_tls_cover_cipher` is the single install/rotation contract: exact active material is an idempotent no-op that preserves sequence numbers, fresh material retires the previous identity and resets both directions, retired material is rejected, and sequence exhaustion fails closed with `AeadLimitReached`. Cover-frame generation never performs lazy reinstallation. On x86 the ChaCha keystream dispatches AVX-512 -> AVX2 -> AVX -> SSE4.1/SSSE3 -> Scalar with telemetry (`CHACHA20_X4_AVX2_OPS`, `CHACHA20_X4_AVX_OPS`, `CHACHA20_X4_SSE41_OPS`, `CHACHA20_X4_SCALAR_OPS`). Override via `QUICFUSCATE_TLS_COVER_CIPHER=auto|chacha|aes`.
- Ownership split: `qftls::CombinedProvider` provides a single runtime interface that keeps rustls as the security-critical protocol owner and composes the cover layer for observable mimicry behavior where enabled.
- ClientHello boundary: `TlsCoverProvider` emits synthetic decoy records and reports no ClientHello-override support. Real ClientHello protocol/configuration remains owned by rustls. `TlsClientHelloProfileCatalog` exposes deterministic persona combinations, while `FingerprintProfile::client_hello` is compatibility/audit metadata only. The transport configuration has no ClientHello template setter or wire override storage; TODO-766 owns this removal. TODO-598 closes the real-TLS ChaCha policy gap and removes the dead advanced builder.
- Fork boundary: rustls/TLS Cover governs the TLS-visible handshake story only. The custom 1-RTT data-plane AEAD posture in `src/crypto/` and `src/transport/*` is a separate fork-specific transport decision, valid only under the explicit full-fork assumption, and must not be interpreted as a TLS cipher-suite or upstream interoperability claim.
- Risk/Tradeoff: enabling TLS Cover increases cover-byte volume and per-packet processing work.
- Certificate tooling: development certificates enabled by feature `dev-certs` (rcgen); production uses PEM chain via `--cert/--key` (server) and CA bundle via `--ca-file` (client).
- Session management: internal session cache for 0-RTT resumption (size-limited, not user-configurable).
  - Anti-replay: 0-RTT data is protected by a SHA-256 strike register (`src/transport/anti_replay.rs`) per RFC 8446 Section 8 and RFC 9001 Section 9.2. The register uses a Bloom fast-negative in front of the full-fingerprint index and a FIFO ring for O(1) capacity eviction. Replayed 0-RTT packets are silently discarded; clients fall back to 1-RTT automatically. Configurable via `[anti_replay]` TOML section.

#### Fingerprint Source Model
- Primary runtime path: `TlsProfile` selection and rustls `ClientConfig` construction from the active `BrowserProfile` and `OsProfile` persona.
- Compatibility/audit path: deterministic in-memory ClientHello synthesis via `TlsCover` and `FingerprintProfile`; the resulting bytes are stored as metadata and are not consumed by the active rustls connection builder.
- Optional external path: top-level `browser_profiles/*.chlo` or `*.chlo.b64` dumps for strict byte-level replay and audit/regression workflows.
- The `qftls` browser profile extension-order metadata keeps unique IANA-registered extension IDs plus intentional GREASE; Chrome's `renegotiation_info` and `compress_certificate` values are covered by regression tests (TODO-595).
- Provider path: `RustlsProvider::rebuild_client_connection` constructs the real client handshake with the shared filtered provider; `create_server_connection` uses the same provider policy.
- Operational rule: external dumps and deterministic compatibility templates are optional; runtime operation remains available without on-disk profile artifacts.

#### Environment Controls
- `QUICFUSCATE_TLS_COVER=0|1` - enable or disable the TLS Cover provider in `qftls` (default: enabled, set to `0` to disable).
- `QUICFUSCATE_USE_TLS_COVER_EXTRAS=0|1` (alias: `QUICFUSCATE_USE_TLS_COVER`) - enable TLS Cover extras in `StealthManager` (ticket manager and cert emulator); does not control the cover provider (default follows active stealth preset: on for `off|performance|base|stealth|anti-dpi|intelligent`, off for `manual` unless explicitly set).
- `QUICFUSCATE_STEALTH_MODE=off|performance|base|stealth|anti-dpi|intelligent|auto|manual` - selects the stealth baseline (`auto` is an alias for `intelligent`); `qftls` uses it only as a fallback/bootstrap hint before the runtime `TlsProfile` has been applied. The canonical cover-performance decision comes from `StealthManager::runtime_tls_profile(...)`.
- `QUICFUSCATE_TLS_COVER_PROFILE=chrome|firefox|safari|edge|random` - select TLS Cover browser profile.
- `QUICFUSCATE_TLS_COVER_CIPHER=auto|chacha|aes` - control TLS Cover cipher (auto prefers AES-128-GCM when hardware AES is detected, else ChaCha20-Poly1305).
- `QUICFUSCATE_TLS_COVER_ULTRA=1` - enable the ultra TLS Cover profile variant (ECH-grease and padding).
- `QUICFUSCATE_TLS_COVER_ROTATE=1` - currently log-only (no rotation implementation).
- `QUICFUSCATE_TLS_COVER_TELEMETRY=1` - currently log-only (no extra telemetry output).
- `QUICFUSCATE_CHACHA20_X4=auto|avx2|avx|sse|scalar` - override the TLS Cover ChaCha20 backend for diagnostics.
- `QUICFUSCATE_PQ_HYBRID=1` - Removed. PQ-hybrid code was deleted (TODO-286). This variable is no longer recognized.
- `QUICFUSCATE_ALLOW_INVALID_CERTS=1|true|yes|on` - accept invalid peer certificates (development/testing only).
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - forward a template name only to a TLS provider that advertises ClientHello override support; the current rustls and TLS Cover providers report unsupported, so no override is applied.
- `QUICFUSCATE_TRACE_TLS=1` - enable additional TLS handshake/key-change diagnostic logging in qftls and transport packet parsing.

Example (RealTLS configuration)
```rust
use quicfuscate::transport::Config;

let mut cfg = Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION).expect("cfg");
cfg.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"]).ok();
cfg.verify_peer(true);
cfg.load_verify_locations_from_file("/etc/ssl/certs/ca-bundle.crt").ok();
// Server side
cfg.load_cert_chain_from_pem_file("tls-cert.pem").expect("cert");
cfg.load_priv_key_from_pem_file("tls-key.pem").expect("key");
// Optional TLS key logging for debugging
cfg.log_keys();
```

#### Zstd FFI (unsafe_rust) + Sweetspot Defaults

- Feature flag: `compression_zstd_ffi` (optional; default OFF). Build example:
  - `cargo build --features "unsafe_rust,compression_zstd_ffi"`
- When enabled, the internal `unsafe_compress` backend in `src/optimize/unsafe.rs` uses native `zstd-sys` with per-call tuning for maximum throughput and low CPU.
- The default mode is a single "sweetspot" profile optimized for network payloads (good ratio at very low CPU). Heuristics (length -> (level, workers, target_block)):
  - `<= 8 KiB` -> `(2, 0, 16 KiB)`
  - `<= 64 KiB` -> `(3, 1, 64 KiB)`
  - `<= 256 KiB` -> `(3, clamp(cpus/4, 1..2), 128 KiB)`
  - `> 256 KiB` -> `(4, clamp(cpus/2, 2..4), 256 KiB)`
  - `cpus` is the available parallelism (logical cores). `clamp(a, x..y)` is bounded to `[x, y]`.
- Manual override (global): set once via environment to force a fixed configuration regardless of payload size:
  - `QUICFUSCATE_ZSTD_MODE=manual|auto` (invalid values warn and retain automatic mode)
  - `QUICFUSCATE_ZSTD_LEVEL=<int>` in `1..=22` (default 3; invalid values warn and retain the default)
  - `QUICFUSCATE_ZSTD_WORKERS=<int>` in `>=0` (default 2; invalid values warn and retain the default)
  - `QUICFUSCATE_ZSTD_TARGET_BLOCK=<bytes>` in `>=1` (default 65536; invalid values warn and retain the default)
- Optional tuning (FFI path only):
  - `QUICFUSCATE_ZSTD_STRATEGY=fast|dfast|greedy|lazy2|btopt` (invalid values warn and use the length-based default)
  - `QUICFUSCATE_ZSTD_WINDOW_LOG=<int>` in `10..=31` (invalid values warn and use the length-based default)
  - `QUICFUSCATE_ZSTD_CHECKSUM=0|1` (invalid values warn and retain `0`)
  - `QUICFUSCATE_ZSTD_CONTENTSIZE=0|1` (invalid values warn and retain `0`)
- Additional initialization hints (FFI path; applied at compressor creation):
  - `ZSTD_c_nbWorkers` is also set from `QUICFUSCATE_ZSTD_WORKERS` if present.
  - `ZSTD_c_targetCBlockSize` is set from `QUICFUSCATE_ZSTD_TARGET_BLOCK` if present.
- Safe fallback behavior: If `compression_zstd_ffi` is OFF, the "unsafe" path uses the safe `zstd` crate under the same nominal headers/mode. Native/fallback ownership, parameter-error, dictionary-failure, initialization, and concurrent-context contracts are not yet proven equivalent and remain TODO-828.

##### Headers and Compatibility
- Basic frame (no dictionary): `0x5A` + 4B big-endian original length, followed by zstd data.
- Dictionary frame: `0x5D` + 2B dict hash + 2B dict version + 4B big-endian original length, followed by zstd data.
- The internal unsafe compressor/decompressor backend reads and writes the same header shapes as `compress.rs` helpers; full feature-on/feature-off interchangeability remains TODO-828.

##### Dictionary Training and Lookup
- Training: `compress.rs::maybe_train()` periodically builds dictionaries from submitted samples and persists them to `dict_cache/`.
- Lookup: `get_dict_by_id(hash, version)` resolves bytes at runtime; the unsafe decompressor prefers the supplied dictionary but falls back to cache lookup by id.

##### Streaming Compression API
- Internal unsafe FFI backend:
  - The internal compressor streams via `ZSTD_compressStream2` with `targetCBlockSize` to reduce end-to-end latency on large inputs.
  - Direct and streaming selection follows the compiled backend contract; `QUICFUSCATE_ZSTD_STREAM_MIN` is not a current runtime key.
  - Header semantics are identical to direct: `0x5A` (no dict) or `0x5D` (with dict-ID: 2B hash, 2B version, then 4B length).
- Safe path (`src/compress.rs`):
  - `CompressionManager::compress_to_pool()` writes zstd output directly into the caller-provided pool block after the `0x5A` header via `zstd::bulk::Compressor::compress_to_buffer`.
  - `CompressionManager::decompress_to_pool()` writes directly into the caller-provided pool block with `zstd::bulk::decompress_to_buffer`, validating the declared original length without an intermediate `Vec`.
  - Dictionary compression and decompression write directly into the caller-provided pool block via the symmetric bulk compressor/decompressor APIs after the `0x5D` dictionary header. Decompression requires the block to hold the declared original length and rejects any decoded length mismatch instead of returning a truncated payload.
  - No API change; behavior is compatible, headers remain `0x5A` and `0x5D` in the safe path.

#### Provider API (Unified)
```rust
use quicfuscate::qftls::create_provider;
use parking_lot::RwLock;
use std::sync::Arc;

let crypto = Arc::new(RwLock::new(quicfuscate::transport::packet::CryptoContext::default()));
let provider = create_provider(false, crypto)?;
```

### Obfuscation-Modes Overview

The stealth stack offers multiple modes balancing performance, compatibility risk, and cover traffic.
Performance stays fast and low-risk, Intelligent is the adaptive default, Stealth spends a moderate
cover budget, and Anti-DPI is the aggressive profile.

Preset layer vs runtime layer:

| Source | Input | Runtime mapping |
|---|---|---|
| Engine config (`engine.stealth.mode`) | `off` | `StealthMode::Off` |
| Engine config (`engine.stealth.mode`) | `performance` (alias: `base`) | `StealthMode::Performance` baseline |
| Engine config (`engine.stealth.mode`) | `stealth` | `StealthMode::Stealth` baseline |
| Engine config (`engine.stealth.mode`) | `anti-dpi` (alias: `antidpi`, `max` for QKey compat) | `StealthMode::AntiDpi` baseline |
| Engine config (`engine.stealth.mode`) | `auto` (alias: `intelligent`) | `StealthMode::Intelligent` adaptive baseline |
| Engine config (`engine.stealth.mode`) | `manual` | `StealthMode::Manual` with explicit sub-fields |
| QKey/Admin preset (`stealth`) | `off` | enforced as `StealthMode::Off` |
| QKey/Admin preset (`stealth`) | `max` | enforced as `StealthMode::AntiDpi` |
| QKey/Admin preset (`stealth`) | `manual` | enforced as `StealthMode::Manual` |
| QKey/Admin preset (`stealth`) | `auto` | no forced override, runtime baseline remains active |
| Runtime/env aliases | `base\|performance` | mapped to `StealthMode::Performance` |
| Runtime/env aliases | `dynamic\|intelligent\|auto` | mapped to `StealthMode::Intelligent` |
| Runtime/env aliases | `stealthmax\|stealth-max\|max\|antidpi` | mapped to `StealthMode::AntiDpi` |

Current Obfuscation-Modes - Matrix & Tuning (on = enabled, off = disabled, values shown when relevant)

| Feature | Performance | Stealth | Anti-DPI | Intelligent |
|---|---:|---:|---:|---:|
| uTLS/Persona | on | on | on | on |
| Domain Fronting | off | explicit only | on with explicit domains or built-in aggressive list | off at Level 0; explicit/escalated only |
| HTTP/3 Masquerading | on | on | on | on |
| QPACK Headers | on | on | on | on |
| XOR Obfuscation | off | off | off | off (dynamic) |
| Traffic Padding | off | Adaptive (max 86) | BrowserMimic (max 256) | off at Level 0; dynamic at Level 1-2 |
| Timing Obfuscation | off | 750 us default | 3000 us default | off (dynamic); forced on after probe |
| Flow Shaper and Dummy Retransmits | off | off | on | off (dynamic) |
| Active Fingerprint Rotation | off | off | off (next-session only) | off (next-session only) |
| Server Push Cover | off | light randomized (0.25, 60 s) | randomized (0.8, 15 s) | Level-dependent randomized (15 s at L2, 30 s at L0/L1) |
| Real-time Choke | off | off | off (compat/manual only) | off (dynamic) |
| DNS-over-HTTPS | on | on | on | on |
| TLS Cover provider | on* | on* | on* | on* |
| WebTransport Cover | off | off | escalated/anti-DPI cover only | Level 2 only |
| Core H3/MASQUE TUN | only if TUN requires it | only if TUN requires it | only if TUN requires it | TUN or escalation |
| Core H3/MASQUE Preference | off | off | off | off at Level 0; dynamic after escalation |
| Cover Traffic Interval | off | 5 s | 5 s (tightened on escalation) | off at Level 0; 5 s from Level 1 |

Notes:
- Active probing detection is enabled in Stealth, Anti-DPI, and Intelligent; Performance keeps overhead minimal with the detector disabled and no H3 cover-request scheduler. Intelligent starts like Performance at Level 0 and can escalate toward Stealth/Anti-DPI features on probe signals.
- `sec-ch-ua*` hints are emitted only for Chromium family (Chrome/Edge); Firefox and Safari typically omit them.
- `StealthManager` owns all preset baselines and the concrete Intelligent-mode runtime policy derivation for pacing, timing, padding, mimic bias, granularity, and CC profile. `StealthBrain` adapts transport ACK policy per connection, and its Intelligent-mode stealth steering flows through a narrow runtime-policy delta instead of embedding raw per-actuator mapping logic inline.
- * TLS Cover provider is enabled by default across modes and can be disabled with `QUICFUSCATE_TLS_COVER=0`. Runtime cover performance mode is now driven by the active stealth mode profile rather than relying on ENV-only shadow state. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) only controls TLS Cover extras (ticket manager and cert emulator).
- Risk/Tradeoff: domain fronting behavior depends on current upstream provider policy and regional filtering rules. It is not a safe default cover signal on modern CDNs.
- Core H3/MASQUE is the production VPN/TUN carrier and the only active MASQUE implementation. Its H3 capsule parser buffers split DATA frames, rejects malformed/truncated FIN tails, and stages decoded events until the enclosing batch is valid.
- Per-packet MASQUE TX/downlink logs are `trace`-only in the production hot path. CONNECT-UDP lifecycle and peer-flow registration remain `info` for operator observability without packet-rate log amplification.

Production Mode Policy

| Mode | Persona/uTLS | Core H3/MASQUE TUN | Domain fronting | Padding/timing | Cover traffic | Brain |
|---|---|---|---|---|---|---|
| Off | off | only if TUN requires it | off | off | off | minimal |
| Performance | on | on | off | off | off | ACK/FEC hints only |
| Intelligent | on | on | off by default, escalation only with vetted config | dynamic | dynamic, none/low at level 0 | full |
| Stealth | on | on | explicit/vetted only | light | light and randomized | medium |
| Anti-DPI | on | on | on with vetted front domains | strong | strong and randomized | full |
| Manual | operator-defined | operator-defined | operator-defined | operator-defined | operator-defined | operator-defined, persona freeze still applies |

Production invariants:
- Persona identity is frozen per connection. Rotation applies to the next connection or reconnect only.
- Domain fronting is not a Performance default and not a blind Intelligent level-0 default.
- Server Push cover is randomized and bounded before it is treated as a strong cover layer.
- WebTransport is an H3 application-cover profile, not a replacement for Core H3/MASQUE.

Final stealth stack:

```text
                operator mode/profile
                       |
                       v
          +--------------------------+
          | connection persona       |
          | Browser + OS + uTLS      |
          | frozen for session       |
          +-------------+------------+
                        |
                        v
          +--------------------------+
          | HTTP/3 application cover |
          | headers, QPACK, PING,    |
          | cover requests, bounded  |
          | server push, WT cover    |
          +-------------+------------+
                        |
                        v
          +--------------------------+
          | Core H3/MASQUE carrier   |
          | production VPN/TUN path  |
          +-------------+------------+
                        |
                        v
          +--------------------------+
          | QUIC transport + AEAD    |
          | ACK, pacing, padding,    |
          | timing, congestion       |
          +-------------+------------+
                        |
                        v
          +--------------------------+
          | FEC repair layer         |
          | interval + redundancy    |
          | from Brain hints, owned  |
          | and capped by FEC        |
          +--------------------------+
```

#### Stealth Modes - Semantics
- Off: no stealth; DoH, fronting, HTTP/3 masquerading, padding, timing, QPACK, and TLS Cover extras are all disabled.
- Performance: uTLS/persona on; DoH on; domain fronting off; HTTP/3 masquerading on; XOR off; no padding; no timing obfuscation; QPACK headers on; active persona rotation off.
- Stealth: uTLS/persona on; DoH on; domain fronting off unless explicit fronting domains are configured; HTTP/3 masquerading on; XOR off; QPACK headers on; adaptive padding (max 86); timing obfuscation on (default 750 us); active persona rotation off; server push cover light (intensity 0.25, 60 s interval).
- Anti-DPI: uTLS/persona on; DoH on; fronting on with explicit domains or the built-in aggressive list; HTTP/3 masquerading on; XOR off; QPACK headers on; BrowserMimic padding (max 256); timing obfuscation on (default 3000 us); flow shaper enabled; active persona rotation is still deferred to next session; server push cover enabled (intensity 0.8, 15 s interval); WebTransport cover enabled as an H3 application-cover session; real-time choke off by default.
- Intelligent: starts like Performance at level 0 (no padding, no cover overhead, no domain fronting); escalates dynamically to Stealth/Anti-DPI timing, padding, cover and FEC-hint behavior on probe signals or brain pressure; server-push burst interval is level-dependent (30 s at L0/L1, 15 s at L2); WebTransport cover is level-2 only.
- Manual: all knobs as configured in TOML or env; no automatic escalation.

#### Real-Time Rate Choke
- Token bucket shaping with `choke_target_mbps` and `choke_burst_ms` limits instantaneous bitrate without heavy CPU overhead.
- When enabled, the Stealth layer sets `Config.set_external_pacing(true)` and injects sleeps only when necessary, avoiding jitter amplification.
- The canonical stealth plan keeps this off by default and reserves it for manual or compatibility-only extreme-pressure tuning.

#### Probe Escalation (runtime)
- Escalation triggers on active probe detection only when `dynamic_enabled` is true (Intelligent mode). Performance and Stealth modes do not auto-escalate on probe - this would violate the user's explicit performance preference.
- Escalation window lasts 20 minutes and tightens cover traffic interval to 2500 ms.
- Server push cover traffic is enabled at runtime during escalation.
- While server push cover is active, the regular cover-request scheduler is suppressed so only one active cover-traffic owner shapes burst behavior at a time.

### StealthBrain Runtime Control

The StealthBrain module (`src/brain.rs`) implements sophisticated ACK policy optimization using machine learning techniques for adaptive transport behavior. It observes telemetry, performs sensor fusion, and applies transport/stealth changes conservatively with step limiting. Intelligent-mode stealth steering now uses a narrow policy handoff:

Runtime wiring is cohesive rather than feature-isolated:

- `StealthManager` enforces mode/profile policy on stealth actuators, remains authoritative for non-Intelligent preset baselines, and derives the concrete Intelligent-mode runtime policy targets.
- `StealthBrain` is attached via `CombinedObserver` and continuously translates one connection's transport signals into connection-local ACK/FEC hints plus an Intelligent-mode-only `StealthRuntimeDelta`.
- `Connection::apply_brain_stealth_runtime_delta(...)` centrally applies that delta instead of receiving several scattered setter calls from the Brain observer.
- `DeepIntegrationOrchestrator` (feature `orchestrator`) contributes cross-signal heuristics for escalation and cover-traffic coordination.
- Profile-derived `stealth_mode`/`fec_mode` preferences are replayed through the same runtime mutation surface used by live intelligent control.

#### StealthBrain Core Components
- **`StealthBrain`**: Main orchestrator with epsilon-greedy bandit for ACK policy selection
- **`CombinedObserver`**: Multi-observer pattern allowing attachment of multiple `TransportObserver` instances
- **`StealthBrainConfig`**: Configuration with ACK bounds, exploration probability, and cooldown parameters

#### Operational Parameters
- Inputs: ACK delay (short/long EWMA), inter-arrival (IAT) histograms, size histograms, ECN (ECT0/ECT1/CE), delivery rate, reorder ratio.
- ACK policy: epsilon-greedy bandit chooses thresholds from {2, 3, 4, 8}; step limiting moves by at most +/-1 per change, clamped to `[ack_min, ack_max]`.
- Timing shaping: derived from deviation between short/long ACK EWMAs with +/-10% dithering; applied only through the Intelligent-mode `StealthRuntimeDelta`, which updates the live connection timing baseline directly.
- External pacing: Brain may steer it only for Intelligent-mode connections, and only through the Stealth-derived runtime policy delta; non-Intelligent modes keep the baseline from `StealthManager` or explicit transport overrides.
- Padding shaping: BrowserMimic bias `1..4`, adaptive granularity (`32|64|128`), and dynamic padding strategy are now derived in `stealth/` and applied through the same Intelligent-mode runtime policy delta; other presets keep the configured StealthManager baseline. At Brain level 0 (clean path, no pressure) padding is disabled for near-zero Intelligent-mode overhead.
- Jitter direction: under ECN congestion (CE > 5%) or high RTT spikes, jitter increases to 85% of budget (more randomization defeats timing fingerprints). Only on the external-pacing clean path is it reduced.
- `jitter_max_us` default: 5000 us (raised from 1500; 1500 was too small to meaningfully randomize timing against a modern DPI system).
- Level-hint passthrough: Brain computes an `effective_level` (0/1/2) via hysteresis and passes it as `level_hint` to `derive_intelligent_runtime_policy`, enabling level-dependent padding and server-push decisions.
- Runtime overrides: `StealthManager` exposes `runtime_padding_rate`, `runtime_timing_rate`, and retained `runtime_rotation_rate` atomics. Padding and timing are set by `escalate_to_level(n)` (0=0%, 1=50% configurable padding and 0% timing, 2=100% padding and timing), then flow through `StealthRuntimePolicy` -> `StealthRuntimeDelta` -> connection config and are consumed by `compute_stealth_padding()` and `transport_stealth_jitter_delay()`. `runtime_rotation_rate` is intentionally kept at 0 for active sessions; fingerprint/persona rotation is next-session only.
- Gradual escalation (TODO-416): Probe detection uses `EscalationState` with a sliding-window probe counter. Escalation 0→1 requires ≥3 probes in 60s; 1→2 requires ≥8 probes in 120s. A single probe does NOT trigger escalation. The state stores timestamp buckets at millisecond resolution, aggregates probes sharing a millisecond, keeps at most 120,001 buckets for the 120-second window, and maintains independent 60-/120-second counters. De-escalation drops at most one level per configurable quiet period (default: 300s), measured from the latest probe or level change. Config knobs: `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (default 3), `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2` (default 8), `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (default 300), `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (default 50).
- Explicit transport overrides win over Brain steering. If an operator sets ACK, pacing, jitter, padding, granularity, or mimic-bias overrides, the corresponding Intelligent-mode Brain actuator is locked out for that connection instead of silently re-overriding the operator choice at runtime.
- FEC hints: updates the connection-local `BrainFecHints` state consumed by that connection's `FecTransportObserver`; no FEC policy crosses connection boundaries.
- ACK batches: `on_ack` aggregates a coherent sum/count batch under a short mutex and applies the batch mean to both ACK-delay EWMAs, so callbacks between policy ticks are not dropped.
- Reorder pressure: lifetime counters remain telemetry, while policy uses exponentially decayed recent counters with a 30-second half-life.
- Configuration: `StealthBrainConfig::try_from_env` validates interdependent bounds such as ACK ordering and padding ordering; `from_env` falls back to defaults and logs on invalid effective configuration.
- Cooldowns: changes respect `policy_cooldown_ms`; exploration bounded by `explore_prob` and current CE ratio.

#### Brain Configuration
```rust
use quicfuscate::brain::{StealthBrain, StealthBrainConfig};

let cfg = StealthBrainConfig {
    ack_min: 2,
    ack_max: 8,
    explore_prob: 0.1,
    policy_cooldown_ms: 200,
    jitter_dither_pct: 10,
    ack_ewma_alpha_short: 0.25,
    ack_ewma_alpha_long: 0.95,
    ..Default::default()
};

let brain = StealthBrain::new(cfg);
```

#### Server Push Cover Traffic (feature `orchestrator`)
The StealthBrain module includes advanced Server Push Cover Traffic coordination for enhanced stealth:

```rust
use quicfuscate::brain::DeepIntegrationOrchestrator;

// Enable Server Push Cover Traffic
let orchestrator = DeepIntegrationOrchestrator::new(
    brain_config,
    pool_capacity,
    block_size
);

// Enable server push based on network conditions
orchestrator.enable_server_push(true);

// Brain automatically determines when to trigger push
if orchestrator.should_trigger_server_push() {
    let intensity = orchestrator.get_server_push_intensity();
    // Intensity ranges from 0.0 to 1.0 based on:
    // - Loss rate
    // - Bandwidth availability
    // - Current ACK policy
    // - Jitter requirements
}
```

**Server Push Heuristics:**
- Triggers when ACK delay > 15ms (high latency detected)
- Increases intensity with loss rate (0-5% loss -> 0.3 intensity, >10% -> 0.8)
- Bandwidth-aware: scales with available bandwidth
- Cooldown period prevents excessive pushing
- Integrates with FEC hints for coordinated redundancy
- Resource gating: avoids cover bursts when CPU/memory are under pressure

#### Connection-local Runtime Hints
The StealthBrain module keeps runtime hints scoped to the owning connection:

- **`BrainFecHints`**: streaming interval and redundancy hints shared only with that connection's `FecTransportObserver`.
- **`IntelligentLevelHints`**: separate Brain-pressure and probe-threshold levels; consumers use their maximum so one source cannot erase the other.
- Timing jitter is delivered only through `StealthRuntimeDelta`, and the live connection applies its own updated runtime timing configuration directly.

#### Combined Observer Pattern
The module implements a multi-observer pattern for aggregating telemetry from multiple sources:

```rust
use quicfuscate::brain::CombinedObserver;
use std::sync::Arc;

// Create multiple observers and combine them
let observers = vec![
    Arc::new(stealth_brain) as Arc<dyn TransportObserver>,
    Arc::new(fec_observer) as Arc<dyn TransportObserver>,
    // Additional observers...
];

let combined_observer = CombinedObserver::new(observers);
```

#### Active Probing Escalation

- Intelligent runtime escalation may select the Core H3/MASQUE carrier when TUN bridging or telemetry pressure requires it; MASQUE is not a separate cover-traffic scheduler.
- On active probing, the stealth stack escalates to a hardened window (~20 minutes):
  - Adds extra pacing (1-3 ms per packet; 3-7 ms in Anti-DPI) in addition to existing timing gates.
  - Tightens cover-traffic cadence (default 5 s to 2.5 s; 2.0 s in Anti-DPI) with realistic GET/HEAD mix.
  - Raises server-push cover intensity and keeps the HTTP/3 persona stable.
  - Automatically clears after the escalation window (interval reset to 5 s).
- The retired standalone MASQUE manager is not compiled or selectable; all active CONNECT-UDP behavior remains in the Core H3 transport path.

#### Reality Fallback (Xray-style Reverse Proxy)

When an active probe is detected (invalid QUIC authentication, suspicious packets), returning silence or "Connection Refused" exposes the server as a VPN. The Reality Fallback module (`src/reality.rs`) mitigates this by transparently forwarding probe packets to a legitimate upstream target and relaying the response back to the scanner.

**Architecture:**
- **`RealityProxy`**: Manages ephemeral proxy sessions per scanner IP, spawns lightweight async tasks for each session.
- **`FallbackResponse`**: Encapsulates upstream response data for relay back to the scanner.
- **Targets (Round-Robin)**: `1.1.1.1:443` (Cloudflare), `8.8.8.8:443` (Google), `9.9.9.9:443` (Quad9) - "Too Big To Block" IPs. Override via `QUICFUSCATE_REALITY_TARGETS=host:port,...`.
- **Session Timeout**: 30 seconds of inactivity; lazy pruning when session count exceeds 100.

**Integration:**
- `core::recv()`: On `transport::recv()` error (auth failure), calls `stealth_manager.handle_fallback(packet, source)`.
- `core::send()`: Prioritizes `stealth_manager.poll_fallback()` responses (bypasses Stealth Scheduler) to reply instantly with upstream data.
- `stealth::StealthManager`: Holds `reality_proxy: Option<Arc<RealityProxy>>` (enabled when `dynamic_enabled = true`) and `fallback_rx: mpsc::Receiver<FallbackResponse>`.

**Effect:** The scanner receives a cryptographically valid QUIC/TLS response from Cloudflare or Google, making the server indistinguishable from a standard web service.

**Background worker ownership (TODO-570):**
- `StealthRuntimeOwner` is created once per client or server runtime generation, including the standalone CLI client path. Production connection construction passes that owner into `StealthManager`; compatibility constructors used by the finite `qf-e2e-client` probe and direct tests remain non-spawning.
- The owner shares one validated `RealityConfig` and one `CoverHandshakeCache` across all connections, owns the cancellation-aware refresh worker, and periodically sweeps `RealityProxy` sessions independently of probe traffic.
- Standalone profile rotation uses the same owner, cancellation signal, generation identity, bounded join timeout, and shutdown barrier. Client and server stop paths explicitly signal and await owned workers; a replacement runtime receives a new generation.
- `StealthRuntimeOwner::start()` and `spawn_owned()` fail closed with an explicit error when no Tokio runtime is active; the compatibility `StealthManager::new()` path constructs without spawning background work.
- Cover TCP connect, TLS handshake, raw-capture collection, refresh delay, and retry delay are bounded. Capture-channel closure is reported as an error rather than converted into an empty successful capture.

#### DoH Endpoint Fallback

The shared DoH primitives and client runtime owner are implemented in `src/dns/mod.rs` and `src/implementations/client/dns_runtime.rs`:
- `DnsProxyConfig` owns the configured endpoint list, pre-pins endpoint addresses before resolver mutation, and caches one `reqwest::Client` for connection reuse.
- `ClientDnsRuntime` binds the configured client listener on localhost UDP/53, applies one shared `DnsAdmission` across its IPv4 and IPv6 listeners, calls `process_dns_query_with_admission()` with the peer source address, and restores the prior platform resolver before TUN or connection teardown. Localhost UDP exposes source-IP identity only, so all processes using one address share that bucket. Excess work is dropped before forwarding without a synthetic response; `ClientDnsRuntime::admission_snapshot()` exposes accepted, in-flight, rate, and bounded-identity counters. The embedded Engine and standalone TUN client use this owner when `enable_doh` is enabled.
- Endpoint resolution occurs before kill-switch connecting policy and before the local resolver changes. Invalid HTTPS endpoints, unsupported credentials/fragments, missing hosts, non-53 listener ports, and non-DoH client configs fail closed.
- The live server TUN path forwards intercepted DNS with plain UDP `forward_dns_query()` rather than this DoH helper. That server ownership model is intentional; `resolve_via_dns_upstreams()` shares the SERVFAIL-versus-upstream-response contract with the client proxy. One `DnsAdmission` now applies 128 concurrent blocking exchanges, a 2,000 PPS aggregate cap with a 4,000-query burst, and a 100 PPS per-identity cap with a 200-query burst. Authenticated MASQUE/TUN callbacks use `DnsAdmissionIdentity::Session`; helper boundaries without a session use `Source(IpAddr)`. Session and source state is removed on close, rebind, and expiry, while idle pruning and a hard 1,024-identity cap bound churn. `ServerConfig.dns_admission` validates optional `QUICFUSCATE_DNS_MAX_IN_FLIGHT`, `QUICFUSCATE_DNS_GLOBAL_PPS`, `QUICFUSCATE_DNS_GLOBAL_BURST`, `QUICFUSCATE_DNS_PER_CLIENT_PPS`, `QUICFUSCATE_DNS_PER_CLIENT_BURST`, `QUICFUSCATE_DNS_MAX_IDENTITIES`, and `QUICFUSCATE_DNS_BUCKET_IDLE_SECS` overrides. The aggregate budget is shared across sequential upstream resolvers; there is no per-resolver multiplication. Admission outcomes are exported through `quicfuscate_dns_intercept_admission_events_total`, while `quicfuscate_dns_intercept_dropped_total` remains the aggregate drop counter. Accepted `spawn_blocking` workers still have no runtime owner or terminal-outcome barrier; TODO-650 owns that lifecycle gap. TODO-669 supplies the shared 4,096-byte DNS message contract, 5-second aggregate DoH/UDP fallback deadline, bounded streamed DoH body, typed public input rejection, UDP oversize sentinel rejection, and non-blocking async plain-DNS boundary. DoH responses now require a response QR bit, standard opcode, exactly one bounded question, matching case-insensitive QNAME, raw QTYPE/QCLASS, and transaction ID; answer, authority, and EDNS sections remain opaque so valid compression and additional records pass through unchanged. The shared query gate now also requires a supported query flag set, exactly one question, bounded RFC name/pointer encodings, and preserves the exact question bytes plus raw QTYPE/QCLASS for synthetic responses. Server IPv4/IPv6 UDP/53 admission enforces exact packet lengths, rejects IPv4 fragments, validates IPv4 header and applicable UDP checksums, and requires the IPv6 UDP checksum. UDP response matching remains TODO-721; native Linux/TUN, Omega, and live publication proof remain separate gates.
- Forwarding uses the shared `DNS_MESSAGE_MAX_SIZE` limit of 4,096 bytes. DoH validates query size before request-body allocation, rejects an oversized `Content-Length`, and accumulates chunked bodies only while the same cap holds. Endpoint fallback shares one monotonic 5-second deadline. Plain UDP uses a 4,097-byte receive sentinel so any datagram above the 4,096-byte contract is rejected instead of returned truncated; resolver fallback uses the same aggregate deadline. The public async plain-DNS branch runs synchronous socket work in an owned `spawn_blocking` task under that deadline, so it does not block a Tokio worker. `benches/dns_forwarding.rs` records separate allocation counts and Criterion latency for client request/response buffers, server UDP receive allocation, and synthetic SERVFAIL construction. These transport guarantees do not include TODO-721 UDP transaction/question matching or native Linux/TUN, Omega, and live publication proof.
- Standalone client mode without TUN does not install an OS resolver owner. macOS uses the existing network-service backend; Linux and Windows receive the active TUN interface name through the platform DNS hook.

#### Async Stealth Scheduler (Non-Blocking)

The stealth timing system has been fully refactored to eliminate blocking `std::thread::sleep()`:
- `stealth::StealthManager::process_outgoing_packet()` returns `Option<Duration>` delay instead of blocking.
- `core::QuicFuscateConnection` is the single outbound timing owner via `next_packet_release: Option<Instant>`.
- `send()` checks `next_packet_release`; if `now < release_time`, returns `Ok(0)` (yield) without blocking the reactor.
- Transport stealth jitter (`stealth_timing_enabled` / `stealth_timing_max_jitter_us`) is merged into the same release deadline; `transport::Connection::send` no longer maintains a parallel gate.
- `RustlsProviderImpl::apply_profile_to_config()` records a profile-ready deadline instead of sleeping; `flush_handshake_io()` suppresses CRYPTO emission until that deadline expires, preserving the synchronous provider API without blocking an executor.
- When delay expires, clears the block and proceeds to flush `outgoing_fec_packets`.

#### Traffic-Analysis Defense Scheduler

`transport::Connection` owns one `TrafficAnalysisScheduler` deadline and one pending chaff slot for both enabled defenses:
- `FullPadding` pads every emitted 1-RTT packet to the current maximum UDP payload and uses independently jittered idle chaff at `chaff_rate_pps`.
- `ConstantRate` emits configured-size idle chaff at an exact phase-locked `constant_rate_pps` cadence. Missed deadlines advance to the next phase boundary without catch-up bursts.
- Real data, ACK-only output, control, recovery, and PMTU probes always take priority and consume a due cadence slot. Only application STREAM or DATAGRAM traffic extends the idle lifecycle, so cover ACKs cannot prevent soft stop. Congestion defers the single pending chaff slot without queue growth or packet-number gaps.
- `idle_timeout_ms` starts a bounded `ramp_down_ms` soft stop; real traffic reactivates the scheduler, while connection shutdown permanently cancels it.
- `QuicFuscateConnection::next_send_deadline()` merges the traffic-analysis deadline with outer pacing, stealth release, and QUIC recovery so live loops cannot oversleep the timer.
- An enabled policy logs its estimated maximum pre-IP/UDP wire cost. Packet size and cadence are bounded by the validated transport policy and current path UDP payload.

The active baseline comes from `[transport.traffic_analysis]`. `[transport.qkey_traffic_analysis_ceiling]` is an independent operator ceiling for per-QKey requests and remains inert until encrypted bearer authentication succeeds. `[transport.intelligent_traffic_analysis_ceiling]` controls post-authentication Intelligent level-2 escalation; its default `off` value is fail-closed. Failed or incomplete QKey authentication cannot activate either upgrade.

### Compression Module

The compression module (`src/compress.rs`) provides adaptive zstd payload compression with intelligent policy control:

#### Compression Core Components
- **`CompressionManager`**: Main compression orchestrator with CPU-profile aware zstd tuning (threads, target block sizes, long-distance matching)
- **`CompressionConfig`**: Configuration with minimum length thresholds and compression levels
- **`CompressionPolicy`**: Runtime policy control for adaptive compression decisions
- **`CompressionAnalysis`**: SIMD-powered preprocessing (ASCII/newline/null/high-bit counters + chunk hashing) feeding telemetry (`COMPRESS_PREPROC_*`) and influencing encoder tuning.
- Pool-backed compression writes compressed zstd frames directly into `MemoryPool` / body-pool blocks with `compress_to_buffer`, avoiding an intermediate compressed `Vec` copy while preserving H3 payload semantics and wire headers. The body pool uses the explicit `MemoryPool::new` contract, so its configured block size and effective allocation size match after the 2 KiB minimum clamp.
- H3 content-type compression uses the policy allow/deny lists centrally; explicit denies override allows, MIME parameters are ignored for matching, and payloads without a content type still require the textuality heuristic.

#### Supported Algorithms
- **zstd** only (levels 1-22), with optional dictionary training
  - Dictionaries trained from samples (best-effort) and cached on disk
  - Dictionary cache directory via `QUICFUSCATE_DICT_DIR` (default: `dict_cache/`)

#### Usage Example
```rust
use quicfuscate::compress::{CompressionManager, CompressionConfig};
use quicfuscate::optimize::OptimizationManager;

let mgr = CompressionManager::new(CompressionConfig::default());
let pool = OptimizationManager::new().memory_pool();
if let Some((block, used)) = mgr.compress_to_pool(&pool, payload) {
    // send &block[..used]
}
```

#### Adaptive Compression
- Decision gates combine length threshold, link speed, RTT and loss:
  - `min_len` (default 256 bytes)
  - Slow link heuristic (<10 Mbps) or high RTT (>80 ms)
  - Loss gate (<15% to avoid CPU burn during heavy loss)
- Lightweight textuality heuristic (`looks_textual`) uses `accelerate::count_ascii_printable` (SSE2/NEON) for the ASCII ratio and an entropy estimator.

#### Compression Telemetry
The module includes comprehensive metrics for performance monitoring:

- **Compression ratio tracking**: Real-time compression effectiveness metrics
- **Algorithm performance**: Per-algorithm timing and efficiency measurements
- **Dictionary effectiveness**: Metrics on dictionary-based compression gains
- **Adaptive decision logging**: Track decision-making process for optimization

Compression telemetry is tracked via global atomic counters in `optimize::telemetry`:
```rust
use quicfuscate::optimize::telemetry;

let text = telemetry::export_telemetry_text();
// Contains COMPRESS_ATTEMPTS, COMPRESS_SUCCESS, COMPRESS_BYTES_IN, COMPRESS_BYTES_OUT
```

### Performance Architecture & Hardware Acceleration

#### SIMD Feature Detection & Dispatch
CPU feature detection is centralized, but the current-source audit found that several call sites still need exact compile-time/runtime subfeature intersections before the acceleration surface can be treated as fully proven:
- **x86_64**: RDRAND, RDSEED, AES-NI, VAES, PCLMULQDQ, SSE2, SSSE3, AVX, AVX2, FMA, AVX512-F/CD/BW/DQ/VL, GFNI
- **aarch64**: AES, PMULL, SHA2, SHA3, NEON, SVE (autodetect), SVE2
- **Feature mapping to CPU profiles**:
  - `X86_P0`: SSE2, AESNI
  - `X86_P1a`: SSE2, AESNI, PCLMULQDQ
  - `X86_P1b`: +AVX, RDRAND, RDSEED
  - `X86_P1f`: +F16C
  - `X86_P2a`: +AVX2, BMI1/2, LZCNT
  - `X86_P2b`: +RDRAND, RDSEED, FMA
  - `X86_P3a`: AVX512F profile base; AVX512BW, AVX512VL, AVX512VNNI, AVX512VBMI2, AVX512VPOPCNTDQ, AVX2, and other subfeatures are independent checks
  - `X86_P3b`: VAES and VPCLMULQDQ profile route
  - `X86_P3c`: AVX512VBMI2 profile route
  - `X86_P3d`: AVX512VPOPCNTDQ profile route
  - `X86_P3e`: GFNI profile route (AMX is detected independently and is not part of the current x86 profile selection; TODO-819)
  - `X86_P4a`: +AVX10.1-256 (internal preview gate `internal_avx10_preview`; inherits AVX2/AVX-512 kernels, telemetry `SIMD_USAGE_AVX10_256`)
  - `X86_P4b`: +AVX10.1-512 (internal preview gate `internal_avx10_preview`; inherits AVX-512 kernels, telemetry `SIMD_USAGE_AVX10_512`)
  - `ARM_A0`: NEON, AES, PMULL
  - `ARM_A1a`: +SHA2
  - `ARM_A1b`: +SHA3
  - `ARM_A1c`: +SVE
  - `ARM_A1d`: +SVE2
  - `ARM_A2`: +SVE-BF16

- **PMULL**: Polynomial multiplication for GHASH

```rust
use quicfuscate::optimize::{SimdPolicy, Avx512Gfni, Sve2};

// Central feature detection and dispatch: selects optimal code paths per CPU (x86: SSE2/AVX2/AVX-512; ARM: NEON), with safe scalar fallbacks
let policy: Box<dyn SimdPolicy> = if cpu_supports_avx512gfni() {
    Box::new(Avx512Gfni)
} else if cpu_supports_sve2() {
    Box::new(Sve2)
} else {
    Box::new(Scalar) // Safe fallback
};
```

#### SIMD Gap Status
 - **Crypto (Poly1305 wide reduction ARM)**: Done - `mac_sve2_block_wide` provides the 256-bit carry chain on `ARM_A2`/Apple M.
 - **FEC (large-window decode acceleration)**: The active Wiedemann path uses a checked scalar GF(256) SpMV fallback. The former raw AMX staging and unverified INT8 kernels are removed because they did not perform GF(256) arithmetic and had no proven tile contract; TODO-818 owns a future real AMX arithmetic backend and proof lane. Planner/detector, profile, and broader tile-ownership boundaries remain under TODO-676, TODO-817, and TODO-819.
 - **Utility (RVV)**: Infrastructure for RISC-V Vector (`RVV`) and additional iterator backends are not active in the current build.
 - **SIMD safety (TODO-593)**: x86 GF(256) matrix kernels validate dimension products in debug builds, BMI2 varint encoding validates its required output capacity, AVX2 header dispatch avoids a discarded 32-byte load by delegating to the scalar first-byte check, and scalar/NEON/GFNI Reed-Solomon encoders zero-pad partial input shards instead of truncating them. Windows-only SHA-256 compression stubs fail loudly if reached. TODO-835's boundary audit confirmed that the matrix and BMI2 checks remain debug-only, the SSE4.2 short-needle path can load sixteen bytes for a shorter slice, and Berlekamp-Massey accepts an unchecked length; release-safe remediation and malformed-input proof remain open.
 - **SIMD Reed-Solomon compatibility path (TODO-594)**: standalone x86 AVX2 and GFNI Reed-Solomon encode/decode now use the canonical GF(256) generator, full augmented-matrix inversion, dynamic per-coefficient nibble LUTs, release-safe shard metadata validation, and scalar tails for non-vector-aligned shards. Rosetta-executed x86 tests cover AVX2/GFNI roundtrips and the AVX2 matrix kernel. These helpers remain internal/test-only; production FEC stays on `src/fec/`. TODO-679 confirmed the old AVX2-to-GFNI delegation claim is stale. Remaining SIMD dispatch, bounds, and proof work is TODO-834 through TODO-836, with the completed FEC audit in TODO-686, GF16 polynomial correctness in TODO-715, and FEC-specific SIMD remediation in TODO-855.

#### Accelerate Module (Re-export)
`accelerate.rs` is now a thin re-export layer for the optimize submodules. All implementation lives under `src/optimize/` while the public API stays stable under `accelerate::*` paths.
The accelerate surface now re-exports only retained acceleration primitives across subsystems, with runtime-owned versus compat/test-only boundaries made explicit below:

##### Network I/O Acceleration (transport_io submodule)
- **UDP GSO/GRO**: retained runtime/compat helper surface for reduced syscall overhead on the active UDP fast-paths
- **sendmmsg/recvmmsg**: runtime-owned Linux batching in `src/optimize/udp.rs`, with `udpfast` reduced to a narrowed compat/harness boundary
- **sendmsg_x (macOS)**: retained macOS batching helper with explicit fallback to per-message `sendmsg`
- **NIC Parallelism**: compatibility-oriented tuning helper, not a separately wired canonical runtime subsystem

Normal product builds do not expose a broad `accelerate::transport_io` consumer API. The active
runtime owner for UDP GSO policy is `src/optimize/udp.rs`, while Rust parity/test
builds retain explicit compatibility access for transport helper coverage.

##### Random Number Generation (random submodule, test/compat surface)
- **Hardware-assisted random helpers**: test/compat-only helper paths now use a secure-seeded non-security per-thread PRNG and are not the canonical security API.
- **Vectorized random generation**: fill arrays faster for parity/heuristic workloads only
- **Central secure entropy API**: `src/rng.rs` is the canonical fail-closed path for security-critical bytes/nonces/tokens.
- **Policy split**:
  - `security-critical`: use `rng::fill_secure`, `rng::fill_secure_or_abort`, `rng::secure_hex`.
  - `transport-security-critical`: use `transport::rand::rand_bytes`, `rand_u8`, `rand_u64`, or `rand_u64_uniform` for connection IDs, path challenges, and transport security material.
  - `transport-heuristic`: use `transport::rand::fast_rand_u64` or `fast_rand_u64_uniform` only for non-security hot-path padding, cover, and timing decisions.
  - `heuristic/perf`: use `accelerate::random` helpers only for randomized heuristics and SIMD-heavy utility paths.

```rust
use quicfuscate::rng;

// Secure random bytes
let mut buf = [0u8; 32];
rng::fill_secure_or_abort(&mut buf, "docs-example-secure-bytes");

// Security-critical tokens/nonces use centralized fail-closed entropy API
let token_hex = rng::secure_hex(32, "docs-example-token");
```

`accelerate::random` remains available only for compatibility tests and SIMD parity coverage. It
does not expose a canonical entropy alias anymore. Its helpers now use a secure-seeded, non-security
per-thread PRNG for heuristic/test workloads, while the canonical runtime entropy contract lives in
[`src/rng.rs`](/Users/christopher/CODE/QuicFuscate/src/rng.rs).
On AArch64, the retained optimize-random contract is limited to `rust-tests`/test helper surfaces
and is not part of the canonical runtime entropy contract.

`transport::rand::fast_rand_*` is the production hot-path exception for transport-local stealth
heuristics. It is seeded once from secure transport entropy per thread, then uses a non-cryptographic
SplitMix64 stream to avoid repeated OS RNG calls in per-packet padding and jitter decisions.

##### Sorting Acceleration (sort submodule)
- **Sorting parity helpers**: `u32` uses Rust's canonical `sort_unstable`; architecture-specific `f32` and argsort helpers retain explicit parity coverage. The removed x86 `u32` kernels shifted bits inside values instead of permuting lanes and were not valid sorting networks.
- **Argsort**: Index-based sorting retains architecture-specific small-slice helpers and a canonical fallback.

These sorting helpers are retained only for `rust-tests`/test parity coverage. They are not part
of the normal product-facing API surface.

##### String Acceleration (string submodule)
- **Fast string search**: ~10x faster via AVX512 bitmap (x86) or SVE2 predicates (ARM)
- `string_contains(...)` is the runtime-owned string acceleration entrypoint used by the active stealth path.
- UTF-8 validation, integer parsing, and base64 encode/decode SIMD helpers are retained for regression/parity coverage under `cfg(any(test, feature = "rust-tests"))`.

This helper remains runtime-owned by the active stealth path. It should be read as an internal
runtime acceleration entrypoint, not as a broad consumer-facing `accelerate::*` API contract.

##### Brain Acceleration (brain submodule)
- **AVX2/FMA/SVE2 statistical computations**: 4-5x faster mean, variance, correlation
- **Matrix multiplication**: AVX512F on x86 and dedicated SVE2 Gather/`svmla` on ARM; no current AMX arithmetic caller is proven (TODO-818, TODO-819)
- **Apple Silicon AMX**: capability metadata exists in CPU detection, but an active matrix kernel and proof lane are not established (TODO-819)
- **Moving averages**: AVX-512/AVX2 (x86) & NEON (ARM/Apple M) sliding windows with telemetry-tracked scalar fallback
- **Histogram decay & Jensen-Shannon divergence**: x86 uses AVX-512/AVX2/SSE4.1 fixed-point pipelines, ARM uses NEON/SVE2; backend selection is visible via `BRAIN_HISTOGRAM_{AVX512,AVX2,SSE,NEON,SVE2,SCALAR}_OPS`, and parity is validated by `scripts/tests/rust/rt-brain-histogram.rs` and `scripts/tests/rust/rt-simd-selfcheck.rs`.

The `accelerate::brain` helpers are retained as internal runtime owners plus explicit Rust parity
surface under `cfg(any(test, feature = "rust-tests"))`. The canonical product contract is the
StealthBrain and telemetry/runtime behavior, not a broad external math API.

##### Iterator Reductions (iter submodule)
- **SIMD-backed sums**: `sum_f32`, `sum_u32`, `sum_u64` dispatch across AVX-512/AVX2/NEON with scalar fallback and telemetry (`ITER_SUM_*`).

`accelerate::iter` is likewise retained for internal runtime ownership and explicit Rust parity
coverage, not as a normal consumer-facing API promise.

##### Stealth Acceleration (stealth submodule)
- **Accelerated string operations**: SIMD-optimized string processing for header manipulation
- **Fast pattern matching**: High-speed pattern matching for header field detection
- **Optimized encryption routines**: Accelerated cryptographic operations for obfuscation
- **Persona cookies & referers**: `AsciiSimdBackend` orchestrates SSE2/AVX2/NEON decimal/hex formatter LUTs and bulk copies so `Http3Masquerade::generate_realistic_cookies_at` / `generate_realistic_referer_for` assemble strings without scalar push-loops while preserving deterministic fallbacks.
- **Persona header templates**: `Http3Masquerade::generate_headers` applies `PersonaTemplate` batches (Safari/Firefox Title-Case & Chrome/Edge Chromium stack) using `AsciiSimdBackend` + `Header::from_parts` to eliminate per-header `Vec::push` loops.

##### Transport Acceleration (transport submodule)
- **Optimized packet processing**: High-speed packet serialization/deserialization
- **Accelerated frame handling**: SIMD-enhanced frame encoding/decoding
- **ACK-Range Merging**: `transport::frames::canonical_ack_blocks` uses a VL-scaling SVE2 merge kernel (predicate + `svmaxv_u64`) on ARM_A2; all other profiles use the proven scalar path.
- **Varint/Header Dispatch**: `transport::pn::{write_varint,read_varint}` and `simd::transport::validate_header` prioritize AVX-512 -> AVX2 -> SSE2 (x86) or SVE2 -> NEON (ARM) and retain the existing error paths.
- **Fast connection management**: Optimized connection state handling

##### Memory Acceleration (memory submodule)
- **Fast allocation/deallocation**: Optimized memory management routines
- **Cache-efficient allocators**: Memory allocators optimized for cache locality
- **Batched operations**: Optimized batch memory operations
- **Workload-local prefetch**: retained only in selected crypto/FEC/transport hot paths where ownership stays explicit
```

#### Memory Pool Architecture
- **Zero-copy memory pools**: Reduces allocation overhead and improves cache locality
- **NUMA-aware allocation**: Optimizes for multi-socket systems with node affinity
- **Huge page support**: 2MB/1GB page allocation for reduced TLB pressure
- **Thread-local caches**: Minimizes contention on high-concurrency systems
- **Workload-local prefetch**: retained only where the hot-path owner still justifies it

```rust
use quicfuscate::optimize::MemoryPool;

// Create a pool with an explicit block-size contract
let pool = MemoryPool::new(1024, 65536); // 1024 blocks of 64 KiB each

// Use MTU-based sizing only through the explicitly adaptive constructor
let packet_pool = MemoryPool::new_adaptive(512, 65536);
```

#### Zero-Copy Memory Architecture

**Memory Pool:**
- Zero-copy memory pool with tunables (`--pool-capacity`, `--pool-block`)
- NUMA-aware allocation with node affinity
- Huge pages support (2MB/1GB) for TLB optimization
- Thread-local caching to minimize contention
- `MemoryPool::new(capacity, block_size)` preserves the requested block size subject only to the 2048-byte minimum; every returned block has the effective `block_size()` length.
- `MemoryPool::new_adaptive(capacity, block_size)` is the separate MTU-based packet-pool constructor. `global_pool()` and the default `OptimizationManager::new()` use this adaptive path; configured engine pools and `body_pool()` use the explicit path.
- Minimum block size is clamped to 2048 bytes for safety; mismatch-sized blocks are dropped on return to preserve invariants.
- The process-wide auto-tuner owns a stop flag and join handle; callers can terminate it explicitly with `MemoryPool::shutdown_auto_tuner()` and the stop path wakes the parked thread immediately.
- Unsafe pool copies require a live, aligned block pointer owned by the pool, validate the block-length bound through a bounded destination slice, and document non-overlap and lifetime invariants.

**Compatibility/Test Utility Structures:**
- `ConstPacketPool` plus its `ConstBuffer` contract remain available only in test and `rust-tests` builds for external regression coverage.
- The old aligned-scratch and lock-free helper cluster in `src/optimize/` is removed from the retained optimize surface because it has no canonical runtime owner in this fork.
- `optimize::memory::transpose_matrix(...)` remains retained as explicit rust-test parity surface, while orphan memory/string utility exports with no runtime or external test owner have been removed.
- `optimize::memory::LockFreeRingBuffer` remains retained only because it still has explicit rust-test parity ownership; the old helper exports for random prefetching, cache-aligned scratch allocation, cache-line clearing, and NUMA-local scratch allocation are removed from the retained surface.
- In `optimize::stealth`, `AsciiSimdBackend` remains the runtime-owned ASCII formatting owner used by persona/header generation, while the old free wrapper functions and perf-smoke shell around it have been reduced or removed because they had no independent runtime or external rust-test owner.
- In `optimize::transport`, `aggregate_congestion(...)` remains the only retained runtime-owned entrypoint, while the old orphan ACK-range search and stream-frame parsing utility surface has been removed; the remaining bitmap/ECN/packet-number helpers stay only as explicit parity/test surface.
- In `optimize::brain`, `decay_histogram(...)` and `jensen_shannon_divergence(...)` remain runtime-owned through `src/brain.rs`, while moving-average, percentile, and activation helpers remain explicit parity/test surface; the old standalone statistics, correlation, and matrix-multiply helper shell has been removed from the retained optimize contract.
- The SVE2 Jensen-Shannon implementation uses a bounded eight-lane stack workspace and limits each predicate to that workspace; it does not allocate a per-call heap buffer.
- `optimize::sort` is no longer part of the normal optimize product surface in non-test builds; `sort_u32(...)`, `sort_f32(...)`, and `argsort(...)` remain available only as explicit rust parity helpers through `cfg(any(test, feature = "rust-tests"))`.
- Windows SIMD correctness is guarded by native `windows-latest` check, parallel test, and Clippy stages. Proof job `88909613077` on `15570abf772766c76959f6aae6ba16b2b9c26fd7` passes Berlekamp boundary parity, canonical u32 sort parity, and all other native core gates.
- In `optimize::telemetry`, the retained public helper surface is limited to the real runtime/export owners such as `export_telemetry_text(...)`, `publish_cpu_profile_mask(...)`, `update_memory_usage(...)`, and `flush(...)`; the old duplicate snapshot helper `telemetry_snapshot_text(...)` has been removed because it had no owner outside the module itself.
- In `optimize::string`, only the real runtime helper `string_contains(...)` and explicit parity-only Base64 helpers remain retained; the old UTF-8-validation and integer-parse helper shell has been removed because it had no runtime or rust-test owner.
- In `optimize::stealth`, only the runtime-owned ASCII/persona path plus explicit parity/test helpers like `inject_pattern(...)`, `add_tls_padding(...)`, `gfni_padding_bytes(...)`, and `generate_fake_hmac(...)` remain; the old entropy-mixing, header-generation, and traffic-shaping helper shell has been removed as ownerless surface.
- The canonical runtime path uses `MemoryPool` plus server/client/transport-owned queues instead of exposing separate packet-pool and lock-free queue primitives as normal product APIs.

#### Platform-Specific Optimizations
- **Linux**: io_uring for async I/O and shared `sendmmsg` batching fallback
- **Windows**: WSASend with scatter-gather, IOCP
- **macOS**: kqueue, Grand Central Dispatch
- Batched processing keeps hot loops in cache
- AF_XDP runtime wiring is retained only behind the internal feature gate `internal_af_xdp_experimental`.
- Legacy AF_XDP socket code is kept behind the internal feature gate `internal_af_xdp_experimental` and is not part of the default production runtime path. Explicit feature-enabled release compilation remains possible, and its UMEM/ring ownership contract is open under TODO-838.
- `OptimizationManager` no longer models live AF_XDP runtime availability as mutable instance state in this fork; there is no separate `available` or `enabled` XDP runtime query surface anymore.
- Optional io_uring UDP Fast Path (Linux, feature `io_uring`) uses `UringBatchSender` in `src/optimize/uring_batch.rs` with the official `io-uring` crate (v0.7). Every public sender call admits at most 256 packets and 524,288 aggregate payload bytes before payload copies. Direct `UringBatchSender` calls remain explicitly synchronous compatibility primitives; client and standalone server runtimes use one bounded `UringBatchWorker` per runtime, with one queued request, one owned blocking thread, a 250 ms controlled completion deadline, quarantine on timeout/cancellation, and a joined teardown. The runtime worker disables SendMsgZc so notification CQEs cannot outlive its operation owner; worker-busy requests fall back to `sendmmsg`/async socket sends, while worker failures become typed data-plane faults rather than unsafe duplicate retries.

#### Prefetch and Memory Optimization
The accelerate module includes sophisticated prefetch and memory optimization techniques accessible through the transport I/O submodule:

- **Adaptive prefetching**: Adjusts prefetch distance based on memory access patterns
- **Cache-aware algorithms**: Optimize data layout for L1/L2/L3 cache efficiency  
- **Non-temporal stores**: Bypass cache for large data copies to avoid cache pollution (ARM NEON implementation)
- **Memory access pattern prediction**: Predicts and preloads data based on access patterns

The retained transport I/O acceleration helpers should be treated as internal runtime mechanics or
Rust parity surface. They are no longer presented as a general-purpose public memory-tuning API.

### TUN Interface (Cross-Platform)

The `interface.rs` module provides a high-performance, cross-platform TUN interface that integrates with QuicFuscate's memory pool for zero-copy I/O.

#### Capability & fastpath runtime API

Runtime probing should be performed before starting client/server data paths:

- `tun_capabilities()` reports whether built-in backends are available, whether an external factory was registered, and whether zero-copy/FD-level features are supported on the active platform.
- `validate_tun_runtime_requirements()` returns early, actionable startup errors when no usable TUN backend exists for the current build/runtime combination.
- `FastpathMode` is selected via `QUICFUSCATE_FASTPATH=auto|off`.
- Linux outbound dispatch is deterministic: `OutboundDispatch::IoUringBatch` (when feature `io_uring` is enabled and the runtime-owned `UringBatchWorker` initialised successfully) submits the full batch through the bounded blocking owner; a busy worker falls back to `sendmmsg` batching, then per-packet socket fallback, while an operation timeout/failure terminates the data-plane owner instead of replaying an ambiguously completed batch.
- The shared `try_sendmmsg_batch()` helper matches every dispatch variant. An accidental `IoUringBatch` call returns an explicit error instead of reporting zero sends, preserving the io_uring sender as the only owner of that dispatch path.
- Linux `SystemIoHotpathAdapter` performs one-time batch socket capability initialization on first `sendmmsg` use via the hidden runtime helper `transport::init_socket_acceleration`, keeping runtime hotpath independent from the test-only `transport::batch::BatchProcessor` surface.

#### Platform-Specific Implementations

**Linux (`LinuxTun`):**
```rust
pub struct LinuxTun {
    name: Arc<str>,
    fd: RawFd,
    mtu: AtomicU16,
}
```
- TUN device creation via `ioctl(TUNSETIFF)` with IFF_TUN | IFF_NO_PI flags
- Requested names are rejected before `TUNSETIFF` when empty, invalid, or longer than 15 bytes; the kernel-returned name must equal the requested name.
- Direct file descriptor I/O via `libc::read`/`libc::write` with EINTR retry
- The descriptor is switched to nonblocking mode after `TUNSETIFF`; async and threaded
  runtime loops treat `WouldBlock` as an idle poll, not as a fatal teardown signal.
- Every post-`TUNSETIFF` setup failure closes the owned descriptor and removes only the exact owned interface, reporting rollback failure together with the primary failure.
- No intermediate buffering
- MTU configuration is applied and read back from the live device; link-up and configured IPv4/IPv6 address/prefix are inspected before readiness.

**macOS (`MacTun`):**
```rust
pub struct MacTun {
    fd: RawFd,
    name: Arc<str>,
    mtu: AtomicU16,
}
```
- utun device creation via `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
- 4-byte AF header handling with `libc::readv`/`libc::writev` using iovecs
- Scatter-gather I/O eliminates header copying
- Control socket configuration via `ioctl(CTLIOCGINFO)`
- IPv4/IPv6 addresses, link-up, and MTU are configured before the descriptor is published; MTU updates are read back from `ifconfig`.
- Descriptor ownership remains armed until all configuration succeeds, so intermediate failures close the utun socket.
- The current unsafe audit found that the shared data-plane owner still needs
  explicit `readv` result bounds, `writev` zero-progress handling, and a
  bounded kernel-reported interface-name contract; these are remediation
  owners TODO-844 and TODO-845, not closed guarantees.

**Windows (`WintunDevice`, feature `tun-windows`):**
- Dynamically loads the upstream `wintun.dll` only from the executable directory or protected System32 search directory.
- Creates and owns the adapter and session, captures the stable adapter LUID, and configures IPv4/IPv6 addresses and active MTU.
- Uses Wintun's session-owned read event plus a device-owned shutdown event. Operation-lifetime synchronization wakes blocked reads before session, adapter, event, and DLL teardown.
- Distinguishes empty-ring, terminating-session, corrupt-ring, full-send-ring, and raw Win32 errors without polling or packet truncation.
- The current unsafe audit confirms receive-buffer bounds but leaves failed
  event/library cleanup, early Drop failure, and unsafe Send/Sync proof open
  under TODO-846. Historical native lifecycle evidence does not close those
  injected-failure cases.
- `scripts/utils/provision-wintun.ps1` downloads upstream Wintun 0.14.1, verifies archive SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, verifies AMD64 DLL SHA-256 `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`, requires a valid Authenticode signature, and refuses to overwrite a different destination file. No DLL blob is tracked.
- Ignored native tests create a dual-stack adapter, verify name/LUID/IPv4/IPv6/MTU/capabilities, transfer UDP payloads through both Wintun directions, force close against a blocked read, repeat open/close, and require zero adapter and test-firewall residue. The WFP gate drives IPv4 and IPv6 UDP probes through the real adapter and distinguishes synchronous access denial from silent packet discard by observing the Wintun ring directly. A child test installs the persistent block policy and exits without cleanup; the parent proves the retained IPv4/IPv6 block, invokes exact stale cleanup, proves restored packet delivery, and requires zero managed-object residue. The required `windows-core-checks` job provisions the verified DLL and executes this suite serially as administrator.
- Local Windows-GNU compilation and product Clippy prove the complete feature-gated Rust surface. Native CI run `30508948149`, job `90764941801` proves commit `afe46e0` on Windows Server 2025 build 26100: MSVC check and test linking, verified upstream Wintun provisioning, 1,931 ordinary tests, privileged adapter/data-plane/close lifecycle, IPv4/IPv6 WFP block, exact endpoint and Wintun-LUID exceptions, disconnect re-block, disable, process-exit retention, stale cleanup, zero managed WFP/adapter/firewall residue, and strict Clippy all pass. Evidence artifact `8746497146` contains `windows-runtime.json` SHA-256 `c9cfc32edab53399171899d527669a95bde41500b3a663b0b62a6315cc7b2a82`, `wfp-residue.json` SHA-256 `dea515b9d6e4831f59387173c26553a23d62a8615ac8038d67f74f939a1d9326`, and `wintun-provenance.json` SHA-256 `32c5af70acfd8842f1cfed2c158e0ca95607d25cae548b33bfb69cfbd6142943`.
- Release run `30533862566`, Windows job `90842338800`, proves the signed `dc72c845699c842d2e11360f35a7e99dd82583a6` MSI path. Artifact `8756518338` has archive digest `f3603ed697054f1547022bc5f34740d9bacfed62594c12a0f73a227da9ff9d25`; `QuicFuscate_0.4.3_x64_en-US.msi` has SHA-256 `09cf1f186df1f7898d8d1c2152f76a84bbe4db32e6a2dc157874ee24671920be`, its updater signature has SHA-256 `d4669f68a2ea322cc8d0651b572644a2aa8a35f4239a43059929c6ea9fa7ecb2`, and the retained provenance has SHA-256 `b164dded0cb9d0a6ff06a593ee035bbfc3a0774d60ef40aadd3bbddf2531e70e`. Administrative extraction found exactly one packaged Wintun DLL with the pinned upstream hash.
- Authenticated Windows-to-Omega runs `30535603045` and `30536002374` prove exact source `281c629748e0fe7d9cceee03fa9119c17c0d0f1f` twice consecutively against unchanged ARM64 server PID `1158967`, binary SHA-256 `36bdb100744772755988248c59605f69f81d9cf1bc8304d090a225a6b4d69a03`, with zero restarts. Each run completed QUIC v2 TLS, encrypted QKey authentication, MASQUE CONNECT-UDP, connected WFP, five IPv4 and five IPv6 tunnel pings, stale cleanup, zero managed WFP objects, zero Wintun adapters, and zero raw-QKey log residue. Result/progress SHA-256 pairs are `1257282285df6bb5c251d92a710953a6dcdd71c439ba66e4509ad366e945ceb4` / `72370af95c9c759cd610ade36744869d6cbcd29cc590157674b57d84f7eb9a27` and `959dd80fab0c2b89162bcaf4bb85fc4a5e9920e19ea2ab82a96d28c62e002fb3` / `10c224782aec17953e0574b77cdab167d54f17b12ba91b4f49cf0a37bc78cad9`. This closes TODO-528's authenticated tunnel, same-process stability, cleanup, and signed-artifact boundaries.

**iOS:**
- External TUN factory pattern via `OnceLock<Box<dyn TunDeviceFactory>>`.
- Platform-specific NetworkExtension implementation is injected at startup.
- Missing factory registration returns a clear configuration error.

#### Shared TUN contract and server platform boundary

- `TunConfig.ip` and `TunConfig.netmask` are one all-or-none IPv4 pair. `TunConfig.ip6` and `TunConfig.prefix6` are one all-or-none IPv6 pair; no backend supplies an implicit address prefix or netmask.
- IPv4 TUN MTU must be at least 576 bytes. An IPv6-enabled TUN must remain at or above 1280 bytes for initial configuration and every live update.
- A registered external factory must apply or already expose the requested MTU and report the exact value before `TunInterface::open` publishes the device.
- `TunInterface` publishes a new MTU only after the backend reports the requested value. Backend and client provisioning errors preserve command spawn, exit status, and diagnostics; exact idempotent postconditions are inspected instead of treating arbitrary failures as duplicates.
- `TunDevice::read_contract()` makes executor ownership explicit. Native Linux and macOS descriptors publish `NonBlocking`; external/custom backends default to `Blocking` and the generic client `IoDriver` rejects them before entering its async outbound loop, so they must use an owned reader boundary. Generic read lengths and short writes remain open under TODO-844.
- Client TUN provisioning rolls back the owned descriptor/interface on every failure after creation. Server Linux routing rejects an IPv4 or IPv6 address already owned by another interface, verifies TUN addresses, prefixes, link-up state, forwarding, and the selected firewall rules before readiness, then rolls back only mutations recorded as owned.
- Shipped server TUN mode is Linux-only. The embedded and standalone server runtimes reject server TUN mode on macOS, Windows, and other platforms before host mutation because those platforms do not yet have a shipped native server routing owner and proof. `RoutingManager::setup()`, `cleanup_stale()`, and `teardown()` also fail closed with `UnsupportedPlatform` on macOS and Windows; those builds retain only pure rule/script generators for tests and future native work. macOS, Windows, and iOS remain client-side TUN platforms through their respective native or external-factory paths.
- Linux routing writes an atomic 0600 ownership record under `/run/quicfuscate/routing/` before the first address, link, or forwarding mutation. Both embedded and standalone startup run `cleanup_stale()` before opening a new TUN, including all persisted records when the standalone CLI lets Linux choose the interface name, so a process-loss restart cannot collide with a newly allocated ifindex. The record binds the requested configuration to the original Linux TUN ifindex and the owning boot ID, PID, and `/proc` start time. Startup `cleanup_stale()` refuses an active owner, rejects boot-identity changes, validates the interface identity, restores only recorded before/after states, preserves externally changed forwarding or interface state, treats a disappeared TUN as already absent, and retains the record when any recovery step fails. Graceful teardown removes the record only after all owned host-state postconditions and firewall cleanup succeed.

#### TUN/MASQUE Backpressure and Packet Ownership

- TUN frames are not consumed from the reader channel until the QUIC DATAGRAM carrier has accepted them (`ConnectionError::DgramQueueFull` is the only retried condition; terminal errors become typed data-plane faults and the frame is released only at the terminal owner boundary).
- `transport::connection::dgram_send` returns `ConnectionError::DgramQueueFull` when the fixed DATAGRAM send queue is at capacity, preserving the original error class through `transport::h3::send_masque_datagram` and `core::{send_tunnel_packet, send_masque_downlink}`.
- Framed H3 fallback is used only for packets that exceed the confirmed MASQUE MTU or for states where it is semantically valid; it is never used as a reaction to transient DATAGRAM pressure.
- Client uplink: `main.rs` holds a single `tun_backpressure_frame` and retries it before reading new frames from the TUN reader channel.
- Server downlink: `src/implementations/server/mod.rs` defers queue-full packets in `LiveServerState::pending_tun_downlinks` and retries them each housekeeping tick before new TUN reads. Admission is bounded to 256 packets, 384 KiB, and 32 packets per target; entries expire after 5 seconds, follow a QUIC path migration to its new remote address, and have explicit capacity, timeout, terminal-error, and shutdown outcomes.
- Server telemetry exports `quicfuscate_tun_downlink_backpressure_pending_{packets,bytes}` plus `quicfuscate_tun_downlink_backpressure_events_total` for enqueue, retry, and exact terminal-drop causes.
- TUN retry admission and its metrics update share one helper, so packet-, byte-, and per-target-capacity rejection cannot occur without an exported cause. A deterministic intentional-overload regression drives all three rejection paths plus MASQUE response packet-capacity rejection and verifies unchanged bounded ownership.
- Server-generated MASQUE DNS and ICMP responses use a separate bounded FIFO of 128 packets or 192 KiB per connection. A `DgramQueueFull` response remains in a connection-owned retry slot ahead of later responses, while packet-capacity, byte-capacity, terminal-send, and shutdown outcomes are exported as `quicfuscate_masque_downlink_response_events_total`. DNS interception additionally owns every blocking resolver task through `DnsInterceptWorkerOwner`; admission closes before drain, response publication is serialized against that close, and worker lifecycle outcomes are exported separately through `quicfuscate_dns_intercept_worker_events_total`.
- The three-client dual-stack harness fetches metrics after the default and opt-in TCP phases. Both pending-depth gauges and both TUN/MASQUE event-counter families must exist and remain zero, making an unobserved queue backlog or retry/drop event a hard failure.
- TUN reader lifecycle: `TunInterface::reader_loop_with_shutdown()` checks an atomic shutdown flag and waits for Unix descriptors with bounded `poll(2)` instead of a 1 ms sleep. The client uses `reader_loop_with_shutdown_owned()` to transfer pool-backed `TunPacket` blocks through its bounded channel without a per-packet `Vec` copy; packet ownership returns the block to the originating pool after carrier acceptance or terminal drop. Client and standalone server runtimes publish cooperative shutdown before dropping the bounded receiver, wake the native reader where required, join the owned `JoinHandle`, and release the descriptor only after the reader exits. `Notify` wakes the event loop when a frame or terminal fault is published.
- Data-plane fault taxonomy: `engine::DataPlaneFault` distinguishes unexpected reader termination, channel disconnect, TUN write failure, transport-send failure, and transport-receive failure. Client runtime fault slots are first-wins and feed the watchdog, `DisconnectReason::DataPlane`, cleanup, `EngineStats.data_plane_ready`, and `EngineStats.data_plane_faults`; the standalone client and server loops preserve the same primary fault through their exit/cleanup result.
- Data-plane readiness and health: connected/QUIC liveness is separate from TUN readiness. Client runtime stats report the owned fault counter and availability, while server metrics expose `quicfuscate_tun_data_plane_ready`, `quicfuscate_tun_data_plane_faults_total`, and `tun_data_plane_ready` in JSON health; a server TUN fault makes health `not_ready` until a new runtime owns a healthy data plane. Deliberate shutdown is excluded from fault telemetry.
- Client IO allocation ownership: `IoDriver::flush_outbound()` receives a loop-owned 65,535-byte buffer, and Linux outbound dispatch reuses one batch-reference vector sized to the normalized batch capacity. The live server outgoing staging path remains bounded by `UDP_DATAGRAM_BURST_LIMIT` (64), while public `UringBatchSender` and `UringBatchWorker` admissions enforce the 256-packet/524,288-byte cap before their respective sender-owned copies. Runtime io_uring sends cross one bounded worker queue and retain their owned request payloads until a controlled completion, quarantine, or joined shutdown. Blacklist refresh is an async HTTPS operation dispatched from housekeeping via `tokio::spawn`.
- Adaptive runtime polling: `QuicFuscateConnection::next_send_deadline()` returns the earliest outer-pacer release, stealth release, or recovery/PTO deadline, so the generic I/O driver does not oversleep an outer-pacer release. Standalone client and server housekeeping use `MissedTickBehavior::Skip`, run at a 5 ms active floor, and back off to a 250 ms idle interval while retaining deadline, heartbeat, queue, and TUN-notification wakeups. Native Linux CPU/TUN acceptance remains an external privileged gate.
- Standalone client liveness: when `heartbeat_timeout_ms` is nonzero, the existing housekeeping owner queues an ack-eliciting QUIC PING every third of the watchdog window. A responsive peer therefore advances inbound activity before the fail-closed deadline without adding a parallel scheduler. The native TCP and UDP harnesses reject retained heartbeat timeouts, `InternalError`, and TUN-send failures even when payload checks otherwise pass.
- Current exact final-source ARM64 liveness and performance proof uses binary SHA-256 `e09cad15ef86ea79a074bf1daff93615a97e9078d8786e346ac77b6f5d82f580`. The three-client TCP matrix completed byte-exact default/opt-in medians of 6.939/11.326 Mbit/s, a 63.21% PMTU gain, and a 26,017,792-byte black-hole recovery transfer in 20.420 seconds. The matched UDP matrix retained 99.71% throughput with Auto FEC versus 94.94% with FEC Off; combined RSS was 284.3-284.4 MiB, one-core CPU 12.70-17.21%, p95 latency 35.3-59.3 ms, and fallback allocations 16,469-52,663. Both matrices retained zero queue/rate-limit events, no forbidden runtime log, and zero process, namespace, link, or qdisc residue.
- Exact ARM64 evidence proves the real authenticated TUN/MASQUE carrier under sustained UDP/FEC and dual-stack TCP pressure. The current CUBIC control uses a short owned admin socket, refuses existing evidence paths and colliding topology, and scans every retained runtime log for panic, decryption, heartbeat, internal, and TUN-send failure. Against binary SHA-256 `e09cad15ef86ea79a074bf1daff93615a97e9078d8786e346ac77b6f5d82f580`, its three-clean/three-loss trials recorded Auto 2.989 Mbit/s and 99.60% retention versus FEC-off 2.849 Mbit/s and 94.94%, a measured delta of 0.140 Mbit/s and 4.66 percentage points; CUBIC/Reno fairness was 1.052/1.069 Mbit/s with Jain 0.999931.
- The three-client dual-stack harness gives caller-selected evidence directories bounded admin-socket ownership and self-contained certificate behavior, retains the exact binary SHA-256, and deletes every owned host veth after namespace teardown. Its paced IPv6 TCP probe requires identical sender/receiver bytes and SHA-256 and uses receiver elapsed time for throughput. Exact final-source ARM64 proof recorded 6.939/11.326 Mbit/s medians, 63.21% PMTU gain, a 26,017,792-byte receiver-valid black-hole transfer in 20.420 seconds, bounded CPU/RSS/latency/allocations, zero queue or rate-limit events, and clean teardown.
- Exact source `47e0a82` removed the unsafe direct standalone timer integration and produced ARM64 binary `a884a6f9e930fc6c64d0641cac88eedf91dbd6414e7e3caa36930f3061cd87f5`. Its real three-client run reached the third 1500-byte opt-in TCP trial, and the retained public logs contain no heartbeat timeout, but the receiver did not produce a result and the harness failed closed. Receiver-verified default trials were 2.536/7.789/8.210 Mbit/s, while completed opt-in trials were 9.393/10.337 Mbit/s; one opt-in client entered persistent congestion at 0.20% loss. Failure metrics recorded 30,681,091 bytes in, 503,242 bytes out, and zero TUN/MASQUE backpressure events. Cleanup again left no product process, namespace, host veth, or qdisc. This disproves neither the PMTU blocker nor its root cause.
- Persistent-congestion accounting now follows the RFC 9002 boundary across ACK frames: an acknowledged ack-eliciting packet at or after a pending loss-run start resets that run, including a reordered ACK for a packet already declared lost. The candidate is scoped by packet-number space and can start only after the first RTT sample; ACK-only losses cannot establish persistent congestion. Focused regressions cover collapse, in-window ACKs, cross-frame ACKs, reordered ACKs, pre-sample losses, and ACK-only loss.
- Exact source `9633afc` validated that correction on ARM64 binary `e93aa65be88316068331885c07bb4dc60616785b013b6844a88a792dea746816`. The safe-1280 phase completed at 8.859/9.270/9.439 Mbit/s (median 9.270), but the first 1500-byte receiver failed to produce a result after client persistent congestion at 0.11% loss and cwnd 6000. The server still reported zero loss and zero TUN/MASQUE backpressure events. Cleanup was clean. The cross-frame recovery bug is fixed, but the live ACK/loss cause remains open.
- Persistent-congestion logs retain the triggering packet-number space, ACK-frame largest packet number, run-start and terminal lost packet numbers, run packet count, run duration, and RFC recovery period. The evidence is emitted only when cwnd collapses and is covered by the focused recovery regression set.
- Exact source `3e64eaa` used ARM64 binary `2fcfef6e5da33f9fdda9060ff737dc74c690320897f5d678f556471f6b609396`. It completed all six receiver-verified TCP trials without persistent-congestion evidence: default 9.232/9.059/9.157 Mbit/s (median 9.157), opt-in 9.710/9.355/9.582 Mbit/s (median 9.582). Its 4.64% result was not a 1500-byte payload-efficiency measurement because both TUN interfaces remained capped at 1280. The corrected harness retains the 15% gate and awaits exact ARM64 proof; collapse and delivery integrity are no longer the active gap.
- Exact source `8808c7f` then exercised the raised client TUN MTU (1400) and failed opt-in trial two after a 90-ms application-space persistent-congestion run at 0.09% observed loss. The selected 1500-byte QUIC packet length is sent directly as the UDP payload, so it exceeds the 1500-byte IPv4 test-link L3 MTU after IPv4 and UDP headers. The harness now qualifies the 1500-byte IPv4 L3 path with a 1472-byte QUIC UDP-payload ceiling without weakening the 15% gate; exact ARM64 evidence remains required.
- After the exact 1472-byte run reached black-hole recovery and then stopped after its 1328-byte re-probe, `Connection::send_with_datagram_overhead()` now permits only that isolated PING+PADDING PMTU probe to cross a closed congestion gate. The bypass is available only when the configured probe interval is at least the current recovery RTT, preserving RFC 8899 probe-rate safety; control frames, STREAM payload, and DATAGRAM payload remain gated, and the probe remains tracked as an ack-eliciting packet. Focused positive and sub-RTT negative regressions, `cargo check --all-targets --features rust-tests`, and `cargo clippy --lib --features rust-tests -- -D warnings` pass locally. Exact ARM64 black-hole recovery proof remains required.
- Native evidence showed that treating every PMTU probe as congestion-neutral is unsafe: 1328 and 1400 were reconfirmed after the reset, but a later regular probe loss entered persistent congestion. `Recovery` records only an isolated DPLPMTUD probe that actually bypassed a closed congestion gate as ack-eliciting loss-detection state outside bytes in flight, congestion-control loss, and persistent-congestion runs. Regular PMTU probes retain normal congestion-control accounting. Focused probe-loss, gate-bypass, sub-RTT rejection, and regular-probe accounting regressions pass locally. Exact ARM64 proof remains required.
- Exact ARM64 source `bfe8bd9` produced binary SHA-256 `f6e3ecdeeac887478e12c0612cf990f3f2295c90a0b63a1df544b43818a4e129` and passed the full three-client dual-stack gate. Receiver-verified default trials were 7.835/7.757/7.701 Mbit/s (median 7.757); 1472-byte opt-in trials were 10.169/10.616/10.186 Mbit/s (median 10.186), a 31.31% gain. The black-hole phase detected the loss within 2 seconds and completed its 18,022,400-byte receiver-valid transfer in 20.732 seconds. Captured server metrics recorded zero TUN-downlink and MASQUE-response queue/retry/drop events; teardown left no product process, namespace, qf523 link, or qdisc residue.
- The native `d5e1937` harness attempt proved the new queue-quiescence assertions during the completed default phase. Two clean opt-in attempts then failed before that assertion after application-space persistent-congestion collapses at 0.07% and 0.12% observed loss; both failure snapshots still had zero TUN/MASQUE pending, retry, and drop counters and both cleanups left no product process, namespace, qf523 link, or qdisc. The correction above must receive a fresh exact-artifact run before any opt-in quiescence claim.
- Historical ARM64 source `12da3cc` built binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`. Its default phase completed receiver-valid trials at 7.281 Mbit/s median, but opt-in trial one failed before producing a receiver result after a 12-packet application-space persistent-congestion run from PN 10177 through 10191: 108 ms against an 80-ms RFC period, with ACK largest PN 10193 and 0.12% observed loss. Failure metrics retained zero TUN/MASQUE pending, retry, and drop counters; cleanup was clean. The later final-source proof above resolved this historical blocker.
- The current local library release gate `cargo test --lib --features rust-tests --quiet` passes all 2,008 tests. The broader `cargo test --workspace --all-targets --features rust-tests` release gate also exits successfully.

#### Network-Stack Fingerprint Normalization

- Each server-side `QuicFuscateConnection` freezes one `PacketNormalizer` from the same immutable `StealthConfig` snapshot that owns its TLS/H3 persona. Profile rotation changes only the next connection, so TLS and raw-IP personas cannot diverge mid-session.
- Client-side connections and `StealthMode::Off` use `OsFingerprintProfile::Disabled`, which returns before packet inspection, mutation, allocation, or IP-ID state advancement.
- Normalization runs exactly once after raw IP is decoded from MASQUE DATAGRAM, MASQUE capsule, compressed capsule, or framed H3 body and before the authenticated server TUN/fanout callback. This includes client-originated active-probe responses travelling back through the tunnel. Server-generated routing, MTU, and time-exceeded ICMP responses use the same frozen profile's TTL or hop limit; ordinary server-to-client raw-IP downlink packets and sealed QUIC datagrams are never rewritten.
- IPv4 normalization sets the profile TTL, DF policy, and monotonic IP ID only on unfragmented packets. TCP window, MSS, window scale, and canonical p0f option layout are rewritten only when SYN is set. Linux, Windows, macOS, and Android profiles retain exact request signatures from p0f 3.09b; iOS maps to the macOS/Darwin network family.
- Canonical option expansion and shrink preserve SYN payload bytes, TCP data offset, IPv4 total length, and full IPv4/TCP checksums. The normalizer uses bounded stack state and caller-owned spare capacity; framed H3 supports the complete valid IPv4 packet-length range without a per-packet heap allocation.
- `suppress_icmp_unreachable=true` drops only non-PMTUD destination-unreachable traffic. IPv4 Fragmentation Needed and ICMPv6 Packet Too Big always pass. Echo payloads remain byte-exact, and locally generated echo responses use the connection's frozen source profile.
- `benches/fingerprint_normalizer.rs` asserts zero allocations after warmup and measures the common IPv4 UDP path. The privileged Omega matrix is owned by `scripts/tests/fingerprint-runtime-proof-netns.sh`. The hook now records ICMP echo, open and closed TCP, closed UDP, packet-trace Nmap output, both TUN directions, checksums, IP-ID progression, disabled byte-exact passthrough, and non-SYN transport-byte preservation under verifier schema `quicfuscate.fingerprint-pcap.v3`. Existing evidence run `evidence-fingerprint-20260731i` against binary SHA-256 `37c4ac6f7c79cd53e3e6f327dc9fcbff780b3d072eee73818110843b42d51dfa` remains the TODO-543 baseline. Completed TODO-765 retains the exact five-profile response-contract evidence at `/home/ubuntu/SOFTWARE/QuicFuscate/candidate-todo765-20260801c/evidence-todo765-20260801c` for binary SHA-256 `f8c8f1e811edd4e9a47f54521c4a893e309e41fb42c02bdb6654d93189ff5b59`: each profile proves 82 client and 82 server response packets, vector counts `tcp_syn_response=30`, `tcp_rst_response=32`, `icmp_echo_reply=11`, `icmp_udp_port_unreachable=6`, and `tcp_sequence_fields=65`; disabled mode is byte-exact, enabled modes preserve non-SYN transport bytes and consecutive server IP IDs, and all checksums pass. p0f passes all five primary profile signatures; Nmap exits successfully but reports no exact OS match for enabled profiles, so no exact active classifier claim is made.

### Cryptography Design (AEAD-First, Efficient by Construction)
- Product-level data-plane AEAD posture: retained `Aegis128L` and `Morus1280_128` families with hardware-aware automatic selection.
- Constant-time tag glue for the documented backends and strict nonce/tag checks on hot paths; the AES table fallback remains separately scoped under TODO-681
- Perfect Forward Secrecy via ephemeral X25519
- Runtime selection via FeatureDetector and `simd::planner` (CryptoAeadPlan) chooses the best internal implementation for the selected data-plane AEAD posture
- TODO-681 completed the read-only unsafe-crypto audit. It found no active out-of-bounds production caller in the inspected primitive paths, but leaves checked `len + 16` arithmetic, owner-only QUIC packet-number enforcement, AES table fallback side-channel scope, GHASH release-control proof, complete key-schedule erasure, and native ISA proof open.

#### AEAD Policy and Implementation Status
- AEGIS implementation is fully internal in `src/crypto/`; there are no active references to external AEGIS forks.
- Canonical data-plane posture is exactly two productive families: `Aegis128L` and `Morus1280_128`.
- Fallback policy: only `Morus1280_128` is retained when AES-backed paths are unavailable.
- This is intentionally retained custom runtime crypto, not a pure external-lib-only posture.
- External crates are used only as baseline vectors, interoperability checks, or differential/reference oracles where available. They are not the canonical runtime providers for the retained AEGIS/MORUS data-plane contract.
- Runtime selection:
  - x86/x86_64 with AES uses AEGIS; large VAES-capable payloads may use `Aegis128X8` as an internal backend.
  - AArch64 uses `Morus1280_128` automatically because Broderick ARM/AArch64 Criterion evidence shows MORUS beats retained AEGIS L/X4/X8 for 64B, 1024B, 1400B, and 8192B single and batch8 seal/open trait paths.
  - Architectures without an evidence-backed AEGIS advantage fall back to `Morus1280_128`.
- Packet hot path dispatch: normal 0-RTT/1-RTT data-plane AEAD slots resolve to `DataAead` enum variants (`Aegis128L`, `Aegis128X4`, `Aegis128X8`, `Morus`) and avoid boxed trait dispatch. Rustls-provided packet keys remain supported through the explicit `PacketAead*::Dynamic` wrapper arm.
- AEGIS secret retirement and concurrency: L/X4/X8 wrappers wipe the retained 16-byte key and 12-byte IV. Single-packet operations construct local derived state; batch operations reuse one local state with `reinit`. No wrapper-level mutex or shared mutable cipher state remains, so concurrent packets on one `DataAead` instance cannot serialize or cross-contaminate state. Inner cipher drop uses the same state-wipe primitive.
- Performance evidence:
  - retained backend evidence is produced by `scripts/benchmarks/suites/bench-retained-crypto-backends.sh`
  - the suite records hardware profile, per-backend throughput, and per-size winners for `Aegis128L`, `Aegis128X4`, `Aegis128X8`, and `Morus1280_128`
  - TODO-582 local Criterion comparison (10 samples, 1-second warm-up, 2-second measurement) found no significant scalar-GHASH regression at 64/1024/8192 B and improved AEGIS-128L 1400 B batch8 seal/open medians from 7.9277/8.3971 us to 7.3575/7.4099 us; exact Omega/Linux throughput evidence remains a separate protected boundary.
- CI regression evidence for retained backend packet trait paths lives in `scripts/benchmarks/ci_regression.rs` as `data_aead_single_seal_batch`, `data_aead_single_open_batch`, `data_aead_batch8_seal`, and `data_aead_batch8_open`.
- AArch64 SVE2 AES batching for the AEGIS update step is not enabled in the current build profile.
- Testing: see `scripts/tests/suites/test-crypto.sh` and the comprehensive test runner. Edge cases (including non-32-byte payloads) are validated to ensure tag verification parity between encrypt/decrypt.

#### GHASH Acceleration (AES-GCM)
- Runtime dispatch selects the fastest GHASH implementation:
  - x86_64: PCLMULQDQ path with Karatsuba carry-less multiplication and reduction modulo `x^128 + x^7 + x^2 + x + 1`; falls back to an SSE4.1/SSSE3 nibble kernel when CLMUL hardware is absent (`GHASH_SSE_OPS`).
  - aarch64: PMULL path (prefers `sve_pmull` if available, otherwise falls back to NEON) is enabled by default; can be disabled via `QUICFUSCATE_GHASH_PMULL=0|false|off`. For non-16-byte-aligned inputs, the software path takes over to ensure parity.
  - Fallback: byte-position table approach (16x256 lookups) avoids per-nibble `mul_x4` cascades and accelerates the SSE4.1/SSSE3 path.
- Correctness
  - Software vs. hardware path parity is verified by unit tests in `src/crypto/`.
  - The scalar fallback builds one 16-entry 4-bit H table per GHASH call and processes each input block in 32 nibble steps; a bit-serial reference remains in-tree for table parity tests and hardware-table construction.
  - AES-GCM tag derivation (`aes_gcm_tag_aad_only`) uses the selected GHASH seamlessly. `QUICFUSCATE_GHASH=auto|vpclmul|pclmul|sse|scalar` allows targeted backend verification (tests use `__test_set_ghash_override`).

TODO-681 records that `QUICFUSCATE_GHASH` on x86 and `QUICFUSCATE_GHASH_PMULL` on AArch64 are production `OnceLock` controls with separate test coverage. The test-only x86 override remains behind `cfg(test)`; release behavior for both environment-controlled surfaces is still an explicit audit gate.

#### Unsafe Crypto Audit Status (TODO-681)
- Scope: all seven `src/crypto` primitive files, every current unsafe function/block, target-feature dispatch, fixed-width load/store, constructor, Drop path, AEAD and batch trait boundary, direct packet/TLS-cover caller, crypto test/runtime fixture, audit script, documentation claim, and relevant history were read.
- Resolved historical claims: TODO-582's AEGIS mutex/`unwrap` path, TODO-626's tag-comparison claim, and TODO-627's exact key/IV constructor boundary remain closed. TODO-631 is valid only for the target-specific `AesGcm128` schedule owner; it does not cover `Aes128Ctx` or temporary AES schedules.
- Open findings: `Aes128Ctx` and temporary schedule erasure, unchecked seal/batch `len + 16`, owner-only 62-bit nonce enforcement, ChaCha nonce/clone erasure, AEGIS copied-state erasure, GHASH release-control proof, AES table fallback side-channel scope, MORUS's debug-only private loader precondition, and native ISA/fail-closed test proof.
- Audit status: no production implementation, build, test execution, runtime probe, commit, or push was performed for TODO-681.
  

### FEC Design (Stability Under Loss)

#### Core Architecture
- **Hybrid design**: Adaptive RLNC + Tetrys-like streaming with automatic mode switching
- **Auto-Mode**: Switches based on observed loss/RTT (bounded by `hysteresis`, smoothed by `lambda`)
- **Telemetry**: Track mode switches via `fec_mode`, `fec_mode_switch_total`
- **Decoder observability**: Process-wide counters expose admitted repair equations, full-solver attempts, successful solves, cumulative solver time, bounded dedup evictions, and a derived solve-success ratio.

#### FEC Modes

**RLNC (Random Linear Network Coding):**
- Sliding-window systematic encoding
- Sources remain intact; repairs emitted when window full
- Window cleared after emission to bound latency
- Configurable window size for loss/latency tradeoff

**Streaming (Tetrys-like):**
- Emits 1 repair per N sources
- `QUICFUSCATE_FEC_STREAM_EVERY`: Overrides repair cadence (min 1; default computed from CPU profile)
- Aggressive profiles can use N=1 for maximum redundancy

#### Benchmark Coverage

- `benches/fec_pipeline.rs` uses `FecConfig::product_default()` for mode variants so Criterion windows match the Engine/CLI product defaults (`window_good=10`, `window_fair=30`, `window_poor=50`) instead of synthetic library-default windows.
- `fec_encode_pipeline` remains the compatibility benchmark for full `on_send()` behavior.
- `fec_systematic_hot_path` is a cold-start guard: it creates fresh `AdaptiveFec` state and output scratch per sample, so it must not be used as the production send-hotpath number.
- `fec_send_reuse_hot_path` measures the production send path with persistent `AdaptiveFec` state, advancing packet IDs, and reusable caller-owned output scratch via `on_send_into()`.
- `fec_decode_pipeline` measures production-style 128-packet receive batches with `on_send_into()` / `on_receive_into()` scratch reuse and a deterministic 10% source-drop mask. This protects realistic clean and lossy decode work instead of single-packet random-loss artifacts.
- `fec_decode_compat_alloc` keeps a separate guard for the allocating `on_receive()` compatibility wrapper without presenting it as the production hot path.
- `fec_lazy_fast_path` isolates lazy receive behavior for zero-mode passthrough and Normal-mode clean receive with reusable output scratch.
- `fec_window_fill_burst` measures the packet that completes a product-sized FEC window for Light/Normal/Medium/Strong separately.
- Broderick ARM/AArch64 product-window burst reference after TODO-488: Light k16 `32.7 us`, Normal k10 `14.9 us`, Medium k30 `23.7 us`, Strong k50 `37.7 us`.
- Broderick ARM/AArch64 product-window burst reference after TODO-506 GF16 coefficient precompute: Normal k10 remains neutral around `14.25 us`, Strong k50 improves to `24.73 us` median with Criterion reporting `-38.568%` time and `+62.782%` throughput.
- Broderick ARM/AArch64 decode-batch reference after TODO-490: Normal clean `282 us`, Normal 10% loss `514 us`, Strong clean `278 us`, Strong 10% loss `17.5-18.5 ms`, Streaming clean `499 us`, Streaming 10% loss `623 us`.
- Broderick ARM/AArch64 decode-batch reference after TODO-491 lazy full-recovery gating: Normal clean `279 us`, Normal 10% loss `506 us`, Strong clean `200 us`, Strong 10% loss `195 us`, Streaming clean `447 us`, Streaming 10% loss `474 us`.
- Broderick ARM/AArch64 streaming decode reference after TODO-501 lazy tail-loss gating: Streaming clean 128-packet batch `211.75 us` (`-99.213%` time versus the stale full-recovery wakeup baseline) and Streaming deterministic 10% loss batch `307.97 us` (`-97.963%` time), while Tetrys-style tail-loss recovery remains green.
- Broderick ARM/AArch64 lazy-fast-path reference after TODO-498 source-buffer replay: zero passthrough `285.14 ns`, zero reuse `266.47 ns`, Normal no-loss `1.284 us`, Normal no-loss reuse `1.244 us`.
- Broderick ARM/AArch64 send-reuse-hotpath reference after TODO-499: Zero/1400B `233.37 ns`, Normal/1400B `1.1081 us`, Strong/1400B `408.48 ns`, Streaming/1400B `380.88 ns`.
- Broderick ARM/AArch64 data AEAD reference after TODO-500: MORUS wins every retained-backend packet trait path tested; 1400B single seal/open are `1.1944 us` / `1.1885 us` for MORUS versus best AEGIS `2.0736 us` / `2.1307 us`, and batch8 seal/open are `9.3550 us` / `9.4560 us` for MORUS versus best AEGIS `16.699 us` / `17.010 us`.
- Broderick server fastpath reference after TODO-502: `scripts/install/setup-netfilter-fastpath.sh` removes stale lower-priority UDP/4433 ACCEPT rules before reinserting at INPUT line 1, so QuicFuscate UDP bypasses `ts-input` and other prepended chains before the measured `nft_do_chain` path. Repeated Broderick runs leave exactly one UDP/4433 ACCEPT rule at line 1.

#### Connection Benchmark Coverage

- `scripts/benchmarks/ci_regression.rs` contains the CI Criterion hotpath groups for transport send/receive, ACK accounting, STREAM frame encoding, multi-stream scheduler membership, Brain policy application, concurrent Brain packet observation, and stealth padding decisions.
- TODO-580 local multi-stream Criterion evidence: `stream_scheduler_multistream` measured median times of `3.299 us` for 16 streams, `10.258 us` for 64 streams, and `81.490 us` for 256 streams on the local ARM64 host.
- TODO-575 local ARM64 Criterion hotpath evidence: `brain_packet_observer` measured `30.614 us` / `33.449 Melem/s` with one worker, `294.47 us` / `13.910 Melem/s` with four workers, and `975.43 us` / `8.3984 Melem/s` with eight workers after the lock-free accumulator and IAT sampling change. The pre-change medians were `168.55 us` / `6.0752 Melem/s`, `668.13 us` / `6.1305 Melem/s`, and `1.2923 ms` / `6.3393 Melem/s` respectively.
- Broderick ARM/AArch64 Brain policy reference after TODO-507 direct histogram divergence: `brain_apply_policy/clean_observer` `600.01 ns`, `intelligent_clean` `599.07 ns`, and `intelligent_pressure_actuating` `550.67 ns`; Criterion reports about `7.33-8.39%` lower time versus the scratch-copy path.
- `connection_1rtt_send_recv` and `connection_1rtt_stealth_compare` use Criterion `iter_batched(..., BatchSize::PerIteration)` so paired-connection construction, CID setup, and key installation are excluded from timed measurement.
- `transport_stealth_padding_decision` protects the real per-packet transport padding decision path. Adaptive padding uses a power-of-two remainder fastpath for the default 64-byte granularity while preserving modulo behavior for custom non-power-of-two granularities.
- Stream readiness membership is kept in HashSets for O(1) average admission checks while VecDeque order remains the scheduling contract; front removals are O(1), and priority reordering remains an explicit control-path scan.
- `QuicFuscateConnection` retains one configured MemoryPool block as the reusable HTTP/3 body-read buffer; the default block is 64 KiB and is returned to the pool on connection drop.
- The measured routine remains the real 1-RTT path: `stream_send -> send -> recv`.
- Broderick ARM/AArch64 reference after TODO-500 AArch64 MORUS auto-selection: `connection_1rtt_send_recv` is about `4.70 us` for 256B, `5.50 us` for 1024B, and `5.84 us` for 1400B; `connection_1rtt_stealth_compare` is about `5.48 us` stealth-off and `5.55 us` stealth-on.

#### Galois Field Implementations

**GF(2^8) - 8-bit Galois Field:**
- Bit-sliced implementation for cache efficiency
- SIMD-accelerated multiply-accumulate
- Large-window sparse solver support
- Block repairs use deterministic Cauchy coefficient rows whenever the block fits the GF(256) symbol space, giving the Normal interleaved path an MDS repair matrix instead of rank-deficient arithmetic rows.
- Lookup tables for small operations
- SSSE3 and AVX2 nibble-LUT slice multiplication preserve the codec's canonical GF(256)/0x11D field and record `FEC_SSSE3_OPS` / `FEC_AVX2_GF_OPS`. Intel GFNI's byte multiply is fixed to the AES 0x11B field, so it is never used for this FEC wire contract.
- VBMI2 nibble gather kernel (`gf16_mul_slice_vbmi2`) drives `FEC_GF16_VBMI2_OPS`; processes 32xu16 per iteration via `_mm512_permutex2var_epi16` tables. Planner selects it for `X86_P3c+`; scalar fallback remains for residual CPUs. Throughput characteristics remain hardware-dependent and are validated on target systems.
- Matrix multiplication delegates coefficient application to the same canonical 0x11D slice kernel; raw AVX-512 GFNI multiplication is excluded because its 0x11B polynomial is wire-incompatible.
- NEON and SVE2 slice kernels share nibble tables with adaptive prefetch; `FEC_NEON_OPS` and `FEC_SVE2_OPS` counters expose runtime usage.
- GF(2^8) lookup tables are initialized once through a synchronized `Once`/`OnceLock` boundary during FEC startup and never re-enter initialization from `gf_mul_table` or `gf_inv8`.

**GF(2^16) - 16-bit Galois Field:**
- AVX2-optimized nibble paths (x86_64)
- NEON-optimized paths (ARM)
- High-throughput MatMul operations
- Consistent byte-width policy

#### Decoder Architecture

**Sparse Gaussian Elimination:**
- Minimal-NNZ (Non-Zero) pivot selection
- Early repair detection
- Progressive decoding support
- Memory-efficient sparse matrices
- Recovery is fail-closed on deficient rank. A decoder materializes no unknown source unless every unknown column has a pivot, and fully solved equation sets are retired instead of accumulating across windows.

**Large-window sparse solver (internal strategy):**
- Internal block-iterative solver for large GF(2^8) recovery systems.
- Parallel per-byte solving via Rayon.
- Every candidate is checked against every original row before materialization; missing or invalid byte solutions fall back to Gaussian elimination.
- Solver attempts and wall-clock nanoseconds are recorded for GF(2^8)/GF(2^16) full elimination; the exported success ratio is derived from attempts and successful solves. Repair-equation admission covers all decoder backends.

**Public contract vs internal machinery:**
- The canonical FEC runtime surface is intentionally narrow: `FecConfig`, `FecMode`, `FecPacket`, and `AdaptiveFec` runtime operations.
- Decoder selection, large-window solver choice, GF math kernels, and similar implementation details are internal policy rather than product-facing feature posture.
- Test-only harness surfaces such as `Encoder8` and `FecDecoder8` remain available for repo validation and fuzz/property paths, not as product contract.

#### Runtime Control Loop (Transport <-> FEC)

Runtime adaptation is applied continuously in the connection loop:

- `transport::Connection::take_fec_control_delta()` provides transport-level control deltas each tick.
- The connection updates `AdaptiveFec` (`set_stream_every`, `force_streaming_mode`, `set_redundancy_ppm`) before the next encode path.
- Transport feedback feeds `AdaptiveFec::report_transport_loss()` only when a classified ACK or declared loss is present. The feedback retains independently owned send, ACK, and loss counts plus the congestion controller's smoothed loss ratio, but send-only callbacks are not controller observations and cannot replay stale loss into Auto FEC. Only classified ACKs can prove a clean link.

This is the convergence point where transport feedback, StealthBrain hints, and FEC policy remain synchronized during live traffic.

#### Active FEC Policy Commands

`QuicFuscateEngine::set_fec_mode()` is synchronous and returns `FecPolicyCommandResult`. The result separates `requested`, `configured`, and optional active `effective` policy, identifies `ActiveConnection` versus `NextConnection` scope, and reports queued source preservation plus repair-only retirement. A client command without a connection updates both Engine and `ClientRuntime` construction state for the next connection or reconnect. The other generic setters (`set_stealth_mode`, `set_cc_algorithm`, `set_traffic_padding`, `set_timing_obfuscation`, and `set_0rtt`) are validated next-connection/reconnect controls for clients; active non-FEC sessions retain their construction snapshot. Startup-owned engine, interface, telemetry, logging, audit, crypto, optimization, and security sections require a stopped client. Batch configuration changes must use validated `update_config()`, which routes FEC changes through the same policy command; `reload_config_from_file()` uses that same complete-candidate boundary. A running embedded server rejects generic mutation because standalone reload owns its next-connection-only policy.

An active client command locks the existing `QuicFuscateConnection` owner already used by send, receive, Brain feedback, loss feedback, reconnect, and shutdown. It adds no packet-path lock. Auto-to-Off preserves queued systematic datagrams byte-exactly, discards queued repairs before acknowledgement, clears emission/recovery scratch, and resets wire epoch state. Off-to-Auto and Auto-to-Off rebuild the adaptive controller, encoder, decoder, estimator, pending transition, and repair-retention state at Zero while preserving cumulative wire telemetry. Repeated commands are idempotent; serialized accepted commands use deterministic last-accepted-wins semantics.

While local policy is Off, framed peer systematic packets remain deliverable to QUIC through source-only parsing. Peer repairs are validated and discarded without creating a receive window or decoder retention. Connection telemetry exposes codec `mode_transitions` and operator `policy_transitions` separately; process telemetry exports `quicfuscate_fec_policy_transitions_total`.

#### Congestion Control Architecture

QuicFuscate uses a pluggable congestion control framework in `src/transport/cc/`. Four algorithms are available, all implemented in-tree with zero external dependencies:

| Algorithm | File | Description |
|-----------|------|-------------|
| **Reno** | `cc/reno.rs` | TCP New Reno (RFC 6582). Conservative AIMD baseline. No pacing. |
| **CUBIC** | `cc/cubic.rs` | RFC 9438 CUBIC with stateful Reno-friendly growth, one reduction per recovery episode, application-limited epoch suspension, explicit pacing, and RFC 9406 HyStart++. |
| **BBR2** | `cc/bbr2.rs` | BBR v2 (IETF draft-ietf-ccwg-bbr). Loss-aware model-based CC with 4-state machine (Startup/Drain/ProbeBW/ProbeRTT), windowed bandwidth estimation, and pacing. |
| **BBR3** | `cc/bbr3.rs` | Stealth-optimized BBR v3. Same state machine as BBR2 but with overridable gain tables for browser-profile shaping. Default and recommended. |

All four implement the `CongestionController` trait (`cc/mod.rs`). Dispatch uses an enum wrapper (`CcImpl`) with eight variants for zero-vtable hot-path performance: `Reno`, `Cubic`, `Bbr2`, `Bbr3` (base variants created at startup) and `StealthReno`, `StealthCubic`, `StealthBbr2`, `StealthBbr3` (stealth-wrapped variants, activated at runtime by `Recovery::set_stealth_mode()`). The macro `cc_dispatch!` handles all eight uniformly.

BBR2 and BBR3 initialize a Startup pacing floor from the initial congestion window and a 100 ms initial RTT. While Startup is probing, transient slow delivery samples may raise but cannot collapse that model floor; optional Stealth shaping is applied once to each recomputed output instead of compounding across ACKs. Both controllers use saturating bytes-in-flight accounting, expire their minimum-RTT filter after the configurable `QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS` window (default 10 seconds), and route RTT timestamps through `time_source`. BBR2 keeps its delivery counter and ACK clock separate from send-side round tracking. `set_cwnd()` changes only the window; validated path migration owns path-model resets through `on_path_change()`. Drain and Probe states use the measured model rate directly. Persistent congestion returns either BBR controller to Startup and reinitializes the same pacing floor from its reset window and current RTT estimate.

**CLI Usage:**
```bash
quicfuscate client --remote server:4433 --cc-algorithm bbr3
quicfuscate server --listen 0.0.0.0:4433 --cc-algorithm cubic
```

**Default:** `bbr3`. Only `reno`, `cubic`, `bbr2`, and `bbr3` are accepted; any other value is rejected.

#### StealthShaper Wrapper

`StealthShaper<T>` (`cc/stealth_shaper.rs`) is an optional decorator that wraps any `CongestionController` to inject stealth traffic shaping. It is **not user-selectable** - it activates automatically when the stealth mode is active (controlled by StealthBrain/StealthManager) and deactivates when stealth mode is off.

**What it does (when active):**
- **Browser-profile gain tables:** Overrides BBR3's ProbeBW gain cycle with browser-specific values (Chrome/Firefox/Safari/Edge) so congestion patterns resemble real browser HTTPS traffic.
- **Pacing jitter:** Injects symmetric randomized timing perturbations via Xoshiro256++ PRNG (+/- the full profile jitter window) to defeat statistical timing analysis.
- **Flow dampening:** Optional 2% pacing reduction for smoother traffic shape.

**Algorithm-specific behavior:**
- **BBR3 + Stealth:** Full effect - gain table injection + pacing jitter. This is the recommended stealth configuration.
- **BBR2 + Stealth:** Pacing jitter only (BBR2 uses its own gain cycle, not overridable). Still effective for timing obfuscation.
- **CUBIC + Stealth:** CUBIC keeps its explicit cwnd/RTT pacing contract; the wrapper applies bounded profile jitter and optional 2% flow dampening after ACK processing.
- **Reno + Stealth:** No effect - Reno does not pace, so there is no pacing rate to jitter. Other stealth features (TLS Cover, HTTP/3 masquerading, domain fronting, DoH) still operate independently at the connection layer.

**Lifecycle:** The user selects the CC algorithm (Reno/CUBIC/BBR2/BBR3) and the stealth mode (Off/Performance/Stealth/AntiDPI/Intelligent/Manual) independently. When stealth mode first activates, `Recovery::set_stealth_mode(true, profile)` uses `std::mem::replace` to swap the current `CcImpl` variant in place - e.g. `CcImpl::Cubic` becomes `CcImpl::StealthCubic(StealthShaper::new(inner, profile))`. Later activation changes update that monomorphic wrapper in place. Deactivation disables its shaping and clears any CUBIC pacing override while preserving the enum variant. No manual configuration is needed.

### FEC Modes & Algorithms (Current)
- Modes: `Zero`, `Light`, `Normal`, `Medium`, `Strong`, `Extreme`, `Ultra`, `Fountain`, `Streaming`.
- Active codec cascade
  - `Zero`: raw QUIC datagrams with no FEC framing or compute overhead.
  - `Light`: GF(2^4) with a 15-source/16-total MDS block and one repair. The fused scalar/AVX2/NEON multiply-XOR kernel avoids temporary repair buffers.
  - Block modes through 255 sources per interleave lane: GF(2^8) with deterministic Cauchy repair rows.
  - Block modes above 255 sources per lane: GF(2^16) with deterministic Cauchy repair rows and exact odd-length recovery. A process-wide 65,536-entry, 128 KiB inverse table is built once in linear field order, preserving every wire coefficient while removing repeated exponentiation from eager row-cache construction.
  - `Streaming`: partial-window GF(2^8) repairs with explicit coverage anchors.
  - `Fountain`: keyed deterministic LT source sets, reserved for explicit severe-loss rescue rather than the normal efficiency path. The seed is HMAC-SHA-256-derived from the local QUIC 1-RTT traffic secret, so the peer derives the same sets without a public seed. The product window is bounded to 128 sources, limiting the current 5x-code-rate completion burst to 512 repairs instead of allowing multi-thousand-packet synchronous stalls.
- Internal large-window decoder strategy
  - Bitsliced multi-lane MatVec with internal heuristics for projection/lanes.
  - Verification path checks `A_k * X == B` on a small sample and falls back to Gauss on mismatch.
- Streaming (Tetrys-like)
  - Emits 1 repair per `N` sources; `QUICFUSCATE_FEC_STREAM_EVERY` overrides cadence (min 1; default computed from CPU profile).
- Atomic transitions
  - Pending codec/window changes commit only at complete source-block boundaries. The sole exception is a de-escalation to raw Zero after at least 32 consecutive transport-classified clean ACKs: an incomplete repair-only encoder window is retired immediately so stale protected state cannot hold a recovered connection above Zero. Each committed shape change advances the wire epoch; retained inbound epochs are decoded independently.

SIMD & Parallelism
- SIMD levels auto-detected: `SSE2`, `AVX2`, `AVX512`, `NEON` (fallback: scalar). Parallel chunking for large payloads.
- Runtime overrides are documented in the FEC Operations Guide.

Wire Format v1 (active 1-RTT DATAGRAM)
```text
[magic:2][version:1][flags:1][codec:1][depth:1][lane:1][reserved:1]
[epoch:4][window:4][sequence:8][source_count:2][total_count:2]
[repair_index:2][payload_len:2][payload:..]
```
The fixed header is 32 bytes. Systematic wire symbols retain the two-byte inner QUIC length, while repair symbols retain that length plus the two-byte outer FEC source length, making the maximum active-FEC overhead exactly 36 bytes. Repair coefficient vectors are never transmitted: codec, block width, lane, and repair ordinal deterministically regenerate GF rows, while Fountain source sets regenerate from an HMAC-SHA-256-derived seed over the matching QUIC 1-RTT traffic secret and never from public wire metadata. Core reserves the full overhead before QUIC serialization, so the outer UDP datagram cannot exceed the active path MTU.

Mode Selection & Hysteresis
- Selection heuristic (loss-driven):
  - Product `Auto` starts in Zero and spends no FEC wire or codec work until measured loss justifies protection.
  - avg_loss < 0.001 -> Zero (ZeroEncoder: absolute zero overhead, counter only, ~2ns/packet)
  - < 0.02 -> Light (GF4, 15-source product window, one repair, 6.67% wire redundancy)
  - < 0.10 -> Normal (GF8: balanced)
  - < 0.22 -> Strong (GF8 through 255 sources per lane, otherwise GF16)
  - < 0.25 -> Extreme (GF8/GF16 selected by block width)
  - >= 0.25 -> Fountain only after at least 32 transport observations and agreement between the EMA and populated recent-loss window; otherwise the controller remains below the Fountain tier
  - Measured burst loss may select Streaming instead of the corresponding block tier
- Hysteresis & stability:
  - Transport adaptation consumes the congestion controller's smoothed loss signal. Independently timed send, classified ACK, and delayed loss observations provide exact counts but are never interpreted as standalone loss-ratio batches. Sends never count as clean delivery; 32 consecutive loss-free classified ACKs clear stale burst history and override asymptotic smoothed-loss residue.
  - Minimum dwell time between switches (default `120 ms` upward and `450 ms` downward; Zero may escalate immediately after sufficient evidence)
  - Switch only if `|avg_loss - last_avg| >= switch_threshold` (relaxes for Streaming/Normal)
  - Commit pending targets only after the current source block is complete, except for the transport-confirmed clean return to Zero described above; decode retained inbound epochs independently

#### Transport Integration (DATAGRAM Ingress/Egress)
- Active 1-RTT sources and repairs are transported over UDP using the versioned FEC v1 envelope above. Initial, Handshake, and stable `Zero` datagrams remain raw QUIC.

- Egress
  - Core polls rustls and the actual Initial/Handshake CRYPTO queues, and rejects active 1-RTT framing while any Initial/Handshake PTO probe is pending, so a pending Finished flight or handshake probe cannot be wrapped as FEC application data.
  - `Connection::send_with_datagram_overhead()` reserves 36 bytes against the minimum of output capacity, configured MTU, and discovered path MTU. Core encodes `[outer FEC source length | inner QUIC length | QUIC]`; systematic wire frames omit the outer length, while repairs retain both length layers, so the reservation always covers the largest active FEC datagram.
  - Emission policy is adaptive: base interval from `QUICFUSCATE_FEC_STREAM_EVERY` (default computed from CPU profile), escalation under loss and ECN-CE.

- Ingress
  - Core recognizes the two-byte magic, validates the complete header before decoder-window allocation, and dispatches by transmitted epoch/profile rather than local receive-side loss estimates.
  - The standalone server bypasses stateless Version Negotiation for the FEC magic before selecting the existing peer session, so active envelopes cannot be mistaken for unsupported long-header Initial packets.
  - Receiver state retains at most four windows, bounds source blocks to 2,048 symbols and total codewords to 12,288 symbols, rejects profile mutation within a retained epoch, and suppresses duplicate repairs with a FIFO set capped at the profile's total repair capacity.
  - Every systematic source and recovered source validates then removes its exact protected QUIC length at the FEC-to-QUIC boundary before decryption. Repairs can never enter header protection or AEAD processing.
  - Malformed, unsupported, or resource-exhausting FEC envelopes are dropped without terminating the authenticated QUIC connection. Recovered QUIC datagrams still pass normal header protection and AEAD authentication.
  - `FecMode::Zero` remains a raw ownership-preserving passthrough, allowing the QUIC core to decrypt and remove header protection in place without an extra copy.

- Semantics & Safety
  - `epoch`, `window`, `sequence`, `source_count`, `total_count`, `interleave_depth`, `block_index`, and `repair_index` fully define decoder ownership and deterministic repair reconstruction.
  - The validated product wire path bounds payload and coefficient lengths against its profile and pool block contract; decoder-internal buffer return and failure cleanup remain TODO-832.
  - Decoder telemetry exports `quicfuscate_fec_decoder_equations_total`, `quicfuscate_fec_decoder_solve_attempts_total`, `quicfuscate_fec_decoder_solve_successes_total`, `quicfuscate_fec_decoder_solve_success_ratio_ppm`, `quicfuscate_fec_decoder_solve_time_ns_total`, and `quicfuscate_fec_decoder_dedup_evictions_total`.
  - The retained `FecPacket::to_stream_raw()` / `from_stream_raw()` format is a legacy internal compatibility/test surface and is not used by Core transport framing.

Performance evidence on Apple Silicon for the product-window repair burst: optimized single-repair GF4 k=15 reaches about `6.69 us` median and `199.45 MiB/s`, versus the measured GF8 k=16 baseline at about `11.67 us` and `114.44 MiB/s`. The exact one-repair policy improves its preceding two-repair GF4 result by about 22% in median time. The v1 envelope itself measures about `29.73 ns` to write and `12.83 ns` to parse at a 1,400-byte outer MTU; deterministic GF8 k=16 row derivation measures about `22.75 ns`.

Live ARM64 evidence on 2026-07-22 uses commit `15570abf772766c76959f6aae6ba16b2b9c26fd7`, GitHub CI `29915916296`, Clippy Matrix `29915916332`, and Release Build `29915916301`. The exact release bundle SHA-256 is `5406170b4175d91722d2169c8c21adc9721e61fe995a513299fc4f52eff9d8fe`; the AArch64 binary SHA-256 is `9b4144a85e452ef37102ac255b0c8c976f1145ad04941c594d07d4fc6130cf5b`. In isolated Omega runtime `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-15570ab`, the original 1,000-packet uniform 0/5/10/25% netem matrix passes `4/4`, and the 1,000-packet correlated-burst matrix passes `2/2` with 2% residual tunnel loss in both burst cases. Retained peer logs prove completed TLS and H3/MASQUE establishment with NEON FEC and no AEAD, decrypt, or panic errors. Deterministic local interleave gates separately prove 1,000 unique byte-exact deliveries, zero duplicates, and bounded recovery latency for seeded 5% random loss and four consecutive losses per sixteen packets.

### Code Layout
QuicFuscate uses a consolidated Rust layout that keeps hot paths explicit and auditable while optimizing safety, performance, and maintainability.

#### Source File Coverage (Exact Path Index)
The sections above describe architecture and behavior. This index maps exact `src/` file paths to their concrete runtime responsibility to keep this document exhaustive and drift-resistant.

Core crate and entrypoints:
- `src/lib.rs` - crate root, module exports/re-exports, and public type surface.
- `src/main.rs` - CLI wiring, client/server runtime bootstrap, hidden diagnostic/bench commands, and process wiring around the centralized server/admin modules.
- `src/time_source.rs` - injectable time abstraction (`TimeSource`) with test install guard.
- `src/implementations/client/io_driver.rs` - client runtime I/O driver; its dispatch/fallback hotpath is isolated behind an internal `IoHotpathAdapter` seam for deterministic tests without real sockets or TUN devices.
- `apps/tauri/src-tauri/src/state_store.rs` - desktop native-host `StateStore` abstraction with file-backed production persistence; missing state is explicit first-run absence, while corrupt, unreadable, or failed-normalization state returns an error and remains unavailable instead of becoming a fabricated default.

Binary entrypoints:
- `src/bin/harness.rs` - script-facing harness binary (3-line entry point); implementation is in `src/harness.rs` (~260 lines).
- `src/bin/qf-e2e-client.rs` - headless QKey-based E2E client for admin/web flows.
- `src/bin/qf-ddos-policy-probe.rs` - bounded real-data GeoIP and strict-HTTPS blacklist policy probe.
- `src/bin/qf-e2e-desktop.rs` - headless desktop-style Engine E2E probe (connect/stats/disconnect).
- `src/bin/quicfuscate-ctl.rs` - Unix admin socket CLI (`status`, `clients`, `kick`, `block`, `reload`, `qkey`, `shutdown`).

Engine module (`src/engine/`):
- `src/engine/mod.rs` - engine module root and public exports.
- `src/engine/config.rs` - typed engine config schema, enums, validation, builder.
- `src/engine/engine.rs` - `QuicFuscateEngine`, lifecycle/state machine, commands/events/stats callbacks.
- `src/engine/qkey.rs` - QKey generation/parsing/id derivation and error types.

Production implementations root:
- `src/implementations/mod.rs` - implementation namespace for client/server production runtimes.

Client implementation (`src/implementations/client/`):
- `src/implementations/client/mod.rs` - `ClientRuntime`, state machine, subsystem composition.
- `src/implementations/client/backend.rs` - unified cross-platform client backend API and state/stats/error model.
- `src/implementations/client/connection.rs` - client connection wrapper around `QuicFuscateConnection`.
- `src/implementations/client/integration.rs` - integration test scaffolding (`MockServer`, `TestClient`, `TestHarness`).
- `src/implementations/client/io_driver.rs` - async packet hotpath driver and performance counters/thresholds.
- `src/implementations/client/killswitch.rs` - platform kill-switch lifecycle and backend execution.
- `src/implementations/client/profile.rs` - standalone profile persistence/load/save and profile manager; deterministic ID ordering, client-owned same-directory `create_new` temporary files, POSIX `0600` sensitive-file mode, temporary-file `sync_all`, atomic replacement, Unix parent-directory sync, guarded cleanup, and dirty-state retention on failed publication are owned here (TODO-662); production ClientRuntime/CLI/desktop/admin callers remain absent.
- `src/implementations/client/quality.rs` - connection quality and bandwidth tracking utilities.
- `src/implementations/client/runtime.rs` - Tokio runtime creation/shared runtime helpers.
- `src/implementations/client/subsystems.rs` - subsystem initialization glue.
- `src/implementations/client/platform/mod.rs` - platform abstraction root and platform selection.
- `src/implementations/client/platform/traits.rs` - platform backend trait contracts (TUN/routes/DNS/privileges).
- `src/implementations/client/platform/linux.rs` - Linux platform backend.
- `src/implementations/client/platform/macos.rs` - macOS platform backend.
- `src/implementations/client/platform/windows.rs` - Windows platform backend.

Server implementation (`src/implementations/server/`):
- `src/implementations/server/mod.rs` - `ServerRuntime`, shared server-domain ownership, embedded host-resource ownership, standalone runtime bootstrap, server state/stats, and orchestration root. Embedded and standalone server flows now both derive accept/remove/expiry/session-traffic semantics from the same shared domain core, with the standalone path bootstrapping its live state, accept loop, and optional TUN directly through `ServerRuntime` instead of open-coded setup in `main.rs`.
- `src/implementations/server/accept.rs` - production accept loop, per-IP limits/backpressure/reject reasons.
- `src/implementations/server/admin.rs` - Unix admin socket protocol, handler contracts, and centralized admin-visible client snapshot projection (`ClientSnapshot` -> `ClientInfo`) for the live CLI server path. Canonical admin IDs use `session:<id>` when the live server domain has a session owner; `remote:<addr>` remains only as compatibility input and as auxiliary transport metadata.
- `src/implementations/server/admin_http.rs` - HTTP admin server, auth/session API, config and QKey endpoints.
- `src/implementations/server/admin_logs.rs` - in-memory admin log buffer and line model.
- `src/implementations/server/ddos.rs` - stateless source/CID/credential-bound QUIC Retry token issuance, validation, and typed enhanced-admission outcomes.
- `src/implementations/server/fsutil.rs` - atomic file write helper (`atomic_write_file`) used by server persistence paths.
- `src/implementations/server/ip_pool.rs` - server-side tunnel IP allocation pool.
- `src/implementations/server/limits.rs` - rate limiting and connection limiting primitives.
- `src/implementations/server/metrics.rs` - runtime metrics registry and HTTP metrics server surface (`MetricsServer` active in CLI/runtime, `GlobalMetricsServer` retained for test/compat coverage).
- `src/implementations/server/qkey_registry.rs` - persistent QKey records, ids, token hash management.
- `src/implementations/server/qkey_registry_storage.rs` - versioned authenticated QKey registry envelope, zeroizing keyring, atomic migration, recovery, and rotation.
- `src/implementations/server/routing.rs` - routing/NAT/forwarding integration and WAN interface detection.
- `src/implementations/server/session.rs` - session ids, session state and session manager.
- `src/implementations/server/systemd.rs` - systemd-oriented service/unit integration helpers.

Audit module (`src/audit/`):
- `src/audit/mod.rs` - one bounded asynchronous audit owner with producer-side JSON-encoded UTF-8 payload bounds, non-blocking producers, schema-v2 typed events, SHA-256 chaining, deterministic segment rotation/retention, atomic durability checkpoints, restart recovery, observable queue/payload/persistence counters, and schema-v1 compatibility. `verify-audit-log <path>` verifies the complete retained set. Every audit artifact is a mode-`0o600` regular file owned by the runtime identity.
- `src/bin/qf-audit-probe.rs` - concurrent release probe for durable throughput, bounded-worker counters including payload rejections, shutdown/restart continuity, and end-to-end verification.

Optimize submodules (`src/optimize/`):
- `src/optimize/brain.rs` - optimize helpers used by brain/statistical hotpaths.
- `src/optimize/compress.rs` - compression-oriented acceleration primitives.
- `src/optimize/crypto/mod.rs` - optimize crypto namespace root.
- `src/optimize/crypto/aegis.rs` - AEGIS acceleration kernels.
- `src/optimize/crypto/morus.rs` - MORUS acceleration kernels.
- `src/optimize/crypto/planner.rs` - crypto backend planning and dispatch helpers.
- `src/optimize/iter.rs` - SIMD-backed reduction helpers.
- `src/optimize/memory.rs` - memory pool and allocation tuning internals.
- `src/optimize/random.rs` - test/compat random helper paths; not the canonical security entropy API.
- `src/optimize/sort.rs` - rust-parity/test-only SIMD sort/argsort helpers.
- `src/optimize/stealth.rs` - stealth acceleration helpers.
- `src/optimize/string.rs` - string/text acceleration helpers.
- `src/optimize/telemetry.rs` - global telemetry counters and snapshot/export helpers.
- `src/optimize/transport.rs` - transport acceleration helpers.
  - Runtime-owned entrypoints: `aggregate_congestion(...)` for rolling congestion-window summarization in `src/core.rs` (+ `src/core_parts/`), and `decode_packet_number(...)` for packet-open PN reconstruction in `src/transport/packet.rs`.
  - Parity/test-only helpers: bitmap range ops, ECN popcount, ACK-range search, and stream-frame parsing acceleration are gated behind `cfg(any(test, feature = "rust-tests"))`.
- `src/optimize/udp.rs` - UDP fastpath helper layer.
- `src/optimize/unsafe.rs` - unsafe FFI backend for zstd compression.
- `src/optimize/uring_batch.rs` - io_uring batch sender and runtime-owned blocking worker (Linux-only, feature-gated).
- `src/optimize/simd.rs` - SIMD dispatch and capability detection helpers.
- `src/optimize/mod.rs` - module root (ConstBuffer, ConstPacketPool, SIMD dispatch entry points).
- `src/optimize/x86_sse2.rs` - x86 SSE2-specific compatibility and helper kernels.

SIMD submodules (`src/simd/`):
- `src/simd/arm_stream.rs` - ARM stream-oriented SIMD helpers.
- `src/simd/arm_varint.rs` - ARM varint SIMD helpers.
- `src/simd/x86_ack.rs` - x86 ACK-related SIMD helper path.
- `src/simd/x86_header.rs` - x86 header parse/validate SIMD helper path.

Transport submodules (`src/transport/`):
- `src/transport/config.rs` - transport configuration surface.
- `src/transport/connection/` - core transport connection state machine and send/recv path. Includes in-order Stream fast path (sequential data bypasses recv_frags BTreeMap, copies directly to recv_buf) and hybrid ACK/loss range draining for sent-packet accounting: sparse/narrow ACK ranges use `BTreeMap::extract_if`, while large contiguous ACK ranges and loss prefixes use `BTreeMap::split_off`. Stored frames use `Frame<'static>` with `Cow::Owned`.
- `src/transport/frames.rs` - frame encoders/decoders and canonical ACK block logic. `from_bytes()` returns `Frame<'a>` with `Cow::Borrowed` data fields for zero-copy parsing; construction sites use `Cow::Owned`.
- `src/transport/h3.rs` - HTTP/3 state machine (streams, QPACK, events, MASQUE wiring).
- `src/transport/packet.rs` - QUIC packet parse/build, encryption/decryption glue.
- `src/transport/pn.rs` - packet number and varint helpers.
- `src/transport/recovery.rs` - loss detection/recovery controller.
- `src/transport/batch.rs` - explicit rust parity/test-only batched IO surface, not part of the normal runtime transport path.
- `src/transport/udpfast.rs` - narrowed UDP fastpath compatibility layer used by harness/XDP-compat coverage; internal buffer/counter machinery is not part of the public runtime contract.
- `src/transport/anti_replay.rs` - 0-RTT strike register (SHA-256 fingerprint dedup, Bloom fast-negative, FIFO ring eviction).
- `src/transport/cc/mod.rs` - pluggable CongestionController trait and CcImpl dispatch.
- `src/transport/cc/reno.rs` - RFC 6582 NewReno implementation.
- `src/transport/cc/bbr2.rs` - BBR v2 standalone implementation (IETF draft-ietf-ccwg-bbr). Four-state machine (Startup/Drain/ProbeBW/ProbeRTT), windowed max-bandwidth filter, loss tracking via EWMA. No external crate dependency.
- `src/transport/cc/bbr3.rs` - BBR v3 implementation (default CC algorithm).
- `src/transport/cc/stealth_shaper.rs` - universal CC wrapper (browser traffic gains + jitter).
- `src/transport/xdp.rs` - internal AF_XDP and compatibility/test machinery. This is not a public transport mode surface; `FastPathTransport` plus its segmented/coalesced helpers remain private compat/test machinery, and AF_XDP stays behind `internal_af_xdp_experimental`.

### Governance Overview
- Cross-cutting engineering principles and policies: see "Governance (Canonical)".
- Contributions: see `docs/CONTRIBUTING.md` for guidelines and PR requirements.
- Linux-only verification tracks: Linux-specific tests and fast-path benchmarks are retained as optional reference tracks.
- Runtime/implementation depth for stealth, transport, optimization, and FEC belongs to the dedicated technical sections below.

## Documentation Index (Aggregated)
This section points to technical documentation and READMEs living under `docs/`. It does not cover the GitHub root README.

Key pointers:
- Usage and suite quickstart - see "Usage".
- Governance and deterministic workflow - see "Governance (Canonical)".
- Example configuration - see "Configuration Reference (Full)".

---
## Build & Dependencies (Current)

There is no external vendor workflow. All functionality (transport, stealth, FEC, crypto) is implemented under `src/` and built with Cargo. The primary Rust validation workflow is `.github/workflows/ci.yml`; Clippy Matrix, Windows Omega, and Release Build are separate workflow surfaces.

### CI Compilation Caching Contract

The current workflows do not configure sccache or any equivalent compiler-result cache. No workflow sets `RUSTC_WRAPPER`, `SCCACHE_GHA_ENABLED`, or a compiler-cache action. Existing `actions/cache@v6` steps cache Cargo registries, Git dependencies, selected `target/` directories, and Criterion baselines; these are directory caches and are not evidence of reusable compiler results.

Current Rust compilation boundaries are spread across the following workflow families:

| Workflow family | Rust work | Current cache contract |
| --- | --- | --- |
| `ci.yml` application, build, Windows, feature, fastpath, traffic, security, fuzz, and benchmark jobs | Cargo metadata/check, Clippy, debug and release builds, tests, fuzz targets, audits, and benchmarks | Registry/Git/selected `target/` or Criterion caches in selected jobs; no compiler cache |
| `clippy-matrix.yml` | Locked all-target Clippy over the feature matrix | Registry/Git/`target/` directory cache; no compiler cache |
| `windows-omega-e2e.yml` | Windows Wintun build, test compilation, and native tests | Registry/Git/`target/` directory cache; no compiler cache |
| `release.yml` server and desktop jobs | Linux and ARM64 server builds plus macOS/Linux/Windows Tauri check, Clippy, and packaging | Registry/Git/`target/` cache for server bundles; desktop packaging has no compiler cache setup |

Cache keys include one or more Cargo.lock files and, in several jobs, the runner OS. They do not constitute a single toolchain-aware sccache key or prove cross-platform hit correctness. Cargo's own fingerprints and the locked build commands remain the current correctness boundary. The repository therefore makes no current claim for compiler-cache hit rate, false-hit absence, cache failure propagation, or the historical 30% improvement claim from TODO-155. That historical claim is retired by TODO-761; the archived task body is retained and labeled historical.

### Rust Toolchain Support Policy

QuicFuscate follows a pinned-stable-only support policy. `rust-toolchain.toml` and `config/tool-versions.env` select Rust `1.97.1` for the root crate, CI, release checks, and the Tauri host. The root and Tauri manifests intentionally omit `rust-version`, and no MSRV CI lane exists; consumers must use the pinned baseline or a newer compatible stable compiler at their own risk. The fuzz manifest uses the separate nightly lane and is not MSRV evidence. The source uses modern standard-library APIs including `OnceLock`, `LazyLock`, `std::io::Error::other`, `Option::{is_some_and,is_none_or}`, and integer `is_multiple_of`, so an older compiler floor must not be inferred from the 2021 edition or dependency metadata. The unresolved fuzz manifest path remains owned by TODO-758.

Build/runtime behavior for TLS fingerprint inputs is documented in the TLS boundary section; see "TLS Boundary: rustls protocol with optional cover overlay -> Fingerprint Source Model".

### Building Binaries (macOS, Linux, Windows)

Platform builds are executed from `src/` via consolidated scripts:

- `./scripts/build/build-pgo-release.sh` - PGO-optimized release build (optional `--features "io_uring zero_copy_dgram"`, optional `--output-dir DIR`)
- `./scripts/build/build-server-bundle.sh` - Server deployment bundle
- `./scripts/tests/build/build-check.sh` - Format/Clippy/Compile/Test/Bench compilation
- `./scripts/tests/build/build-env-doctor.sh` - Toolchain diagnostics

Each invocation creates a unique evidence directory at `scripts/out/build/pgo-<UTC>-<random>/` (or below the caller-provided `--output-dir`). The directory contains the copied `quicfuscate` binary, `manifest.json`, `merged.profdata`, `profile-data/*.profraw`, `workloads.ndjson`, phase logs, and the run-scoped Cargo target. `manifest.json` uses schema `quicfuscate.pgo-release.v1` and records the run ID, create-new artifact ownership, source revision and dirty state, feature set, toolchain versions, build argv/environment, workload and profile counts, merge validation, final binary size, and SHA-256. The helper never deletes a global or another run's profile directory; interrupted and failed runs retain their bounded diagnostics and exit nonzero. `--features` adds to the always-enabled `benches` feature, while `--output-dir` changes only the evidence root.

#### TLS Profile Sidecars (Generating and Verifying)
These utilities are only relevant if you maintain external base64 ClientHello dumps (for example in `browser_profiles/`). The runtime does not require on-disk profiles because it generates ClientHello bytes in memory.

- Generate sidecars snapshot: `./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh` (writes to `scripts/out/utils/.../sidecars/`)
- Verify all profiles: `./scripts/tests/utils/util-e2e-verify-all.sh` (optional `--sidecars-dir <scripts/out/.../sidecars>` to verify snapshot sidecars)

Tool detection and portability
- Base64: The utilities auto-detect the correct decode flag at runtime (GNU `base64 -d`; BSD or macOS `base64 -D`) and always read input via stdin.
- Hashing: Uses `shasum -a 256` when available, otherwise `sha256sum`. Only the first whitespace-delimited field (hex digest) is compared.
- Locations: External dumps are discovered under top-level `browser_profiles/` (preferred). Sidecars are written next to the dumps.

Tips
- Use `./scripts/tests/utils/util-e2e-verify-current.sh` to validate only the active profile, selected via `QUICFUSCATE_BROWSER` and `QUICFUSCATE_OS` (optional `--sidecars-dir`).
- The decode and verify helpers operate locally and do not perform any network I/O.

### AEGIS
- Integrated internally in `src/crypto/`; validated via integration tests in `scripts/tests/rust/rt-baseline-oracles.rs`.
- Workflow: develop -> test -> clippy. Deterministic, offline; run in repo root.
- Data-plane AEAD selection can be overridden via config (`[crypto] aead_preference` / `force_aead`) with canonical product-family choices `aegis-128l` and `morus`; `aegis-128x4` and `aegis-128x8` are internal backend names, not supported runtime config values. Initial/Handshake remain AES-128-GCM for QUIC long-header compatibility.
- `src/profile.rs` is a test/compat alias surface for `Aegis128Profile` and converts to/from `simd::CryptoAeadPlan` via `select()`/`select_for_len()` helpers. It is gated behind `cfg(any(test, feature = "rust-tests"))` and is not part of the default product-facing crate surface.

We do not list the crate's file structure exhaustively; instead we focus on the essential aspects and how to run the tests.

#### Rationale & Changes
- Why:
  - AEAD-first design with strong performance (AEGIS-128L) and constant-time tag verification.
  - Security behavior: on authentication failure (wrong tag/AD/nonce) an error is returned; no plaintext is produced.
  - Fully internal retained AEGIS runtime implementation; baseline-oracle coverage exists separately and does not define runtime ownership.
- What:
  - Internal implementation in `src/crypto/`: `Aegis128L` with retained internal batching backends `Aegis128X4` / `Aegis128X8`, plus `Morus1280_128`.
  - Tests:
    - `scripts/tests/rust/rt-baseline-oracles.rs` covers baseline vectors and oracle-style roundtrips.
    - `scripts/tests/rust/rt-security-suite.rs`, `scripts/tests/rust/rt-property-suite.rs`, and `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs` are the primary retained proof surfaces for the custom runtime contract and backend parity.
  - Tooling: central runner `./scripts/tests/suites/test-crypto.sh` executes crypto tests and Clippy with strict `-D warnings`.
    - Manual invocation (equivalent in repo root):
      - `cargo test`
      - `cargo clippy -- -D warnings`

#### Overview and Quick Start
Use the dedicated test script to run crypto tests and Clippy locally:

```bash
./scripts/tests/suites/test-crypto.sh
cargo test
```

#### Step-by-Step Guide
1. Install prerequisites: the pinned Rust `1.97.1` toolchain with Cargo.
2. Run the test script: `./scripts/tests/suites/test-crypto.sh`.
3. Manual invocation (in repo root):
   - `cargo test`
   - `cargo clippy -- -D warnings`

#### Integration Guidelines and Optimization Strategy
- Data-plane AEAD follows `CryptoAeadPlan` from `src/simd/` and is resolved once in `src/crypto/` into concrete packet dispatch wrappers.
- On tag failure: constant-time verify -> error; no plaintext is emitted.
- Keep cipher concerns isolated; avoid mixing AEGIS logic into transport code.
- Keep performance- and safety-critical crypto changes covered by `scripts/tests/suites/test-crypto.sh`.

### Accelerate Module Integration
The accelerate module provides the retained acceleration re-export surface for runtime-owned and compat/test-only subsystems:

#### SIMD Policy Dispatch (Accelerate Module)
The retained `accelerate::*` re-export surface exists to keep internal runtime call sites and
explicit Rust parity coverage coherent without compiling duplicate module trees. It should not be
read as a broad normal-build public API matrix. Internal AVX10 preview support remains behind the
internal Cargo feature `internal_avx10_preview`, while `FeatureDetector` exposes the resulting
runtime profile through the canonical SIMD telemetry counters.

#### Performance Metrics for Acceleration
- **Performance counters**: Track SIMD utilization via global atomic counters in `optimize::telemetry`
- **Feature detection caching**: Efficient CPU feature detection with thread-safe caching
- **Runtime dispatch optimization**: Minimize overhead of selecting optimal implementations

```rust
use quicfuscate::optimize::telemetry;

// Access acceleration telemetry via export
let text = telemetry::export_telemetry_text();
// Contains counters: SIMD_OPS, AVX2_OPS, NEON_OPS, SVE2_OPS, etc.
```

#### Hardware Acceleration Topology (Kernel Map)

- `src/optimize/`
  - FeatureDetector (CPU features -> `CpuProfile`)
  - Central SIMD dispatch helpers (`SimdDispatch`), MemoryPool, telemetry
  - ARM: `xor_repeating_key_32` provides a dedicated SVE2 kernel with key rotation; NEON serves as fallback
- `src/simd/`
  - Acceleration planner (`planner::AccelerationPlanner`) with per-domain plans
  - CryptoAeadPlan (LAesni/LNeon/Morus by default; wider plans exist but are not selected by default)
  - QPACK Huffman encoding/decoding: runtime dispatch includes AVX2 (x86), NEON (ARM) and an SVE2 wrapper (encode/decode) with scalar fallback
  - QUIC varint encode/decode & header validation dispatch: SVE2 (VL-scalable predicates) -> NEON -> scalar; `transport::pn` uses these paths directly.
  - Bitstream pack/unpack: NEON fast paths for bit widths 1-8; SVE2 wrapper routes to NEON.
  - Core popcount: NEON (`vcntq_u8` + horizontal sum); SVE2 wrapper present.
- `src/accelerate.rs`
  - Thin re-export of `src/optimize/*` (transport_io, random, iter, sort, string, compress, brain, stealth, transport, memory). Implementations and telemetry live in optimize modules; accelerate paths remain stable.
- `src/fec/`
  - Versioned active-1-RTT framing in `wire.rs`; bounded receiver-owned epoch/window state and deterministic repair reconstruction
  - RLNC/Streaming encoders/decoders using scalar/AVX2/NEON/SVE2/SSSE3 kernels; GF4 uses a fused multiply-XOR path and GF16 uses carryless polynomial multiplication plus one process-wide inverse table for bounded deterministic row construction
  - Adaptive decoder policy: Gaussian elimination for small systems (<32 equations), Wiedemann for larger sparse systems with Gauss fallback
  - Wiedemann/Berlekamp-Massey and bitsliced GF multiplication on ARM NEON are always available (feature `internal_wiedemann` enables Wiedemann test coverage); Berlekamp-Massey has a VL-aware SVE2 path (`FEC_BERLEKAMP_SVE2_OPS` telemetry), otherwise falls back to NEON/scalar.
  - SVE2-aware matrix multiply uses real VL-SVE2 XOR-stores; SSSE3 dispatch added (`matrix_multiply_ssse3`) falling back to scalar only for `X86_P0a`.
- `src/crypto/`
  - AEAD glue; consumes FeatureDetector/plan at instantiation for runtime selection. Retained data-plane packet AEADs use enum dispatch, with boxed dispatch retained only for Rustls packet-key adapters and public benchmark/test helper APIs.
- MORUS-1280-128 scalar and SIMD backends are instrumented via `MORUS1280_SCALAR_OPS`, `MORUS1280_SSE2_OPS`, `MORUS1280_SSSE3_OPS`, `MORUS1280_SSE41_OPS`, `MORUS1280_SSE42_OPS`, and `MORUS1280_NEON_OPS`.
  - ChaCha20-Poly1305: ChaCha keystream SIMD XOR (SSE4.1/SSSE3->AVX->AVX2->AVX-512, NEON & SVE2), Poly1305 MAC dispatch (SSE2/AVX2/AVX-512, NEON/SVE2)
  - AES-128-GCM: `Aes128Ctx` caches round keys once; CTR uses 4-lane AESNI/AESE batches, SSSE3 hosts use SIMD fallback (`aes128_encrypt_block_ssse3`, `ctr_xor_ssse3`, telemetry `AES_BLOCK_SSSE3_OPS`/`AES_CTR_SSSE3_OPS`), NEON/SVE2 use AESE/PMULL paths, and non-SIMD CPUs use the scalar T-Table.
  - SHA-256/HMAC: `Sha256Plan` streams 64-byte blocks zero-copy into the `sha2-asm::compress256` backend (batch size 1 for AVX2, 2 for VNNI), places T0/T1 prefetches ahead and prioritizes AVX2/VNNI -> SHA-NI -> NEON/SVE2. Telemetry logs all paths (`SHA256_*`, `HMAC_SHA256_*`).

### Core Traits Architecture

#### Engine and Runtime Control Types

The canonical cross-layer runtime contracts are exposed through the Engine and observer systems:

- `engine::EngineCommand` and `engine::EngineEvent` provide typed control-plane mutations and status/event delivery.
- `engine::EngineState` and `engine::EngineStats` are the authoritative lifecycle and runtime metric surfaces for embedding integrations.
- `brain::DeepIntegrationOrchestrator` coordinates server-push and adaptive control hints when orchestrator coupling is enabled.

Representative API surface:

```rust
pub enum EngineCommand {
    Start,
    Stop,
    Connect,
    Disconnect,
    Reconnect,
    SetStealthMode(StealthMode),
    SetFecMode(FecMode),
    SetCongestionControl(CongestionControlAlgorithm),
    SetTrafficPadding(bool),
    SetTimingObfuscation(bool),
    SetZeroRtt(bool),
    GetTunCapabilities,
    GetState,
    GetStats,
}

pub enum EngineEvent {
    StateChanged(EngineState),
    Connected,
    Disconnected(DisconnectReason),
    Error(EngineError),
    StatsUpdated(EngineStats),
    StealthEscalated { level: String },
}
```

#### Transport Observer Pattern

```rust
pub trait TransportObserver: Send + Sync {
    fn on_ack(&self, ack_delay: u64, ranges: &[(u64, u64)]) {}
    fn on_packet_recv(&self, pn: u64, pt_len: usize) {}
    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {}
    fn apply_policy(&self, conn: &mut crate::transport::Connection) {}
}
```

`FecTransportObserver` is the production observer used for transport-to-FEC coupling. It samples ACK/ECN signals, maintains ACK-delay smoothing for FEC cadence decisions, and syncs only FEC-owned transport deltas (`set_fec_*` and `take_fec_control_delta()`). Generic transport actuators such as ACK threshold and external pacing are no longer written by the FEC observer; those stay on the transport/stealth adaptive path, while `core.rs` periodically pulls the observer's FEC cadence/redundancy view into `AdaptiveFec`.

#### TLS Provider Interface
```rust
pub trait QuicTlsProvider: Send + Sync {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError>;
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError>;
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError>;
    fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)>;
    fn poll_secrets_and_install(&mut self, crypto: &Arc<RwLock<CryptoContext>>) -> Result<(), ConnectionError>;
    fn handshake_complete(&self) -> bool;
    fn alpn(&self) -> Option<&str>;
    fn peer_cert(&self) -> Option<Vec<u8>>;
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError>;
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)>;
    fn export_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, ConnectionError>;
    fn get_quic_transport_params(&self) -> Vec<u8>;
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError>;
    fn key_update(&mut self) -> Result<(), ConnectionError>;
    fn provider_name(&self) -> &str;
    fn supports_ch_override(&self) -> bool;
    fn apply_ch_override(&mut self, template: &[u8]) -> Result<(), ConnectionError>;
}

#### TUN Device Abstraction

See `src/interface.rs` for platform-specific implementations and factory registration details.
```rust
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mtu(&self) -> u16;
    fn read_contract(&self) -> TunReadContract;
    fn set_mtu(&self, mtu: u16) -> io::Result<()>;
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
}
```

`TunReadContract::NonBlocking` means `read()` returns promptly with data,
`WouldBlock`, or another result. `TunReadContract::Blocking` means a caller
must provide a dedicated reader owner and a cooperative shutdown wake-up.
The trait default is `Blocking`, which makes unverified external backends fail
closed in the generic client async loop.

#### SIMD Policy Dispatch (Trait Layer)

```rust
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}
// Select best implementation at runtime via optimize::dispatch() or dispatch_bitslice().
```

#### AEAD Cipher Traits

```rust
pub trait AeadOpen {
    fn open_with_u64_counter(
        &self, 
        counter: u64, 
        ad: &[u8], 
        buf: &mut [u8]
    ) -> Result<usize, ConnectionError>;
}

pub trait AeadSeal {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>
    ) -> Result<usize, ConnectionError>;
}

pub trait HeaderProtector {
    fn apply(&self, sample: &[u8], mask: &mut [u8]);
    fn remove(&self, sample: &[u8], mask: &mut [u8]);
    fn new_mask(&self, sample: &[u8]) -> [u8; 5];
}

pub trait KeyScheduleHooks {
    fn set_read_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
    fn set_write_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
}

#### Buffer Management Traits

```rust
pub trait BufFactory: Clone + Default + Debug {
    type Buf: Clone + Debug + AsRef<[u8]>;
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}

pub trait BufSplit {
    fn split_at(&mut self, at: usize) -> Self;
    fn try_add_prefix(&mut self, prefix: &[u8]) -> bool;
}

pub trait NameValue {
    fn name(&self) -> &[u8];
    fn value(&self) -> &[u8];
}
```

### Module Integration Examples

#### StealthBrain Integration with Transport
```rust
use quicfuscate::brain::{StealthBrain, CombinedObserver};
use quicfuscate::transport::TransportObserver;
use std::sync::Arc;

let brain = Arc::new(StealthBrain::new(Default::default()));
let fec_observer = /* Arc<dyn TransportObserver> */;
let observer = CombinedObserver::new(vec![
    brain as Arc<dyn TransportObserver>,
    fec_observer,
]);

// pass `observer` into the runtime path that creates the connection
```

#### Compression Integration
```rust
use quicfuscate::compress::{CompressionConfig, CompressionManager};
use quicfuscate::optimize::OptimizationManager;

let compress = CompressionManager::new(CompressionConfig::default());
let pool = OptimizationManager::new().memory_pool();

if compress.should_compress(payload.len(), rtt_ms, loss, bw_bps) {
    if let Some((block, used)) = compress.compress_to_pool(&pool, payload) {
        let compressed = &block[..used];
        // send compressed bytes
    }
}
```

Pool-backed compression and decompression return a plain `AlignedBox<[u8]>`; the caller must return a successful block through `MemoryPool::free()`. A direct `AlignedBox` drop deallocates the block without updating pool accounting. Error-path cleanup for compression, decompression, TUN reads, and batch frame encoding remains open under TODO-831; exact decompression-length validation remains TODO-603.

#### Unified TLS Provider Usage
```rust
use quicfuscate::qftls::create_provider;
use std::sync::{Arc};
use parking_lot::RwLock;

let crypto = Arc::new(RwLock::new(quicfuscate::transport::packet::CryptoContext::default()));
let mut provider = create_provider(is_server, crypto)?;
// provider now drives QUIC CRYPTO frames (RealTLS) and optional TLS Cover internally
```

#### Build System
- Pure Cargo build; no external system dependencies beyond the Rust toolchain.
- AEGIS and MORUS are implemented under `src/crypto/` and are part of the core build.

#### Custom TLS Hooks
Not applicable. AEGIS is a symmetric AEAD and does not expose TLS handshake hooks.

#### Browser Fingerprints
See "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model" for canonical runtime and optional external-dump behavior.

#### Advanced Optimizations
- Crypto hotpaths use Rust `#[target_feature]` gated intrinsics (`aes`, `sse2`, `avx2`, `vaes`, `neon`); runtime dispatch via `cpufeatures` and `FeatureDetector` selects the best backend. Hardware ISA names are not Cargo features and must not be used as hardware-proof selectors.
- AEGIS/MORUS implementations include unsafe blocks for SIMD lanes where necessary; all sensitive operations remain constant-time by design.
- Transport/H3 uses zero-copy iovecs, io_uring fast paths (feature `io_uring`, crate `io-uring` v0.7), pool-backed compression buffers, and aligned pools (`MemoryPool`) for minimal copies. The client `IoDriver` submits batch `SendMsg` work through the runtime-owned `UringBatchWorker` before falling back to `sendmmsg`; direct `UringBatchSender` remains the synchronous compatibility primitive. The client also uses pool-backed `UringRecvBatch` slots on Linux so inbound datagrams can enter FEC through `core::recv_pooled_block()` without an intermediate `Vec` copy. In FEC Zero mode, receive keeps the payload uniquely owned so the core avoids the copy-on-mutate fallback.
- Frame parsing is zero-copy: `Frame<'a>` uses `Cow<'a, [u8]>` for data fields, borrowing directly from the decrypted packet buffer in `from_bytes()`. Combined with the in-order Stream fast path (sequential data copies directly to recv_buf, skipping the recv_frags BTreeMap), the common-case receive path avoids heap allocation entirely. Vec-backed stream send flushes use `frames::write_stream_frame()` to encode directly from `send_buf` into the packet buffer, avoiding a temporary owned `Frame::Stream` payload allocation.
- ACK sent-byte accounting drains acknowledged and packet-threshold-lost ranges from `sent_packets_by_pn` without collect-then-remove passes. Sparse/narrow ACK ranges use `BTreeMap::extract_if`; large contiguous ACK ranges and packet-threshold loss prefixes use `BTreeMap::split_off`. ACK frames with many sparse ranges classify the packet-threshold prefix in one ordered drain pass, preserving largest-ACK RTT sampling and recovery/loss semantics while reducing repeated prefix walks.
- Stealth hotpaths (header/QPACK building and persona-driven shaping) prefer SIMD kernels with safe scalar fallback; mutex/atomic usage is minimized in hotpaths.

#### Feature Matrix (Crypto)
- The root manifest declares exactly 27 direct feature entries. Cargo metadata exposes 30 effective selectors because the optional dependencies `rcgen`, `time`, and `maxminddb` also remain available as implicit dependency selectors. Those three selectors are implementation dependencies, not user-facing product groups.
- Canonical feature taxonomy and consumer semantics:

| Class | Feature | Dependencies | Consumer or owner semantics |
| --- | --- | --- | --- |
| meta | `default` | `client`, `server`, `rate_limiter` | Canonical product build profile |
| product | `client` | none | Client role and CLI profile |
| product | `server` | `rcgen`, `time`, `maxminddb` | Server role, certificate generation, and GeoIP support |
| runtime | `io_uring` | `dep:io-uring` | Linux client/server async I/O path |
| runtime | `aggressive_inline` | none | Explicit optimization build knob |
| runtime | `compression_zstd_ffi` | `dep:zstd-sys` | Optional zstd FFI compression path |
| runtime | `orchestrator` | none | Brain/connection/stealth orchestration path |
| runtime | `prefetch` | none | Cache and transport prefetch hints |
| runtime | `rate_limiter` | none | Server admission and rate-limiting path |
| runtime | `std` | none | AEGIS standard-library compatibility branch |
| runtime | `stream_ring_buffer` | none | Stream transport ring-buffer path |
| meta | `throughput` | `stream_ring_buffer`, `prefetch`, `aggressive_inline` | Throughput-oriented runtime profile |
| runtime | `unsafe_rust` | none | Explicit unsafe optimization/build lane |
| runtime | `zero_copy_dgram` | none | Datagram buffer ownership fast path |
| test | `dev-certs` | `rcgen`, `time` | Development certificate generation |
| platform | `tun-windows` | none | Windows Wintun/WFP integration |
| platform | `tun-ios` | none | Reserved iOS platform selector; no current Rust consumer |
| internal | `internal_af_xdp_experimental` | none | Internal Linux AF_XDP experiment |
| internal | `internal_wiedemann` | none | Internal FEC Wiedemann policy |
| internal | `internal_avx10_preview` | none | Internal AVX10 preview dispatch branch |
| test | `rust-tests` | none | Rust integration and feature-gated test targets |
| test | `benches` | none | Criterion and benchmark target compilation |
| test | `masque-tests` | none | MASQUE-specific test branches |
| test | `tun-tests` | none | TUN example/test target contract |
| test | `simd-selfcheck` | none | SIMD parity and telemetry self-check target |
| meta | `test-suite` | `rust-tests`, `benches` | Aggregate test and benchmark compilation profile |
| meta | `experimental` | `internal_af_xdp_experimental`, `internal_wiedemann`, `internal_avx10_preview` | Aggregate internal-only profile |
| runtime dependency | `rcgen` | `dep:rcgen` | Implicit selector enabled by `server` or `dev-certs`; do not select directly |
| runtime dependency | `time` | `dep:time` | Implicit selector enabled by `server` or `dev-certs`; do not select directly |
| runtime dependency | `maxminddb` | `dep:maxminddb` | Implicit selector enabled by `server`; do not select directly |
- TODO-176's proposed public groups `cpu-simd`, `stealth`, `fec`, `crypto`, `transport`, and `test-crypto`, plus the historical `simd-all` selector, are retired and are not current Cargo features. Cargo must reject direct selection of each name. TODO-760 owns the separate hardware/SIMD semantics; this matrix makes no hardware proof or broad subsystem meta-feature claim.
- Product posture notes:
  - The canonical product contract is still the default `client`/`server` runtime.
  - Internal features must not be advertised as normal deployment knobs.
  - Decoder policy such as Wiedemann remains an internal FEC/runtime policy concern, not a top-level product identity.
  - Hardware selection is intentionally split into three contracts: Rust `#[target_feature]`/`#[target_feature(enable = ...)]` controls compiled ISA bodies; `RUSTFLAGS` with `-C target-feature=...` or `-C target-cpu=...` controls the build target; and `FeatureDetector`/`cpufeatures` controls runtime dispatch. No Cargo feature enables an ISA, and the feature matrix must not be used as hardware proof.
  - `simd-selfcheck` is a test-only Cargo feature for the `rt-simd-selfcheck` target. It validates parity and telemetry on the active build; it does not claim that a particular ISA was compiled or selected.

Examples
```bash
cargo test
cargo build --release
```

#### Runtime Dispatch (Selector)

At runtime, the data-plane AEAD plan is selected based on CPU features and measured backend policy (via `cpufeatures`, the internal `FeatureDetector`, and `simd::planner`). The build must select a target CPU or explicit Rust target features separately when an ISA-specific binary is required:

```bash
RUSTFLAGS="-C target-feature=+avx2" cargo build --release
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

```rust
use quicfuscate::simd::CryptoAeadPlan;

let plan = CryptoAeadPlan::select();
let selected = match plan {
    CryptoAeadPlan::Aegis128L => "aegis-128l",
    CryptoAeadPlan::Aegis128X4 => "aegis-128l (x4 backend)",
    CryptoAeadPlan::Aegis128X8 => "aegis-128l (x8 backend)",
    CryptoAeadPlan::Morus => "morus-1280-128",
};
```

Benchmarks
- Script: `./scripts/benchmarks/suites/bench-crypto.sh` - runs the explicit `--fast` native-cell smoke matrix or the complete architecture matrix and records the effective mode and selected cells in `results.json` under `scripts/out/benchmarks/`.
- Optional (feature-gated): build with `--features benches` to run the `crypto-bench` subcommand.

#### Automated Build and CI/CD
- The general CI workflow `ci.yml` runs frontend checks, frontend E2E, security audit, the release-version contract, app backend checks, release compilation and tests, fuzz target checks, non-duplicated feature-matrix tests, benchmark regression checks on pull requests, and Linux fastpath evidence.
- `scripts/audits/verify-simd-feature-contract.sh` is run by the CI feature matrix, the strict Clippy matrix, and the comprehensive audit. It proves that no hardware ISA name is declared as a Cargo feature, that `rust-tests,simd-selfcheck` remains a valid positive test contract, that `--all-features` remains metadata-valid, and that each removed hardware/meta selector is rejected by Cargo rather than silently accepted as hardware proof.
- `scripts/audits/verify-cargo-feature-taxonomy.sh` is run beside the SIMD gate by CI, the strict Clippy matrix, and the comprehensive audit. It checks the exact 27-entry manifest taxonomy, the 30-selector Cargo metadata surface including implicit optional-dependency selectors, every Rust cfg and target `required-features` reference, positive aggregate build profiles, and rejection of TODO-176's retired feature-group names.
- `scripts/audits/verify-web-admin-publish-contract.sh` is run by the CI release-contract job, the release version-contract job, and the comprehensive audit. It proves that `assets/web-admin/` is generated and ignored, checks the build/release/installer/E2E prerequisite ordering, and runs a bounded missing-`index.html` bundle negative probe without building or modifying UI sources.
- `scripts/audits/verify-tls-clienthello-contract.sh` is run by the CI release-contract job, the release version-contract job, and the comprehensive audit. It proves that the retired transport ClientHello storage/setters and injection helpers are absent, deterministic bytes remain metadata-only, rustls remains the wire owner, and canonical docs/tests describe the same boundary.
- The `app-backend-checks` job validates the native desktop backend without UI source edits: it builds the existing `apps/svelte-desktop` bundle for Tauri context, then runs `cargo metadata --locked`, `cargo check --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo test --locked` in `apps/tauri/src-tauri`.
- The `windows-core-checks` job caps Cargo at two jobs, checks and lints `tun-windows,rust-tests`, compiles its unit-test binary, provisions the integrity-checked upstream DLL beside that binary, executes ordinary tests plus serial privileged Wintun adapter/I/O/close and WFP packet-outcome/process-exit suites, independently verifies zero managed WFP objects even after a failed behavior step, rejects owned adapter or legacy firewall-rule residue, and uploads provenance plus Windows-build evidence. Run `30508948149`, job `90764941801` proves commit `afe46e0` with the complete native Wintun and WFP lifecycle green. Manual Windows-Omega runs `30535603045` and `30536002374` add two consecutive authenticated dual-stack Wintun/WFP data-plane proofs against one unchanged ARM64 server process. The `release-contract` job runs `scripts/audits/verify-release-version.sh` on pushes and pull requests.
- `.github/workflows/clippy-matrix.yml` runs the Rust clippy feature matrix on stable Rust with `-D warnings`.
- `.github/workflows/release.yml` runs only for `v*` tags or explicit manual dispatch. It builds required native x86_64 and ARM64 server bundles, optional signed macOS/Linux desktop artifacts, and a required signed Windows MSI. The Windows job enables `tun-windows`, provisions the same verified upstream DLL as a Windows-only Tauri resource beside the executable, administratively extracts every produced MSI, and verifies exactly one byte-identical DLL before upload. Tagged publication requires both server architectures and the Windows artifact and maps the MSI signature into `latest.json` as `windows-x86_64`.
- Current workflow status is reported by GitHub Actions for the active branch or release tag.

#### Local Development Workflow
- Use `cargo test` for unit/integration tests and the suite scripts under `scripts/tests/suites/` for end-to-end coverage.

#### Maintenance
- Track upstream changes; maintain constant-time implementations; integrate upstream test vectors where applicable.
- Keep crypto changes minimal and well-isolated; extend test vectors and suite coverage when touching hot paths.

---

### Core Module Functions

#### HTTP/3 Polling Functions
```rust
use quicfuscate::core::QuicFuscateConnection;

// Poll with custom body handler
conn.poll_http3_with(|data| {
    println!("{} bytes", data.len());
})?;
```

The H3 connection reuses one caller-owned 64 KiB STREAM receive buffer instead of allocating on
each poll. Its polling GC removes terminal stream IDs and MASQUE flow mappings together with the
transport stream state, and releases completed Server Push promises with their cover payloads.
The MASQUE DATAGRAM receive buffer is allocated once per H3 connection from the configured
transport UDP payload ceiling, capped at the QUIC maximum DATAGRAM size. FEC threshold selection
remains connection-local through the FEC configuration; H3 construction does not mutate process-global
environment state.

#### MASQUE Handler Registration
The current fork uses Core H3/MASQUE as the production VPN/TUN carrier inside the HTTP/3 stack.
There is no public `QuicFuscateConnection` setter surface such as
`set_masque_capsule_handler(...)`, `set_masque_datagram_handler(...)`, or
`set_masque_control_handler(...)` in the active API. Operational MASQUE behavior should therefore
be read from `src/core_parts/connection.rs` and `src/transport/h3_parts/connection.rs` rather than
from standalone connection-level callback registration.

#### Connection Management Functions
```rust
use quicfuscate::core::QuicFuscateConnection;

// Start validated migration toward a new peer path
let new_addr = "127.0.0.1:0".parse().unwrap();
let path_id = conn.migrate_connection(new_addr)?;

// Check connection state
if conn.is_established() {
    println!("Connection is active");
}

// Get connection statistics
let stats = conn.get_stats();
println!("RTT: {}ms, Delivery rate: {}bps", 
         stats.rtt.as_millis(), 
         stats.delivery_rate);
```

The low-level `transport::Connection::key_update()` returns a `Result`. When a TLS provider is
configured, the provider exclusively owns the write-key transition; a provider failure is
reported without rotating the transport fallback or toggling the short-header key phase. A
providerless test/compatibility connection uses its transport-owned 1-RTT secret. Repeated
`DataBlocked` and `StreamDataBlocked` notifications are coalesced per connection window and
stream window in the bounded control queue.


## Deployment

### Linux Server Deployment

Step-by-step guide for deploying QuicFuscate on a Linux server.

#### System Requirements
- Linux server (Ubuntu 22.04+ / Debian 12+ / RHEL 9+ recommended)
- Minimum 2 CPU cores, 2 GB RAM (4+ cores recommended for production)
- Pinned Rust `1.97.1` toolchain (for building from source)
- Root or sudo access for TUN device and firewall configuration

**System dependencies (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
```

**System dependencies (RHEL/Fedora):**
```bash
sudo dnf install -y gcc make openssl-devel
```

#### Building for Production
```bash
git clone <repo-url> && cd quicfuscate
cargo build --release
# Binary: target/release/quicfuscate
```

#### Service User and Binary Installation
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin quicfuscate
sudo mkdir -p /opt/quicfuscate/bin /etc/quicfuscate
sudo cp target/release/quicfuscate /opt/quicfuscate/bin/
sudo cp config/server-linux.default.toml /etc/quicfuscate/quicfuscate.toml
sudo chown -R quicfuscate:quicfuscate /opt/quicfuscate /etc/quicfuscate
sudo chmod 750 /opt/quicfuscate/bin/quicfuscate
sudo chmod 640 /etc/quicfuscate/quicfuscate.toml
```

#### Systemd Service
Create `/etc/systemd/system/quicfuscate.service`:

```ini
[Unit]
Description=QuicFuscate VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
Group=quicfuscate
ExecStart=/opt/quicfuscate/bin/quicfuscate server --config /etc/quicfuscate/quicfuscate.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_CHOWN CAP_SETGID CAP_SETUID
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/quicfuscate /var/lib/quicfuscate /var/log/quicfuscate

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quicfuscate
sudo systemctl status quicfuscate
```

#### TLS Certificate Setup

**Self-signed (testing):**
```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/quicfuscate/server.key \
  -out /etc/quicfuscate/server.crt \
  -days 365 -nodes \
  -subj "/CN=quicfuscate-server"
sudo chown quicfuscate:quicfuscate /etc/quicfuscate/server.{key,crt}
sudo chmod 600 /etc/quicfuscate/server.key
```

**Let's Encrypt (production):**
```bash
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d your-domain.com
# In /etc/quicfuscate/quicfuscate.toml:
#   cert_file = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
#   key_file  = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

Auto-renewal with service reload:
```bash
echo '#!/bin/bash
systemctl reload quicfuscate' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/quicfuscate.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/quicfuscate.sh
```

#### Firewall Configuration

**iptables:**
```bash
sudo iptables -A INPUT -p udp --dport 4433 -j ACCEPT
sudo iptables -A INPUT -i lo -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**nftables:**
```bash
sudo nft add rule inet filter input udp dport 4433 accept
sudo nft add rule inet filter input iif lo tcp dport 8080 accept
sudo nft add rule inet filter input tcp dport 8080 drop
```

**UFW:**
```bash
sudo ufw allow 4433/udp comment "QuicFuscate QUIC"
sudo ufw deny 8080/tcp comment "QuicFuscate admin - localhost only"
```

#### QKey Management

QKeys authenticate clients to the server. The server stores only SHA-256 hashes of tokens; the plaintext token is given to the client and never persisted on the server. In-memory issuance bytes, raw token text, decoded QKey JSON, decoded binary tokens, client configuration/profile copies, and live connection copies use explicit zeroizing owners. Registry hashing consumes the typed token owner and retains only the public QKey ID plus SHA-256 verifier.

**Generate a QKey:**
```bash
TOKEN=$(openssl rand -hex 32)
ID=$(openssl rand -hex 6)
echo "QKey ID: $ID"
echo "QKey Token: $TOKEN"
```

Register the QKey via the admin API or add it directly to the server configuration. In the client TOML:
```toml
[connection]
qkey_id = "<12-char-hex-id>"
qkey_token = "<64-char-hex-token>"
```

#### Logging Setup
```bash
sudo mkdir -p /var/log/quicfuscate
sudo chown quicfuscate:quicfuscate /var/log/quicfuscate
```

Configure in `/etc/quicfuscate/quicfuscate.toml`:
```toml
[logging]
mode = "normal"     # verbose | normal | minimal | no-log
level = "info"
log_to_file = true
log_file_path = "/var/log/quicfuscate/server.log"
log_to_stdout = false
format = "json"
max_file_size_bytes = 104857600
max_files = 5
```

For privacy-sensitive deployments, use `mode = "no-log"` for in-memory-only ring buffer with zero disk writes.

The effective `[logging]` section is parsed and validated before Tokio and before the single global logger is installed. File, stderr, RFC 5424 UDP syslog, and the admin ring buffer are sink properties of that logger and are never replaced by a later level change. File and syslog I/O run on one bounded 8,192-record worker queue; saturation drops the newest record and increments `logging::stats().dropped_records`, while sink failures increment `sink_errors` without recursive logging or process termination. Clean shutdown uses `logging::FlushGuard` to enqueue a barrier and wait up to five seconds for all earlier records and owned file/stderr flushes. File rotation retains `max_files` numbered generations and can be requested either by the authenticated `POST /api/logs/rotate` action or by the size threshold. Each request is a FIFO writer command with a bounded acknowledgement; records queued before the command are flushed before the acknowledgement. Unix SIGHUP first runs the existing validated `NextConnectionOnly` configuration reload and then independently reopens the file sink through the writer owner. This supports external `rename` and `copytruncate` logrotate workflows: perform the external pathname operation, then send SIGHUP. Reopen refreshes tracked size from the newly opened pathname, and failure is reported separately from configuration reload failure in logs and typed audit events. POSIX operational log files use the explicit `0o640` mode on initial creation, reopen, truncation, and the new active file after rotation, independent of the process umask. The production runtime calls `logging::init()` once; the isolated `qf-logging-probe` still contains a duplicate call tracked by TODO-674. TODO-812 now retains the temporary writer handle and sends `Shutdown` plus `join()` when global logger installation fails, so `LoggerAlreadyInstalled` is returned only after the temporary worker and its sinks have terminated.

The stable JSON format is NDJSON with required `ts`, `level`, `target`, and `msg` keys. Optional `file` and `line` keys are emitted when the `log::Record` provides them. `log_to_stdout` retains its compatibility name but writes to stderr for systemd/journald capture. `file_path` takes precedence over `log_file_path`; `syslog_addr` adds RFC 5424 UDP delivery; `module_levels` applies longest-prefix module filtering. Invalid levels, empty enabled paths, zero file-size bounds, zero ring capacity, port-zero syslog targets, and invalid module overrides fail startup before network or privileged runtime setup.

Audit persistence is configured independently:
```toml
[audit]
queue_capacity = 16384
max_segment_bytes = 67108864
max_segments = 8
flush_timeout_ms = 5000
```

`AuditOptions::validate()` is the single contract for product configuration and direct API use. `queue_capacity` is limited to `1..=65,536`, `max_segment_bytes` to `1..=134,217,728`, `max_segments` to `1..=64`, and `flush_timeout_ms` to `1..=60,000`; invalid values fail before path inspection, file creation, channel allocation, or worker spawn. `queue_capacity` bounds accepted commands by count, `max_segment_bytes` controls deterministic rotation, `max_segments` includes the active segment, and `flush_timeout_ms` bounds only enqueue plus acknowledgement waits, not the worker's underlying filesystem calls. The release `qf-audit-probe` adds `--flush-timeout-ms`, limits events to `1..=1,000,000` and producers to `1..=64`, reuses the shared persistence limits, and reports both effective options and all ceilings in its JSON result.

#### Common Operational Tasks
```bash
# Reload configuration
sudo systemctl reload quicfuscate

# After external rename/copytruncate rotation, reopen the active sink and reload config
sudo systemctl kill -s HUP quicfuscate

# View active connections
curl -s http://localhost:8080/api/status | jq .

# Check service health
sudo systemctl is-active quicfuscate
curl -sf http://localhost:8080/api/health || echo "Admin API unreachable"

# Follow logs
sudo journalctl -u quicfuscate -f

# Authenticated admin API force-rotation (send the deployment's session and CSRF headers)
curl -X POST http://localhost:8080/api/logs/rotate

# Update binary
sudo systemctl stop quicfuscate
sudo cp quicfuscate-new /opt/quicfuscate/bin/quicfuscate
sudo systemctl start quicfuscate
```

### Linux Install Script (systemd)

Preferred Linux install flow uses the scripts under `scripts/`:
- installer: `scripts/install/install-server-linux.sh`
- systemd unit template: `scripts/install/quicfuscate-server.service`
- server config template: `config/server-linux.default.toml`

FHS paths used by the installer:
- config: `/etc/quicfuscate/quicfuscate.toml`
- env (admin creds, bind, paths): `/etc/quicfuscate/quicfuscate.env`
- persisted admin auth: `/etc/quicfuscate/admin-auth.json`
- QKey registry encryption key: `/etc/quicfuscate/qkey-registry.key`
- web assets: `/usr/share/quicfuscate/admin-web`
- state (QKey registry): `/var/lib/quicfuscate/qkeys.json` (via `quicfuscate server --qkey-store`)

Installer flow is `scripts/install/install-server-linux.sh` together with `scripts/install/quicfuscate-server.service`.

The installer validates required commands, account compatibility, source binary, admin assets, config and unit templates, systemd paths, QKey key-source consistency, and TOML support before its first persistent mutation. It creates `quicfuscate:quicfuscate`, keeps `/etc/quicfuscate` and `/var/lib/quicfuscate` as `root:quicfuscate` mode `0770`, keeps individual config, environment, registry-key, and registry files at mode `0640`, and lets the daemon create `admin-auth.json` as mode `0600`. The service root-starts with primary group `quicfuscate` and a bounded effective/permitted setup set. It intentionally does not use `AmbientCapabilities`, which would also populate the inheritable set on every thread.

Linux server startup resolves `--drop-user` and `--drop-group` before opening privileged resources. Selectors containing only decimal digits are treated strictly as numeric UID/GID values; all other selectors are resolved as names through NSS. TLS certificate and private-key PEM are validated and retained in memory before the transition, so new connections never reopen a root-owned key file. After socket, TUN, and routing setup, the process clears supplementary groups, sets real/effective/saved GID and UID, clears effective/permitted/inheritable/ambient capabilities, and verifies every Linux thread has the target IDs, empty groups, zero capability sets, and `PR_SET_NO_NEW_PRIVS`. The destructive root-regain proof is isolated in `qf-privilege-probe`; it is not run inside the multi-threaded service. The shipped systemd unit root-starts with only `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_CHOWN`, `CAP_SETGID`, and `CAP_SETUID` in `CapabilityBoundingSet`, and the process removes all capabilities before accepting traffic. Service-manager confinement and privileged host-routing teardown remain platform responsibilities.

`quicfuscate capabilities --json --user quicfuscate --group quicfuscate --tun --listen-port 4433` reports real/effective UID and GID, saved UID and GID when the platform exposes a reliable saved-ID query, supplementary groups, effective/permitted/inheritable/ambient/bounding capability masks, `no_new_privileges`, target-account resolution, and readiness for the requested startup operations. Unsupported saved-ID fields are serialized as `null`; the report never infers them from effective IDs.

Idempotency behavior of `scripts/install/install-server-linux.sh`:
- Existing `quicfuscate.toml` is preserved (created only if missing).
- Existing `quicfuscate.env` entries are preserved; a missing QKey registry key-file source is appended without replacing the file.
- Existing `admin-auth.json` is loaded and preserved by the server across installer reruns.
- Existing `qkey-registry.key` is preserved. A missing key is generated from `/dev/urandom` as 32 raw bytes and installed as `root:quicfuscate` mode `0640`.
- Existing `qkeys.json` is preserved (created only if missing).
- Binary, assets, and unit template are reinstalled safely on reruns.
- `systemctl daemon-reload` is called on every install run.

Native disposable verification is owned by `scripts/tests/suites/test-linux-installer.sh` and `scripts/tests/suites/test-linux-installer-guest.sh`. The host harness uses temporary `systemd-nspawn` machines, signature-checked Debian 12 `debootstrap`, and AlmaLinux 9 BaseOS/AppStream with pinned signing-key fingerprint `BF18AC2876178908D6E71267D36CB86CB86B3716`. Its default path builds the release server inside AlmaLinux 9 with two Cargo jobs and no incremental compilation, then installs that exact binary in both guests. It proves every prerequisite failure before mutation, exact account and file metadata, systemd activation, zero capability sets after the runtime drop, preserved config and credentials on rerun, actionable journal output on invalid TLS material, recovery, byte-identical cross-distro installation, and allowlisted zero-residue teardown. Docker and redirected production paths are not used.

#### Reverse Proxy (Admin Web)

The admin panel is typically bound to localhost (`127.0.0.1:9000`) and exposed through a TLS reverse proxy.

Nginx example:
```nginx
server {
    listen 443 ssl http2;
    server_name admin.example.com;

    ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy example:
```caddy
admin.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

#### Health Checks (Server Deployments)

Service-level checks:
```bash
systemctl is-active quicfuscate.service
systemctl --no-pager --full status quicfuscate.service
journalctl -u quicfuscate.service -n 100 --no-pager
```

Socket/listener checks:
```bash
ss -lntup | rg quicfuscate
```

Admin API checks (session-based; Basic Auth is not accepted):
```bash
curl -fsS -c /tmp/qf-cookie -H 'Content-Type: application/json' \
  -X POST -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
  http://127.0.0.1:9000/api/login
curl -fsS -b /tmp/qf-cookie http://127.0.0.1:9000/api/status
curl -fsS -b /tmp/qf-cookie http://127.0.0.1:9000/api/metrics
```

## Usage

### Script-Based Operations
Execute specific functionality using dedicated scripts organized in purpose-built directories:

Common examples:
```bash
./scripts/tests/build/build-check.sh
./scripts/tests/utils/util-run-full-suite.sh
./scripts/tests/suites/test-core.sh
./scripts/tests/suites/test-crypto.sh
./scripts/tests/utils/util-e2e-verify-all.sh
```

Each script is self-contained and handles specific functionality. Scripts can be combined for complex workflows or executed individually for targeted operations. Use environment variables like `QUICFUSCATE_BROWSER` and `QUICFUSCATE_OS` to override the active fingerprint profile.

All scripts include a unified, minimal help handler accessible via `-h`, `--help`, or `help`. It prints `Usage: <script>` together with the first `# Description:` line found in the script, then exits early with code `0` and no side effects.

### Profiling Evidence Contract

The profiling runners are measurement entrypoints, not performance claims. Every invocation creates a unique run directory below the selected output root:

- `scripts/benchmarks/profiling-baseline.sh` records scenarios `a`-`c` through the UDP harness and scenarios `d`-`f` through the real loopback client/server. The connection scenarios use explicit FEC and cover-feature flags; there is no standalone CLI `stealth_mode` argument to claim.
- `scripts/benchmarks/profiling-tun-mode.sh` records TUN scenarios `g`-`k` and requires Linux, root, `tc`, `iperf3`, the release binary, certificates, `perf`, and both FlameGraph tools. Netem ownership begins only after a successful `tc qdisc add` and is removed only by the owning run.
- `scripts/benchmarks/profiling-zc.sh` is the canonical zero-copy entrypoint. It runs the real product server and client with `QUICFUSCATE_IO_URING_ZC=1` and `--telemetry`, then requires positive `quicfuscate_io_uring_zc_sends_total` and `quicfuscate_io_uring_zc_notifs_total` telemetry before a scenario can pass.
- `scripts/benchmarks/profiling-common.sh` owns schema version `1`, provenance, structured command serialization, tool-version capture, CSV quoting, process/readiness waits, iperf validation, telemetry validation, cleanup status, and flamegraph execution. Scenario and manifest files use exclusive creation and reject replacement.

Each scenario JSON records the source revision, executable SHA-256, host, kernel, tool versions, prerequisites, structured command identity, readiness evidence, process exit statuses, `perf` and flamegraph status, metric completeness, cleanup status, and UTC timestamps. `manifest.json` contains the same provenance and a result count for every emitted scenario. The only result values are `PASS`, `FAIL`, `SKIP`, and `UNAVAILABLE`.

Missing native prerequisites are `UNAVAILABLE`. Failed process startup, netem setup, traffic, metric extraction, perf capture, flamegraph generation, or cleanup is `FAIL`. Missing metrics are never serialized as `N/A`, and a CSV row cannot turn an incomplete run into a pass. `--dry-run` emits `SKIP` evidence without starting a process.

Generated output under `docs/profiling/` remains ignored by Git. The historical files in that boundary are external evidence only and do not replace the current tracked runner contract. Durable source truth is the runner, its schema, the fast negative fixture `scripts/tests/fast/test-profiling-evidence-contract.sh`, and this documentation. The fixture runs the portable gates locally and leaves privileged Linux process/netem branches conditional on real native prerequisites.

Example commands:

```bash
scripts/benchmarks/profiling-baseline.sh --dry-run --scenario a
scripts/benchmarks/profiling-tun-mode.sh --dry-run --scenario g
scripts/benchmarks/profiling-zc.sh --dry-run
scripts/tests/fast/test-profiling-evidence-contract.sh
```

### TUN interface example (feature-gated)
The TUN example is intentionally gated by both Cargo's `required-features = ["tun-tests"]` target contract and the example's crate-level cfg, so it does not affect default builds. It demonstrates external factory registration with an in-process test device; it is not a Wintun or NetworkExtension backend proof. The `tun-windows` and `tun-ios` features do not select this example.
```bash
# Run example demonstrating factory registration
cargo run --features tun-tests --example tun_factory_example
```

Notes:
- The example integrates with `MemoryPool` to exercise zero-copy paths.
- Platform backend coverage remains under the dedicated `tun-windows` and iOS/platform integration paths.

### Client

  ```
  quicfuscate client \
    --remote 203.0.113.1:4433 \
    --local 127.0.0.1:1080 \
    --profile chrome \
    --os windows \
    --cc-algorithm bbr3 \
    --front-domain cdn.example.com \
    --verify-peer \
    --config ./config/quicfuscate.toml
  ```

Telemetry metrics are disabled by default. Launch the binary with `--telemetry` to enable internal counters and expose a local snapshot at `/telemetry` through `metrics::spawn_telemetry_server()` (bind address `QUICFUSCATE_METRICS_ADDR`, default `127.0.0.1:9898`), or call `telemetry::export_telemetry_text()` programmatically.

#### Telemetry Metrics
Telemetry metrics exposed by `telemetry::export_telemetry_text()` include:

**MASQUE/Transport:**
- `quicfuscate_masque_capsule_00_total`, `quicfuscate_masque_capsule_21_total`, `quicfuscate_masque_capsule_22_total`

**Compression Module:**
- `quicfuscate_compress_attempts_total`, `quicfuscate_compress_success_total`
- `quicfuscate_compress_bytes_in_total`, `quicfuscate_compress_bytes_out_total`

**Memory/Pool:**
- `quicfuscate_body_pool_allocs_total`, `quicfuscate_mem_pool_hits_tls_total`, `quicfuscate_mem_pool_hits_queue_total`
- `quicfuscate_mem_pool_alloc_grow_total`, `quicfuscate_mem_pool_alloc_ephemeral_total`

**SIMD/Performance:**
- `quicfuscate_simd_usage_avx2_total`, `quicfuscate_simd_usage_avx512_total`

#### Client Runtime Orchestration

`implementations::client::ClientRuntime` wires the production client execution path:

- zero-copy `MemoryPool`,
- optional `TunInterface`,
- `StealthManager`,
- `AdaptiveFec`,
- `IoDriver`,
- optional `KillSwitch`,
- shared Tokio runtime state.

The client module separately exports `Profile`, `ProfileError`, and `ProfileManager` as a standalone profile-storage API. The current `ClientRuntime`, CLI, and desktop/admin surfaces do not own or call `ProfileManager`. New `Profile::from_qkey()` IDs are 32 lowercase hexadecimal characters backed by 128 bits of OS CSPRNG output; empty and duplicate IDs are rejected, while non-empty legacy IDs are preserved without automatic migration. `ProfileManager::save()` sorts records by ID, writes credential-bearing JSON to a client-owned same-directory `create_new` temporary file with POSIX mode `0600`, writes and syncs the complete temporary file, atomically replaces the destination, and syncs the parent directory on Unix before clearing the dirty flag. Windows uses `MoveFileExW` with replacement and write-through flags; Windows ACL policy remains outside this standalone API. A guard removes the current uncommitted temporary artifact on ordinary write or replacement failures, while artifacts left by process termination are ignored by `load()` and never treated as the destination. The temporary-file `sync_all` plus atomic replacement prevents torn JSON; parent-directory synchronization is also required and performed on Unix for power-loss durability of the directory entry. TODO-662 remains the owner of profile atomic publication and crash safety; TODO-671's cross-project mode inventory is resolved.

`KillSwitch` is implemented in `implementations::client::killswitch` with Linux nftables or iptables, macOS pfctl, and native Windows Filtering Platform management. Windows policy lives in `src/implementations/client/killswitch/windows.rs`: fixed persistent provider, sublayer, and filter identities are replaced in one BFE transaction across IPv4/IPv6 outbound transport layers. Windows places those layers at the top of the network layer, where they also classify third-party transports and raw packets while retaining the protocol and port fields needed for an exact VPN UDP tuple. Higher-weight loopback, exact VPN endpoint, and connected Wintun-LUID permits precede a lower-weight catch-all block in the same sublayer. Failed replacement aborts to the previous policy; process exit retains the last committed policy; explicit disable or stale cleanup deletes only the fixed QuicFuscate objects and exact legacy `netsh` rule identities. Native policy proof observes exact IPv4/IPv6 UDP payloads at the Wintun ring because a WFP block may discard an accepted socket send without returning `PermissionDenied`. CI run `30508948149`, job `90764941801` proves every packet state plus child-process exit retention, parent-process stale cleanup, and zero residue. Windows-Omega runs `30535603045` and `30536002374` prove the connected policy twice with encrypted QKey/MASQUE traffic, five IPv4 and five IPv6 tunnel pings, and zero post-run WFP or adapter residue against one unchanged server process. Linux resolves one validated backend at startup for both client kill-switch and server routing ownership. Omitting `security.firewall.backend` selects nftables when its live ruleset is accessible, then iptables only when the complete dual-stack toolchain is usable. An explicit `iptables` or `nftables` request fails closed when unavailable and is never replaced by the other backend.

Packet flow is unified across CLI and embedded paths:

- outbound: `TUN -> Stealth -> FEC -> QUIC`
- inbound: `QUIC -> FEC decode/recovery -> Stealth unwrap -> TUN`

Connection teardown is deterministic: handshake-timeout failure paths clean up the
client runtime before returning the engine to `Running`, and client disconnect
requests cancel owned I/O tasks before dropping sockets and TUN handles. This keeps
unreachable-server attempts from leaving detached TUN readers behind.

`--profile-seq` and `--profile-interval` feed the same runtime control path used by command/API overrides.

### Server

  ```
  quicfuscate server \
    --listen 0.0.0.0:4433 \
    --cert ./tls-cert.pem \
    --key ./tls-key.pem \
    --profile firefox \
    --os linux \
    --cc-algorithm bbr3 \
    --config ./config/quicfuscate.toml
  ```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

Use the `--config` flag to load a unified TOML file containing FEC, stealth and optimization settings. See the section "Configuration Reference (Full)" for details.

#### Server Runtime Orchestration

`implementations::server::ServerRuntime` is the canonical server runtime surface used by `engine::QuicFuscateEngine` and CLI standalone mode. It combines:

- engine/server configuration domains,
- memory pool and transport runtime,
- TUN bridging,
- session manager and IP pool allocation,
- NAT/routing management,
- rate/connection limiters,
- telemetry/metrics export surfaces.

`ServerRuntime` owns standalone UDP listener loop execution and is launched productively through `run_standalone(...)`; `run_loop(...)` remains internal runtime machinery. The same runtime entry is used by CLI standalone mode and embedded engine server mode.
Embedded `EngineMode::Server` is therefore a real headless live server runtime in the current codebase, not a bootstrap-only helper surface. It reuses the standalone listener loop and runtime ownership model, but does not expose the standalone admin service bundle by default. Construction and polling occur on the same dedicated Tokio runtime; the synchronous Engine owner receives its shutdown sender and shared metrics only after construction succeeds.
Engine server-mode stats now follow the same runtime truth: bytes, packets, and active-client counts are projected from runtime-owned `implementations/server::Metrics`, while server-side RTT and loss remain `0` until explicit server-owned producers exist.
Each `QuicFuscateEngine` retains one `Arc<GlobalMetrics>` acquired during construction, so repeated `stats()` refreshes read the shared registry without cloning the global `Arc` on every call.
Admin orchestration helpers (`ServerAdminCore`, `AdminAction`) live in `implementations/server`, so admin, reload, metrics, and shutdown wiring no longer depend on a CLI-local server state island.
Datagram admission is ordered and bounded: global packet cap -> GeoIP -> external blacklist -> one per-IP packet/byte bucket -> enhanced Retry policy. Interval-delta accepted PPS feeds a monotonic EWMA state machine with sustained activation and clear windows. Enhanced mode preserves only cryptographically established traffic at normal per-IP cost; half-open clients remain new traffic. New traffic consumes the configured higher token cost and requires a stateless QUIC Retry for supported Initial packets. Retry tokens bind source IP, original and Retry connection IDs, the public Initial credential, issuance time, and an HMAC. After validation, live authentication restores the public credential while RFC 9001 Initial keys derive from the Retry SCID carried as the retried packet's DCID. Stateless Version Negotiation remains connection-allocation-free but cannot bypass the global or source admission caps.
Configured GeoIP activation is fail-closed: `GeoIpBlocker::try_new` validates uppercase ISO alpha-2 codes, requires a regular non-empty database file, opens and fully verifies the MaxMind reader, and rejects non-country database metadata before runtime readiness. A disabled policy has neither path nor country set and takes a zero-cost allow branch. Database lookup/decode errors drop the datagram as `DdosDropReason::GeoIp` and increment explicit lookup-error telemetry. Health, admin status, JSON metrics, and Prometheus expose the actual `disabled|active` runtime state; typed activation failures are logged and propagated before readiness, while the `failed|not_ready` state remains available for an owned failed runtime. Configured activation failures propagate through `SharedServerDomain`, `LiveServerState`, `ServerRuntime`, and standalone startup instead of creating an allow-all runtime.
External blacklist synchronization accepts only HTTPS, applies request-timeout, streamed body-size, strict UTF-8, line-format, and unique-entry bounds, and preserves the active last-known-good set on every failure. An optional custom CA bundle is limited to a non-empty regular PEM file of at most 1 MiB and is parsed before use without disabling certificate validation. A validated replacement is atomically persisted as a bounded versioned cache before it becomes active; startup ignores stale, malformed, oversized, or unsupported cache state. Cache persistence can be disabled explicitly without disabling in-memory or remote policy.
Exact ARM64 source tree `856e99f2a5079bd02b2f3674a8c9be7ee27ce772` passes the privileged process gate on Omega. Release binaries `31b6e57377fc61e31ccf1857ace5f580aa16652ab8978d62d9ba67f1ad3981ed`, `ccd56fdebf8a646f0b5e44c058c1fa5e08abd616306a594eaa4458d60d30017f`, and `8c6cfbe2bd95a0d44eaf646ef938ce753c1eef662eefd42c72f30f9d471203a1` prove a pinned real MaxMind database, strict custom-CA HTTPS refresh, cache restart, failed-refresh retention, 820 controlled Initial packets, one activation and one clear, one Retry-protected handshake, and a pre-existing authenticated connection that exchanged 120 PING and 120 ACK packets across the flood. The measured server bounds were 10,340 KiB RSS growth and 240 ms CPU; the locally retained evidence archive SHA-256 is `26cd028e2222458550099e326a90f1889958365951039320ee53725b0e1bdc5f`. Candidate teardown left no TODO-540 process or source residue and did not restart or modify the independent server process. The final local source passes the complete workspace/all-target `rust-tests` matrix, including 1,999 library tests, strict all-target/all-feature Clippy, formatting, Bash/ShellCheck, runtime guardrails with zero critical findings, exact process evidence, diff hygiene, and protected-UI isolation.
Within the live server path, ownership is now intentionally split only along one line:
- `LiveServerDomain` owns remote/session/IP-pool/connection-limiter/packet-rate-limiter/snapshot state.
- `LiveServerState` owns active QUIC connection objects, the bounded per-IP QKey auth policy, pending QKey auth attempts, runtime QKey revocation state, and the SessionId-to-QKey tracker used to terminate active sessions on revoke. One monotonic attempt ID survives the Initial ID lookup through the encrypted HTTP/3 bearer result; success, failure, timeout, pre-auth close, and internal abandonment each complete it at most once. Explicit QKey revocation drains the tracker, queues a QUIC CONNECTION_CLOSE on each affected transport, and lets the next runtime flush/reconcile remove the closed session; revoked records use the validated `QUICFUSCATE_REVOCATION_RETENTION_SECS` window and are pruned at most every five minutes from housekeeping, with `quicfuscate_revocation_pruned_total` exposing the count; no inert automatic QKey-rotation scheduler is polled from housekeeping.
TODO-573 local evidence (2026-08-02): 12 focused revocation/tracker/race tests and the full workspace/all-target `rust-tests` matrix (2,023 tests) pass with strict all-feature Clippy. `scripts/out/tests/test-e2e-admin-web-20260802_004925/` proves productive QKey authentication, active-session close observed by the runtime client, revoked-key handling, and zero stale clients; `scripts/out/tests/qkey-auth-policy-20260802_004538/` proves bounded auth policy and flood behavior; `scripts/out/tests/qkey-registry-encryption-20260802_004754/` proves encrypted registry migration, restart, rotation, rejection, mode `0640`, secrecy, and zero residue.
The standalone path also delegates DCID-based live path rebinding, closed-client reconciliation, control-plane shutdown registration, and runtime reload normalization to `implementations/server`, so runtime lifecycle and bookkeeping now converge on one canonical server model.
Timeouts have distinct lifecycle owners. The transport derives its idle deadline from the configured `max_idle_timeout`; zero disables idle expiry. Expiry is terminal and silent at the QUIC layer, allowing closed-client reconciliation to release the session, IPv4/IPv6 pool addresses, QKey association, and policy state without emitting a CONNECTION_CLOSE frame. Standalone housekeeping separately reaps expired shared-domain sessions according to `client_timeout_secs`. `QKEY_AUTH_TIMEOUT` remains a short post-handshake gate for encrypted HTTP/3 bearer authentication rather than a replacement for either timeout. Its deadline starts once after QUIC/TLS establishment, so handshake latency cannot consume the authentication window.

#### Per-Session Bandwidth, Quota, and Fairness

Every accepted session owns one `BandwidthPolicy` with independent uplink/downlink token buckets, one shared UTC daily quota, one shared UTC calendar-month quota, and a deficit-round-robin weight. Zero rate plus zero burst disables rate limiting; zero quota means unlimited. Rate and burst must both be zero or both nonzero, and weight must be `1..=1000`; invalid startup, QKey, or admin policy fails closed.

Policy precedence is deterministic: validated global environment defaults apply at session creation, an optional persisted QKey policy replaces them only after encrypted bearer authentication, and a later authenticated admin update replaces the live effective policy. Policy updates preserve daily/monthly usage; only the explicit quota-reset route clears it. Session close, expiry, QKey revocation, and administrative kick remove the same state.

Uplink admission occurs after authentication at both MASQUE DATAGRAM and framed-H3 TUN boundaries. Unshaped downlinks with no session backlog use direct bandwidth admission and transport enqueue; shared shaping, rate backpressure, or transport backpressure enters one bounded pending owner: 256 packets, 384 KiB total, 32 packets per session, and five-second age. Weighted byte-deficit round robin preserves FIFO within each queued session and never creates an unbounded retry path. Selection returns immediately when every active session is deferred, while its visit budget derives from the largest eligible front packet rather than total queue capacity. An optional shared downlink token bucket creates the aggregate service boundary required for proportional shares such as `1:2:1` under saturation. Its rate and burst must both be zero or both nonzero; zero plus zero keeps the direct path work-conserving. Rate-limited downlinks remain queued for a later bounded attempt; daily/monthly quota denials are terminal for that packet.

Authenticated HTTP operations accept canonical session IDs, remote socket addresses, or assigned IPv4/IPv6 TUN addresses:

- `GET /api/clients/{id}/bandwidth`
- `POST /api/clients/{id}/bandwidth` with a complete `BandwidthPolicy` JSON body
- `POST /api/clients/{id}/quota/reset`

QKey creation accepts the same object as optional `bandwidth_policy` and accepts an optional validated `traffic_analysis_policy`. The traffic-analysis request is persisted but remains inert until encrypted bearer authentication, then is bounded by `[transport.qkey_traffic_analysis_ceiling]`. Runtime denials and admin mutations emit typed audit context. Prometheus exports allowed bytes and `rate_limited`, `daily_quota_exceeded`, and `monthly_quota_exceeded` outcomes by direction, plus active DRR clients and delivered packet/byte totals.

Commit `b9a338317e38cd6df2b9b87ba9d9bde085351e0c` passes CI `30487629259` and Clippy Matrix `30487632307`. Its exact isolated ARM64 source archive `73f2c10d2f85daa4e5701b011e242200bd66b3546fc628d1361807ded20c062b` produced binary `fa841b580df82bddeae1f1449e719285ede18f895543eca6eaeb27b1c7939434`. The production-loglevel three-client proof passed unlimited throughput at 12.56-12.62 Mbit/s, exact 10-Mbit/s policies at 9.97 Mbit/s, burst at 22.57-22.67 Mbit/s, exact 2.4-MB daily quota exhaustion at 6.14 Mbit/s, and weighted `1:2:1` service at 2.47/4.75/2.42 Mbit/s. Both baseline and shaped topologies retained exact policy and binary manifests, used `info` logging, reported empty runtime-error files, and removed every owned process, namespace, link, and admin socket.
 
Server Options (selected):

```
    --tun                   Enable TUN bridging (optional)
    --tun-name <name>       TUN interface name
    --tun-mtu <mtu>         TUN MTU (default 1500)
    --tun-ip <addr>         TUN IP address
    --tun-netmask <addr>    TUN netmask
    --admin-socket <path>   Unix admin socket (status/clients/kick/block/reload/qkey/shutdown)
    --admin-web <addr>      HTTP admin web bind address (e.g. 127.0.0.1:9000)
    --admin-web-max-connections <count>
                            Maximum simultaneous admin web connections (default: 16, maximum: 1024)
    --admin-web-operation-timeout-ms <milliseconds>
                            Per-request operation deadline (default: 30000, range: 50..=120000)
    --admin-web-root <dir>  Static root for the generated web admin bundle (default: assets/web-admin; build first)
    --admin-web-user <user> Admin username (or env QUICFUSCATE_ADMIN_USER)
    --admin-web-password <pass> Admin password (or env QUICFUSCATE_ADMIN_PASSWORD, minimum 6 characters)
    --qkey-ttl-secs <secs> Default QKey TTL in seconds (0 disables expiration; env QUICFUSCATE_QKEY_TTL_SECS)
    --qkey-store <path> QKey registry store path (recommended: /var/lib/quicfuscate/qkeys.json)
    --metrics-port <port>   Metrics HTTP port (text format at /metrics)
    --audit-log <path>      Base path for the tamper-evident NDJSON audit segment set.
                            Active log, rotated segments, and durability checkpoint use
                            mode 0o600 and the resolved runtime identity. Queue, rotation,
                            retention, and flush bounds come from the [audit] config.
    --no-drop-privileges    Skip privilege dropping (debugging only, never use in production)
```

QKey registry encryption is configured only through environment variables, so master-key material never appears in process arguments:

- `QUICFUSCATE_QKEY_ENC_KEY_FILE`: current 32-byte raw key file or 64-character hexadecimal key file. Production deployments should use this source with mode `0600` or `0640`; symlinks and other-readable or group-writable files are rejected.
- `QUICFUSCATE_QKEY_ENC_KEY`: current 64-character hexadecimal key supplied directly through the environment. Do not configure it together with the current key-file source.
- `QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY_FILE` or `QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY`: optional previous key used only to authenticate and rotate an existing registry. A previous key requires a distinct current key.

Rotation procedure: install the new current key, retain the old current key as the previous source, and restart. Startup authenticates the old envelope and atomically rewrites it under the new key while retaining only encrypted recovery data. After one successful restart and registry operation, remove the previous source and restart again. Never remove the old source before the first successful rotation startup.

Verify the active file plus its checkpoint-declared retained segments without starting a client or server:

```text
quicfuscate verify-audit-log <path>
```

### Admin CLI (quicfuscate-ctl)

`quicfuscate-ctl` talks to the Unix admin socket exposed by `--admin-socket`. It uses
`/var/run/quicfuscate/ctl.sock` by default and can be overridden via `QUICFUSCATE_CTL_SOCKET`.

The CLI accepts one newline-terminated UTF-8 response frame with a maximum size of 1 MiB. Empty, unterminated, oversized, invalid-UTF-8, malformed-JSON, and schema-drifted responses fail with a nonzero result. `status`, `clients`, `qkey`, and message commands use separate typed response contracts with required fields; unknown fields are rejected, QKeys are parsed and checksum-validated, and client byte totals use checked addition. Missing values never become zero, `?`, an empty QKey, or a generic pretty-printed fallback.

The Unix-only `quicfuscate-ctl` target is registered in Cargo and constructs typed `AdminCommand` values before opening the socket. `kick`, `block`, and `unblock` require exactly one value; values are trimmed, reject empty/control-character input, and are capped at 256 UTF-8 bytes. Client identities and IP addresses are canonicalized by the shared server contract. The custom command deserializer rejects unknown fields and unknown command names. The encoded request is one newline-terminated JSON frame capped at 8 KiB including the newline, and the server revalidates the same contract before dispatch.

Examples:

```
quicfuscate-ctl status
QUICFUSCATE_CTL_SOCKET=/tmp/quicfuscate.sock quicfuscate-ctl clients
```

### Stealth Options (server)

```
    --front-domain <d>     Domain used for fronting (repeatable or comma-separated)
    --doh-provider <url>   Custom DNS-over-HTTPS resolver
    --disable-doh          Disable DNS over HTTPS
    --disable-fronting     Disable domain fronting
    --disable-http3        Disable HTTP/3 masquerading
    --profile-seq <list>   Comma-separated browser@os entries to cycle (e.g., chrome@windows,firefox@linux)
    --profile-interval <s> Interval in seconds for profile switching
```

Profile rotation allows QuicFuscate to periodically switch the active browser/OS fingerprint to diversify observable characteristics on the wire.

### Performance Options

```
    --cc-algorithm <alg>    Congestion control: reno|cubic|bbr2|bbr3 (default: bbr3)
```

### Client Options

```
    --local <addr>          Local UDP bind address (default: 0.0.0.0:0)
    --url <url>             HTTPS target URL; omitted uses https://cloudflare-dns.com/
    --tun                   Enable TUN bridging (optional)
    --tun-name <name>       TUN interface name
    --tun-mtu <mtu>         TUN MTU (default 1500)
    --tun-ip <addr>         TUN IP address
    --tun-netmask <addr>    TUN netmask
```

### Standard Configuration

The following setup provides a good starting point on most systems:

```
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --profile chrome \
  --front-domain cdn.example.com \
  --pool-capacity 1024 \
  --pool-block 4096 \

```

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./tls-cert.pem \
  --key ./tls-key.pem \
  --profile chrome \
  --pool-capacity 1024 \
  --pool-block 4096 \

```

### Connection Migration

To start validated migration for an established connection to a new peer path, call `migrate_connection` on the active session:

```rust
let new_addr = "127.0.0.1:0".parse().unwrap();
let path_id = conn.migrate_connection(new_addr).unwrap();
println!("started validation for path {path_id}");
```

`migrate_connection` starts PATH_CHALLENGE probing immediately, but the active path only changes after a matching PATH_RESPONSE validates the candidate path.

The `[connection]` migration policy is operator-configurable:

- `migration_cwnd_reduction_factor = 0.5` retains that fraction of the previous congestion window for a port-only rebinding. `0` resets to the initial window and `1` retains the complete prior window.
- `migration_cooldown_ms = 750` sets the minimum interval between successful local migrations. `0` disables the cooldown.
- `migration_probe_target = "previous-window"` uses the previous congestion window as the recovery boundary. `"reduced-window"` uses the post-reduction window.

The retained-window policy applies only when the local and peer IP addresses remain unchanged. A validated IP-address change resets Reno, CUBIC, BBR2, or BBR3 congestion and RTT models to a fresh path per RFC 9000 Section 9.4. The PATH_CHALLENGE/PATH_RESPONSE delay supplies the initial path estimate, but it is not recorded as an ordinary ACK RTT sample.

Recovery increments a path epoch, preserves sent-packet and bytes-in-flight ownership, resets loss/PTO timers deliberately, and prevents ACK or loss events from the previous epoch from changing the new path's congestion or RTT model. Those old events only release their existing bytes-in-flight accounting.

PATH_CHALLENGE and PATH_RESPONSE datagrams carry explicit path-control metadata. The Core prioritizes them ahead of buffered FEC output, bypasses FEC encapsulation, outer pacing, and stealth delay, and still enforces the server amplification budget. Completing or timing out a simultaneous local validation removes only its own PATH_CHALLENGE; a queued response to the peer's challenge remains sendable.

On the standalone server, a new `(local, peer)` tuple remains a candidate route until the matching response validates it. Only then does the DCID route registry commit the new peer address. Successful validated migrations increment the internal `PATH_MIGRATIONS` telemetry counter.

The headless `qf-e2e-client --migration-local` proof keeps the migration and throughput assertions fail closed and performs the HTTP/3 request-stream body/FIN finalization before emitting `migration-proof`. The proof includes `finalization=accepted` when the FIN operation is accepted and `finalization=already-done` when the transport reports its documented terminal `Done` state for an already-finished local stream. Any other finalization error, including an unavailable HTTP/3 session, returns a nonzero result and suppresses the success marker.

---

### NAT Traversal and Path Discovery

NAT traversal is an optional connectivity and path-discovery layer. It is not a default stealth mechanism and it must not generate permanent background STUN/ICE traffic on clean links.

Runtime policy:
- Default: disabled (`enabled = false`, `mode = "off"`).
- Modes: `off`, `connectivity-fallback`, `roaming`, `mesh`, `always`.
- Reasons: direct-path failure, roaming, mesh, or manual request.
- Discovery is cooldown-limited by `probe_interval_ms` and capped by `max_candidates`.
- With `ice_enabled = false`, discovery returns bounded host candidates only.
- With `ice_enabled = true`, discovery may gather STUN server-reflexive candidates from configured STUN servers.

Code ownership:
- `src/transport/nat.rs`: `StunClient`, `IceAgent`, `TurnClient`, and `NatPathDiscovery`.
- `src/transport/config.rs`: `NatTraversalConfig`, `NatTraversalMode`, and `NatDiscoveryReason`.
- `src/engine/config.rs`: `[nat_traversal]` TOML section and validation.
- `src/engine/engine.rs` and `src/implementations/client/connection.rs`: runtime config propagation into transport config.

Operational rule: use NAT traversal for connectivity fallback, roaming path discovery, or explicit mesh experiments. Do not enable it as a blanket stealth default.

---

## Applications

### Desktop App (Tauri 2)

The active desktop client is split across `apps/svelte-desktop/` (Svelte frontend) and `apps/tauri/src-tauri/` (native Tauri host/runtime bridge).
Current status: early beta for desktop delivery. Core tunnel operations are functional; desktop packaging/signing hardening and some platform-specific release tracks remain in progress.

**Stack (`apps/svelte-desktop/` + `apps/tauri/src-tauri/`):**
- Runtime: Tauri 2 (Rust sidecar with webview)
- Frontend: SvelteKit (adapter-static SPA) + Svelte 5 + TypeScript, Vite, Tailwind v4
- Components: bits-ui v2 (Dialog, popover primitives) + shared `@quicfuscate/ui` package
- State: Svelte 5 runes ($state, $derived, $effect) in `$lib/stores/app.svelte.ts`
- Styling: shared `@quicfuscate/theme` CSS package (glass morphism, layout tokens, animations, buttons, login, scrollbar)
- Dialogs: bits-ui `Dialog.Portal` targeting `#qf-app-stage` container (absolute positioning within fixed 900x670px stage)
- Native host: `apps/tauri/src-tauri` owns desktop commands, persistence, secrets, tray, and bundling metadata while consuming the Svelte frontend build output

**Views:**
- **Tunnels**: List of configured tunnels with live state indicators (active/inactive/activating), real-time stats (latency, loss, throughput, uptime, stealth mode, FEC mode), connect/disconnect actions, and an add-tunnel dialog.
- **Settings**: Three-tab layout (General, Connection, Hardware) with server-authoritative connection policy:
  - Stealth and FEC are displayed as server-driven values from the active QKey policy.
  - No local client override is applied for Stealth/FEC policy.
  - General tab includes startup policy (`autoConnectOnLaunch`, `startAtLogin` preference) and updater policy/channel toggles.
  - Updater state panel exposes deterministic no-update, update-available, download/install progress, and signature-failure states.
  - Hardware tab detects CPU SIMD features via Tauri `invoke("detect_cpu_features")`.
- **Logs**: Scrollable log viewer with level-colored entries (error/warn/info/debug/trace), auto-scroll, and clear functionality.
- **About**: Version and system information.

**Engine Polling:**
- Status poller (500 ms): fetches `engine_status` and updates tunnel state map through one in-flight owner; a poller generation rejects delayed results after teardown or replacement.
- Stats poller (900 ms): fetches `engine_stats` for the active tunnel (latency, loss, bytes, packets, uptime, stealth/FEC mode) and commits only when the status generation and active tunnel captured at request start are still current.
- Logs poller (350 ms): incremental `engine_logs_since` fetches are serialized, cursor regressions are rejected, and a cursor epoch invalidates responses that overlap log clearing; the ring buffer retains 2000 entries.

**Persistence:**
- State (tunnels, settings, selected tunnel) is loaded on startup via `invoke("load_state")` and saved on change via `invoke("save_state")` with a 450 ms debounce timer to avoid excessive disk writes. A missing file is the only first-run absence; corrupt, unreadable, or failed-normalization state propagates as unavailable. Start-at-login writes read the current OS registration, apply the OS change, persist the new state, and compensate the OS on persistence failure; an unsuccessful compensation is returned as a retryable partial result.

**Build:**
```bash
cd apps/svelte-desktop && bun install && bun run build
cd ../tauri && bun run tauri build
```

The `apps/tauri/` package is a thin command wrapper around `apps/svelte-desktop/` plus the retained `apps/tauri/src-tauri/` native host. The frontend is the SvelteKit SPA from `apps/svelte-desktop/`; no separate build pipeline is needed.
GitHub CI validates the native desktop backend through the `app-backend-checks` job: the existing desktop frontend bundle is built for Tauri context, then `cargo check` and `cargo test` run in `apps/tauri/src-tauri`.

**Window Model:**
- The production desktop window is fixed to `900 x 670` in `apps/tauri/src-tauri/tauri.conf.json` with `resizable: false`, `minWidth: 900`, `minHeight: 670`, `maxWidth: 900`, and `maxHeight: 670`.

**Tray and Startup Behavior:**
- Closing the main window hides it instead of exiting; runtime continues in tray.
- Tray menu exposes status, active tunnel summary, connect/disconnect, open/hide app, auto-connect-on-launch toggle, start-at-login preference toggle, and quit. If persisted state is unavailable, both preference items are disabled and labeled `(unavailable)` rather than shown as unchecked values.
- Auto-connect-on-launch reads persisted desktop settings and attempts connection on startup when enabled. Corrupt or unreadable state disables startup preference hydration and does not trigger an OS autostart mutation.
- Start-at-login persists user preference and is wired to OS auto-start registration via the desktop runtime plugin. Every mutation reads the current OS state first; failed enable/disable and failed durable saves are compensated when possible, and compensation failure is surfaced as a retryable partial result.
- Native engine cleanup is transactional at the host boundary: a connected engine is disconnected before it is stopped, both results are retained in order, and the original error context reaches the caller. A failed cleanup retains the engine owner and active tunnel for retry when the engine is not terminal; an engine that reaches `Stopped` is released but keeps the cleanup failure in `last_error`. Replacement-connect aborts before creating a new engine when the previous owner cannot reach an accepted terminal state.
- Tray quit records the bounded cleanup outcome in the native log, retains the owner while the process is still alive when cleanup is incomplete, and exits with status `1` on cleanup failure. Successful shutdown exits with status `0`; the next startup's mandatory stale kill-switch cleanup remains the recovery boundary for process-exit residue.

**Updater Integration (source-first and signed-release boundary):**
- Updater plugin path is integrated but runtime-gated behind `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE`.
- Default is disabled for source-first or unsigned builds; signed artifacts and a matching manifest entry are required before enabling update delivery in shipped binaries.
- The tracked release workflow now includes a required signed Windows MSI path, but native MSI and tagged manifest proof remain open under TODO-519.
- Desktop UI includes updater policy/status so no-update, available, download/install, and signature-failure states are explicit.

**Verification (frontend):**
```bash
cd apps/svelte-desktop && bun run check
cd apps/svelte-desktop && bun run test:unit
cd apps/tauri && bun run check
cd apps/tauri && bun run build
cd apps/tauri/src-tauri && cargo check
```

### Web Admin

The active web admin UI lives in `apps/svelte-admin/`. `assets/web-admin/` is generated output, not a tracked runtime input. `scripts/build/build-web-admin.sh` performs the frozen Bun install, builds the Svelte bundle, and copies it into that ignored path. A fresh checkout must run this step before server startup with `--admin-web`, local E2E, or server-bundle creation:

```
scripts/build/build-web-admin.sh
```

The bundle output layout is the SvelteKit static adapter publish tree: `assets/web-admin/index.html`, `assets/web-admin/robots.txt`, and `assets/web-admin/_app/immutable/*` for hashed JS/CSS/assets. `build-server-bundle.sh` and `install-server-linux.sh` fail closed when `index.html` is missing; local E2E rebuilds the ignored tree when needed. Release Linux jobs build the generated tree before calling `build-server-bundle.sh`.
Keep `--admin-web-root` pointing at `assets/web-admin` so `/_app/...` paths resolve correctly after the generated tree exists.

Admin HTTP contract notes:
- JSON endpoints respond with `AdminResponse { success, message, data }` and `/api/clients` is wrapped.
- Admin-web admission is owned by the server CLI option `--admin-web-max-connections`; the default is `16`, the accepted range is `1..=1024`, and there is no environment or TOML alias. Invalid zero, overflow, and out-of-range values fail before listener publication.
- The admission permit is acquired immediately after `accept()` and before task creation. An excess socket is dropped, so `pending_connections` remains zero by invariant and no user-space pending queue is created. `AdminHttpServer::admission_snapshot()` reports configured capacity, active, pending, admitted, rejected, and completed counts.
- Accepted connection tasks are owned by a `JoinSet`; shutdown aborts and joins them before `AdminHttpServer::run()` returns. Each request uses one validated `--admin-web-operation-timeout-ms` deadline (`50..=120000` ms, default `30000`) and an owned bounded blocking-worker protocol. Body collection timeout returns `408`; an operation timeout returns `504` and closes the connection, while the outer response writer receives a one-second grace period. Timeout, cancellation, panic, late-completion, and shutdown-expiry counters are exposed through `AdminHttpOperationSnapshot`. The outer standalone service-task handle remains TODO-700, and request-body memory admission remains TODO-712.
- Admin API failures return appropriate HTTP error statuses (`4xx`/`5xx`) while keeping the same `AdminResponse` envelope (`success: false`, optional `message`/`data`).
- `/api/qkey` is `POST` only, accepts `{ stealth, fec, ttl_seconds, bandwidth_policy, traffic_analysis_policy }` (presets, optional TTL, and optional validated policies), and returns `{ qkey, created_at, expires_at }` in `data`. The returned `qkey` is the one-time reveal point for the raw credential.
- `/api/qkeys` returns metadata-only entries (`id`, optional `name`, `created_at`, optional `expires_at`, optional policy hints). Expired entries are pruned and the endpoint does not expose or reconstruct raw QKey strings.
- QKey strings include the embedded token field and are validated at issuance/import boundaries rather than being replayed through the registry list contract.
- `/api/clients/{id}/kick` is supported as an alias for `/api/kick`.
- `/api/status` includes `config_writable` for UI gating.
- `/api/config/logging` (`GET`/`POST`): read and set logging mode (verbose/normal/minimal/no-log).
- `/api/logs?cursor=<n>` (`GET`): incremental log retrieval with cursor-based pagination.
- `/api/admin/auth` (`GET`/`POST`): authenticated users can query `requires_password_change` and rotate admin credentials (`current_password`, optional `new_username`, optional `new_password`). The server validates the candidate verifier, durably writes `admin-auth.json` before publishing the in-memory credential, and clears active sessions only after a successful commit; failed persistence returns an error and retains the previous credential.
- **Frontend request lifecycle:** Dashboard status, clients, metrics, and blocked-IP calls; Configuration status/configuration; Logs mode/status/log calls; and the nested admin-auth/QKey panels share per-resource serialized request ownership. Initial loads, timers, manual refresh, saves, optimistic mutations, and reconciliation use generation checks and teardown invalidation so stale responses cannot overwrite current loading, error, optimistic, history, or cursor state.
- **Confirmation lifecycle:** The global unsaved-change dialog uses monotonically increasing request IDs and explicit latest-wins cancellation. A request superseded by a newer navigation, refresh, logout, keyboard reload, or close request resolves `false`; the rendered dialog callback must carry the active ID, so a delayed callback cannot resolve another caller. Layout teardown cancels the active request with `false`, leaving no pending confirmation Promise.
- `QUICFUSCATE_TRUST_PROXY=0|1|true|false` enables forwarded client-IP resolution only for peers in `QUICFUSCATE_TRUSTED_PROXY_IPS`; malformed allowlist entries fail closed and the default remains the socket peer address.
- Oversized admin HTTP payloads are rejected with 413.
- Auth uses `POST /api/login` to issue a session cookie and `POST /api/logout` to clear it.
- `/api/health` (`GET`): unauthenticated health probe returning `{"status":"ok"}` with HTTP 200. Suitable for external liveness/readiness probes. No session required, no sensitive information exposed.
- Install/update endpoints are not exposed in the admin HTTP API.

#### Stack (`apps/svelte-admin/`):
- Frontend: SvelteKit (adapter-static SPA) + Svelte 5 + TypeScript, Vite, Tailwind v4
- Components: bits-ui v2 (Dialog primitives) + shared `@quicfuscate/ui` package (Switch, Select, Toast, GlassCard, etc.) + local controls (`TextInput`, `Sparkline`, `FatalErrorScreen`)
- State: Svelte 5 runes ($state, $derived, $effect) in `$lib/stores/app.svelte.ts`
- API: Typed fetch wrappers (`apps/svelte-admin/src/lib/api.ts`) with `ApiError` class, CSRF token management (session-scoped with nonce replay protection), and automatic 401/403/423 -> auth-required flow
- Styling: shared `@quicfuscate/theme` CSS package (glass morphism, layout tokens, animations, buttons, login, scrollbar)
- Dialogs: bits-ui `Dialog.Portal` targeting `#qf-app-stage` container (absolute positioning within responsive viewport stage)
- Dev proxy: Vite proxy `/api` -> `http://127.0.0.1:9000` (no `changeOrigin` to preserve Origin/Host header parity for CSRF same-origin validation)

#### Views (4 tabs):
- **Dashboard**: Server status (version, uptime, bytes in/out, listen address), active clients with kick/block actions, blocked IP management (block/unblock), and Prometheus-style metrics display. Auto-refreshes status/clients every 5 s and metrics/blocked IPs every 15 s.
- **Configuration**: Composite view with embedded panels:
  - Stealth/FEC/Transport panel: stealth preset (`Auto`, `Performance`, `Stealth`, `AntiDPI`, `Manual`, `Off`), manual stealth mode expands inline and exposes the canonical per-feature toggles (domain fronting, HTTP3 masquerading, TLS Cover extras, QPACK headers, padding, timing obfuscation, protocol mimicry, DoH). XOR remains compatibility-only and is not part of the product-facing controls. FEC preset (`Auto` or `Off`). Transport controls: congestion control algorithm and MTU validation (1200-9000). Unsaved-changes warning on page leave, explicit Save/Reset, and pacing pinned on in config writes.
  - QKey panel: generate server-issued QKeys with optional display name, reveal the raw credential once at issuance, copy it from that one-time dialog, then manage issued entries through a metadata-only list with single or bulk revoke. TTL is not exposed in the admin UI flow.
  - Admin settings panel: change username and password. Default credentials are detected and the UI warns until changed. The active minimum password length for updates is 6 characters.
  - Reference guide panel: configuration reference inline.
- **Logs**: Real-time log viewer with configurable logging mode (verbose/normal/minimal/no-log). No-Log suppresses all server log output and the UI stops polling logs. Logs are fetched incrementally via cursor-based pagination.
- **About**: Version, system information, and project credits.

#### Authentication:
- Login modal with username/password fields (empty by default).
- On 401/403 API responses, the UI automatically shows the login modal via the auth-required rune-store state.
- If the server reports `requires_password_change` (or returns HTTP `423`), the UI enters a password-change-locked state: Settings remains accessible while configuration/QKey mutation flows are blocked until the password is changed.
- Rate-limited auth updates (HTTP `429`) are surfaced as error banners without dropping the current session.

#### Verification (frontend)
Typecheck + build:
```bash
cd apps/svelte-admin && bun run check
cd apps/svelte-admin && bun run build
```

E2E UI tests (Playwright):
```bash
cd apps/svelte-admin && bun run test:e2e
cd apps/svelte-desktop && bun run test:e2e
bash scripts/tests/smoke/smoke-ui-frontends.sh
bash scripts/build/build-web-admin.sh
```

Notes:
- The package-owned Playwright configs in `apps/svelte-admin/` and `apps/svelte-desktop/` are the canonical frontend E2E entrypoints; the actual specs live under `scripts/tests/frontend/`.
- Unit test suites: `scripts/tests/frontend/web-admin/unit/` (24 files, 279 tests), `scripts/tests/frontend/desktop/unit/` (30 files, 368 tests), `scripts/tests/frontend/shared-ui/unit/` (9 files, 82 tests). Total: 63 files, 729 vitest tests.
- Active app unit harnesses run without file-level parallelism and the package-owned unit scripts force Vitest's fork pool (`--pool=forks`). This avoids Bun/Vite/Svelte transform contention that can turn passing component assertions into false timeout failures under full-suite load. The web-admin and desktop setup hooks clean up Svelte Testing Library state and restore real timers after each test. The stabilized harness is verified with web-admin 279/279, desktop 368/368, and shared UI 82/82 unit tests passing.
- `apps/tauri` is a minimal wrapper package for the native Tauri host and delegates its frontend build/check path to `apps/svelte-desktop`.
- `packages/ui` uses package `exports` entries with explicit `svelte` conditions so the shared Svelte component package resolves cleanly without `vite-plugin-svelte` packaging warnings.
- On a fresh machine, install the Playwright browser runtime once before the first E2E run: `cd apps/svelte-admin && bunx playwright install chromium`.
- Playwright does not reuse an existing server by default. Set `PW_REUSE_SERVER=1` only when intentionally reusing a running preview instance during local debugging.
- The Svelte admin dev server runs on port 1430 (`bun run dev --port 1430`) and proxies `/api/*` to the backend on port 9000.

#### Server-Side Persistence

The admin HTTP server persists the following state to JSON files derived from the main config path:
- **Blocked IPs** (`<config>.blocked.json`): loaded on startup, written on every block/unblock action.
- **Logging mode** (`<config>.logging.json`): absent state is an explicit normal-mode default; an existing file is strict JSON containing exactly one of `verbose`, `normal`, `minimal`, or `no-log`. Malformed, unreadable, missing-mode, unknown-field, and unsupported-mode state aborts standalone bootstrap with an operator-visible error instead of silently becoming normal. Admin updates with a config path atomically persist the typed mode before publishing it to the live runtime; failed persistence retains the previous live mode and returns an error. Updates without a config path are explicitly reported as live-only and are not restored after restart. When set to `no-log`, the server immediately calls `log::set_max_level(LevelFilter::Off)` to suppress all runtime logging output including to stderr and syslog.
- **QKey registry** (`--qkey-store` or `<config>.qkeys.json`): loaded on startup and transactionally written on generate/revoke. With a current encryption key configured, storage uses the `QFQREG` version-1 ChaCha20-Poly1305 envelope whose authenticated header binds magic, version, flags, key identifier, and nonce. Missing/wrong keys, corrupt or truncated ciphertext, unsupported versions, insecure permissions, serialization failures, and I/O failures abort startup or mutation without plaintext fallback. Plaintext remains supported only when no encryption source is configured. Enabling a key atomically migrates plaintext to encrypted primary and encrypted recovery files. Legacy `QFENC1` files require a valid configured key and are immediately upgraded.
- **Admin auth** (`<config_dir>/admin-auth.json`): Argon2 PHC string (`password_phc`) with `updated_at` timestamp and `requires_password_change`. File permissions set to `0o600` on Unix. A missing file is initialized before listener startup; malformed JSON, an invalid PHC verifier, unreadable storage, or initial persistence failure aborts startup. Credential changes validate and atomically persist a candidate before replacing in-memory state and invalidating sessions; failed writes retain the previous valid credential, remove the uncommitted temporary file, and return an explicit error.
- Repository-local fallback paths (when no explicit `--config`/`--qkey-store` parent applies): `config/local/qkeys.json` and `config/local/admin-auth.json`.

#### No-Log Enforcement

When the logging mode is set to `no-log` (via API or persisted config):
- `log::set_max_level(LevelFilter::Off)` is called immediately, suppressing all `log::*` macro output.
- This is enforced both at startup (if the persisted mode is `no-log`) and at runtime (when the mode is changed via `/api/config/logging`).
- Other modes map to: `minimal` -> `Warn`, `normal` -> `Info`, `verbose` -> `Trace`.

#### Login Rate-Limiting

The admin HTTP server enforces IP-based login rate limiting to prevent brute-force attacks:
- Maximum 5 failed login attempts per IP address.
- 60-second lockout window after exceeding the limit.
- Locked IPs receive HTTP 429 ("Too many login attempts. Try again later.").
- Successful login clears the failure counter for that IP.
- Failed attempts are pruned automatically after the lockout window expires.

#### SPA Fallback

The static file server implements SPA (Single Page Application) fallback: when a non-API `GET` request does not match a static file, the server serves `index.html` instead of returning 404. This enables browser refresh on client-side routes like `/logs` or `/configuration`.

#### Session Cookie Security

Session cookies are hardened with the following attributes:
- `HttpOnly`: prevents JavaScript access (XSS mitigation).
- `SameSite=Strict`: prevents CSRF by restricting cross-origin cookie sending.
- `Secure`: set dynamically when the request arrives over HTTPS.
- `Max-Age`: matches the session TTL (1 hour).
- Session tokens are 32 bytes from the centralized fail-closed `rng::fill_secure_or_abort` path, base64url-encoded.
- Sessions are pruned on every access; credential changes invalidate all active sessions.

Then run the server:

```
quicfuscate server --admin-web 127.0.0.1:9000 --admin-web-user <USER> --admin-web-password <PASS>
```

For local helper-driven development only, `scripts/utils/util-run-local-admin-web.sh` and `scripts/utils/util-run-local-ui.sh` intentionally override this with `admin / 123` behind `QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1`. Operators who want a different local password should edit those helper command lines directly or start the server manually with their own `--admin-web-password`.


## Command Line Interface

QuicFuscate provides a comprehensive CLI with multiple subcommands for different operational modes and internal utilities:

### Main Subcommands

Global CLI flags (all commands):
- `--verbose` - enables verbose logging initialization.
- `--telemetry` - enables runtime telemetry metrics export surfaces.

#### **`client`** - Runs the QuicFuscate client
**Required Options:**
- `--remote`: Server address to connect to

**Network Options:**
- `--local`: Local UDP address (default: 0.0.0.0:0)
- `--url`: Optional HTTPS target URL. Omission selects the default target `https://cloudflare-dns.com/` with `source=default`; an explicit value is accepted only with an `https` scheme, a non-empty domain or IP authority, and a port in `1..=65535`. An empty path becomes `/`, queries remain part of the HTTP/3 `:path`, explicit ports remain part of `:authority`, IPv6 authorities are bracketed while the SNI host is not, and userinfo, fragments, hostless forms, malformed authorities, and unsupported schemes fail before socket binding with `source=explicit` never falling back to the default.
- `--cc-algorithm`: Congestion control (reno, cubic, bbr2, bbr3) [default: bbr3]

**Stealth Options:**
- `--profile`: Browser fingerprint (chrome, firefox, safari, edge) [default: chrome]
- `--os`: Operating system (windows, macos, linux, ios, android) [default: windows]
- `--profile-seq`: Comma-separated profiles for rotation
- `--profile-interval`: Rotation interval in seconds
- `--doh-provider`: DNS-over-HTTPS URL (default: https://cloudflare-dns.com/dns-query)
- `--front-domain`: Domain fronting targets (comma-separated)

- `--disable-doh`: Disable DNS over HTTPS
- `--disable-fronting`: Disable domain fronting
- `--disable-http3`: Disable HTTP/3 masquerading

Note: TLS provider selection and fingerprinting are internal.

**TLS/Debug (client only):**
- `--verify-peer` - compatibility flag; server certificate validation is already enabled
- `--ca-file <PATH>` - CA file for verification
- `--no-utls` - disable uTLS and use standard TLS
- `--debug-tls` - enable additional TLS trace diagnostics through the `QUICFUSCATE_TRACE_TLS` path; transport keylog export is not wired in this fork
- `--list-fingerprints` - list available browser fingerprints

**FEC Options:**
- `--fec-mode`: FEC mode (`auto` or `off`) [default: auto]
- `--fec-config`: Path to FEC configuration TOML

The user-facing FEC contract is `auto` / `off`. Any other value is a hard error.

**Memory Options:**
- `--pool-capacity`: Memory pool capacity (default: 1024)
- `--pool-block`: Block size in bytes (default: 4096)

**TUN Options:**
- `--tun`: Enable TUN bridging
- `--tun-name`: TUN interface name
- `--tun-mtu`: TUN MTU
- `--tun-ip`: TUN IP address
- `--tun-netmask`: TUN netmask

Server TUN mode is supported only on Linux. Client-side TUN support remains platform-specific as described in the TUN contract above.

**Configuration:**
- `--config`: Path to unified TOML configuration

#### **`server`** - Runs the QuicFuscate server
**Required Options:**
- `--cert`: Certificate file path
- `--key`: Private key file path

**Network Options:**
- `--listen`: Listen address (default: 127.0.0.1:4433)
- `--cc-algorithm`: Congestion control (reno, cubic, bbr2, bbr3) [default: bbr3]

**Other options mirror the client subcommand**

#### Hidden Diagnostic Subcommands  
- **`cross-fade-sim`** - legacy command name for block-boundary FEC transition simulation
- **`high-loss-sim`** - High packet loss simulation for testing resilience
- **`optimize-probe`** - Internal capability probe for system diagnostics
- **`capabilities`** - System capability detection and feature availability

#### Benchmark Subcommands (feature-gated `--features benches`)
- `fec-bench` - FEC benchmark (sequential vs parallel)
  - Options: `--packets|--iterations`, `--payload`, `--mode <FecMode>`, `--pool-capacity`, `--block-size`, `--warmup`, `--json`
- `pool-bench` - Memory pool micro-benchmark
  - Options: `--iterations|--packets`, `--payload`, `--pool-capacity`, `--block-size`, `--warmup`, `--json`
- `crypto-bench` - Crypto/encode micro-benchmark
  - Options: `--iterations`, `--payload`, `--mode {fnv1a|xor|rolling}`, `--warmup`, `--json`
- `net-bench` - Synthetic networking micro-benchmark
  - Options: `--iterations`, `--payload`, `--warmup`, `--json`

### Crypto Benchmark Modes

The `crypto-bench` subcommand supports different hashing/encoding modes:

```rust
pub enum CryptoMode {
    Fnv1a,   // FNV-1a hash
    Xor,     // XOR encoding
    Rolling, // Rolling hash
}
```

**Usage:**
```bash
# Benchmark FNV-1a hashing
quicfuscate crypto-bench --mode fnv1a --iterations 1000000

# Benchmark XOR encoding
quicfuscate crypto-bench --mode xor --payload 4096

# Benchmark rolling hash
quicfuscate crypto-bench --mode rolling --warmup 1000
```

### Clap Value Enums
- **`BrowserProfile`** - Browser fingerprint profiles (Chrome, Firefox, Safari, Edge)
- **`OsProfile`** - Operating system profiles (Windows, macOS, Linux, iOS, Android)
- **`FecMode`** - Internal Adaptive FEC/test modes (Zero, Light, Normal, Medium, Strong, Extreme, Ultra, Fountain, Streaming)
- **`CryptoMode`** - Cryptographic operation modes (Fnv1a, Xor, Rolling)

### Common Configuration Options
Both client and server subcommands support extensive configuration:
- Browser and OS fingerprinting profiles with rotation capabilities
- FEC mode selection and memory pool tuning
- UDP/io_uring fast paths (experimental AF_XDP socket code stays outside the canonical runtime path)
- Stealth features: uTLS persona shaping, DoH, explicit domain fronting, HTTP/3 masquerading, adaptive padding, timing shaping, bounded cover traffic
- TOML configuration file support
- TLS debugging and certificate validation options

## Configuration

QuicFuscate uses a unified TOML configuration file for runtime settings. The canonical source is `config/quicfuscate.toml`.
This section stays intentionally quick-start oriented. Full key-by-key schema, defaults, and environment overrides are documented in "Configuration Reference (Full)".

### Quick Start Configurations

#### Minimal (Performance Focus)
```toml
[stealth]
mode = "off"

[fec]
mode = "off"
```

#### Balanced (Default)
```toml
[stealth]
mode = "stealth"

[fec]
mode = "auto"
```

#### Maximum Stealth
```toml
[stealth]
mode = "anti-dpi"

[fec]
mode = "auto"

[fingerprint_rotation]
enabled = true
mode = "all"
```

### Preset Guidance

- Minimal - prioritize lowest overhead and disable stealth/FEC extras.
- Balanced - default operational baseline for mixed latency/loss environments.
- Maximum Stealth - anti-DPI posture with aggressive cover, explicit fronting policy, next-session persona rotation, and adaptive recovery enabled.

For full stealth-mode semantics and all `[stealth]` keys, use:
- "Obfuscation-Modes Overview" and "Stealth Modes - Semantics"
- "Configuration Reference (Full)"

### Configuration Reference (Full)

For the complete, commented runtime configuration with all canonical sections and defaults, see `config/quicfuscate.toml`.

Traffic-analysis configuration uses three independent policy sections:
- `[transport.traffic_analysis]`: active baseline with `defense`, `chaff_rate_pps`, `chaff_size_bytes`, `constant_rate_pps`, `idle_timeout_ms`, and `ramp_down_ms`.
- `[transport.qkey_traffic_analysis_ceiling]`: maximum policy an authenticated QKey may request.
- `[transport.intelligent_traffic_analysis_ceiling]`: maximum post-authentication Intelligent escalation policy.

Valid defenses are `off`, `full-padding`, and `constant-rate`. Enabled policies are intentionally bandwidth-expensive and emit a startup warning with their bounded estimated bit rate.

#### EngineConfig Validation and Adapter Contract

`EngineConfig::from_toml()` performs parsing; every runtime boundary must call `EngineConfig::validate()` before consuming the document. The complete schema uses strict unknown-field rejection at the top level and on every serialized section, including the three nested traffic-analysis policies and `[security.firewall]`. Validation covers engine lifecycle, socket endpoints, transport limits and policies, NAT traversal, crypto, interface, telemetry, logging, audit, FEC, stealth, fingerprint rotation, optimization, anti-replay, and security.

`AppConfig` is a deliberately reduced runtime projection. It contains validated FEC, stealth, optimization, and anti-replay state. Transport policies remain owned by the transport builders; telemetry, logging, audit, crypto, interface, NAT, and security remain in the validated source document and are consumed by their dedicated startup/runtime owners. No adapter may silently substitute a default for an invalid typed string or silently discard an unknown key.

The unified `[fec]` section accepts product control modes `auto` and `off`. Its `initial_mode` compatibility hint accepts `auto` or `off`; complete codec modes belong to the standalone `[adaptive_fec]` source. Partial recovery is controlled by `QUICFUSCATE_FEC_PARTIAL`, so `fec.enable_partial = false` is rejected instead of being ignored; `enable_pid = false` is likewise rejected because the adaptive controller owns that behavior. `optimization.memory_pool_size = 0` resolves through the shared automatic pool-sizing policy, and every adapter derives the same block size and capacity contract.

Fingerprint slots use canonical `browser:os` strings; the server parser also accepts the legacy `browser@os` spelling. Persona rotation remains connection-scoped and therefore applies to the next connection or reconnect only. Transactional reload publication remains owned by TODO-724, while full rotation lifecycle and selection semantics remain owned by TODO-751.

### Environment Variable Overrides

At runtime you can override selected stealth options without changing the config file. The following variables are recognized (case-insensitive values where applicable):

Environment parsing has a deterministic helper contract but is not a universal live-reload contract. `src/env_utils.rs` owns the shared `EnvSnapshot` and helper paths used by the active Brain, FEC, Reality, stealth, TLS Cover, core, and transport construction boundaries. TODO-811 completes the direct-parser authority inventory: compression, memory-pool, zstd, Reality targets, trusted-proxy state, CLI socket, metrics address, NUMA, SIMD overrides, and io_uring now use one construction snapshot or an explicitly documented validated subsystem boundary. Dedicated server auth, DDoS, rate-limit, GeoIP, blacklist, and QKey policy loaders remain their own validated boundaries because they return typed errors, preserve non-Unicode secret inputs where required, or validate cross-field policy before publication.

#### Environment Parsing and Runtime Snapshot Contract

- `EnvSnapshot::capture()` copies the Unicode process environment once. A runtime owner must pass that immutable snapshot through all dependent construction paths; it must not read the process environment again for the same runtime generation.
- `StealthManager` owns the primary connection-generation snapshot. `QuicFuscateConnection` reuses it for FEC observer and adaptive-FEC policy, Brain, Reality, stealth overrides, TLS ClientHello overrides, and the intelligent orchestrator. `transport::Connection` receives the same snapshot before its first TLS enable and retains it for TLS provider rebuilds, recovery selection, and BBR2/BBR3 minimum-RTT configuration.
- Standalone constructors that are not attached to a parent runtime capture their own snapshot at construction. Environment mutation after construction is unsupported; reconstruct or restart the owning runtime to apply changed values.
- Boolean helpers trim whitespace and accept `1`, `true`, `yes`, `on`, `0`, `false`, `no`, and `off`. A present but invalid boolean warns and retains the configured default. Numeric helpers trim input, warn and ignore invalid values, reject non-finite floats, and reject non-positive values for positive-only controls. Range-constrained consumers warn and clamp or ignore values according to their existing safety contract.
- Ordered alias helpers ignore empty and invalid canonical values before trying legacy aliases. Unset values and invalid values therefore remain distinguishable at the helper boundary even when the consumer intentionally preserves its default.
- The shared test-only environment lock coordinates process-global mutation across library modules. The separate binary test crate retains its own lock because Rust test cfg boundaries prevent access to the library-only guard; it remains a separate process boundary rather than a claimed cross-crate lock.
- Direct production parsers outside `src/env_utils.rs` are listed in the authority inventory below. They are either snapshot-backed or intentionally retained as validated startup boundaries; test-only, build-only, and operating-system environment variables are not product configuration.

#### Complete Environment Authority Inventory (TODO-811)

The following table is the ownership and invalid-value contract for every production `QUICFUSCATE_*` key. The detailed lists below provide the per-key syntax and defaults; this table defines the parser owner and read timing.

| Owner | Key families | Accepted input and invalid disposition | Read timing |
| --- | --- | --- | --- |
| `StealthManager`, `StealthConfig`, TLS Cover | `BROWSER`, `OS`, `STEALTH_*`, `ACK_*`, `DOH*`, `FRONTING*`, `H3_MASQUERADE`, `QPACK`, `SERVER_PUSH_*`, `FINGERPRINT_*`, `MASQUE_*`, `USE_TLS_COVER*`, `TLS_COVER_*`, `SUPPRESS_ICMP_UNREACHABLE` | Enums, booleans, finite numbers, and trimmed lists as documented below. Invalid values warn and retain the current/default policy; legacy aliases are tried only after an empty or invalid canonical value. | One immutable connection/runtime snapshot; no live reread. |
| `StealthBrain` | `BRAIN_*` | Typed integer and finite-float controls with documented ranges; range violations warn and clamp or retain the default. | Connection snapshot at Brain construction. |
| `FecRuntimePolicy` and FEC subsystem loaders | `FEC_*`, `FOUNTAIN_*`, `KALMAN_*`, `WM_*`, `RAYON_THREADS`, `MTU_HINT` | Decoder names are allowlisted; booleans and numbers use trimmed snapshot helpers; bounded values warn and clamp or ignore according to the FEC policy. | Connection/runtime snapshot; adaptive feedback never reads the process environment. |
| `CompressionPolicy`, body pool, dictionary cache | `COMPRESS*`, `BODYPOOL_*`, `DICT_DIR` | Booleans and numbers use typed helpers; compression level is `1..=22`, body capacity/block are positive with a `2048`-byte block minimum, and allow/deny lists are trimmed. Invalid overrides warn and retain defaults. | Global compression policy and dictionary directory are first-use `OnceLock` values; body pool captures one snapshot at first construction. |
| `MemoryPoolRuntimeConfig`, NUMA allocator | `POOL_*`, `TLS_*`, `MADVISE_HUGEPAGE`, `NUMA_POLICY` | Positive capacities/ticks reject zero; utilization percentages clamp with a warning; booleans and NUMA modes are parsed from the snapshot. Invalid values retain safe defaults. | One immutable pool-construction snapshot. The background auto-tuner reads only its stored typed policy and never rereads the process environment. |
| `RealityConfig`, `RealityProxy` | `REALITY_*` | Booleans, positive ports, durations, and non-empty hosts use typed parsing. `REALITY_TARGETS` is a whole-list contract: any empty, malformed, zero-port, or unbracketed IPv6 entry rejects the override and retains the complete built-in set. | Runtime-generation snapshot; proxy target list is fixed for the proxy instance. |
| `AdminHttpEnvironment` | `TRUST_PROXY`, `TRUSTED_PROXY_IPS`, `ENABLE_ADMIN_SHUTDOWN` | Booleans use the canonical flag parser. The trusted-proxy list is all-or-nothing; any empty or malformed IP drops the complete allowlist, so forwarded identity remains fail-closed. | Captured once when the production admin server is constructed. |
| Engine, transport, crypto, and I/O startup owners | `MEMORY_POOL_MB`, `FASTPATH`, `GHASH*`, `CHACHA20_X4`, `FEC_KERNEL`, `BBR_MIN_RTT_WINDOW_MS`, `IO_URING_ZC`, `TRACE_TLS`, `TLS_CH_OVERRIDE_TEMPLATE`, `BRAIN`, `ORCHESTRATOR`, `METRICS_ADDR`, `CTL_SOCKET` | Typed flags, positive numbers, allowlisted modes, and trimmed endpoint/path strings. Invalid values warn and retain safe defaults; hardware overrides fall back to runtime capability dispatch. | Owner construction or first-use snapshot; no background live reread. |
| Validated server policy loaders | `AUTH_*`, `DDOS_*`, `RATE_LIMIT_*`, `CLIENT_*`, `SERVER_DOWNLINK_*`, `DNS_*`, `GEOIP_*`, `BLACKLIST_*`, `QKEY_TTL_SECS`, `ADMIN_USER`, `ADMIN_PASSWORD`, `ALLOW_WEAK_ADMIN_DEFAULTS` | Deliberate subsystem exception. Direct reads are startup-bound, cross-field validated, and return typed configuration errors or explicit warnings. | Server configuration construction; no live reread. |
| QKey encrypted registry loader | `QKEY_ENC_KEY`, `QKEY_ENC_KEY_FILE`, `QKEY_ENC_PREVIOUS_KEY`, `QKEY_ENC_PREVIOUS_KEY_FILE` | Deliberate `var_os` exception for secret material. Exactly one value/file source is accepted per role; malformed, unreadable, non-Unicode file-selector, or conflicting sources return a typed error. | Registry load/reload boundary; no per-request environment read. |
| Test/build/OS environment | `MORUS`, `PROFILE_OVERRIDE`, `QFTLS_PRELOAD_CHILD`, `WFP_PERSISTENCE_CHILD`, `GITHUB_SHA`, `HOSTNAME`, `COMPUTERNAME`, `WATCHDOG_*`, `NOTIFY_SOCKET` | Not product runtime configuration. These values belong to isolated tests, build evidence, hostname discovery, or systemd protocol integration. | Test/process or operating-system boundary only. |

**Core Stealth:**
- `QUICFUSCATE_BROWSER`: `chrome|firefox|safari|edge`
- `QUICFUSCATE_OS`: `windows|linux|macos|ios|android`
- `QUICFUSCATE_STEALTH_MODE`: `off|performance|base|stealth|anti-dpi|intelligent|auto|manual` (aliases: `antidpi`, `stealthmax`, `stealth-max`, `dynamic`, `auto`)
- `QUICFUSCATE_USE_TLS_COVER_EXTRAS` (alias: `QUICFUSCATE_USE_TLS_COVER`): `0|1|true|false` - enables TLS Cover extras in `StealthManager` (ticket manager and cert emulator)
- `QUICFUSCATE_TLS_COVER_PROFILE`: `chrome|firefox|safari|edge|random`
- `QUICFUSCATE_TLS_COVER_CIPHER`: `auto|chacha|aes`
- `QUICFUSCATE_TLS_COVER_ULTRA`: `0|1|true|false`
- `QUICFUSCATE_DOH`: `0|1|true|false`
- `QUICFUSCATE_DOH_PROVIDER`: URL
- `QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION`: `0|1|true|false` - enables decoded server-uplink network-stack normalization; forced off in `StealthMode::Off`
- `QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE`: `0|1|true|false` - suppresses only non-PMTUD destination-unreachable traffic

**Compression Module (current):**
- `QUICFUSCATE_COMPRESS`: `0|1|false|true` - Enable/disable compression
- `QUICFUSCATE_COMPRESS_MIN`: integer - Minimum payload size for compression (bytes)
- `QUICFUSCATE_COMPRESS_LEVEL`: `1-22` - zstd compression level
- `QUICFUSCATE_COMPRESS_ALLOW`: comma-separated content-types to allow (e.g., `text/*,application/json`)
- `QUICFUSCATE_COMPRESS_DENY`: comma-separated content-types to deny (e.g., `image/*,video/*`)
- `QUICFUSCATE_BODYPOOL_CAP`: integer - Body pool capacity (blocks)
- `QUICFUSCATE_BODYPOOL_BLOCK`: integer - Explicit body-pool block size (bytes), with the `2048`-byte minimum; telemetry reports the effective value.
- `QUICFUSCATE_DICT_DIR`: path - Dictionary cache directory

**Core H3/MASQUE controls:**
- `QUICFUSCATE_MASQUE_PROXY`: hostname of the MASQUE proxy (e.g., `masque.example.com`); used as the Core H3 `:authority` override when configured.
- `QUICFUSCATE_MASQUE_DATAGRAM`: `0|1|true|false` - explicitly enable Core H3 MASQUE DATAGRAM draining outside an active TUN sink.
- The former `QUICFUSCATE_MASQUE_ENABLE` compatibility toggle is retired and has no runtime effect. Core H3/MASQUE is selected by an active TUN bridge or the Intelligent runtime policy.

**StealthBrain Module:**
- `QUICFUSCATE_BRAIN_ACK_MAX`: integer - Maximum ACK threshold (default from code)
- `QUICFUSCATE_BRAIN_JITTER_MAX_US`: integer - Max jitter in microseconds
- `QUICFUSCATE_BRAIN_SIZE_BINS`: integer (8..64) - Histogram size bins
- `QUICFUSCATE_BRAIN_IAT_BINS`: integer (8..64) - Histogram inter-arrival bins
- `QUICFUSCATE_BRAIN_PROBE_MAX_PER_MIN`: integer (<=30)
- `QUICFUSCATE_BRAIN_PROBE_COOLDOWN_MS`: integer - Probe cooldown in ms
- `QUICFUSCATE_BRAIN_POLICY_COOLDOWN_MS`: integer - Policy cooldown in ms
- `QUICFUSCATE_BRAIN_EXPLORE`: float (0.0..0.25) - Exploration probability
- `QUICFUSCATE_BRAIN_HIST_DECAY`: float (0.80..0.999)
- `QUICFUSCATE_BRAIN_PAD_MAX_LOW`: integer (16..512)
- `QUICFUSCATE_BRAIN_PAD_MAX_HIGH`: integer (>= low, <=2048)

**TLS Provider (qftls):**
- `QUICFUSCATE_ALLOW_INVALID_CERTS=1|true|yes|on` - Accept invalid peer certificates (development/testing only)
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - Forward a template name only when the active provider returns `supports_ch_override() == true`; current providers return false.
- `QUICFUSCATE_TRACE_TLS=1` - Enable additional TLS handshake/key-change diagnostics in qftls/transport

**Global toggles:**
- `QUICFUSCATE_BRAIN=0|1|false|true` - Enable StealthBrain transport observer coupling (default: enabled)
- `QUICFUSCATE_ORCHESTRATOR=0|1|false|true` - Enable DeepIntegrationOrchestrator when feature is compiled (default: enabled)
- `QUICFUSCATE_RAYON_THREADS=<n>` - Cap Rayon global thread pool used for parallel FEC kernels

**Telemetry server:**
- `QUICFUSCATE_METRICS_ADDR` - `host:port` for the `--telemetry` HTTP endpoint (default: `127.0.0.1:9898`).

**Transport and IO (advanced):**
- `QUICFUSCATE_CLIENT_RATE_BYTES_PER_SECOND` / `QUICFUSCATE_CLIENT_BURST_BYTES` - per-session sustained bytes/second and initial/maximum burst for each direction. Both must be zero for unlimited or both nonzero.
- `QUICFUSCATE_CLIENT_DAILY_QUOTA_BYTES` / `QUICFUSCATE_CLIENT_MONTHLY_QUOTA_BYTES` - combined uplink plus downlink quota for the current UTC day/calendar month (`0` = unlimited).
- `QUICFUSCATE_CLIENT_BANDWIDTH_WEIGHT` - weighted byte-deficit scheduler share from `1` through `1000` (default: `1`).
- `QUICFUSCATE_SERVER_DOWNLINK_RATE_BYTES_PER_SECOND` / `QUICFUSCATE_SERVER_DOWNLINK_BURST_BYTES` - optional shared downlink service capacity used by the weighted scheduler. Both must be zero for unshaped operation or both nonzero.
- `QUICFUSCATE_AUTH_POLICY_ENABLED` - `true|false|1|0`; explicit disable switch for per-IP QKey auth backoff and block state (default: `true`).
- `QUICFUSCATE_AUTH_BACKOFF_AFTER_FAILURES` - first consecutive terminal failure that schedules backoff (default: `3`).
- `QUICFUSCATE_AUTH_BACKOFF_BASE_MS` / `QUICFUSCATE_AUTH_BACKOFF_MAX_MS` - exponential delay base and cap (defaults: `250` / `8000`).
- `QUICFUSCATE_AUTH_BLOCK_AFTER_FAILURES` / `QUICFUSCATE_AUTH_BLOCK_DURATION_SECS` - explicit block threshold and duration (defaults: `10` / `300`).
- `QUICFUSCATE_AUTH_IDLE_TIMEOUT_SECS` / `QUICFUSCATE_AUTH_PRUNE_INTERVAL_SECS` - idle-state retention and periodic prune interval (defaults: `900` / `30`).
- `QUICFUSCATE_AUTH_MAX_TRACKED_IPS` / `QUICFUSCATE_AUTH_MAX_PENDING_PER_IP` - hard attacker-controlled state bounds (defaults: `65536` / `4`).
- `QUICFUSCATE_REVOCATION_RETENTION_SECS` - revoked QKey record retention in seconds (default: `7,776,000`, 90 days); zero is rejected.
  - Auth policy values are validated together. Invalid booleans, zero bounds/durations, a block threshold at or below the backoff threshold, or a maximum delay below its base fail server configuration.
- `QUICFUSCATE_RATE_LIMIT_PPS` - integer `>=1`; overrides per-source packet rate limit in server runtime path (default: `10000`).
- `QUICFUSCATE_RATE_LIMIT_BPS` - integer; overrides per-source byte rate limit (`0` = unlimited, default: `0`).
- `QUICFUSCATE_RATE_LIMIT_BURST` - integer packet-token burst capacity (`0` = `2 * max_pps`, default: `0`). The byte bucket derives its initial capacity as `ceil(max_bps * effective_burst / max_pps)`; the value is never treated as a byte count directly.
- `QUICFUSCATE_RATE_LIMIT_REFILL_MS` - integer `>=1`; token-bucket refill interval in milliseconds (default: `1000`).
  - These overrides are active only when the binary is built with the `rate_limiter` feature.
- `QUICFUSCATE_DDOS_ENABLED` / `QUICFUSCATE_DDOS_RETRY_ENABLED` - strict boolean switches for sustained enhanced admission and stateless QUIC Retry (defaults: `true` / `true`).
- `QUICFUSCATE_DDOS_SAMPLE_INTERVAL_MS`, `QUICFUSCATE_DDOS_ACTIVATION_WINDOW_MS`, `QUICFUSCATE_DDOS_CLEAR_WINDOW_MS` - monotonic sampling and hysteresis durations (defaults: `1000`, `5000`, `15000`).
- `QUICFUSCATE_DDOS_EWMA_ALPHA`, `QUICFUSCATE_DDOS_SPIKE_MULTIPLIER`, `QUICFUSCATE_DDOS_CLEAR_FACTOR` - validated EWMA and transition factors (defaults: `0.1`, `3.0`, `1.5`).
- `QUICFUSCATE_DDOS_ENHANCED_PACKET_COST` - per-IP token cost for new traffic while enhanced admission is active (default: `2`).
- `QUICFUSCATE_DDOS_RETRY_TOKEN_LIFETIME_SECS` - stateless Retry-token validity window (default: `10`).
- `QUICFUSCATE_GEOIP_DB_PATH` / `QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES` - optional MaxMind country database and comma-separated ISO alpha-2 codes, trimmed and normalized to uppercase before validation. Supplying only one variable, an empty code, or a malformed code fails configuration; supplying both activates only after the regular file is non-empty, fully verified, and identified as a country database, while a valid non-country database is rejected. Activation failure stops server startup before readiness. Runtime health, admin, and metrics expose actual `disabled` or `active` state; the typed `failed`/`not_ready` state is reserved for an owned failed runtime. Lookup/decode failures are dropped fail-closed and counted by `quicfuscate_geoip_lookup_errors_total`.
- `QUICFUSCATE_BLACKLIST_SYNC_URL`, `QUICFUSCATE_BLACKLIST_TTL_SECS`, `QUICFUSCATE_BLACKLIST_SYNC_INTERVAL_SECS` - optional strict-HTTPS feed, entry TTL, and refresh interval.
- `QUICFUSCATE_BLACKLIST_CA_PATH` - optional bounded PEM CA bundle for private HTTPS feed endpoints; public feeds continue using platform roots.
- `QUICFUSCATE_BLACKLIST_REQUEST_TIMEOUT_SECS`, `QUICFUSCATE_BLACKLIST_MAX_BODY_BYTES`, `QUICFUSCATE_BLACKLIST_MAX_ENTRIES` - fetch and parsed-state bounds (defaults: `30`, `16777216`, `250000`). Absolute ceilings are `300` seconds for request timeout, `16777216` bytes for body/cache size, and `250000` unique entries; TTL and sync interval are each capped at `604800` seconds.
- `QUICFUSCATE_BLACKLIST_CACHE_PATH` - atomic last-known-good cache path, or `disabled` for no persistence (default: `config/local/blacklist-cache.json`).
- `QUICFUSCATE_FASTPATH` - `auto|off` (default: `auto`). Controls XDP/UDP fast-path selection.
- io_uring queue depth and SQPOLL are probed automatically at runtime with no env override needed.
  SQPOLL requires `CAP_SYS_ADMIN` on kernels < 5.12 and falls back to standard mode silently.
  SendMsgZc requires kernel 6.0+ and `QUICFUSCATE_IO_URING_ZC=1`; without that explicit opt-in,
  the production send path stays on batched SendMsg.
- `QUICFUSCATE_IO_URING_ZC` - `1|true|yes|on` enables experimental Linux `SendMsgZc` zero-copy
  after the runtime probe succeeds (default: disabled).
- `QUICFUSCATE_TRUST_PROXY` - `0|1|true|false`; enables forwarded-proxy headers only when the peer is in the trusted allowlist (default: `false`).
- `QUICFUSCATE_TRUSTED_PROXY_IPS` - comma-separated IP allowlist. Any empty or malformed entry rejects the complete list and keeps forwarded identity disabled.
- `QUICFUSCATE_ENABLE_ADMIN_SHUTDOWN` - `0|1|true|false`; exposes admin drain/shutdown endpoints (default: `false`). Captured at admin-server construction.

#### Congestion Control Environment Overrides

- `QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS` - Positive minimum-RTT filter window in milliseconds for BBR2 and BBR3. Default: `10000`; invalid or zero values use the default.

#### Memory Pool (Optimization) Environment Overrides

All memory-pool controls in this section are parsed into one `MemoryPoolRuntimeConfig` from the pool's immutable construction snapshot. `MemoryPool::new()` and `MemoryPool::new_adaptive()` capture their own snapshot when no parent runtime supplies one; the global pool and body pool pass their existing snapshot through. The auto-tuner stores the typed values at startup and never rereads process environment variables. Positive controls reject zero with a warning; utilization values are clamped to their documented percentages with a warning; `POOL_MAX_CAP` is normalized to at least the effective minimum capacity.

- `QUICFUSCATE_POOL_CAPACITY` - Initial pool capacity (blocks). Default: `512`.
- `QUICFUSCATE_POOL_BLOCK_SIZE` - Requested block size in bytes for the lazy adaptive global packet pool. Default request: `65536` (64 KiB). With adaptive sizing enabled, the effective size is selected from `QUICFUSCATE_MTU_HINT`; `quicfuscate_mem_pool_block_size_bytes` and `MemoryPool::block_size()` expose the effective size. Set `QUICFUSCATE_POOL_ADAPTIVE_BLOCK=0` to make the global request explicit. A minimum of `2048` bytes is enforced.
- `QUICFUSCATE_POOL_HARD_MAX_CAP` - Explicit hard upper limit for capacity growth in blocks. The default is the greater of the configured initial capacity and 64 MiB divided by the effective block size.
- `QUICFUSCATE_POOL_AUTO_TUNE` - `0|1|false|true` to enable auto-tuner. Default: `true`.
- `QUICFUSCATE_POOL_MIN_CAP` - Minimum capacity for auto-tuner. Default: `64`.
- `QUICFUSCATE_POOL_MAX_CAP` - Maximum capacity requested by the auto-tuner. Default: `1024`; the per-pool byte bound remains authoritative.
- `QUICFUSCATE_POOL_TICK_MS` - Auto-tuner tick duration in milliseconds. Default: `1000`.
- `MemoryPool::shutdown_auto_tuner()` - Explicitly stops and joins the auto-tuner when a short-lived process or test owns the global pool.
- `QUICFUSCATE_POOL_UTIL_HIGH` - Utilization percent that triggers growth (default: `80`).
- `QUICFUSCATE_POOL_UTIL_LOW` - Utilization percent that triggers shrink (default: `30`).
- `QUICFUSCATE_TLS_HIGH` - TLS cache size under high utilization after explicit TLS-cache opt-in (default: `48`).
- `QUICFUSCATE_TLS_LOW` - TLS cache size under low utilization after explicit TLS-cache opt-in (default: `24`).
- `QUICFUSCATE_POOL_ADAPTIVE_BLOCK` - `0|1|false|true` for the explicitly adaptive packet-pool constructors (default: `true`). If enabled, block size is selected from MTU hints: `<=1500 -> 4096`, `<=9000 -> 16384`, otherwise `65536`. It does not override `MemoryPool::new()` or `QUICFUSCATE_BODYPOOL_BLOCK`.
- `QUICFUSCATE_MTU_HINT` - Integer hint for typical link MTU used by adaptive block sizing (default: `1500`).
- `QUICFUSCATE_TLS_CACHE` - Per-thread cache size for pooled blocks (default: `0`). The active `MemoryPool` cache is actual thread-local storage keyed by pool identity, but pool lifetime and capacity accounting for cached blocks remain open under TODO-827. The separate feature-gated `UnsafeMemoryPool` cache is not covered by this guarantee and is tracked under TODO-826.
- `QUICFUSCATE_POOL_DEBUG_SLACK` / `QUICFUSCATE_POOL_DEBUG_GRACE` - Debug-only invariants slack to reduce spurious warnings under bursty workloads.
- `QUICFUSCATE_MADVISE_HUGEPAGE` - `0|1|false|true` to disable or enable MADV_HUGEPAGE hints on Linux (default: `true`).
- `QUICFUSCATE_NUMA_POLICY` - `local|interleave|preferred:<n>` for NUMA placement on Linux (default: `local`). The policy is initialized from the same global-pool construction snapshot.

Notes:
- Pool growth targets 64 MiB per pool by default, or an explicitly larger initial pool, and `QUICFUSCATE_POOL_HARD_MAX_CAP` cannot reduce an already configured initial capacity. At the hard cap, an ephemeral allocation path exists, but its return, origin, TLS-cache, and counter semantics are not yet proven; TODO-827 owns that contract.
- `check_invariants()` is diagnostic rather than a release enforcement gate: it uses configurable debug slack/grace and is skipped in test and release builds. Exact ownership and counter invariants remain open under TODO-827.

**Stealth fine-tuning (runtime overrides):**
- `QUICFUSCATE_STEALTH_PADDING_MAX`: positive integer; caps per-packet padding in bytes
- `QUICFUSCATE_STEALTH_PADDING_STRATEGY`: `random|fixed|adaptive|browser|browser-mimic` (aliases: `1|2|3|4`)
- `QUICFUSCATE_STEALTH_JITTER_US`: non-negative integer microseconds; `0` disables timing gate
- `QUICFUSCATE_STEALTH_ADAPTIVE_GRAN`: positive integer bytes; adaptive padding granularity (default `64`)
- `QUICFUSCATE_STEALTH_MIMIC_BIAS`: `1|2|3|4` or `very_small|small|default|mobile|safari|firefox|android|chromium|chrome|edge` (browser or OS-shaped bias for BrowserMimic)
- `QUICFUSCATE_BROWSER`: `chrome|firefox|safari|edge` (legacy alias: `QUICFUSCATE_BROWSER_PROFILE`)
- `QUICFUSCATE_OS`: `windows|linux|macos|android|ios` (legacy alias: `QUICFUSCATE_OS_PROFILE`)
- `QUICFUSCATE_DOH`: `0|1|true|false` (legacy alias: `QUICFUSCATE_DOH_ENABLED`)
- `QUICFUSCATE_FRONTING`: `0|1|true|false`
- `QUICFUSCATE_FRONTING_DOMAINS`: comma-separated fronting domain list
- `QUICFUSCATE_H3_MASQUERADE`: `0|1|true|false`
- `QUICFUSCATE_QPACK`: `0|1|true|false`
- `QUICFUSCATE_STEALTH_PADDING`: `0|1|true|false`
- `QUICFUSCATE_STEALTH_PADDING_MAX`: positive integer; canonical padding cap (legacy alias: `QUICFUSCATE_STEALTH_MAX_PADDING`)
- `QUICFUSCATE_STEALTH_PADDING_STRATEGY`: `random|fixed|adaptive|browser|browser-mimic` (aliases: `1|2|3|4`; legacy alias: `QUICFUSCATE_PADDING_STRATEGY`)
- `QUICFUSCATE_FINGERPRINT_ROTATION`: `0|1|true|false`
- `QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL`: integer seconds
- `QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION`: `0|1|true|false`
- `QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE`: `0|1|true|false`
- `QUICFUSCATE_STEALTH_DYNAMIC`: `0|1|true|false` - enable dynamic escalation and de-escalation
- `QUICFUSCATE_CHOKE_ENABLE`: `0|1|true|false` - enable real-time rate choke
- `QUICFUSCATE_CHOKE_TARGET_MBPS`: integer - target Mbps for rate choke
- `QUICFUSCATE_CHOKE_BURST_MS`: integer - allowed burst window in milliseconds
- `QUICFUSCATE_SERVER_PUSH_COVER`: `0|1|true|false`
- `QUICFUSCATE_SERVER_PUSH_INTENSITY`: float
- `QUICFUSCATE_SERVER_PUSH_BASE_PATH`: path
- `QUICFUSCATE_SERVER_PUSH_BURST_INTERVAL`: integer seconds
- `QUICFUSCATE_ACK_THRESHOLD`: integer - override transport ACK threshold used by StealthBrain coupling
- `QUICFUSCATE_ACK_MAX_DELAY_MS`: integer - override transport max ACK delay
- `QUICFUSCATE_EXTERNAL_PACING`: `0|1|true|false` - force external pacing in transport
- Explicit ACK / pacing / jitter / padding / granularity / mimic-bias overrides also lock the matching Intelligent-mode Brain actuator for that connection, so operator-selected transport tuning remains authoritative at runtime.

### Mode Presets (ENV)

For quick switching between modes at runtime without editing TOML, source one of the presets:

Note: Select modes via TOML configuration using `StealthConfig::from_mode()` or environment variables like `QUICFUSCATE_STEALTH_MODE`.

Notes:
- Presets set `QUICFUSCATE_*` variables for the current shell only. They do not modify configuration files.
- You can override any single knob after sourcing a preset, e.g. `export QUICFUSCATE_STEALTH_JITTER_US=1000`.

#### FEC Environment Variable Overrides

See "FEC Operations Guide -> Environment controls (runtime)" for the authoritative list and semantics of FEC runtime variables. This section intentionally avoids duplication.

Example:

```bash
export QUICFUSCATE_BROWSER=firefox
export QUICFUSCATE_OS=linux
export QUICFUSCATE_DOH_PROVIDER=https://dns.google/dns-query
export QUICFUSCATE_FRONTING=true
```

### Advanced Stealth Components

#### Cover Traffic Scheduler
```rust
struct CoverTrafficScheduler {
    target_domain: String,
    interval_ms: Arc<AtomicU64>,
    // ...
}

// Generates realistic browser traffic patterns - internal to StealthManager
// Created automatically when enable_http3_masquerading = true
let scheduler = CoverTrafficScheduler::new("example.com", 5000);
```

#### Active Probe Detection
```rust
pub struct ActiveProbeDetector {
    patterns: Vec<ProbePattern>,   // GFW_TLS_Probe; DPI_QUIC_Scan remains response-selector compatibility only
    history: Arc<Mutex<VecDeque<Instant>>>,
    threshold: usize,
    history_limit: usize,          // max(threshold, 1)
    response_mode: ProbeResponseMode,
}

// Detects and responds to DPI probes
let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
if let Some(mode) = detector.check_packet(&packet, source_addr) {
    // mode is Ignore | Fake | Switch | Block
}
```
`check_packet` records matching probes as timestamps in a bounded rolling 60-second history. The history limit is `max(threshold, 1)`, so the detector retains enough entries to preserve the configured threshold while sustained matching traffic evicts the oldest timestamp. Below the configured threshold it returns the configured response mode; once the recent matching count reaches the threshold it returns `Switch` for escalation. The current `StealthManager` path uses a threshold of 5 when dynamic stealth, traffic padding, or timing obfuscation is enabled. The downstream `EscalationState` has an independent bounded 120-second millisecond-bucket history and separate 60-/120-second counters.

#### Flow Shaping
```rust
pub struct FlowShaper {
    jitter_min_us: u64,
    jitter_max_us: u64,
    packet_history: Arc<Mutex<VecDeque<PacketInfo>>>,
    _enabled: AtomicBool,
}

// Advanced traffic shaping
let shaper = FlowShaper::new(50_000, true);
let jitter = shaper.apply_jitter();
```

#### MASQUE Tunnel Management
Core H3/MASQUE tunnel state is internal production machinery inside
`src/core_parts/connection.rs` and `src/transport/h3_parts/connection.rs`. There is no stable public
`MasqueTunnel::connect(...)` product API in the current runtime; the live carrier is wired through
the authenticated Core H3 connection.

### Advanced TLS Features

#### Certificate Chain Emulation
- Certificate-chain emulation is part of the retained TLS Cover extras path in `src/stealth/`.
- It is controlled through `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) and
  the active stealth runtime mode, not through a standalone public `CertChainEmulator` API.
- 2-3 level certificate chain
- ECDSA-P256 + SHA-256
- Realistic SANs
- 60-90 days validity

#### Session Tickets & Resumption
- Ticket realism is likewise part of the TLS Cover extras path in `src/stealth/`.
- There is no standalone public `SessionTicketManager` type exposed as a stable product API in the
  current codebase.
- 1-2 NewSessionTicket records
- PSK with realistic ages
- Timer jitter for authenticity
- Automatic 0-RTT resumption support

#### ECH GREASE
- Encrypted Client Hello GREASE
- Modern browser behavior
- 64 Bytes GREASE Data

### Fingerprint Rotation

Fingerprint/persona rotation is connection-scoped. The settings below remain useful as a sequence
source, but an established connection does not change browser, operating system, TLS, H3, or QPACK
persona mid-session. Rotation selects the next persona only for a new connection or explicit reconnect.

#### Configuration
```toml
[fingerprint_rotation]
enabled = true
interval_secs = 180  # 3 minutes
mode = "slots"  # fixed, slots, all
profile_slots = [
    "chrome:windows",
    "firefox:macos",
    "safari:ios",
]
```

#### Rotation Modes
- **Fixed**: single profile, no rotation
- **Slots**: rotate through configured slots (up to 64)
- **All**: rotate through all available profiles

### Browser Profile

Available combinations:
- **Windows**: Chrome, Firefox, Edge
- **macOS**: Safari, Chrome, Firefox, Edge
- **Linux**: Chrome, Firefox
- **Android**: Chrome, Firefox, Edge
- **iOS**: Safari, Chrome

### Traffic Obfuscation

#### Padding Strategies
1. **Random**: randomized padding `0..=max_size`
2. **Fixed**: fixed padding up to `max_size`
3. **Adaptive**: adaptive padding based on size and granularity
4. **BrowserMimic**: profile-biased padding using the mimic bias and granularity knobs

### Domain Fronting

Curated domain sets are defined in `CdnProvider` and `DomainFrontingManager::ultra_stealth` in `src/stealth/`. Production policy is explicit-only outside Anti-DPI:

- Performance, Intelligent level 0, and Stealth do not enable domain fronting by default.
- Fronting activates outside Anti-DPI only when explicit `fronting_domains` are configured and runtime policy has not disabled fronting.
- Anti-DPI remains the aggressive profile and may use the built-in ultra list when fronting is enabled without explicit domains.
- Active sessions do not rotate fronting hosts or browser/OS personas mid-connection.

### Performance Optimizations

#### SIMD XOR Obfuscation
- SSE2 on x86_64: 32-byte chunks
- NEON on aarch64: 32-byte chunks
- Fallback: Byte-wise XOR

#### Zero-Copy Operations
- In-place Obfuscation/Deobfuscation
- Pooled memory for HTTP/3 headers
- Aligned buffers for SIMD


## Stealth & Protocol Reference

### TUN Bridging over HTTP/3

QuicFuscate bridges a TUN interface through an adaptive MASQUE/HTTP/3 carrier:

- Client fast path: packets within the confirmed MASQUE payload use CONNECT-UDP datagrams. The payload ceiling is derived from confirmed DPLPMTUD, peer/configured UDP bounds, the 36-byte FEC envelope, and the bounded QUIC/MASQUE reserve.
- Client fallback: IPv6-minimum packets that exceed one MASQUE datagram but remain within the effective tunnel MTU use `QFT1` plus a two-byte packet length on the `/tun` H3 stream. Per-stream bounded reassembly preserves exact IP-packet boundaries across arbitrary H3 DATA segmentation and coalescing.
- Reliable fallback: transport owns at most 16 MiB of immutable STREAM payload ranges. Exact ACK retirement, packet-threshold loss, and tail PTO requeue lost ranges before new data. A PMTU decrease splits queued transmissions to the new exact packet budget, and a late ACK of the original packet retires every derived segment exactly once.
- Packetization and pacing: new and retransmitted STREAM frames use the full confirmed PMTU rather than the discovery floor. The core-owned outbound pacer gates every congestion-controlled QUIC/FEC datagram while ACK-only output bypasses pacing.
- MTU lifecycle: DPLPMTUD policy exposes validated minimum, maximum, probe interval, and black-hole timeout values. The client opens TUN at the lower of the configured ceiling and effective tunnel MTU, then applies confirmed changes through the platform backend. Packets above the live boundary receive local IPv4 Fragmentation Needed or IPv6 Packet Too Big instead of silent loss.
- Server uplink MTU disposition: `allow_client_uplink()` rejects IPv4 packets larger than the server TUN MTU with IPv4 Fragmentation Needed for both DF=0 and DF=1 before either the MASQUE or framed-H3 TUN write. The server intentionally does not perform userspace IPv4 fragmentation, making the oversized-packet contract independent of platform-specific TUN write behavior.
- Standalone client activation: `--tun` is a required data-plane request, not a best-effort bridge. TUN open/configuration errors, reader-thread ownership failures, and subsequent reader errors fail closed instead of silently disabling the bridge. Startup cleanup closes the QUIC connection, retains the kill switch in block-only state, and shuts down the stealth runtime within its bounded timeout while preserving the primary TUN error. Connected policy is published only while every requested TUN resource is owned and the reader remains healthy. Generic `ClientRuntime` and standalone server startup retain their existing fail-closed setup and rollback contracts; platforms without a native backend report explicit unavailability.
- Server Linux: with `--tun`, authenticated MASQUE CONNECT-UDP datagrams carrying raw IP packets are written to the verified Linux TUN interface. Standalone server mode derives `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool from explicit `--tun-ip` / `--tun-netmask`, so runtime session routing and OS TUN addressing stay aligned.
- Standalone initial transport gate: the client must first construct a non-empty QUIC datagram and successfully send that datagram on the connected UDP socket. Construction and socket-send outcomes are logged and counted separately. Either failure runs bounded startup cleanup, preserves the original error kind and context, and returns before HTTP/3 requests, TUN activation, or connected readiness.
- Server macOS/Windows: embedded and standalone server TUN startup rejects the mode before host mutation because no native server routing owner and privileged proof are shipped for those platforms. `RoutingManager` does not expose a mutating server setup, stale cleanup, or teardown path there; only non-mutating rule/script generation remains internal and is not an advertised server capability.
- Multi-client routing: authenticated source ownership is enforced for both datagram and framed-stream uplink. Owned unicast is destination-routed; IPv4 directed broadcast/multicast and IPv6 multicast use explicit authenticated fan-out; client-to-client unicast remains default-deny unless explicitly enabled.
- Server hotpath: after a TUN packet is queued as MASQUE downlink for one session, only that target client's connection is flushed. The server does not scan and flush all clients per TUN packet.
- Authentication: the public QKey ID in the QUIC Initial selects the server-side record. The client sends the bearer only after 1-RTT encryption through the H3/MASQUE `x-qf-auth` header. The server gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state and closes missing or invalid authentication attempts.
- Platform support (interface.rs):
  - Linux/Android: `/dev/net/tun` via `TUNSETIFF` (IFF_TUN | IFF_NO_PI)
  - macOS: `utun` (PF_SYSTEM/SYSPROTO_CONTROL), 4-byte AF header using readv/writev
  - Windows: built-in Wintun adapter when `tun-windows` is enabled, with external factory override retained
  - Other Unix: external factory via trait injection
  - All use the shared `MemoryPool` for zero-copy slices where possible.

Exact ARM64 run35 evidence uses source archive SHA-256 `b3140e9c14300af3416d021de6e81476ec41e3b57b775c7b1605a9fcaaf2ce3e` and binary SHA-256 `d985c254fb55792afc9d2e1bc88d14b68b8737a3bfcb7507961fc8b1a1c09888`. Local and native full tests plus strict all-target/all-feature Clippy pass. The isolated three-client run proves dual-stack allocation/routing/NAT, source ownership, spoof rejection, default-deny and explicit opt-in client unicast, authenticated fan-out, client/server IPv4 and IPv6 PTB, DPLPMTUD 1280-to-1500 discovery, black-hole fallback to 1280, and bounded re-confirmation to 1500. Its historical throughput medians and reported 38.85% gain are not PMTU payload-efficiency proof: both phases then hard-coded the TUN ceiling to 1280 and route setup reset it to 1280. The harness now gives each phase its configured TUN ceiling, leaves client MTU changes to confirmed DPLPMTUD synchronization, and retains the 15% gain gate; fresh exact ARM64 evidence is required. Cleanup leaves no product process or network namespace.

### CUBIC Conformance and Runtime Evidence

The CUBIC controller follows RFC 9438 epoch math, including `K = cbrt((W_max - cwnd_epoch) / C)`, bounded `W_cubic(t + RTT)` targeting, a stateful Reno-friendly estimate, one multiplicative decrease per QUIC recovery episode, and application-limited epoch suspension. RFC 9406 HyStart++ uses round minima, at least eight RTT samples, a 4-16 ms delay threshold, Conservative Slow Start at one-quarter growth, spurious-exit recovery, and five CSS rounds. Precision vectors keep relative error below `1e-6`, and the CUBIC controller remains less than 200 bytes larger than Reno on supported architectures.

The deterministic shared drop-tail test records CUBIC `13,389,600` bytes, Reno `14,367,600` bytes, and Jain fairness `0.998760`. Exact Omega run06 uses build-source archive SHA-256 `df1aed74696ed45ca1bb66e06556cf39b8298620fc60878570427dbcda4d0837`, compile-input digest `423cb07e9b4f64c3605ba28034257edcfb4124a4e5ccd86850908d6c5109a680`, and native AArch64 binary SHA-256 `2dc42fd87b77f50eaef96c0244a15adf8126f19d4593c5497f26acdb048483eb`. On the shared 2 Mbit/s bottleneck, CUBIC reaches 0.961 Mbit/s, Reno reaches 0.951 Mbit/s, and Jain fairness is `0.999974`. Across three clean and three `netem loss random 5%` CUBIC trials on a 5 Mbit/s bottleneck, median throughput is 3.001 Mbit/s clean and 2.862 Mbit/s under loss, retaining 95.38%. Local and native full Rust tests and strict all-target/all-feature Clippy pass. Evidence is retained at `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo535/evidence/run06`; cleanup leaves no product process, network namespace, or test qdisc.

Harness source `046a567c40cda342635ea4634753fe74d64cd091` keeps the control durable when an explicit evidence directory is long: its owned `QF_E2E_ADMIN_SOCKET` default is a checked short `/tmp` path, so the Unix-domain socket limit cannot suppress server startup. It executes three clean and three 5%-loss trials for each of Auto and FEC-off and emits per-policy JSON plus a combined comparison. Against verified ARM64 binary SHA-256 `ee0243f6aae50ee66115ba9f11d596004c3f057e240654e9a4bf340461e95e88`, Auto recorded 3.001/2.984 Mbit/s and 99.45% retention; FEC-off recorded 3.001/2.857 Mbit/s and 95.20% retention; the observed Auto-minus-Off difference was 0.128 Mbit/s and 4.25 percentage points. The run measured CUBIC/Reno at 1.045/1.080 Mbit/s with Jain `0.999726`, retained its evidence under the isolated candidate, and left no product process, namespace, bridge, or test veth behind.

The current control additionally samples exact process CPU/RSS and standalone allocation/backpressure metrics every 200 ms and records 40-sample p50/p95 tunnel latency per phase. Final-source ARM64 binary SHA-256 `e09cad15ef86ea79a074bf1daff93615a97e9078d8786e346ac77b6f5d82f580` passes the tightened 50%-of-one-core CPU, 384-MiB combined RSS, 75,000 fallback-allocation, and 75/100-ms clean/impaired p95 limits. Auto recorded 3.001/2.992 Mbit/s and 99.71% retention; Off recorded 3.001/2.849 Mbit/s and 94.94%; fairness was `0.999979`. Across all four phases, combined RSS was 284.3-284.4 MiB, CPU 12.70-17.21%, p95 35.3-59.3 ms, fallback allocations 16,469-52,663, and pending queue/rate-limit counters zero. Evidence is retained at `/tmp/qf-ff9d316-final-udp-20260729-0148`.

### Real TLS Fingerprints

This section is an operational view; canonical behavior is defined in "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".

QuicFuscate performs native TLS handshake profile selection using `TlsProfile` values selected by `--profile` and `--os`; rustls constructs the real wire ClientHello. Deterministic in-memory ClientHello metadata remains available for compatibility and audit inspection, but is not a transport override. Runtime operation does not require on-disk profile dumps.

Generated compatibility ClientHello metadata is attached to the in-memory fingerprint profile used by compatibility and audit paths.

If you maintain external profile dumps for audit/regression purposes, place them under `browser_profiles/` and use the TLS utilities to inspect and verify them.
Example:
```bash
./scripts/tests/utils/util-tls-list-profiles.sh
./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh
./scripts/tests/utils/util-e2e-verify-all.sh
```

#### Available Browser/OS Profiles

The following consolidated profiles are available and validated at startup:

| Browser | OS |
|---|---|
| Chrome | Windows, MacOS, Linux, Android, iOS |
| Firefox | Windows, MacOS, Linux, Android |
| Safari | MacOS, iOS |
| Edge | Windows, MacOS, Linux, Android |

Notes
- `--profile` and `--os` select the active pair. For rotation, use `--profile-seq` and `--profile-interval`.
- Each profile harmonizes UA string, Accept-Language, cipher suites and QUIC transport parameters (max data/streams, idle timeout).

### TLS Cover Exchange

TLS Cover is a lightweight synthetic exchange for stealth shaping and traffic realism. It derives profile-scoped cover-record material from the active fingerprint profile and emits synthesized reply artifacts with shorter message sizing than a full handshake. It does not generate or replace a real ClientHello. Real ClientHello bytes are owned by rustls; deterministic compatibility metadata is not consumed on the wire.

TLS Cover is optional and does not replace native TLS security semantics.

**Scope - handshake phase only:** TLS Cover generates synthetic QUIC `CRYPTO` frames during the handshake phase only. This is correct QUIC behavior: per RFC 9001, QUIC `CRYPTO` frames only appear during the handshake. After the handshake completes, injecting `CRYPTO` frames would be anomalous and detectable. Post-handshake cover traffic is provided by three complementary mechanisms described below.

**Post-handshake cover mechanisms (three layers):**

1. **Cover PINGs** (`StealthConfig.enable_cover_ping`, `cover_ping_interval_ms`): ack-eliciting QUIC `PING` frames injected at the configured interval (default 30 s for Stealth, 15 s for Anti-DPI). Wired in `core.rs` via `StealthManager::should_send_cover_ping()` -> `Connection::queue_cover_ping()`. Mimics idle browser/HTTP3 keepalive patterns.

2. **PacketNormalize padding** (`PaddingStrategy::PacketNormalize`): all 1-RTT packets are padded to `normalize_target_size` bytes so wire-visible packet sizes are uniform. Prevents length-based traffic analysis.

3. **Native H3 cover**: `CoverTrafficScheduler` emits persona-shaped H3 request headers, while Server Push and escalated WebTransport use H3-framed application cover. The H3 parser remains fail-closed for malformed or oversized frames; no fixed stream is reserved and no raw random payload bypasses H3 framing.

To force TLS Cover via the configuration file add:

```toml
[stealth]
use_tls_cover = true
```

### Server Push Cover Traffic (HTTP/3)

QuicFuscate generates realistic HTTP/3 Server Push traffic to mask real flows. This feature is governed by `StealthConfig` and transport H3 internals.

Server Push cover is not a fixed repeating signature. Production-grade cover bursts use bounded
variation in resource count, ordering, payload size, path names, and cache headers. Performance mode
keeps Server Push cover off; Intelligent level 0 stays off or near-zero; Stealth and Anti-DPI use
randomized bursts according to their cover budget.

- Configuration (Stealth):
  - `enable_server_push_cover`: enable/disable cover traffic.
  - `server_push_intensity`: 0.0-1.0 scaling for burst size/frequency.
  - `server_push_base_path`: base URI path for pushed resources (e.g., `/assets`).
  - `server_push_burst_interval`: minimum seconds between bursts.
- Generation (Transport):
  - `create_server_push_promise()` and `generate_stealth_cover_burst()` synthesize push promises with realistic content types.
  - Payloads: generated CSS, JS and small image blobs with deterministic variability to evade static signatures.
  - State: maintains `next_push_id`, tracks open push streams, and injects cover DATA frames interleaved with real traffic.
  - Lifecycle: completed push streams are released by the H3 polling GC together with their stream state and cover payload; terminal stream IDs and MASQUE flow mappings are released at the same boundary.
- Telemetry: MASQUE/cover traffic counters under `optimize::telemetry::*` record bytes and capsule usage (when applicable).

Example (runtime behavior)
```text
Anti-DPI escalates -> enable_server_push_cover=true, intensity~0.8, burst_interval=15 s.
Transport emits PUSH_PROMISE and DATA with CSS/JS payloads across multiple streams.
```

#### Cover Burst Example

```rust
use quicfuscate::transport;

// Assume an established transport connection `conn` and a configured H3 connection
let mut cfg = transport::Config::new().expect("config");
let mut h3 = transport::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

// Generate a burst of realistic cover pushes under /assets
let push_ids: Vec<u64> = h3.generate_stealth_cover_burst("/assets").expect("cover burst");

// Typical content-types generated per push:
//  - text/css (CSS)
//  - application/javascript (JS)
//  - image/jpeg or image/png (images)

// Application may continue polling events; pushed streams carry DATA frames with the cover payloads.
```

#### Handling Server Push Events

```rust
use quicfuscate::transport::h3::{Connection as H3, Event};

fn poll_h3_events(h3: &mut H3, conn: &mut quicfuscate::transport::Connection) {
    while let Ok(Some(ev)) = h3.poll(conn) {
        match ev {
            Event::PushPromise { push_id, headers } => {
                // Observe pushed resource headers for realism
                for h in &headers { log::debug!("push {}: {:?} -> {:?}", push_id, h.name(), h.value()); }
            }
            Event::Data => {
                // Read DATA frames for active/pushed streams internally
            }
            _ => {}
        }
    }
}
```

### MASQUE CONNECT-UDP

Core H3/MASQUE is the canonical VPN/TUN data-plane carrier and the only active CONNECT-UDP implementation. The live path is owned by `src/core_parts/connection.rs` and `src/transport/h3_parts/connection.rs`; the retired stealth manager and stealth-local DoH source remain recoverable under `archive/` and are not compiled.

- Streams: establishes CONNECT-UDP control streams; keeps them open for duration of the tunnel.
- DATAGRAM: registers Flow-ID/Context-ID; sends UDP payloads over QUIC DATAGRAM frames.
- Capsules: encodes/decodes MASQUE capsules using varints.
  - Common types observed in telemetry: `0x00` (DATAGRAM), `0x21`, `0x22` (implementation-specific control/data hints).
- QPACK: MASQUE headers use QPACK with dynamic table; preferred indexing keys are set via `set_qpack_index_policy()`.
- Telemetry: `MASQUE_BYTES_SENT`, `MASQUE_BYTES_RECEIVED`, and capsule counters per type.

Notes
- Canonical Stealth, Anti-DPI, Performance, and Intelligent modes use the production H3/MASQUE TUN carrier when TUN mode is active.
- Split capsule varints use the full 1/2/4/8-byte QUIC widths, including 16,384-byte payload lengths. A malformed capsule or truncated FIN suffix fails closed before staged events are exposed.
- `src/dns/mod.rs` remains the owner of shared DoH primitives, and `src/implementations/client/dns_runtime.rs` owns the active client lifecycle; the retired `stealth/parts/doh.rs` resolver and `stealth::MasqueManager` source are preserved under `archive/stealth/` for historical inspection only. TODO-771 completed the runtime wiring.
- If you maintain external profile dumps, `scripts/tests/utils/util-tls-export-active-profile.sh` exports them under `scripts/out/utils/.../profiles/` by default (or a caller-provided `--output-dir`) for regression tracking.

#### MASQUE Roundtrip Example

```rust
use quicfuscate::transport::h3::{Header, qpack};

// Minimal, reproducible header set
let headers = vec![
    Header::new(b":method", b"GET"),
    Header::new(b":scheme", b"https"),
    Header::new(b":authority", b"example.com"),
    Header::new(b":path", b"/"),
    Header::new(b"accept-encoding", b"gzip, deflate, br"),
];

// Encode
let mut enc = qpack::Encoder::with_capacity(1024);
enc.set_index_policy(&[b":method", b":scheme", b":authority", b":path", b"accept-encoding"]);
let mut buf = vec![0u8; 1024];
let n = enc.encode(&headers, &mut buf).expect("encode");
let payload = &buf[..n];

// Decode
let mut dec = qpack::Decoder::with_capacity(1024);
let decoded = dec.decode(payload).expect("decode");

assert_eq!(decoded.len(), headers.len());
for (a, b) in decoded.iter().zip(headers.iter()) {
    assert_eq!(a.name(),  b.name());
    assert_eq!(a.value(), b.value());
}
```

### HTTP/3 Masquerade Headers API (QPACK)

- __StealthManager::get_http3_masquerade_headers(host, path) -> Option<Vec<u8>>__
  - On x86 profiles the Huffman stage dispatches to AVX2/SSSE3 kernels; other platforms use the scalar fallback.
  - Returns a QPACK-encoded header block as `Vec<u8>`.
  - Encodes into a pooled buffer first and then materializes an exact-sized `Vec`, returning the pool block afterwards.
  - On pooled-buffer failure increments `telemetry::STEALTH_QPACK_POOL_FALLBACKS` (telemetry counter: `stealth_qpack_pool_fallback_total`) and re-encodes using a heap `Vec`.
  - Ownership: the caller fully owns the returned `Vec`.

- __StealthManager::get_http3_masquerade_headers_boxed(host, path) -> Option<(AlignedBox<[u8]>, usize, bool pooled)>__
  - Returns an aligned buffer (`AlignedBox<[u8]>`), the valid length (`usize`), and a flag `pooled`.
  - `pooled == true`: buffer comes from the internal pool and must be returned via `StealthManager::free_pooled_block`.
  - `pooled == false`: aligned fallback allocation (64-byte alignment); drop when no longer needed.
  - On pooled-buffer failure increments `telemetry::STEALTH_QPACK_POOL_FALLBACKS` (telemetry counter: `stealth_qpack_pool_fallback_total`).

- __StealthManager::free_pooled_block(block: AlignedBox<[u8]>)__
  - Only return buffers that originated from the pool (`pooled == true`). Do not call this for aligned fallback buffers.

Notes:
- Telemetry export is disabled by default; enable via `--telemetry` (see "Telemetry Metrics").
- A structural header list is also available via `StealthManager::get_http3_header_list(..)`.

Cover Traffic integration:
- __StealthManager::cover_headers_due() -> Option<Vec<Header>>__
  - Returns a small, persona-shaped GET/HEAD header set when due (rate-limited by the scheduler).
- `core::QuicFuscateConnection::poll_http3()` opportunistically calls `cover_headers_due()` on each poll iteration and sends a cover request when returned.

#### Pseudo-Headers & Typical Header Set
- Pseudo-headers in fixed order: `:method`, `:scheme`, `:authority`, `:path`.
- Realistic profile-driven headers (excerpt):
  - `user-agent`, `accept`, `accept-language`, `accept-encoding: gzip, deflate, br`
  - Chromium: `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`, `upgrade-insecure-requests`
  - Referer: depends on fronting/navigation (e.g., search portal or same-origin)

#### Index Policy (Dynamic Table)
- The QPACK encoder carries a preferred index policy (`set_index_policy`) to prioritize common names for better compression.
- Default seeds (when capacity allows): `content-type` (CSS/JS/JSON/JPEG/PNG), `cache-control`, `accept-encoding`, `accept`, `x-cdn-cache`.

#### Encoding Behavior (internal)
- Fully static indexed entry: `0x80 | index`
- Static name, literal value (Huffman): `0x40 | index` followed by string (Huffman)
- Dynamic indexed entry (name+value): `0xA0 <varint index>`
- Literal name+value: `0x20 <name> <value>` (strings Huffman-encoded)

Illustration (simplified)
```text
[:method=GET]        -> 0x80 | idx(":method=GET")
[:scheme=https]      -> 0x80 | idx(":scheme=https")
[:authority=host]    -> 0x40 | idx(":authority") <huff(host)>
[:path=/p]           -> 0x40 | idx(":path") <huff("/p")>
[accept-encoding=...]-> 0x80 | idx("accept-encoding=gzip, deflate, br")
[user-agent=...]     -> 0x20 <huff("user-agent")> <huff(UA)>
```

#### QPACK Roundtrip Example (encode -> decode)

```rust
use quicfuscate::transport::h3::{Header, qpack};

// Minimal, reproducible header set
let headers = vec![
    Header::new(b":method", b"GET"),
    Header::new(b":scheme", b"https"),
    Header::new(b":authority", b"example.com"),
    Header::new(b":path", b"/"),
    Header::new(b"accept-encoding", b"gzip, deflate, br"),
];

// Encode
let mut enc = qpack::Encoder::with_capacity(1024);
enc.set_index_policy(&[b":method", b":scheme", b":authority", b":path", b"accept-encoding"]);
let mut buf = vec![0u8; 1024];
let n = enc.encode(&headers, &mut buf).expect("encode");
let payload = &buf[..n];

// Decode
let mut dec = qpack::Decoder::with_capacity(1024);
let decoded = dec.decode(payload).expect("decode");

assert_eq!(decoded.len(), headers.len());
for (a, b) in decoded.iter().zip(headers.iter()) {
    assert_eq!(a.name(),  b.name());
    assert_eq!(a.value(), b.value());
}
```

### Domain Fronting API

- `DomainFrontingManager::get_fronted_domain(&self) -> String` uses strict
  round-robin selection. Serial calls are deterministic; concurrent calls
  reserve unique sequence slots but their completion order follows scheduling.
- `DomainFrontingManager::random_domain(&self) -> String` is the explicit
  unpredictable selection path and is not selected by configuration implicitly.
- Both methods return `cdn.cloudflare.com` when the manager has no domains.
- Production cover-scheduler initialization, SNI/Host fronting, and
  WebTransport cover consume strict round-robin. MASQUE proxy authority stays
  on the first configured domain plus `:443` as a stable connection endpoint.
- Domains are stored as `Arc<[String]>`; the current public selection methods
  return owned `String` values and therefore retain their existing clone
  contract.

## Verification Harness Contracts

The affected test and benchmark wrappers preserve operator and CI arguments as arrays. `scripts/tests/lib/lib-common.sh` validates control-free values, bounded decimal integers, feature lists, output paths, and environment assignments; `run_cargo_with_env` exports validated assignments without `eval`, `bash -lc`, word splitting, or loss of argument boundaries. FEC, FEC simulation, StealthBrain, optimization, security/fuzzing, and crypto benchmark suites use the shared boundary and record per-cell `PASS`, `FAIL`, or `SKIP` status with command status and bounded command/environment identity.

Internal JSON artifacts use the shared serializer contract. `run` records command identity as `argv` plus an `environment` object; it never stores Bash-escaped command text as JSON. `qf_json_append_object` validates typed fields before appending and supplies empty structured `argv` and `environment` fields when an item does not execute a command, `json_end` parses the completed document before the caller can report success, and `qf_json_write_raw_file` validates and installs standalone JSON atomically. Default ownership is create-new: `json_begin`, `qf_json_write_object_file`, and standalone writers refuse an existing target. `QUICFUSCATE_ARTIFACT_POLICY=replace-with-backup` is the only replacement mode and moves the previous file to a unique `.previous-<run-id>` path before installing the new document. Suite headers and standalone object artifacts record run ID, path, ownership, replacement policy, and source revision.

The suite result schema is the canonical envelope for test, benchmark, audit, and utility result streams. Standalone summary objects such as FEC matrices and analysis reports use the same parser-backed writer and retain their domain fields beside the artifact provenance object. Foreign JSON produced directly by Cargo, curl, iperf3, or a probe process remains a separately validated input or measurement artifact and is not misrepresented as a shell serializer output.

`scripts/benchmarks/suites/bench-orchestrator.sh` resolves fixed suite names to executable-plus-argv arrays, passes output directories as one argument, records structured `argv` and command identity in `manifest.json`, marks dry-run children as `SKIP`, and exits nonzero for failed children or unknown requested suites. `bench-qpack-encode.sh`, `micro-udpfast-throughput.sh`, and `micro-crypto-all.sh` validate numeric, size, endpoint, feature, jobs, flag, and path input before execution or numeric JSON serialization. The Admin E2E wrapper validates credentials, addresses, paths, timeout, and TTL, passes dynamic JSON values through Python `sys.argv`, and makes `--dry-run` a complete non-executing plan that does not require curl, PKI generation, server startup, or readiness polling.

Benchmark and analysis mode truth is explicit. `bench-crypto.sh`, `bench-fec.sh`, `bench-optimization.sh`, `bench-stealth.sh`, and `bench-transport.sh` accept `--fast` and `--full`, select different documented Criterion or test cells, and write a `meta` item with `mode`, `selected_cells`, and `cell_count`. `bench-orchestrator.sh` records `selected_suites` and propagates the matching flag to each mode-aware child. `analysis-coverage-summary.sh --fast` is a bounded static function/test inventory with no Cargo coverage run; `--full` runs the cargo-llvm-cov summary when available or the documented Cargo-test proxy. All dry-run paths serialize the selected mode without executing Cargo.

`scripts/tests/fast/test-harness-argument-safety.sh` is the real negative contract for argument boundaries. `scripts/tests/fast/test-benchmark-fast-mode-contract.sh` is the positive mode contract: it runs every affected benchmark and analysis helper in fast and full dry-run modes, validates JSON metadata and selected cells, checks orchestrator propagation, and uses paths containing spaces. TODO-781 owns this fast/full mode contract; TODO-735 remains the owner for the broader benchmark result-status and build/export contract, and TODO-738 remains the owner for typed parsing and checked workload arithmetic inside the Rust benchmark/probe examples.

## Scripts Reference
This section is the authoritative build/packaging script reference in this document. Script-produced artifacts are written to `scripts/out/<category>/` (including build-release artifacts under `scripts/out/build/...`).
For the broader script inventory and repository-wide file index, use `docs/MAP.md`.

#### Build and Packaging (`scripts/build/`)
- `build-web-admin.sh` - Builds `apps/svelte-admin` with frozen Bun dependencies and publishes generated output to ignored `assets/web-admin/`.
- `build-server-bundle.sh` - Produces a server bundle into `scripts/out/build/` for deployment packaging.

#### Build (`scripts/tests/build/`)
- `build-check.sh` - Format, Clippy, compile checks, test/bench compilation
- `build-clippy-matrix.sh` - Clippy feature-matrix sweep (aligns with CI variants)
- `build-env-doctor.sh` - Environment/Toolchain diagnostics

#### Build (`scripts/build/`)
- `build-pgo-release.sh` - Isolated PGO release build with run-scoped profiles, workload/merge validation, final binary hash, and `quicfuscate.pgo-release.v1` provenance manifest under `scripts/out/build/pgo-<UTC>-<random>/`
- `build-server-bundle.sh` - Server deployment bundle (binary + assets + systemd unit)
- `build-web-admin.sh` - SvelteKit admin UI static build to ignored generated output `assets/web-admin/`

#### Analysis (`scripts/tests/analysis/`)
- `analysis-coverage-summary.sh` - Coverage summary (JSON/text); `--fast` emits the bounded static function/test inventory, while `--full` runs the complete coverage path
- `analysis-dead-code-report.sh` - Dead code report (JSON/text)
- `analysis-scripts-quality.sh` - Script quality/static consistency checks
- `analysis-suite-matrix.sh` - Test/benchmark suite matrix report generation

#### Library (`scripts/tests/lib/`)
- `lib-common.sh` - Shared helpers (logging, typed JSON serialization and validation, create-new artifact ownership, environment detection, array-safe Cargo execution, and bounded harness-input validation)

#### Tests (`scripts/tests/`)
**Suites (`scripts/tests/suites/`)**
- `test-core.sh` - Core integration tests (CLI/telemetry/profile/qftls/reality/config)
- `test-profile-overrides.sh` - Deterministic profile override parity tests
- `test-profile-fuzz-parity.sh` - Fuzz-style parity tests (scalar vs SIMD) with forced profiles
- `test-fec.sh` - FEC suite (all modes + GF16/GF8/Wiedemann/Partial/Adaptive/Stress; add `--refactor` / `--refactor-only` for structural invariants; environment and Cargo arguments stay array-safe)
- `test-fec-simulation.sh` - FEC simulation under varied loss/threads/mode matrices with per-cell command status
- `test-fec-e2e-loss.sh` - Deterministic FEC model-loss matrix using seeded `fec_sim` runs and explicit ratio thresholds; it does not exercise real QUIC, TLS, congestion control, ACK processing, or TUN delivery. Native transport proof is owned by the `tun-e2e-fec-*` netns harnesses.
- `test-stealth.sh` - Stealth suite (browser/OS profiles, padding, DoH, H3 masquerade, rotation)
- `test-stealth-brain.sh` - StealthBrain ACK policy optimization tests with per-cell required-command status and explicit optional probe status
- `test-probe-detection.sh` - Active-probe validation (detector invariants, reality fallback rotation, optional stealth pressure path)
- `test-crypto.sh` - Crypto suite (AEGIS/MORUS/AES-GCM/ChaCha20/HKDF/CT operations)
- `test-transport.sh` - Transport suite (varint/frames/loss/BBR/0-RTT/validated migration/DATAGRAM; io_uring on Linux)
- `test-optimization.sh` - Optimize suite (MemoryPool/NUMA/HugePages/SIMD/prefetch/zero-copy) + SIMD/accelerate fixtures (`--features rust-tests,simd-selfcheck`; override via `CARGO_FEATURES`). Optional library tests use target-scoped discovery and fail closed on discovery or zero-test execution.
- `test-security-fuzzing.sh` - Security & fuzzing (ASAN/MSAN/UBSAN, fuzz targets, concurrency, `rt-property-suite` via proptest). Dynamic library-test selection uses release/`--lib` discovery with explicit feature and prerequisite status.
- `test-performance-regression.sh` - Performance regression with baseline comparison; optional library checks use the same release/`--lib` and feature scope for discovery and execution.
- `test-e2e.sh` - End-to-end integration tests with real network scenarios
- `tun-provisioning-negative-netns.sh` - Privileged Linux network-namespace proof for fail-closed TUN creation, duplicate/conflicting resources, permission denial, routing failure/retry, missing-interface rollback, and zero owned residue
- `tun-e2e-netns.sh` - Process-real Linux TUN/MASQUE proof whose server startup recovers durable routing state before opening the TUN, publishes a new ownership record, kills and restarts the server to exercise stale recovery, verifies authenticated H3/MASQUE traffic and a hard 0%-loss ping assertion, then requires graceful shutdown to remove the record
- `fingerprint-runtime-proof-netns.sh` - Privileged five-profile packet/capture/p0f proof with exact artifact hash, non-overwriting evidence directories, protected-process and namespace gates, and explicit active-nmap match status. Use `QF_FINGERPRINT_NMAP_GATE=record` for evidence collection; `match` is intentionally fail-closed when a profile has no exact active result.
- `fingerprint-runtime-proof-hook.sh` - Synchronous hook used while `tun-e2e-netns.sh` owns the authenticated namespaces and product processes; captures both TUN directions, runs p0f and nmap, and invokes the pure Python pcap verifier.
- `utils/verify-fingerprint-pcap.py` - Dependency-free pcap parser and checksum/vector verifier. Schema `quicfuscate.fingerprint-pcap.v3` distinguishes normalized client-originated SYN responses and non-SYN active responses from the ordinary server downlink SYN-ACK passthrough boundary, and fails closed on missing TCP reset, ICMP echo, ICMP UDP port-unreachable, checksum, IP-ID, or disabled/full transport-byte evidence.
- `tun-e2e-traffic-analysis-netns.sh` - Exact-artifact Linux capture proof for 10 PPS full-padding idle chaff and 100 PPS constant-rate defense. It verifies complete ten-second capture windows, exact UDP payload sizes, reverse ACK/control traffic, explicit cost warnings, CPU and bandwidth ceilings, artifact identity, and residue-free teardown.
- `tun-e2e-multi-client-dual-stack-netns.sh` - Exact-artifact Linux proof for three isolated dual-stack clients, source ownership, fan-out, PTB, DPLPMTUD black-hole recovery, positive-interval throughput, NAT, explicit client-to-client policy, and clean teardown
- `tun-e2e-dns-leak-netns.sh` - Linux network-namespace DNS leak proof: real server/client TUN over MASQUE, explicit TUN DNS plus a normal OS-resolver query through a private resolver mount, resolver restoration, and tcpdump assertion that the client underlay sees zero raw TCP/UDP port 53 packets
- `test-e2e-admin-web.sh` - Admin web E2E (login/status/config/QKey API plus productive runtime QKey authentication, active-session revocation close, revoked-key rejection, and zero-stale-client reconciliation; dynamic JSON values use process arguments, and `--dry-run` is a complete non-executing plan; desktop transport validation remains in dedicated integration suites)
- `test-qkey-auth-policy.sh` - Exact-process QKey auth backoff, block, expiry, second-IP isolation, idle-prune, bounded-resource, metric, audit, and 100-attempt flood proof
- `test-ddos-admission.sh` - Exact-process sustained DDoS activation/clear, established-client PING/ACK continuity, QUIC Retry, real MaxMind GeoIP with typed activation-outcome rejection coverage, custom-CA HTTPS blacklist, cache restart, failed-refresh last-known-good, resource, secret, UI-isolation, and cleanup proof
- `test-desktop-webadmin-rust-integration.sh` - Cross-surface desktop/web-admin/core integration contract checks
- `test-fec-all.sh` - Dispatcher: runs all FEC suites (test-fec, test-fec-simulation, test-fec-e2e-loss, auto-controller)
- `test-fec-auto-controller-scenarios.sh` - FEC auto-controller scenario-driven tests
- `test-fec-auto-controller-proof.sh` - FEC auto-controller proof orchestration
- `tun-e2e-fec-netns.sh` - Linux netns FEC acceptance over the real tunnel with tc-netem loss. `UNIFORM_PING_SCENARIOS` owns every loss/bound pair and `UNIFORM_IPERF_SCENARIOS` owns every receiver-verified throughput case. A new absolute artifact path retains exact binary identity, the executed contract, endpoint handshakes, raw ping and iperf JSON, machine-readable results, and zero panic/decryption/runtime-liveness evidence.
- Latest uniform-loss proof ran on Omega against ARM64 binary SHA-256 `e09cad15ef86ea79a074bf1daff93615a97e9078d8786e346ac77b6f5d82f580`. All six cases passed: tunnel loss was 0/3/5/27% at 0/5/10/25% netem loss, JSON-verified receiver throughput was 1.047514/1.047487 Mbit/s at 0/10%, and every runtime row was clean.
- `tun-e2e-fec-burst-netns.sh` - Linux netns correlated burst-loss proof. `BURST_SCENARIOS` owns each profile, loss, correlation, median bound, and worst-sample bound. The harness retains every raw trial, aggregate, endpoint handshake, binary identity, and zero panic/decryption/runtime-liveness result without overwriting prior evidence.
- Latest burst evidence uses the explicit three-trial contract against the same binary. Mild samples were 1/2/1% (median 1%, maximum 2%); heavy samples were 1/3/4% (median 3%, maximum 4%). Every handshake and runtime row passed.
- `tun-e2e-fec-transition-netns.sh` - Linux netns clean, impaired, and recovered policy proof whose `TRANSITION_SCENARIOS` is the single source for every profile's netem loss, phase ping counts, observed-loss bounds, recovery settle, maximum measured recovery duration, and Fountain policy. Off must remain Zero with no repairs, switches, or wire overhead. Auto must remain Zero and overhead-free while clean, commit a non-Zero mode and positive wire overhead under loss, emit repairs, and return to Zero within the declared bound. Every phase fails closed on missing telemetry, panic, decryption, heartbeat, internal, or TUN-send failure.
- Latest transition proof used the same binary: Auto/moderate was 0/8/0% with 35,370 ms recovery, Off/moderate was 0/16/0% with 35,341 ms recovery, and Auto/severe was 0/40/0% with 35,512 ms recovery. Every result stayed inside its loss and 40,000-ms recovery bounds, passed quantitative telemetry, and recorded zero runtime failures.
- `tun-e2e-fec-netem-adversity.sh` - Linux netns 25-scenario liveness matrix whose six contracts own every netem input, phase timing, and loss bound. Every scenario captures both endpoints' FEC telemetry and records measured loss, RTT, bound, exact binary identity, and zero runtime failures. `QF_ADVERSITY_PING_COUNT` supports a larger declared statistical sample; `tun-e2e-fec-loss-stability.sh` requires 200 packets per level across three isolated trials and rejects child failure, runtime failure, wrong sample count, incomplete evidence, binary mismatch, or a bound violation.
- Latest exact-artifact liveness proof passed all 25 Omega cases against the same binary. Loss was 0/0/2/8/36/42%, jitter was 0% throughout, bandwidth was 0% throughout, RTT was 8/0/4/2/2/2%, combined was 8%, and recovery was 0/22/0%. The manifest recorded zero runtime failures.
- The first exact-artifact parity run of the single-source harness, commit `09239dad9d5bea1b4052171cfcd8638524a167de`, is a release-blocking 23/25 result against the same binary: 50% netem loss produced 82% tunnel loss against its declared 65% limit and 500-ms jitter produced 28% against 10%. Bandwidth, all RTT cases, combined adversity, and clean/loss/clean recovery passed. The remote source tree, product process set, namespaces, and veths were clean after the negative run. Do not treat the earlier 25/25 proof as current parity for this source.
- Isolated repeat source `a81f7ad` confirms high-loss instability instead of a single 50% outlier: its six-case loss suite was 5/6, with 25% netem loss reaching 54% tunnel loss against 40%, while its 50% case was 46% against 65%. The failing threshold shifts with the run, so the current high-loss liveness contract is not production-stable.
- Diagnostic source `ae59a97` completed a clean exact-artifact Omega loss run against the same ARM64 SHA-256: 0/2/2/6/24/50% tunnel loss at 0/1/5/10/25/50% netem, each within its 15/16/20/25/40/65% bound. The client telemetry at 25/50% recorded 16/28 observed losses, 2/18 repairs, and two mode switches, proving controller feedback and repair activity rather than a missing loss callback. This single pass does not discharge the earlier high-loss variance blocker; only a declared repeated acceptance run can do so.
- `tun-e2e-fec-loss-stability.sh` runs the exact loss matrix three times with 200 packets per level. It preserves each child manifest and telemetry snapshot, writes a TSV aggregate, and fails on a child or runtime failure, wrong sample count, missing or duplicate result, incomplete matrix, binary mismatch, or declared-bound violation.
- The latest three-trial Omega contract passed all 18 cases. At 25% netem loss, tunnel loss was 15/22/26% against 40%; at 50%, 50/51/46% against 65%. Each child recorded `runtime_failure_count=0`, `ping_count=200`, and the exact binary hash.
- Harness-source `9b57474` completed the full 25-scenario Omega adversity matrix against the same binary with all manifest bounds satisfied: loss 0/0/0/18/28/56%, jitter 0/0/0/0/0/0%, bandwidth 0% in all five cases, RTT 4/4/4/4/2/6%, combined 2%, and recovery 0/14/0%. The 55 retained files at `/tmp/qf-9b57474-adversity.Ul6zGU` contain every endpoint telemetry snapshot and the validated 25-result manifest; remote process, namespace, veth, and source-tree cleanup was clean.
- Exact TODO-555 artifact inventory for TODO-557 invalidated broader acceptance claims without invalidating the bounded lifecycle proof. Under 20% netem loss, the former explicit `--fec-mode off` path reached Streaming mode with 75 switches; TODO-558 subsequently closed lifetime hard-Off and live observability with exact local, native, release, and repeated Omega proof. The uniform-loss iperf parser reported `1.05 Mbit/s` from a `105 Kbit/s` sender line while the receiver reported zero bytes; it now requires bounded JSON output, both endpoint exits, and positive receiver bytes/rate in every interval. Retransmits are retained as informational output because an exact zero count is not a stable FEC acceptance. Sustained TUN traffic emitted repeated MASQUE and H3 `InternalError` failures, TUN send failures, and a heartbeat timeout. TODO-544 owns canonical recovery deadlines; TODO-559 owns carrier backpressure and sustained delivery; TODO-557 consumes those contracts before quantitative closure.
- `test-runtime-soak-chaos.sh` - Runtime soak/chaos (delegates to E2E, FEC loss, admin web)
- `test-security.sh` - Security suite (rt-security-suite + rt-property-suite)
> Note: `test-all.sh` was archived; run suites sequentially or use `util-run-full-suite.sh` which delegates to the individual suite scripts.
> Note: Linux TUN/netns E2E scripts acquire a global `flock` guard before touching shared namespace/process/log/cert/admin-socket state. Override with `QF_E2E_LOCK_FILE` or `QF_E2E_LOCK_TIMEOUT` only when running isolated copies.

**Fuzzing (cargo-fuzz, optional)**
- Tooling: `cargo install cargo-fuzz` (requires a nightly Rust toolchain for fuzz runs).
- Targets live under `scripts/tests/fuzz/fuzz_targets/` and are wired in `scripts/tests/fuzz/Cargo.toml`.
- Seed corpora live under `scripts/tests/fuzz/seeds/<target>/`.
- List targets: `cd scripts/tests/fuzz && cargo fuzz list`
- Run a target: `cd scripts/tests/fuzz && cargo fuzz run packet_parsing`
- Runtime corpus/crash/target outputs are centralized under `scripts/out/tests/<run>/fuzz/...` by `scripts/tests/suites/test-security-fuzzing.sh`.
- Local paths `scripts/tests/fuzz/corpus/` and `scripts/tests/fuzz/artifacts/` are not part of the runtime output workflow.
- Seed dedupe utility: `scripts/tests/utils/util-fuzz-seed-curate.sh` (per-target SHA-256 deduplication).

**Fast runs (`scripts/tests/fast/`)**
- `test-fast-crypto.sh` - Fast crypto sanity (TLS Cover parity + Wiedemann scalar telemetry)
- `test-dynamic-discovery-fail-closed.sh` - Real Cargo contract for discovery command failure, target mismatch, stale patterns, and zero-test execution
- `test-fast-fec.sh` - Fast FEC sanity; runs separate `fec::tests::`, `gf16`, `wiedemann`, and `streaming` filters with `benches,rust-tests`, requires a positive executed-test count per filter, and records a separate bench compile result
- `test-fast-fec-fail-closed.sh` - Negative contract proving a real focused Cargo failure propagates as nonzero, records bounded failure evidence, and cannot reach the green completion marker or bench stage
- `test-benchmark-fast-mode-contract.sh` - Positive fast/full benchmark and coverage-mode contract with JSON cell metadata, orchestrator propagation, and dry-run path safety
- `test-harness-argument-safety.sh` - Real negative contract for array-safe suite propagation, redacted Admin E2E dry-run, malformed QPACK sizes, invalid microbench numerics, paths with spaces, and shell-side-effect rejection
- `test-profiling-evidence-contract.sh` - Negative contract for profiling dry-run safety, unavailable native tools, missing iperf/SendMsgZc metrics, failed-process markers, failed-netem markers, and missing flamegraph tooling
- `test-shared-artifact-writer-contract.sh` - Shared JSON contract for escaped argv/environment values, parser-backed serialization failure, create-new rerun protection, backup replacement, standalone metadata, and profiling scenario/manifest ownership

**Quick validation profile (macOS / Apple Silicon)**
- Fast confidence pass:
  - `scripts/tests/fast/test-fast-crypto.sh`
- Telemetry counter snapshot:
  - `cargo test --features rust-tests --test rt-telemetry-counters -- telemetry_counters_snapshot --nocapture`
- Optional longer micro-benchmark refresh:
  - `scripts/benchmarks/micro/micro-crypto-all.sh --fast`

**Smoke (`scripts/tests/smoke/`)**
- `smoke-avx10.sh` - AVX10.1 feature detection + targeted SIMD self-checks & microbench capture (skips when hardware absent; run with `cargo build --features internal_avx10_preview`)
- `smoke-sve2.sh` - SVE2 smoke (self-check + telemetry + stream parse)
- `smoke-ui-frontends.sh` - Frontend smoke pass for desktop/web-admin build-level sanity

**Rust test helpers (`scripts/tests/rust/`)**
- Parity and telemetry-only Rust fixtures used by suites/smoke
- `rt-security-suite` covers security suite patterns (malformed input, overflow, concurrency, protocol abuse, crypto/FEC properties) for `test-security-fuzzing.sh`.
- `rt-profile-overrides` validates `QUICFUSCATE_PROFILE_OVERRIDE` parity between scalar and SIMD paths.
- `rt-profile-fuzz-parity` runs randomized parity checks across scalar and SIMD fast paths.

> Note: Linux fast paths (io_uring datagram send/recv, MASQUE DATAGRAM) are runtime-gated and auto-enable when the kernel exposes the required syscalls. macOS tooling still skips these checks by default - run targeted Linux smoke suites when touching transport, receive buffering, or MASQUE code paths.

> AVX10 rollout: Once real AVX10.1 hardware is available, build with `cargo build --features internal_avx10_preview` and run `./scripts/tests/smoke/smoke-avx10.sh --require --output-dir <artifacts>`, archive the generated logs (profile + bench CSVs), and update this document with validated results.

#### Benchmarks (`scripts/benchmarks/`)
**Suites (`scripts/benchmarks/suites/`)**
- `bench-orchestrator.sh` - Orchestrates the explicit fast or full benchmark matrix with fixed executable argv resolution; writes structured `manifest.json`, `summary.txt`, mode metadata, and per-suite logs under `scripts/out/benchmarks/`, and fails on unknown or failed requested suites
- `bench-fec.sh` - FEC benchmarks; full runs matrix multiply plus pipeline, while fast runs the pipeline cell only
- `bench-fec-simulation.sh` - FEC performance under simulated network conditions with per-cell command statuses
- `bench-crypto.sh` - Extended crypto benchmarks with per-cell command result artifacts; fast keeps one native cell per primitive, full adds architecture-specific cells
- `bench-transport.sh` - Transport benchmarks; fast runs varint, full adds packet-number encoding
- `bench-optimization.sh` - Runtime-owned SIMD optimization benchmarks; fast runs the 1024-element sort cell, full runs sort and shuffle; memory microprimitives are rust-tests parity-only
- `bench-stealth.sh` - Stealth padding performance; fast runs the 512-byte padding cell, full runs the complete padding group
- `bench-stealth-brain.sh` - StealthBrain ACK policy optimization benchmarks with per-cell command statuses
- `bench-compression.sh` - Compression microbenchmarks (`examples/compress_bench.rs`) for text and binary payloads with JSON output
- `bench-qpack-encode.sh` - QPACK encode benchmark harness with bounded size grammar, preflight rejection, and per-cell status
- `bench-profile-transport-fastpaths.sh` - Transport profiling (Tokio vs io_uring)
- `profiling-baseline.sh` - Fail-closed UDP harness and loopback client/server baseline with per-scenario provenance and measurement status
- `profiling-common.sh` - Shared profiling evidence schema, status, metric, process, and cleanup helpers
- `profiling-tun-mode.sh` - Fail-closed Linux TUN plus tc-netem profiling with owned qdisc cleanup and iperf3 JSON metrics
- `profiling-zc.sh` - Real product SendMsgZc profiling with telemetry counters and perf/flamegraph evidence
- `bench-linux-send-path-decision.sh` - Linux send-path decision benchmark
- `bench-retained-crypto-backends.sh` - Crypto backend comparison benchmark
- `bench-fec-all.sh` - Dispatcher: runs all FEC benchmarks
- `bench-ci-regression.sh` - CI regression benchmark gate (Criterion)
- Root Criterion target `fingerprint_normalizer` - allocation and throughput proof for decoded raw-IP normalization (`cargo bench --bench fingerprint_normalizer --features benches`)

**Micro (`scripts/benchmarks/micro/`)**
- `micro-crypto-all.sh`, `micro-aes-block.sh`, `micro-aes-gcm.sh`, `micro-ghash.sh`, `micro-chacha-x4.sh`, `micro-udpfast-throughput.sh`
  - Affected micro scripts validate CLI input before execution and write a `meta` object plus per-command `PASS`, `FAIL`, or `SKIP` entries with command status and bounded output identity.

#### Audits (`scripts/tests/audits/`)
- `audit-runtime-guardrails.sh` - Fast runtime/docs/structure anti-drift gate for reachability, contract, and shadow-path regressions
- `audit-all-comprehensive.sh` - Consolidated audit (security/dependencies/quality/performance) with clear exit codes
- `audit-readiness-gates.sh` - Readiness gate checks for release and CI quality thresholds
- `verify-audit-completeness.sh` - Fail-closed TODO register, archive reconciliation, schema, dependency, and Git-scope coverage gate
- `test-verify-audit-completeness.sh` - Positive and negative fixture coverage for the completeness validator

Guardrail remediation playbook:
- `Critical` failure: treat as contract drift or structural regression. Fix code/docs first, then rerun `audit-runtime-guardrails.sh`.
- `Warning`: treat as a suspected owner/surface drift. Either tighten the code path or explicitly narrow/document the retained compat/test-only boundary.
- When a guardrail touches feature claims, update runtime truth and `docs/DOCUMENTATION.md` in the same change set.

#### Utils (`scripts/tests/utils/`)
- `util-run-full-suite.sh`
- `verify-icmp-time-exceeded-pcap.py` - Dependency-free IPv4 ICMP Time Exceeded pcap verifier. Schema `quicfuscate.icmp-time-exceeded-pcap.v1` validates the request and server response endpoints, TTLs, ICMP type/code, IPv4 and ICMP checksums, and exact quoted-request bytes without replacing an existing result.
- TLS utilities: `util-tls-generate-sha256-sidecars.sh`, `util-tls-diff-profiles.sh`, `util-tls-export-active-profile.sh`, `util-tls-list-profiles.sh`, `util-tls-profile-head.sh`, `util-tls-show-active-env.sh`
- E2E profile utilities: `util-e2e-decode-all-profiles.sh`, `util-e2e-verify-all.sh`, `util-e2e-verify-current.sh`
 
General utilities (`scripts/utils/`):
- `util-analyze-codebase.sh`, `util-check-quality.sh`, `util-release-source-package.sh`
- `util-cleanup-workspace.sh` - primary cleanup entrypoint (`--safe|--full`, `--keep-releases N`, optional `--cargo-clean`)
- `util-dev-uis-start.sh`, `util-dev-uis-stop.sh` - start/stop local frontend dev servers with PID tracking under `scripts/out/run/dev-uis`
- `util-run-local-ui.sh`, `util-stop-local-ui.sh` - local stack orchestration helpers for UI + server workflows
- `util-run-local-admin-web.sh`, `util-stop-local-admin-web.sh` - isolated local admin-web stack helpers

Local admin-helper credential note:
- `scripts/utils/util-run-local-admin-web.sh` and `scripts/utils/util-run-local-ui.sh` intentionally start the local admin server with `QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1` and `--admin-web-password 123` for fast loopback-only development.
- Change those defaults directly in the helper script command line if a different local password is needed.
- Outside those helpers, the canonical runtime policy is `min 6 chars` (enforced in `admin_http.rs`); there is no separate UI setting for weak-default behavior.

#### Artifacts (`scripts/out/`)
- Bench/test scripts write timestamped artifacts here, e.g., `scripts/out/<category>/<script>-<timestamp>/` with JSON + logs.
- `scripts/out/` is intentionally gitignored and remains the canonical runtime/build/test artifact sink.
  Exported JSON reports originate from the individual suite scripts; `util-run-full-suite.sh` aggregates test runs, and benchmark suites emit their own summaries.
- A caller-provided output directory is not a rerun cache. Shared directory writers reject non-empty directories, and file writers reject an existing target by default. Use a fresh run directory for normal evidence collection.
- Explicit replacement is opt-in through `QUICFUSCATE_ARTIFACT_POLICY=replace-with-backup`; the prior target is preserved beside the new file with a unique `.previous-<run-id>` suffix and the active document records the replacement policy.
- Internal Linux E2E summaries and Python probe/sampler writers also use exclusive creation and parser-safe JSON serialization. Their domain-specific payloads remain separate schemas; externally produced `curl`, `cargo`, `iperf`, and third-party probe outputs remain foreign inputs and are never rewritten by the shared artifact writer.

**JSON schema (suite results)**
```json
{
  "schema": "<suite-schema-id>",
  "tool": "quicfuscate",
  "suite": "test-crypto",
  "timestamp": "2026-01-25T12:34:56-08:00",
  "artifact": {
    "run_id": "<uuid-hex>",
    "path": "<absolute-or-selected-output-path>",
    "ownership": "create-new",
    "replacement": "create-new",
    "source_revision": "<git-revision>"
  },
  "system": {
    "os": "Darwin",
    "arch": "arm64",
    "cpu_cores": 8,
    "memory_gb": "16.0"
  },
  "items": [
    {"argv": ["cargo", "test", "--release", "..."], "environment": {}, "rc": 0, "duration_sec": 12}
  ]
}
```

**JSON schema (micro benches)**
- Each micro script writes `<name>.json` with a leading `meta` object and per-command entries.
```json
{
  "schema": "<bench-schema-id>",
  "tool": "quicfuscate",
  "suite": "micro-aes-block",
  "timestamp": "2026-01-25T12:34:56-08:00",
  "artifact": { "ownership": "create-new", "replacement": "create-new" },
  "system": { "os": "Darwin", "arch": "arm64", "cpu_cores": 8, "memory_gb": "16.0" },
  "items": [
    {"meta": {"iters": 1000, "sizes": "256B 1KiB 16KiB 1MiB"}},
    {"argv": ["cargo", "run", "--release", "..."], "environment": {}, "rc": 0, "duration_sec": 3}
  ]
}
```

Compile-time bench metadata (feature `benches`):
- `QUICFUSCATE_GIT_REV`, `QUICFUSCATE_CPU_MODEL`, `QUICFUSCATE_RUSTC_VERSION` are read via `option_env!` at build time and embedded in the JSON output.

#### Benchmarking Scripts - Guide
Performance measurements are consolidated via the individual benchmark suites (optionally coordinated with `bench-orchestrator.sh`). All scripts detect OS/Arch/features, including Linux `io_uring` capability and retained internal AF_XDP experimental feature availability where relevant, and export reports (text/JSON) to `scripts/out/<category>/`.

**Tooling status**
- Tooling naming and structure finalized: tests use `test-*.sh`, benchmarks use `bench-*.sh`, micro benches use `micro-*.sh`.
- `test-fec.sh` handles `--refactor` directly.
Notes:
- Build runs automatically in release mode with native flags.
- JSON exports include `time`/`throughput` per sub-benchmark.
- Comparison blocks (FEC/Crypto) summarize key metrics.

Microbench CLI (example harness): `bitpack <bw> <vals> <iters>`, `bitunpack <bw> <vals> <iters>`, `qpack-enc <bytes> <iters>`, `qpack-dec <bytes> <iters>`, `popcnt <bytes> <iters>`. Coverage: NEON bitpack (1-8 bit widths) with SVE2 wrapper, NEON/SVE2 QPACK encode/decode wrappers, NEON core popcount (`vcntq_u8` + horizontal sum).



#### Environment-driven benchmark controls
Benchmark scripts do not define a shared benchmark env interface. Use the runtime env
overrides documented elsewhere (for example `QUICFUSCATE_FEC_KERNEL`, `QUICFUSCATE_RAYON_THREADS`,
`QUICFUSCATE_MADVISE_HUGEPAGE`, `QUICFUSCATE_NUMA_POLICY`) when invoking the benches. Script-specific
flags are documented in each `bench-*.sh` header.

#### Script Organization

All scripts live under `scripts/` and are categorized in lowercase:
- `scripts/tests/build/`
- `scripts/benchmarks/`
- `scripts/tests/audits/`
- `scripts/tests/`
- `scripts/tests/utils/`

Each category contains focused runners with consistent naming and robust error handling.
Naming uses lowercase kebab-case with a category prefix (e.g., `test-crypto.sh`, `test-fast-fec.sh`, `micro-ghash.sh`).

#### Upstream Utilities
The transport core is derived from Cloudflare's quiche QUIC implementation, maintained in-tree with custom extensions for packet protection, FEC integration, stealth shaping, and control-plane runtime. There is no build-time dependency on upstream quiche; all scripts operate solely against `src/`.

## FEC Operations Guide

This section is the operational reference for runtime FEC controls, practical tuning, and the most relevant telemetry counters.
Use these overrides only when you need deterministic policy behavior beyond default auto-adaptation.

The constructor/runtime boundary is explicit:
- `AdaptiveFec::new()` performs global FEC resource initialization first, then snapshots constructor ambient inputs, then derives the runtime plan from config plus that snapshot.
- The retained ambient constructor inputs are named and instance-owned:
  - `FecComputeProfile` carries CPU-profile and NEON capability for constructor planning.
  - `FecObserverProfilePolicy` with `FecObserverPlatformHints` carries observer profile classification as either `Explicit(...)` or retained `Ambient(...)`.
- Detection and derivation are intentionally split, so repeated same-process construction stays deterministic per instance rather than re-reading environment state from live runtime paths.

### Standalone FEC file configuration
- `--fec-config PATH` is an explicit standalone input. File I/O, TOML parsing, enum decoding, and semantic validation must all succeed before `AdaptiveFec` construction; any failure returns a nonzero startup result and never selects `FecConfig::product_default()` as a fallback.
- The standalone file schema is `[adaptive_fec]`. `initial_mode` accepts `auto`, `off`, `zero`, `light`, `normal`, `on`, `medium`, `strong`, `extreme`, `ultra`, `fountain`, or `streaming`. `modes[].name` accepts the nine public codec modes: `zero`, `light`, `normal`, `medium`, `strong`, `extreme`, `ultra`, `fountain`, and `streaming`. Unknown values are rejected with the field and submitted value.
- Scalar validation requires `lambda` in `0..=1`, `hysteresis` in `0..1`, positive `burst_window`, finite positive `kalman_q` and `kalman_r`, and positive `stream_every` when supplied. Window validation requires `Zero=0`, every other mode in `1..=2048`, and `Fountain` in `1..=128`.
- `--config` and `--fec-config` are mutually exclusive because the standalone path must not silently discard one of two submitted FEC sources. The accepted source is recorded by the runtime log as `Accepted FEC policy source=product-default`, `standalone-file:<path>`, or `unified-config:<path>`.

The unified engine `[fec]` adapter is intentionally narrower than the standalone file: `mode` and `initial_mode` are limited to `auto`/`off`, product windows are projected into the canonical `FecConfig`, and `stream_every = 0` is rejected before the adapter can normalize it. Environment controls remain the owner for partial recovery and advanced codec behavior.

### Environment controls (runtime)
- `QUICFUSCATE_FEC_PARTIAL`: `0|1|true|false` - controls partial recovery emission (default: enabled).
- `QUICFUSCATE_FEC_LAZY`: `0|1|true|false` - lazy decoder gating (default: enabled).
- `QUICFUSCATE_FEC_INTERLEAVE`: `0|1|true|false` - enable interleaving for burst protection (default: enabled).
- `QUICFUSCATE_FEC_INTERLEAVE_DEPTH`: integer `1..8` - depth for interleaving (default: `4` when `k > 16`, else `1`).
- `QUICFUSCATE_FEC_DECODER`: `auto|gauss|wiedemann` - advanced/internal decoder override; `auto` keeps the canonical runtime policy and selects by large-window threshold.
- `QUICFUSCATE_FEC_WIEDEMANN_K`: integer (default `256`) - advanced/internal threshold for enabling the large-window decoder strategy at high `k`.
- `QUICFUSCATE_FEC_STREAM_EVERY`: integer `N` (min `1`) - streaming cadence override; computed from CPU profile when unset.
- `QUICFUSCATE_FEC_AUTO_STREAM`: `0|1|true|false` - allow Streaming mode in auto switch (default: enabled).
- `QUICFUSCATE_FEC_AUTO_GF4`: `0|1|true|false` - allow GF4 for ultra-low loss in auto (default: enabled).
- `QUICFUSCATE_FEC_SWITCH_THRESH`: float `0.0..1.0` - mode switch threshold (default: `0.02`).
- `QUICFUSCATE_FEC_SWITCH_MIN_UP_MS`: integer milliseconds (default: `120`) - minimum dwell time before Auto-Mode may escalate to a higher FEC tier.
- `QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS`: integer milliseconds (default: `450`) - minimum dwell time before Auto-Mode may de-escalate to a lower FEC tier.
- `QUICFUSCATE_FEC_FOUNTAIN_WINDOW`: integer `1..128` - bounded source window when switching to Fountain (default and maximum: `128`).
- `QUICFUSCATE_FEC_EXTREME_WINDOW`: integer - window size for extreme loss escalation (default: `1024`).
- `QUICFUSCATE_FOUNTAIN_SYMBOL`: integer bytes - fountain symbol size (default: `MTU_HINT-80`, fallback `1500`, clamp `600..16384`).
- `QUICFUSCATE_KALMAN_Q`: float - process noise override (default: `0.001`).
- `QUICFUSCATE_KALMAN_R`: float - measurement noise override (default: `0.01`).
- `QUICFUSCATE_PROFILE`: `mobile|server|desktop` - transport profile override for FEC observer.
- `QUICFUSCATE_MTU_HINT`: integer - used by fountain symbol sizing and memory pool sizing.
- `QUICFUSCATE_RAYON_THREADS`: integer - cap Rayon thread pool used by parallel FEC paths.
- `QUICFUSCATE_FEC_KERNEL`: `scalar|avx512vbmi2|avx512|avx2|neon|sve2` - override SIMD kernel selection for GF16 bitslice.

Notes:
- Operator policy is independent from codec state. Engine/CLI `FecMode::Off` maps to `FecControlPolicy::Off`, forces the initial and lifetime codec to `Zero`, rejects adaptive transitions and streaming/redundancy hints, emits no repairs, and retains no encoder window state. `FecControlPolicy::Auto` also bootstraps in `Zero`, then owns the adaptive Zero -> GF4/GF8/GF16 -> Fountain/Streaming cascade.
- Transport feedback ownership is split deliberately: recovery callbacks produce independent exact send/loss packet counters, transport ACK-range classification owns exact acknowledged-packet counts, and the active congestion controller produces the smoothed ratio that drives adaptation. Sends cannot masquerade as clean delivery. A loss resets the clean streak; 32 consecutive loss-free classified ACKs clear stale burst history, suppress stale disturbance state, and permit the bounded return to Zero despite asymptotic congestion-controller residue. The estimator still requires both its EMA and populated recent-loss window to confirm the Fountain threshold, so a delayed loss callback cannot masquerade as a self-contained `1/1` sample.
- Fountain rescue uses a fixed product liveness bound: the runtime default and accepted override maximum are 128 source packets. At the current 5x total code rate this caps synchronous block-completion work at 512 repair packets. A deterministic regression rejects oversized ambient overrides and proves the emitted burst remains bounded.
- Auto tuning never mutates process-global environment state. Decoder strategy and streaming cadence are updated only in the owning connection's cached runtime policy. `QUICFUSCATE_FEC_STREAM_BURST`, `QUICFUSCATE_FEC_PARALLEL`, `QUICFUSCATE_WM_BITSLICE`, `QUICFUSCATE_WM_LANE_PAR`, `QUICFUSCATE_WM_LANES`, and `QUICFUSCATE_WM_U` have no product runtime read path.
- `QUICFUSCATE_FEC_DECODER` and `QUICFUSCATE_FEC_WIEDEMANN_K` are snapshotted at connection construction as advanced/internal controls for diagnostics and compatibility. `auto` permits connection-local decoder adaptation; explicit `gauss` or `wiedemann` remains immutable for that connection. They do not widen the canonical product contract.
- Fountain symbol sizing and Rayon thread-pool setup follow explicit owner boundaries: they are snapshotted or initialized during construction instead of being repeatedly resolved inside live adaptation logic.
- Rayon thread-pool setup is now represented explicitly as FEC global-resource policy (`Default` or `ThreadCap(n)`) before initialization, rather than a hidden optional env parse embedded in the side effect itself.
- Constructor and observer ambient policy is now centralized: `AdaptiveFec::new()` resolves explicit FEC ambient/runtime inputs once, stores the resulting `FecRuntimePolicy` on the instance, and reuses that same snapshot for internal runtime/transition builders; `FecTransportObserver` snapshots its profile/base-stream inputs once; its retained transport-profile heuristic is represented explicitly as observer policy (`Explicit(profile)` or `Ambient(profile)`); the remaining FEC mode-policy env overrides are read through one `FecRuntimePolicy` snapshot instead of scattered per-call environment reads.
- Deterministic regression coverage exists for the remaining allowed ambient FEC controls: stream cadence stays stable per `AdaptiveFec` instance, `FecTransportObserver` stream policy snapshots per observer instance, decoder policy snapshots per `Decoder8` instance, and Fountain symbol size snapshots per Fountain encoder/decoder construction.
- Lazy receive polling is gated by `recovery_needed()` and `full_recovery_needed()`: clean blocks return systematic packets without polling heavy recovery, gap-only systematic arrivals stay lazy while retaining bounded source context, flushed repairs or tail-loss repair availability replay buffered sources into the heavy decoder and trigger full recovery, and clean complete blocks prune their sequence tracker and source buffer so long-running stable links do not retain unbounded FEC source IDs.
- Interleaved lazy gap tracking is depth-aware: each lazy block normalizes source sequence numbers by interleave depth before gap detection, so clean streams such as `0,4,8,12` at depth `4` do not trigger false recovery polling.
- Interleaved full recovery is lane-scoped: `InterleavedDecoder::get_result()` runs full recovery only for blocks whose lazy decoder reports `full_recovery_needed()`, drains partial results only from recovery-active blocks, and leaves idle clean-lane repair buffers lazy. Broderick streaming decode improved from about `220.83 us` to `180.48 us` for clean 128-packet batches and from about `499.58 us` to `256.97 us` for deterministic 10% source loss.
- Repair `id` is the authoritative maximum source ID for its encoder lane and coefficient positions map backward from that anchor with the configured interleave stride. Decoders do not synthesize alternate anchors. Deterministic transport-roundtrip gates cover 1,000 contract packets at 5% seeded random packet loss and four consecutive systematic losses per sixteen, asserting 1,000 unique byte-exact deliveries, zero duplicates, and at most 63 source sends of recovery latency after a 24-packet tail flush.
- Zero-mode receive bypasses decoder retention entirely while no transition is active, preserving unique ownership of pooled payloads for in-place QUIC processing. Recovery-capable modes still retain decoder state as required for source reconstruction.
- Send-side hot paths should call `AdaptiveFec::on_send_into(packet, output)` with a reused output buffer. `AdaptiveFec::on_send(packet)` remains a compatibility wrapper, while `QuicFuscateConnection` uses per-instance scratch vectors so clean-link sends do not allocate a fresh FEC output vector per packet.
- Send-side repair telemetry tracks only emitted repair packets for uniqueness and order-depth diagnostics. Systematic-only sends avoid HashSet/VecDeque repair-history maintenance while `FEC_EMITTED_QUEUE` continues to report non-zero-mode output queue depth.
- Block repair rows are deterministic from the active codec, block width, and repair ordinal. Encoders may cache those rows internally, but the v1 transport envelope never transmits coefficient vectors.
- Receive-side hot paths should call `AdaptiveFec::on_receive_into(packet, output)` with a reused output buffer. `AdaptiveFec::on_receive(packet)` remains a compatibility wrapper and keeps the direct zero-mode passthrough fast path, while `QuicFuscateConnection` reuses per-instance receive scratch vectors.

Examples (manual tuning):

```bash
# Low-loss emphasis (efficient)
export QUICFUSCATE_FEC_STREAM_EVERY=3
export QUICFUSCATE_FEC_INTERLEAVE=1
export QUICFUSCATE_FEC_LAZY=1

# High-loss emphasis (robust)
export QUICFUSCATE_FEC_STREAM_EVERY=1
export QUICFUSCATE_FEC_INTERLEAVE_DEPTH=4
export QUICFUSCATE_FEC_FOUNTAIN_WINDOW=128
```

### Telemetry quick reference
Exported telemetry metrics (via `telemetry::export_telemetry_text()`):

- ACK delay mimicry
  - `quicfuscate_ack_delay_bucket_le_1ms_total`
  - `quicfuscate_ack_delay_bucket_le_4ms_total`
  - `quicfuscate_ack_delay_bucket_le_16ms_total`
  - `quicfuscate_ack_delay_bucket_le_64ms_total`
  - `quicfuscate_ack_delay_bucket_le_256ms_total`
  - `quicfuscate_ack_delay_bucket_gt_256ms_total`
  - `quicfuscate_ack_delay_last_us`

- Pacing / choke accounting
  - `quicfuscate_choked_bytes_total`
  - `quicfuscate_choke_sleep_ms_total`

- MASQUE capsules
  - `quicfuscate_masque_capsule_00_total`
  - `quicfuscate_masque_capsule_21_total`
  - `quicfuscate_masque_capsule_22_total`

- Compression
  - `quicfuscate_compress_attempts_total`
  - `quicfuscate_compress_success_total`
  - `quicfuscate_compress_bytes_in_total`
  - `quicfuscate_compress_bytes_out_total`

- Memory/Pool
  - `quicfuscate_body_pool_allocs_total`
  - `quicfuscate_mem_pool_hits_tls_total`
  - `quicfuscate_mem_pool_hits_queue_total`
  - `quicfuscate_mem_pool_alloc_grow_total`
  - `quicfuscate_mem_pool_alloc_ephemeral_total`

- SIMD usage (counters)
  - `quicfuscate_simd_usage_avx2_total`
  - `quicfuscate_simd_usage_avx512_total`

- FEC policy and process aggregates
  - `quicfuscate_fec_active_connections{mode="<name>",mode_id="<0..8>"}` for every stable mapping: `0=zero`, `1=light`, `2=normal`, `3=medium`, `4=strong`, `5=extreme`, `6=ultra`, `7=fountain`, `8=streaming`
  - `quicfuscate_fec_active_connections_total`
  - `quicfuscate_fec_effective_window_source_packets_sum`
  - `quicfuscate_fec_observed_packets_total`, `quicfuscate_fec_observed_lost_packets_total`, `quicfuscate_fec_observed_loss_ppm`: process-wide exact transport send callbacks, the lost subset reported independently when recovery declares loss, and their cumulative ratio
  - `quicfuscate_fec_mode_switches_total`, `quicfuscate_fec_switch_reason_{adaptive,force_on,extreme,disturbance,streaming_hint}_total`
  - `quicfuscate_fec_policy_transitions_total`
  - `quicfuscate_fec_{source,repair}_packets_{sent,received}_total`
  - `quicfuscate_fec_source_payload_bytes_{sent,received}_total`
  - `quicfuscate_fec_{source,repair}_wire_bytes_{sent,received}_total`
  - `quicfuscate_fec_wire_overhead_{sent,received}_ppm`
  - `quicfuscate_fec_decoded_packets_total`, `quicfuscate_fec_recovered_packets_total`, `quicfuscate_fec_recovered_payload_bytes_total`

#### Telemetry HTTP endpoints

Telemetry and metrics endpoints are exposed by different runtime surfaces:

- `GET /telemetry`: text snapshot from `telemetry::export_telemetry_text()` served by `src/metrics.rs` (`spawn_telemetry_server`, bind via `QUICFUSCATE_METRICS_ADDR`, default `127.0.0.1:9898`).
- `GET /metrics` and `GET /health`: server metrics/health exposed by `implementations::server::metrics::MetricsServer` when server metrics are enabled.

The server metrics and systemd health surfaces use the shared bounded HTTP reader in `src/implementations/server/http.rs`: request headers are read incrementally up to 8 KiB with a five-second per-read deadline, oversized unterminated requests receive an explicit 413 response, and each accept loop admits at most 32 connection workers. This does not change the explicit `MetricsServer::new(port, metrics)` bind contract or the environment-configured telemetry endpoint.

`GlobalMetricsServer` (same module) is currently retained only for test/compat coverage around global instrumentation export and is not part of the active CLI/runtime metrics path.

#### Server `/metrics` families (default server runtime)

The default server metrics endpoint (`implementations::server::metrics::Metrics::export`) includes:

- `quicfuscate_up`, `quicfuscate_uptime_seconds`
- `quicfuscate_clients_active`, `quicfuscate_clients_total`, `quicfuscate_connections_accepted`, `quicfuscate_connections_rejected`
- `quicfuscate_bytes_in_total`, `quicfuscate_bytes_out_total`, `quicfuscate_packets_in_total`, `quicfuscate_packets_out_total`
- `quicfuscate_stealth_http3_active`, `quicfuscate_stealth_tls13_active`
- `quicfuscate_fec_packets_encoded`, `quicfuscate_fec_packets_decoded`, `quicfuscate_fec_packets_recovered`
- `quicfuscate_auth_attempts_total`, `quicfuscate_auth_succeeded_total`, `quicfuscate_auth_failed_total`
- `quicfuscate_auth_backoff_rejected_total`, `quicfuscate_auth_blocked_rejected_total`, `quicfuscate_auth_capacity_rejected_total`, `quicfuscate_auth_abandoned_total`
- `quicfuscate_auth_state_tracked_ips`, `quicfuscate_auth_state_pruned_total`, `quicfuscate_rate_limited_total`
- `quicfuscate_ddos_active`, `quicfuscate_ddos_current_pps`, `quicfuscate_ddos_transitions_total`
- `quicfuscate_ddos_retry_total`, `quicfuscate_ddos_drops_total`
- `quicfuscate_bandwidth_allowed_bytes_total`, `quicfuscate_bandwidth_denials_total`
- `quicfuscate_bandwidth_scheduler_active_clients`, `quicfuscate_bandwidth_scheduler_delivered_total`

The three legacy server FEC counters are read-only projections of the canonical process telemetry producers, not independent atomics: `encoded` is actual source plus repair datagrams written by the FEC layer, `decoded` is original plus recovered source packets delivered by the FEC layer, and `recovered` is the decoded subset reconstructed from repair data. Their scope is the server process.
Accepted connections are now produced by the standalone live runtime at the same point that `clients_total` is incremented, so the standalone admin/metrics surfaces report one consistent accept/reject/auth-failure story instead of mixing runtime counts with partial projections.
The standalone server runtime now also records accepted, rejected, rate-limited, ingress, and egress events through explicit `Metrics` methods rather than scattered raw atomic increments in the live loop and QKey-auth branches.
Engine server-mode stats now treat RTT and loss as unavailable unless a truthful server-owned producer exists. The engine no longer reuses global client transport RTT/loss instrumentation for embedded server stats.
For rejected/auth-failed/rate-limited events and ingress/egress traffic, those standalone `Metrics` producers now also mirror the event into `crate::instrumentation::global()` so the optional global instrumentation export does not drift away from the standalone server metrics story.
That mirror contract is covered by a dedicated regression test in `src/implementations/server/metrics.rs`.
QKey auth attempts now use one bounded monotonic state machine. The public Initial ID lookup starts an attempt but does not reset prior failures; only the encrypted HTTP/3 bearer success resets consecutive-failure, backoff, and block state. The bounded bearer-auth timeout starts once after QUIC/TLS establishment and is never extended by later housekeeping ticks. Every attempt has one terminal owner, so `quicfuscate_auth_failed_total` reflects each of these exactly once:
- missing or invalid public Initial QKey ID lookup
- live HTTP/3 `x-qf-auth` rejects
- QKey auth timeout closes
- pending-auth connection or session closes
Backoff, explicit block, global state-capacity, and per-IP pending-capacity rejections occur before QKey registry lookup. They expose distinct metrics and internal audit reasons but produce no credential-validity distinction on the wire.
Auth-policy configuration is resolved and validated before audit-log, admin-socket, QKey-state, TLS, or other runtime resource setup, so an invalid policy fails startup without leaving service-owned artifacts. `scripts/tests/suites/test-qkey-auth-policy.sh` proves the real process contract against caller-selected exact binaries: strict invalid-config rejection, CA-verified H3 bearer success, the configured backoff schedule, block expiry, successful-client reset, independent secondary-loopback success, idle pruning, exact metrics/audit accounting, 100 Initial attempts, bounded RSS/CPU, raw-QKey absence, protected-UI isolation, and owned-process cleanup.
The final local gate passed workspace/all-target Rust checking, strict all-feature Clippy, all 1,903 library tests plus every binary and integration target, 11 focused auth-policy tests, Bash/ShellCheck validation, runtime guardrails, and the macOS process harness with its explicit second-IP skip. The isolated native ARM64 candidate passed the 11 focused release tests and full process harness against server SHA-256 `b724556e7e99f2194848339f06a343e3790e221f525900ee65c0b4f6b5be7faa` and probe SHA-256 `3f0866421ea4de1a7c2020dcba9c4b20d5dfb923784e2b8799a97a606f2faf4c`: lifecycle `10` attempts, `2` successes, second-IP proof `1`, idle-pruned states `1`; flood `100` attempts, `4` terminal failures, `2` backoff rejects, `94` blocked rejects, one tracked IP, `80 KiB` RSS growth, and zero owned-process or protected-UI residue. The generated remote candidate was removed after the evidence archive was verified locally as SHA-256 `909cd47abda45edec7f845f705cb0970c3ff1ac1cfc045e293e422960a95d551`.
Global server lifecycle metrics now keep accepted-connection ownership separate from session/client lifecycle: `connections_accepted` remains an explicit accept event, while `client_connected()` only reflects active/total client lifecycle. The runtime audit suite enforces that split.

#### Global instrumentation metric families (optional/embedded)

`instrumentation::GlobalMetrics` extends the optimize snapshot with runtime-wide families, including:

- Server lifecycle: `quicfuscate_up`, `quicfuscate_uptime_seconds`, `quicfuscate_clients_active`, `quicfuscate_clients_total`, `quicfuscate_connections_accepted`, `quicfuscate_connections_rejected`, `quicfuscate_sessions_created`, `quicfuscate_sessions_expired`, `quicfuscate_auth_failed`, `quicfuscate_rate_limited`.
- Transport activity: `quicfuscate_bytes_in`, `quicfuscate_bytes_out`, `quicfuscate_packets_in`, `quicfuscate_packets_out`, `quicfuscate_packets_lost`, `quicfuscate_rtt_avg_ms`, `quicfuscate_loss_rate`.
- Stealth/FEC state: `quicfuscate_stealth_http3`, `quicfuscate_stealth_tls13`, `quicfuscate_padding_bytes`, `quicfuscate_fec_encoded`, `quicfuscate_fec_decoded`, `quicfuscate_fec_recovered`, `quicfuscate_fec_recovery_rate`, `quicfuscate_fec_redundancy`.

#### Telemetry environment controls (runtime)

- `QUICFUSCATE_ACK_THRESHOLD`: override ACK-eliciting threshold in stealth ACK behavior.
- `QUICFUSCATE_ACK_MAX_DELAY_MS`: override max ACK delay in milliseconds for stealth ACK scheduling.
- `QUICFUSCATE_EXTERNAL_PACING`: enable external pacing mode for pacing/choke paths.

Telemetry collection/export is runtime-surface driven (`--telemetry` / metrics endpoints). There is no standalone `QUICFUSCATE_TELEMETRY_ENABLED` runtime read path in the current code.
Disabled telemetry performs no operating-system process scan. Enabled connection maintenance coalesces resource refreshes process-wide to at most once per second, refreshes only the current process with memory-only fields, and stores the byte value returned by `sysinfo` without unit conversion. An explicit shutdown `telemetry::flush()` remains unthrottled. Optional orchestrator sampling is skipped when the runtime orchestrator is disabled; when active, each connection retains its current-process sampler for CPU and memory deltas instead of rebuilding or enumerating the system process table.

#### Telemetry access and operational interpretation

- ACK delay buckets model browser-like ACK timing distributions and can be used to validate profile behavior under different network conditions.
- Choke counters (`choked_bytes`, `choke_sleep_ms`) quantify pacing pressure and allow correlation with throughput/latency trade-offs.
- Exact ARM64 candidate `eeb7049` added passive standalone egress metrics under `--telemetry`, but two clients reached the 30-second heartbeat watchdog before the default phase could retain all snapshots. The candidate was reverted. Do not use telemetry instrumentation as a standalone scheduling correction until its timing sensitivity is isolated.
- `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh` has an opt-in external diagnostic, `QF_E2E_EXTERNAL_EGRESS_CAPTURE=1`. It captures only client 1's underlay UDP packets to the server on the host-side `qf523h1` veth, only during each three-trial throughput phase, and writes bounded per-trial packet-count and inter-packet-gap summaries using the probe's wall-clock interval. Exact ARM64 source `8ed1cbc` passed the complete gate against binary `c54d2d5e1c600790fcc0c2d437fdb5f3942e8337dadd2138896f0bf958ac6a2e`: default 8.176 Mbit/s, opt-in 9.965 Mbit/s, 21.89% gain, 3-second black-hole detection, and a 6,356,992-byte recovery transfer in 28.769 seconds. Its three default trials had 65,372/78,915/52,858-us maximum gaps; opt-in had 67,156/105,044/104,909 us. Therefore an isolated 100-ms egress gap is not sufficient to explain the earlier clean-path persistent-congestion collapse. Both queue families and cleanup remained zero; the product runtime, normal gate, packet payloads, and credentials remain untouched.
- The same dual-stack contract accepts `QF_E2E_FEC_MODE=auto|off` as a controlled diagnosis boundary. The selected policy is written into the generated configuration consumed by both endpoints and retained in the stability manifest. Exact ARM64 source `82c954c` reused binary SHA-256 `9088126f68f1bf37b05921f6216023b0bb41bd784b175fdb12ee6546d612610e` with FEC Off and reproduced both clean and black-hole stalls. The retained failures correlated exactly with positive `quicfuscate_rate_limited_total`: 49 during child one's black-hole failure, 37 during child two's clean opt-in timeout, and 52 during child three's 27.103-second default receiver trial. Corresponding clean phases had zero rate-limit events. The 1,000-PPS per-source default was therefore manufacturing transport loss before `Connection::recv`, which caused missing ACKs, persistent congestion, and inner TCP retransmission timeout. The runtime default is restored to the documented 10,000 PPS, and the throughput gate now requires zero rate-limit events plus bounded trial duration.
- `scripts/tests/tun-e2e-multi-client-dual-stack-stability.sh` is the repeated exact-artifact acceptance wrapper for that diagnostic boundary. It forces the external capture for three isolated complete dual-stack runs, preserves every child artifact, verifies the child binary SHA-256 against one parent identity, independently revalidates all six receiver byte/hash/wall-clock results, positive per-child PMTU gain, the unchanged 15% three-child median gain, the black-hole bounds, and six complete per-trial egress summaries, then emits one bounded TSV row per run. A failed child or incomplete evidence fails the aggregate without discarding later raw evidence.
- Exact ARM64 source `f392f45`, binary SHA-256 `781fbe6ddb988d1ae1f91f3d1e252d3e700fbd8e00b283af82adf41d597646c0`, proves the rate-limit correction under Auto FEC. All 18 clean receiver trials completed with byte/hash equality and bounded duration, every retained rate-limit counter was zero, and no client or server UDP socket recorded a kernel drop. Children two and three passed the complete gate at 41.98% and 55.49% PMTU gain, 3-second and 2-second black-hole detection, and 17,694,720 and 19,595,264 recovery bytes. Child one completed all clean trials with a positive 12.70% gain but stopped before black-hole recovery because the child-level 15% assertion preempted the repeated aggregate. The stability contract now retains complete evidence for all children, rejects any non-positive child gain, and applies the unchanged 15% requirement to the median of three complete gains. Standalone runs retain their original per-run 15% gate. Local Bash, ShellCheck, positive and negative aggregate regressions, and runtime guardrails pass.
- Exact stability harness source `b2a08d3` reused that product binary because only harnesses and documentation changed. All three complete Auto-FEC children passed with default/opt-in medians of 7.604/10.336, 7.821/11.259, and 7.117/11.109 Mbit/s. Per-child gains were 35.93%, 43.95%, and 56.09%; the enforced median was 43.95%. Black-hole detection completed in 3/3/2 seconds and receiver-valid transfers delivered 18,284,544, 27,656,192, and 18,808,832 bytes in 20.935/20.910/21.020 seconds. All 12 retained phase metric snapshots reported zero rate-limit events, every UDP socket drop delta was zero, and teardown left no product process, namespace, qf523 link, or qdisc. The retained artifact is `/tmp/qf-b2a08d3-complete-stability-20260728-2324`.
- The external capture now records the same client-1 underlay UDP flow at two host-side boundaries: ingress on `qf523h1` and the matching server-veth `qf523hs` observation with bidirectional capture direction filtering. The bounded per-trial summary requires at least two packets at each boundary, retains each boundary's packet counts and gap distribution, and does not treat capture-count differences as product packet loss. This separates a missing bridge-delivery observation from a later server receive or ACK-progression failure without inspecting encrypted payloads. Native exact-artifact evidence is pending.
- Exact source `259ed60` ran the new capture against fresh binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`. Its default and opt-in throughput phases completed at 7.193 and 10.136 Mbit/s, a 40.91% gain. Client egress and server-veth ingress were exactly equal at 24,817 default and 31,276 opt-in packets, including all three interval counts, so the clean throughput flow traversed the host bridge to the server-veth observation. The later deliberate black-hole phase still failed before recovery evidence after a 13-packet application-space run from PN 37207 through 37221 over 108 ms against a 79-ms period. The capture validates the bridge boundary in completed clean phases but does not cover that later black-hole interval; cleanup was zero product process, namespace, qf523 link, and qdisc.
- The initial stability run used stale root-target binary `c54d2d5e1c600790fcc0c2d437fdb5f3942e8337dadd2138896f0bf958ac6a2e`, whose executable omitted the current persistent-congestion provenance strings; it is retained only as an environment control, not source proof. A fresh `cargo clean` plus Release build from exact source `24c4a92` produced `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26` with the expected provenance strings. Its three-child contract failed closed in every child. Children 1 and 3 completed default medians of 7.308 and 7.551 Mbit/s, then failed opt-in before a receiver artifact after application-space persistent congestion: PN 14639-14652, 12 losses, 78-ms period, 107-ms run; and PN 17889-17902, 12 losses, 87-ms period, 121-ms run. Child 2 completed 7.833 to 10.287 Mbit/s and 31.33% gain, then the deliberate black-hole phase reached PN 38527-38541, 13 losses, 87-ms period, and 99-ms run before recovery evidence. All children used the same fresh binary and forced external capture, and teardown left no product process, namespace, qf523 link, or qdisc. This is a reproducible production blocker, not a scheduler correction candidate.
- Exact ARM64 source `ca33b6a` built from a clean candidate to binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`. Default receiver trials completed at 7.119, 6.920, and 8.537 Mbit/s; opt-in trial one completed at 10.204 Mbit/s, then opt-in trial two failed before a receiver result. Every recorded server port 4433 UDP drop delta was zero, including the failed interval, while the completed forward captures matched at the client host-veth and server host-veth boundaries. Server kernel UDP receive-buffer overflow is therefore excluded for this clean-path collapse. The next bounded diagnostic must distinguish server ACK emission, reverse bridge delivery, and client valid-packet processing without inspecting encrypted payloads; cleanup was zero product process, namespace, qf523 link, and qdisc.
- The next harness-only diagnostic retains a start/end window and client exit status for every throughput trial before evaluating its result, so a failed trial still has a bounded observation interval. It observes the encrypted reverse UDP flow at the server `qf523hs` and client `qf523h1` host-veth boundaries, reports zero packets explicitly rather than inferring loss, and preserves the established forward capture and server socket-drop proof. Local helper self-test, Bash syntax, ShellCheck warning-level, and the runtime guardrail audit pass; exact ARM64 evidence is pending.
- Exact ARM64 harness source `57a2eed` ran against the unchanged fresh binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`; there is no `Cargo.toml`, `Cargo.lock`, or `src/` difference from `ca33b6a`. The complete gate passed: default receiver median 7.649 Mbit/s, opt-in median 9.763 Mbit/s, 27.64% gain, and an 8,847,360-byte black-hole recovery transfer in 21.574 seconds. Per-trial forward client/server counts were exactly 8,779/8,702/8,897 default and 10,179/10,975/8,764 opt-in; reverse server/client counts were exactly 5,116/5,157/5,304 and 8,610/9,485/7,673. Every server socket drop delta was zero and teardown was zero product process, namespace, qf523 link, and qdisc. This proves server reply emission and bridge delivery through the client host-veth for a clean full run, not yet for a collapsed interval.
- The three-run exact-artifact stability attempt from `57a2eed` failed closed with child statuses failed, failed, passed while preserving all raw artifacts. Child one completed its six clean throughput trials but failed during black-hole recovery. Child two timed out in clean opt-in trial three with client exit status 124: forward client/server counts were both 7,086 and reverse server/client counts were both 6,072 inside the retained failure window; the server socket drop delta was zero. Child three completed at default median 7.582 Mbit/s, opt-in median 9.370 Mbit/s, 23.58% gain, and a 16,252,928-byte black-hole recovery transfer in 20.877 seconds. Teardown was clean. The clean-path failure is therefore beyond server UDP receive, server reply emission, and host-veth bridge delivery; next isolate client valid-packet processing before changing runtime behavior.
- The next harness-only revision captures the connected client UDP socket selected by remote port 4433 before and after each receiver-valid TCP trial, including retained failure paths. The evidence helper records and verifies both local and remote endpoints, then fails on any client receive-drop delta. It does not inspect encrypted payloads or alter product scheduling. Local helper self-test, Bash syntax, ShellCheck warning-level, and runtime guardrails are green; exact ARM64 evidence is pending.
- Exact ARM64 source `681705d` ran the client-socket revision against the unchanged `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26` binary. All 18 clean receiver-valid trials retained stable endpoint pairs and client UDP kernel drops of `0 -> 0`. Child one passed completely at default median 7.473 Mbit/s, opt-in median 9.833 Mbit/s, 31.58% gain, and a 17,498,112-byte black-hole recovery transfer in 20.733 seconds. Children two and three completed all clean trials at 7.572/10.744 and 7.683/10.409 Mbit/s before failing only during their deliberate black-hole recovery. This excludes client kernel receive-buffer overflow from those clean trials, but does not yet observe a collapsed clean-path interval. Source and owned runtime residue were clean after the aggregate.
- The bounded client-processing diagnostic is enabled only by `QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS=1`. At a heartbeat timeout it records socket datagrams/bytes, Core receive outcomes and activity advancement, every Core send poll/outcome/datagram/byte, time since the last emitted datagram, queued request/MASQUE/WFP state, transport sent/received/lost counts, DATAGRAM depth, bytes in flight, cwnd, pending ACK state, and pacing/recovery deadlines. The normal runtime is unchanged when the variable is absent. The dual-stack harness preserves the single heartbeat line in a non-overwriting failure artifact. Local focused tests, full strict all-feature Clippy, Windows-GNU product checks, runtime guardrails, and native Windows runs `30535603045` / `30536002374` pass.
- Exact ARM64 source `a3ced4d` built cleanly after `cargo clean` to binary `bbdf747d8ad67ac5af5ccc1cb0904652d77cb1e84d25e34161ec6db20cad6616`. The three-child run failed closed: children one and two completed all six clean receiver-valid TCP trials at 7.241/9.965 and 7.824/10.478 Mbit/s, 37.61% and 33.93% gain, then failed only in deliberate black-hole recovery. Child three completed its default median at 7.156 Mbit/s, then clean opt-in trial one timed out with exit status 124. Client/server encrypted boundary counts were equal at 8,667 forward and 4,965 reverse packets; both client and server UDP socket drop deltas were zero. The client heartbeat had not fired, so its artifact correctly reports receive diagnostics unavailable. The preceding client log instead recorded application-space persistent congestion at cwnd 5,888 from PN 8,549 through 8,564: 12 losses over 109 ms against a 78-ms period. This excludes a heartbeat-only receive-path explanation for that retained clean failure and preserves the product blocker.
- The persistent-congestion event now retains triggering ACK newly-acked/lost counts, decoded ACK delay, largest-ACKed packet age, per-threshold triggering-loss counts, terminal packet-versus-time classification, and exact-microsecond RTT/loss/period/run timings. On a failed TCP probe the harness saves the last such client event in a separate non-overwriting artifact. This has no scheduling or recovery-policy change. Native ARM64 evidence is pending.
- Exact ARM64 source `36a97d0` built after `cargo clean` to binary `784f90a6db113439c907bd1056631dc3eca19f31aedfd6f44a077afddcfb85e1`. All three children failed closed after completing their default phases, retaining persistent-congestion evidence during clean opt-in TCP failure. Each decision had one newly acknowledged packet and 12 losses; the terminal loss met the time threshold in all three, while only one also met the packet threshold. The retained periods/runs were 92/133 ms, 172/219 ms, and 80/107 ms. Two runs reported sub-millisecond smoothed RTT in the millisecond log projection. This narrows the blocker to ACK progression and time-threshold loss provenance, not heartbeat handling, socket drops, or underlay delivery.
- Exact ARM64 source `d9149d0` built after `cargo clean` to binary `a4c31c030ffcdb6db05cf468723873dc7b1c7135fe73b10b1ab05e4aebeef7cb`. Children one and two failed only in deliberate black-hole IPv6 recovery, then their raw client logs recorded application-space persistent congestion after the 1472-to-1280 reset. The harness did not preserve a dedicated persistent-congestion artifact on that early black-hole failure path. Child three passed with receiver-verified default/opt-in throughput of `7.640`/`10.509` Mbit/s, `37.55%` gain, 3-second black-hole detection, and a `7,929,856`-byte recovery transfer in `26.299s`. The source and owned process, namespace, bridge, and qdisc cleanup were clean. This does not close TODO-559 because the repeated black-hole acceptance contract remains unstable.
- The active black-hole diagnostic now preserves the last client persistent-congestion event before reporting a failed recovery transfer. Its bounded event also records the effective PMTU and smallest/largest packet size in the complete loss run, separating stale oversized in-flight losses from losses that continue at the 1280-byte floor. This does not alter recovery policy or the acceptance gate.
- Exact ARM64 source `4a63c3b` retained a failed black-hole recovery artifact with `pmtu_effective=1280`, `run_min_packet_size=40`, and `run_max_packet_size=1280`. The collapse therefore continued at the floor and is not explained by stale 1472-byte in-flight packets. `core.rs` already reserves FEC outer datagram overhead before calling transport packetization, so no FEC-overhead root cause is established.
- The external diagnostic now starts all four encrypted host-veth boundary captures for the deliberate black-hole interval. It records the recovery probe start/end/exit-status in the existing non-overwriting window format, stops the captures before failure reporting, and emits the bounded four-boundary summary for client failure, server failure, and success. It observes encrypted packet metadata only and leaves recovery policy unchanged.
- Exact ARM64 harness source `e47d3bf` built after `cargo clean` to `a6fa317fc3df9236552628bb3e9856a2503d56c818f25b81b0b5eeb25ed76aa8`. Its three-child contract failed closed only because child one timed out during black-hole recovery. That retained interval had exactly matching client-egress/server-ingress counts of 6,662 and matching server-return/client-ingress counts of 5,374, so the encrypted flow reached both host-veth boundaries in both directions. Its client then established application-space persistent congestion at `pmtu_effective=1280`, with a 40-to-1280-byte loss run lasting 119,988 us against an 89,489-us period. Children two and three passed their black-hole transfers in 20.689 and 23.803 seconds after 2-second detection, with matching forward/reverse boundary counts of 16,734/9,446 and 7,487/6,139. Large capture gaps also occur in successful runs, so the captured gaps alone are not a root-cause claim. Candidate source and owned product process, namespace, link, and qdisc cleanup were clean.
- At the 1280-byte PMTU floor, `effective_tunnel_mtu()` keeps the IPv6 minimum while `effective_masque_mtu()` is 1180 bytes after QUIC and MASQUE reserve. A 1280-byte TUN frame therefore takes the existing framed H3 STREAM fallback. `PersistentCongestionEvidence` now retains independent control, STREAM, and DATAGRAM packet counts for the loss run, including co-carriage, so the next exact native failure can prove whether that fallback occupies the collapsing run. This instrumentation does not change recovery policy, packet scheduling, or the acceptance gate.
- Exact ARM64 source `7d866f6` built after `cargo clean` to binary `70af5f218b611b5f0bad1ce18df3a9ffabb9b1afdba6b9fa4e2c90e9dccd7d79`. Its three-child contract failed closed in children one and three, while child two passed at 7.613/10.955 Mbit/s, 43.91% gain, 2-second detection, and 17,170,432 receiver bytes in 22.086 seconds. Child three retained a 1280-byte-floor collapse with 13 losses over 109,745 us against a 94,910-us period: 11 carried STREAM, 2 carried control, and none carried DATAGRAM. This proves that the H3 STREAM fallback occupies the collapsing loss run. It does not yet prove why those STREAM carriers cease to be acknowledged, so recovery policy remains unchanged. Candidate and evidence remain retained; owned runtime cleanup was zero process, namespace, link, and qdisc residue.
- STREAM loss-run provenance now separates fresh range emissions from retransmissions of previously lost ranges. The next exact native failure can therefore distinguish first-delivery loss from a retransmission loop without exposing payloads or changing recovery policy, packet scheduling, or acceptance thresholds.
- FEC telemetry is an explicit process aggregate. Active mode is a nine-bucket connection distribution, effective window is a source-packet sum across active connections, and observed loss is derived from cumulative lost/observed controller samples.
- Clean-link proof is connection-local controller state rather than a process metric. `Connection` counts only packets removed by transport ACK classification; `QuicFuscateConnection` transfers and resets typed feedback with independent send/loss counters, but forwards it to `AdaptiveFec` only when it contains ACK or loss evidence, without exporting a misleading aggregate ACK gauge.
- Source/repair send counters advance only after network-facing serialization into the connection output buffer succeeds; they measure datagrams emitted by the FEC layer for transmission, not UDP syscall completion. Receive and recovery counters advance only after `WireFecReceiver` accepts the datagram and reports its original versus reconstructed decoder output. Generated, queued, dropped, malformed, and duplicate symbols do not satisfy these metrics.
- `AdaptiveFec::telemetry_snapshot()` and `QuicFuscateConnection::fec_telemetry_snapshot()` provide exact connection-local policy, committed mode/window, loss, transition, wire, decode, and recovery evidence. Packet collection is snapshotted from `--telemetry` before connection construction.
- Compression and SIMD counters provide backend-selection and efficiency visibility without changing data-plane behavior.

### Operational hints
- Rayon thread pool sizing (parallel repairs)
  - Parallel generation uses the global Rayon pool. To cap threads, set `QUICFUSCATE_RAYON_THREADS=<n>` before launch.
  - The constructor now resolves this as an explicit FEC global-resource policy step before initializing the one process-global Rayon pool.
  - There is no runtime toggle for parallel vs sequential in the current code; selection is internal.
  - In async deployments (Tokio), avoid oversubscription: choose `<n>` near the number of physical cores or the Tokio worker count when CPU contention is observed.
  - Measure with `--telemetry` and watch the active-mode distribution, effective-window sum, mode switches, wire overhead, and throughput counters when adjusting.

- Hysteresis and loss smoothing (mode stability)
  - `hysteresis` dampens mode flapping; larger values reduce oscillation on jittery links. Typical range: `0.01-0.03`.
  - `lambda` (EMA factor) near `1.0` reacts quickly to current loss; smaller values increase smoothing. Tests use `lambda=1.0` to trigger fast path deterministically.

- Streaming cadence trade-off
  - Lower `QUICFUSCATE_FEC_STREAM_EVERY` improves recovery latency but increases overhead; default is computed from CPU profile (often 1-3). Tests often use `1` for clear recovery behavior.

- Disturbance handling
  - The controller reacts to change-points (CUSUM) by escalating to streaming and, when necessary, increasing the FEC window (`QUICFUSCATE_FEC_EXTREME_WINDOW`).
  - Auto-Mode resets to efficient profiles once stability returns (EMA/variance gates).

- Telemetry for tuning
  - Enable `--telemetry` and monitor active-mode buckets, `quicfuscate_fec_mode_switches_total`, `quicfuscate_fec_effective_window_source_packets_sum`, `quicfuscate_fec_observed_loss_ppm`, wire-overhead gauges, and switch-reason counters during tuning iterations.

Notes
- `QUICFUSCATE_FEC_STREAM_EVERY` is read once per `AdaptiveFec::new`. Use a new instance to pick up changes.
- Telemetry updates are no-ops unless telemetry is enabled at runtime; exporting is handled by the `telemetry` module.

### Test-only Environment Overrides
These env vars are only read under `#[cfg(test)]` or with the `rust-tests` feature; they are not part of the runtime contract:
- `QUICFUSCATE_MORUS` - force MORUS plan selection.
- `QUICFUSCATE_PROFILE_OVERRIDE` - override CPU profile selection in tests.
- `QUICFUSCATE_GF16_TEST_ITERS` - iteration count for GF16 consistency tests.
- `QUICFUSCATE_TEST_UNSET` - used only by EnvGuard tests.

## Governance (Canonical)

### QuicFuscate Governance and Deterministic Workflow
Canonical cross-cutting engineering principles, policies, and deterministic offline-first workflow.

#### Principles and Policies
- Security: AEAD-only; strict nonce/tag checks.
- Stealth: TLS Cover + RealTLS (rustls) and HTTP/3/QPACK mirror real browsers (JA3/JA4). Domain fronting coherence.
- Performance: centralized CPU feature detection and dispatch; SIMD and zero-copy where safe.
- Modularity: single sources of truth; avoid duplication and scattered hot-paths.
- Determinism: offline, script-driven workflows; reproducible builds/benches; stable telemetry schemas; no secrets in logs.
- Documentation equals implementation.

#### Deterministic Offline Workflow
- Modular script architecture under `scripts/{build,tests,benchmarks,audits,utils}/`.
- Individual scripts for specific operations with clear separation of concerns.
- E2E TLS fingerprint checks integrated (decode/verify via shell-based actions; sidecar generation via utils).
- Artifacts under `scripts/out/<category>/`; deterministic timestamps and seeds.

#### QA Gates and Ownership
Security/Stealth/Performance/Reliability/Documentation gates are enforced in the project workflow.

## Production Configuration
When deploying QuicFuscate in a production environment you may enable telemetry
and export metrics through your own endpoint:

- Start the binary with `--telemetry` to activate counters, then periodically
  call `telemetry::export_telemetry_text()` and serve the result via
  your HTTP endpoint (or use the built-in `/telemetry` endpoint).
- Increase the `MemoryPool` capacity to match expected traffic volume.
- Configure a reliable DoH provider in `StealthConfig` for consistent DNS
  resolution.
- Use `FecConfig::from_file` to tune window sizes and PID constants for your
  network conditions.

### Telemetry HowTo
- Enable telemetry via CLI: start with `--telemetry` to activate counters.
- Exporting metrics: call `telemetry::export_telemetry_text()` to obtain a plain text snapshot, or use the built-in `/telemetry` endpoint.
- Integration: serve the snapshot via your own HTTP endpoint or exporter; call `telemetry::flush()` to refresh process and pool resource gauges immediately before exporting a one-off snapshot.

### AF_XDP Experimental Status
Status: `experimental/internal` for the retained AF_XDP socket code behind `internal_af_xdp_experimental`.

AF_XDP runtime wiring is not part of the canonical runtime in this fork. The retained AF_XDP socket code remains available only behind the internal feature gate `internal_af_xdp_experimental`; an explicitly feature-enabled release can still compile the module, so its UMEM/ring ownership contract remains open under TODO-838. The canonical Linux high-end send path is `io_uring`.

## Static Policy Checks
To validate security and stealth policies without performing a build, use the dedicated audit and utility scripts:

- **TLS Profile Validation**:
  - `./scripts/tests/utils/util-e2e-decode-all-profiles.sh` - Decode and sanity-check all CHLO files
  - `./scripts/tests/utils/util-e2e-verify-all.sh` - Verify all profiles match their SHA256 sidecars (`--sidecars-dir` supported)
  - `./scripts/tests/utils/util-e2e-verify-current.sh` - Verify active `${QUICFUSCATE_BROWSER}/${QUICFUSCATE_OS}` profile (`--sidecars-dir` supported)

- **Static Code Hardening**:
  - `./scripts/tests/audits/audit-runtime-guardrails.sh` - Runtime/docs/structure anti-drift gate with fail-fast contract checks
  - `./scripts/tests/audits/audit-all-comprehensive.sh` - Consolidated audit (unsafe patterns, deps, quality)

- **TLS Profile Management**:
  - `./scripts/tests/utils/util-tls-list-profiles.sh` - List all available TLS profiles
  - `./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh` - Generate SHA256 checksums snapshot under `scripts/out/utils/.../sidecars/`
  - `./scripts/tests/utils/util-tls-show-active-env.sh` - Display current TLS environment settings

These checks are deterministic, offline, and fast, designed to integrate into an entirely local workflow. All scripts are organized in the `scripts/` directory with clear categorization by purpose.

## Global Atomic State Audit

The codebase uses 117 scalar global `AtomicU64`/`AtomicU32`/`AtomicBool`/`AtomicUsize`/`AtomicI64`/`AtomicU8` instances across modules, plus 270 `SafeGauge(AtomicI64)` and `Counter(AtomicU64)` newtype-wrapped statics in `src/optimize/telemetry.rs` (387 total global atomic-backed state surfaces). The wrapped counters are the preferred pattern for new metrics: they encapsulate the atomic and provide a type-safe `inc()`/`read()` interface. This section documents the rationale, ownership, and future direction of the raw atomics; the wrapped counters are all read-only metrics and are covered by the same coupling analysis.

### Why Global Atomics

Global atomics provide lock-free, zero-overhead cross-module coordination for a high-throughput data-plane runtime. They avoid mutex contention on hot paths (packet processing, FEC, AEAD selection) where even microsecond-level lock waits would degrade throughput. The trade-off is implicit coupling between subsystems - readers and writers are connected through shared global state rather than explicit interfaces.

### Ownership by Module

| Module | Count | Category | Purpose |
|---|---|---|---|
| `src/optimize/telemetry.rs` | 101 | Metrics/Counters + Runtime config | 95 telemetry counters (H3, stealth, FEC, SIMD, memory pool, io_uring, CPU features, I/O driver) + 6 runtime config gates (`COLLECT_PACKET_STATS`, `COLLECT_STREAM_STATS`, `COLLECT_CONGESTION_STATS`, `COLLECT_FEC_STATS`, `COLLECT_STEALTH_STATS`, `TELEMETRY_ENABLED`). Read-only observation surface for dashboards and diagnostics, plus collection on/off gates. |
| `src/brain.rs` | 0 | Connection-local hints | `BrainFecHints` and `IntelligentLevelHints` are owned by one connection and passed explicitly to its FEC observer and stealth manager. They are not process-global atomic statics. |
| `src/optimize/` | 5 | Runtime config | `RR_NODE` (NUMA round-robin), `NUMA_NODES` (node count), `PROFILE_OVERRIDE` (profile override), `TLS_LIMIT_RUNTIME` (TLS limit), `LOCK_BLOCKS` (mlock gate for MemoryPool blocks, TODO-516). Hardware-adaptive runtime state. |
| `src/transport/batch.rs` | 3 | Metrics | Batch send/recv/packet counters for transport telemetry. |
| `src/crypto/` | 2 | Runtime config | `DATA_AEAD_OVERRIDE_MODE` (AEAD selection), `ARM_AES_OK` (ARM AES capability cache). |
| `src/fec/` | 1 | Sequencing | `REPAIR_ID_COUNTER` - monotonic repair packet ID generator. |
| `src/stealth/parts/runtime.rs` | 1 | Runtime generation | `NEXT_STEALTH_RUNTIME_GENERATION` - monotonic runtime-owner generation identity. |
| `src/qftls.rs` | 2 | Runtime gate | `TLS_OVERRIDE_REQUIRED` (TLS cover override flag), `MAX_EARLY_DATA_SIZE` (0-RTT data limit). |
| `src/rng.rs` | 1 | Test gate | `TEST_FORCE_SECURE_ENTROPY_FAILURE` - test-only entropy failure injection. |
| `src/main.rs` | 1 | Sequencing | `NEXT_ID` - connection ID generator. |

**Total: 117 scalar atomic statics** (recounted 2026-08-02 after TODO-584 and TODO-597). The previous 120-count included three process-global brain hint channels that are now connection-local. The retired stealth-local DoH rotation counter was removed and the runtime-owner generation counter is listed explicitly. The telemetry array `FEC_ACTIVE_CONNECTIONS_BY_MODE` remains an atomic-backed static but is not included in the scalar declaration count.

### Trade-offs

**Performance benefit**: Zero-cost reads on hot paths. No lock contention. No allocation. Compiler can optimize `Relaxed` loads into single instructions.

**Coupling cost**: Implicit data flow between subsystems. The former brain-to-FEC and brain-to-stealth process-global channels have been replaced by explicit connection-owned `BrainFecHints` and `IntelligentLevelHints` (TODO-584). The remaining globals still require ownership-aware tracing, and testing individual modules in isolation requires awareness of global state.

### Future Direction

- **Metrics/counters (98 of 117 raw statics, plus 270 wrapped telemetry statics)**: These are read-only observation surfaces (95 in `telemetry.rs` + 3 in `transport/batch.rs`) and are appropriate as globals. No change planned.
- **Connection-local brain hints (0 global statics)**: DONE (TODO-584). `BrainFecHints` carries FEC interval and redundancy policy to the matching observer, while `IntelligentLevelHints` combines independent Brain-pressure and probe-threshold levels inside one connection. No process-global brain actuator remains.
- **Runtime config (15 across telemetry.rs, optimize/, crypto/, qftls.rs)**: 6 telemetry collection gates + 5 optimize/ hardware-adaptive + 2 crypto/ AEAD/AES + 2 qftls/ TLS gates. Could migrate to a shared `RuntimeConfig` struct passed through the call chain, but current usage is stable and well-bounded.
- **Sequencing (2 in fec/, main.rs)**: Standard pattern for ID generation. No change needed.
- **Runtime generation (1 in `src/stealth/parts/runtime.rs`)**: Standard monotonic owner identity used to correlate runtime generations. No change needed.
- **Test gates (1 in rng.rs)**: Test-only, acceptable as-is.

The overall approach prioritizes runtime performance over architectural purity. The highest-return coupling-reduction target (the brain.rs hint channels) is now closed; the remaining globals are either read-only metrics, stable runtime config, or standard sequencing/round-robin/test primitives.

## Troubleshooting

### Connection Failures

#### TLS Handshake Errors
**Symptoms:** Connection times out during handshake, "TLS failure" or "TLS alert" in logs.

**Common causes:**
- Certificate mismatch between client SNI and server certificate CN/SAN
- Expired, untrusted, CA-marked end-entity, or SNI-mismatched server certificate
- ALPN protocol mismatch

**Fixes:**
1. Verify certificate validity: `openssl x509 -in server.crt -noout -dates`
2. Check SNI matches: ensure `connection.sni` in client config matches the server certificate
3. For debug-build testing only, set `connection.verify_peer = false` or `QUICFUSCATE_ALLOW_INVALID_CERTS=1`; release builds always verify
4. Verify ALPN alignment between client and server `connection.alpn` arrays

#### Connection Timeout
**Symptoms:** "Timeout" error after idle_timeout_ms.

**Fixes:**
1. Increase `connection.idle_timeout_ms` (default: 30000ms)
2. Check firewall allows UDP on the configured port (default: 4433)
3. Verify NAT/router does not drop long-lived UDP sessions
4. Check `transport.max_idle_timeout` is consistent on both sides

#### Connection Error Ownership
`transport::Connection` keeps the first locally decided failure in `local_error` so a later shutdown or protocol event cannot replace the root cause. Local `APPLICATION_CLOSE` and `CONNECTION_CLOSE` calls use structured `LocalApplicationClosed` and `LocalConnectionClosed` errors with their wire code and raw reason bytes. A peer `CONNECTION_CLOSE` or `APPLICATION_CLOSE` is recorded separately in `remote_error` with its error code, frame type where applicable, and raw reason bytes. `Connection::error()` exposes the local root cause when present and otherwise the first peer close; `local_error()` and `remote_error()` expose each side independently. `ClientConnection::close()` emits an application close, `close_transport()` emits a transport close, and both wrappers expose cloned `error()`, `local_error()`, and `remote_error()` accessors. This separation keeps local timeout/TLS failures observable while preserving a later peer close for diagnostics.

TLS CRYPTO processing converts provider failures into a local `CRYPTO_ERROR` close with the
`0x0100` TLS-alert base code before returning the error. Receiving a peer close remains terminal
without sending a second close frame; the peer-provided close is retained through `remote_error`.

#### QKey Authentication Failure
**Symptoms:** "Connection refused" or "Invalid token" immediately after handshake.

**Fixes:**
1. Verify `qkey_id` is exactly 12 hex characters
2. Verify `qkey_token` matches what was registered on the server
3. Check the QKey has not been revoked on the server
4. For TUN/MASQUE failures, verify the public Initial QKey ID resolves to the intended server record and the encrypted H3 `x-qf-auth` CONNECT-UDP header carries the matching bearer. MASQUE DATAGRAM delivery to TUN is intentionally blocked until that proof validates.

### DNS Leak Detection and Prevention

#### Detecting DNS Leaks
```bash
# While connected, test DNS resolution path:
nslookup -type=A example.com
# The response should come from your configured VPN DNS servers, not your ISP
```

Linux root validation uses `scripts/tests/tun-e2e-dns-leak-netns.sh`. The gate creates server/client namespaces, opens a real QKey-authenticated TUN/MASQUE tunnel, runs one explicit query through the server TUN IP and one normal resolver query through a private `/etc/resolv.conf` mount pointed at the client localhost proxy, verifies resolver restoration, and captures the client underlay with tcpdump. Passing evidence requires both DNS responses plus `raw_port_53_packets=0`. Set `QF_E2E_DOH_PROVIDER` for a reachable provider-success run; the default endpoint intentionally proves local ownership and cleanup with a SERVFAIL fallback when the test provider is unreachable.

#### Common DNS Leak Causes
1. **Split-tunnel configuration:** Ensure all DNS traffic routes through the tunnel
2. **IPv6 DNS fallback:** Configure IPv6 DNS explicitly when IPv6 is enabled. The live server intercepts both IPv4 and IPv6 UDP/53 DNS packets that arrive through the MASQUE/TUN path. The client proxy owns IPv4 localhost UDP/53 and binds IPv6 localhost UDP/53 when available; the OS resolver is configured with the supported platform backend.
3. **macOS and Windows:** Native resolver mutation requires the corresponding privileged platform gate. The local Linux namespace proof does not claim native proof for those platforms.

#### Prevention
Configure DNS servers explicitly:
```toml
[interface]
dns_servers = ["1.1.1.1", "9.9.9.9"]
```
Enable kill-switch to prevent any traffic outside the tunnel.

### Kill-Switch Issues

#### Linux
**iptables rules not applied:**
- Check `iptables -L QUICFUSCATE_KS -n` to verify rules exist in the dedicated chain
- Ensure the binary has `CAP_NET_ADMIN` capability or runs as root
- Verify no conflicting firewall manager (ufw, firewalld) is resetting rules

**Traffic leaks during connect/disconnect:**
- nftables is the preferred automatic backend. Client state replaces only `inet quicfuscate_ks`, while server NAT/forwarding replaces only `inet quicfuscate_rt`; each replacement is one rollback-safe `nft -f -` transaction covering IPv4 and IPv6.
- The iptables fallback rebuilds only `QUICFUSCATE_KS`, `QUICFUSCATE_RT`, and `QUICFUSCATE_NAT` through `iptables-restore --noflush` and `ip6tables-restore --noflush`. Shared `OUTPUT`, `FORWARD`, and `POSTROUTING` chains contain only exact jumps to those owned chains.
- Configure an explicit backend with `[security.firewall] backend = "iptables"` or `backend = "nftables"`. Omit `backend` for automatic selection. Startup logs the requested backend, selected backend, and both live availability probes exactly once per process.

**Stale rules from crashed session:**
- Run `quicfuscate client --cleanup-firewall` to remove stale kill-switch rules
- This removes only the owned `quicfuscate_ks` table or `QUICFUSCATE_KS` chains and their exact OUTPUT jumps. It does not flush or replace an unrelated host ruleset.
- A kill-switch-enabled client always performs the same stale cleanup before runtime or firewall setup. Cleanup failure aborts startup; `cleanup_firewall_on_start` remains a parsed compatibility key but cannot disable this safety invariant.
- Cleanup uses exact typed resource identities, at most three attempts with 100 ms spacing, and an absent-resource postcondition. Success distinguishes an already-absent resource from a removed resource. Persistent inspection, removal, or postcondition failure propagates through CLI, Engine, and server shutdown results.
- An unavailable Linux firewall tool is skipped only during cross-backend stale-residue inspection. Explicit selection of that backend still fails closed before firewall mutation, while an installed backend must complete and verify cleanup.
- The exact ARM64 release artifact `54aa80dca01a67dfb7716aa35853245a7fd0334737fc7ad6af00743a127197fb` passes both privileged nftables and real iptables-only crash/restart lifecycles. The harness retains unrelated firewall fingerprints across atomic replacement failure, stale recovery, restart, and clean shutdown and leaves no owned namespace, link, rule, table, chain, or process residue.

#### macOS
**pf rules not loading:**
- Check pf status: `sudo pfctl -s info`
- Verify rules file: `sudo pfctl -s rules`
- QuicFuscate refuses to claim kill-switch support unless a successful `pfctl -sr` query exposes an actual `anchor "com.quicfuscate.killswitch"` or matching `com.quicfuscate/*` statement. If the anchor was loaded before that check fails, the client flushes the just-loaded anchor and removes its PID-scoped config; if rollback fails, the failure is reported as retained fail-closed ownership for explicit cleanup. Run the read-only privileged proof with `sudo scripts/tests/macos-pf-anchor-proof.sh`. Managed anchor installation and the privileged lifecycle proof remain TODO-548.

**Temp file conflicts:**
- Kill-switch config uses PID-scoped temp files (`/tmp/quicfuscate_killswitch_<pid>.conf`) to avoid multi-instance conflicts
- Stale rules can be cleaned with `quicfuscate client --cleanup-firewall`
- Cleanup flushes and verifies only `com.quicfuscate.killswitch`. It never disables the shared PF service.

#### Windows
The Windows kill switch uses WFP rather than `netsh advfirewall`. One fixed persistent provider and sublayer own IPv4/IPv6 outbound-transport filters, which Windows applies to ordinary, third-party-transport, and raw packets while exposing the exact UDP tuple. Every block-only, connecting, connected, disable, and stale-cleanup transition is one BFE transaction. Loopback, the exact UDP VPN endpoint, and the connected Wintun LUID use higher filter-weight ranges than the same-sublayer catch-all block. A failed transaction retains the previous policy, and an enabled policy survives process exit until exact startup cleanup. The former `netsh` design remains rejected because broad Windows Firewall block rules override narrower allow rules; cleanup still removes only the two exact legacy rule names. The legacy `WindowsPlatform` adapter path remains `Unsupported` before host mutation. Native CI run `30508948149`, job `90764941801` proves exact IPv4/IPv6 packet absence and presence at the real Wintun ring for every policy state, retained blocking after the installer child exits, restored delivery after stale cleanup, and zero managed WFP, adapter, and firewall residue. Signed MSI run `30533862566` and consecutive authenticated Windows-Omega runs `30535603045` / `30536002374` close the packaged-DLL, connected dual-stack traffic, same-process stability, and cleanup proof.

### Heartbeat Watchdog

The client runtime owns one automatic 50 ms watchdog. It detects an explicit remote close at every setting and detects inbound inactivity when `heartbeat_timeout_ms` is nonzero. Unexpected remote close, socket failure, or heartbeat timeout atomically reapplies the block-only firewall policy and retains it across process exit. Explicit signal or engine shutdown removes owned rules; `--cleanup-firewall` removes rules retained after a crash or unexpected loss.

**Configuration:**
```toml
[security]
kill_switch = true              # Enable kill switch
heartbeat_timeout_ms = 30000    # 30s default; 0 to disable
cleanup_firewall_on_start = false  # Compatibility key; cleanup remains mandatory
```

`engine.check_heartbeat()` is now a compatibility probe only. It reports a loss already handled by the runtime-owned watchdog and must not be driven as a second polling loop. The standalone client exposes `--heartbeat-timeout-ms` and `--vpn-dns`; connected policy permits only the exact VPN UDP endpoint, selected VPN resolvers on TCP/UDP port 53 through the TUN interface, and remaining traffic through that TUN. Every other IPv4/IPv6 DNS destination is dropped before the general TUN allowance.

### IPv6 Dual-Stack Support

The VPN server supports dual-stack IPv4/IPv6 operation. When IPv6 is enabled (default), the server:
- Assigns IPv6 addresses to the Linux TUN interface via `ip addr add` and verifies the exact address/prefix before readiness
- Allocates IPv6 addresses to clients from a dedicated `Ipv6Pool`
- Routes IPv6 packets via `get_by_client_ipv6()` session lookup
- Sets up Linux ip6tables or nftables MASQUERADE and forwarding rules

`Ipv6Pool` allocation uses a forward cursor plus a FIFO of released addresses, so it never enumerates an entire configured prefix. IPv6 capacity counters use `u128`; the mathematically unrepresentable full `2^128` address range is explicitly saturated at `u128::MAX`. Both IPv4 and IPv6 pools ignore releases outside their configured ranges.

The shipped server runtime does not advertise macOS pf or Windows NetNat as server TUN backends. The server routing manager returns `UnsupportedPlatform` before host mutation for those targets; the retained macOS pf and Windows NetNat functions are pure rule/script generators only and require a native ownership and privileged proof before any runtime wiring.

**Configuration:**
```toml
# Server defaults (fd00::/64 ULA range)
ipv6_pool_start = "fd00::2"
ipv6_pool_end = "fd00::fe"
ipv6_server_ip = "fd00::1"
ipv6_prefix_len = 64
ipv6_dns_servers = ["2606:4700:4700::1111", "2001:4860:4860::8888"]
```

**Client CLI:**
```
quicfuscate client --tun-ip6 fd00::2 --tun-prefix6 64 ...
```

The standalone CLI and generic `EngineConfig`/`ClientRuntime` paths now share the same typed
address contract at the TUN boundary. `InterfaceConfig::client_tunnel_addresses()` resolves
IPv4-only, IPv6-only, and dual-stack state into `ClientTunnelAddresses`; `ClientRuntime::start()`
projects that model into `TunConfig.ip`, `TunConfig.netmask`, `TunConfig.ip6`, and
`TunConfig.prefix6`. The legacy `tun_ip`/`tun_netmask` IPv4 pair remains compatible, and a
legacy IPv6 pair remains accepted for single-family compatibility. Canonical `tun_ip6` plus
`tun_prefix6` is the explicit IPv6 source for generic dual-stack configuration; conflicting
IPv6 sources and malformed prefixes fail validation. The public compatibility `ClientBackend`
remains intentionally single-family and rejects canonical IPv6 fields instead of dropping them.

Server TUN network authority is separate and explicit. `ServerConfig.server_ip`/
`server_netmask` and `ipv6_server_ip`/`ipv6_prefix_len` are the single effective IPv4/IPv6
server-network source for TUN provisioning, Linux routing and firewall subnets,
`ClientIsolationManager`, live local-address handling, and IPv4/IPv6 client pools. Embedded
`EngineConfig.interface` addresses are optional compatibility assertions: matching values are
accepted, while a mismatch fails with typed configuration error before host resources or a TUN
are opened. Embedded TUN creation projects the validated `ServerConfig` network directly.
Standalone `TunConfig` address fields follow the same contract: missing addresses inherit the
validated server network, matching explicit values are retained, and conflicting or malformed
overrides fail before TUN open. Server startup rejects reversed, out-of-network, or server-owned
client-pool ranges so firewall subnet, TUN address/prefix, local ICMP/source ownership, and
allocated client addresses cannot describe different networks.
Local regression coverage proves matching embedded and standalone projections, conflicting
IPv4/IPv6 rejection before host/TUN startup, and out-of-network pool rejection. Privileged Linux
TUN/routing/firewall execution and authenticated live-wire proof remain external runtime gates.

Server-side `client_ipv6` assignment is still consumed only by server routing/session ownership
and is not currently propagated to the generic client through a tunnel-configuration
control-plane message. TODO-663 closes the static schema and projection boundary; TODO-866 owns
the authenticated server-assignment/control-plane contract. TODO-731 owns malformed standalone
CLI address parsing.

To disable IPv6, set `ipv6_server_ip = None` and `ipv6_pool_start = None` in the server config.

### Performance Tuning

#### MTU Optimization
Optimal MTU depends on your network path. Start with defaults and adjust:
```toml
[transport]
mtu = 1400              # QUIC packet MTU
max_udp_payload = 1350  # Maximum UDP payload

[interface]
tun_mtu = 1500          # TUN device MTU
```
If you see fragmentation or retransmissions, reduce `mtu` by 50 until stable.

#### Buffer Sizing
For high-throughput scenarios:
```toml
[transport]
initial_max_data = 10000000
initial_max_stream_data_bidi_local = 1000000
```

#### Congestion Control
Four algorithms are available: Reno (conservative AIMD), CUBIC (RFC 9438 plus RFC 9406 HyStart++), BBR2 (loss-aware model-based), and BBR3 (stealth-optimized, default). All are real implementations, selectable through the CLI and canonical runtime configuration. Protected UI selectors remain unchanged.

```toml
[transport]
cc_algorithm = "bbr3"   # Options: "reno", "cubic", "bbr2", "bbr3"
```

When stealth mode is active, the StealthShaper automatically wraps paced CUBIC, BBR2, and BBR3 with bounded pacing jitter. CUBIC and BBR2 can additionally apply optional 2% dampening. Reno has no pacing and is unaffected by stealth shaping.

#### CPU Affinity and Thread Count
```toml
[optimization]
num_worker_threads = 0   # 0 = auto (uses default of 8 threads)
```

#### Memory Pool
The engine memory pool auto-scales to 5% of system RAM (clamped 16-64 MB). `optimization.memory_pool_size = 0` selects this same automatic size. Runtime adapters derive an explicit minimum 64 KiB block size from `memory_pool_alignment` and compute capacity from the resolved byte size, with a minimum of one block. Override the automatic size via environment variable:
```bash
export QUICFUSCATE_MEMORY_POOL_MB=128
```

### Log Interpretation

#### Log Levels
- `error`: Critical failures requiring immediate attention
- `warn`: Degraded operation, potential issues
- `info`: Normal operational events (connections, disconnections)
- `debug`: Detailed protocol-level information
- `trace`: Maximum verbosity (packet-level, very high volume)

#### Enable Debug Logging
```toml
[logging]
mode = "verbose"
# Or for specific control:
level = "debug"
```

#### Common Log Messages

| Message | Meaning | Action |
|---------|---------|--------|
| `TLS handshake error` | Certificate or protocol mismatch | Check TLS config |
| `AEAD limit reached` | Key update needed | Automatic per QUIC spec - reconnect if persistent |
| `Flow control violation` | Peer exceeded data limits | Check transport limits |
| `No viable path` | Network path unavailable | Check connectivity |
| `Buffer too short` | Packet truncation | Increase MTU/buffer sizes |

### Platform-Specific Issues

#### Linux
**io_uring not available:**
- Requires kernel 5.6+ for basic io_uring support; check with `uname -r`
- The runtime falls back to sendmmsg automatically

**Permission denied for TUN:**
- Use the shipped root-started systemd unit with `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_CHOWN`, `CAP_SETGID`, and `CAP_SETUID` in `CapabilityBoundingSet`. Do not add `AmbientCapabilities`; root setup already receives the bounded effective/permitted set and ambient capabilities would populate the inheritable set.
- Run `quicfuscate capabilities --json --tun` before startup to identify the exact missing capability or target-account failure.

#### macOS
**utun interface creation fails:**
- Requires root or network extension entitlement
- Run with `sudo` for development/testing

#### Windows
**Wintun adapter cannot start:**
- Build with the `tun-windows` feature and place the verified upstream `wintun.dll` beside the executable.
- On Windows development hosts, run `scripts/utils/provision-wintun.ps1` with explicit destination and evidence paths instead of downloading or copying an unverified DLL manually.
- Run QuicFuscate as Administrator. The native backend creates and owns the adapter; do not create a persistent adapter manually.
- The tracked Windows MSI path provisions and hashes the DLL automatically. Wintun lifecycle, WFP packet policy, process-exit retention, stale cleanup, signed packaging, and authenticated dual-stack tunnel traffic are native-green in CI/release runs `30508948149`, `30533862566`, `30535603045`, and `30536002374`.

### Admin Interface Issues

**Cannot connect to admin API:**
1. Verify admin is listening: `ss -tulnp | grep 8080`
2. Check binding address in config (default: localhost only)
3. Verify authentication credentials

**Authentication failures:**
- Admin password is set on first startup
- If locked out, delete `config/admin-auth.json` and restart (resets auth)
- Session tokens expire after the configured TTL
- The active admin password floor is 6 characters; if rotation fails with `Password too short`, verify the new value is at least 6 characters long

**Local helper scripts use `admin / 123`:**
- `scripts/utils/util-run-local-admin-web.sh` and `scripts/utils/util-run-local-ui.sh` intentionally set `QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1` and use `--admin-web-user admin --admin-web-password 123`
- This is a loopback-focused local-development shortcut, not a deployment recommendation
- To use a different password, edit those scripts or launch the server manually with `--admin-web-user` and `--admin-web-password`

## Deep Audit Findings (2026-08-01)

A full deep-audit sweep of `src/` was performed with parallel read-only module scans and `cargo check`/`cargo clippy` verification. The scan produced new TODO entries (TODO-626 through TODO-689) and augmented existing TODOs with additional evidence. The findings span crypto correctness, FEC resource bounds, transport/stealth hot-path issues, privilege and unsafe-code correctness, client/server lifecycle, DNS behavior, time-source consistency, SIMD static mutables, and a full unsafe-code surface audit (memory pools, SIMD, crypto, transport, interface, privilege, FEC, io_uring, and auxiliary modules).

### Security-Critical Findings

- **Constant-time tag comparison**: `src/crypto/mod.rs::subtle_ct_eq` is not constant-time; the compiler may short-circuit on first mismatch, creating a timing oracle for all AEADs. Tracked in TODO-626.
- **Key/IV length validation**: crypto constructors in `src/crypto/mod.rs`, `src/crypto/aegis.rs`, and `src/crypto/morus.rs` now reject malformed key/IV material through `KeyMaterialError`; the constructor boundary is closed by TODO-627. Header-protection sample bounds remain separately tracked in TODO-629.
- **AEGIS unwrap panics**: the former `Mutex<Option<...>>` seal/open state and its `.unwrap()` path were removed by TODO-582; the concurrent-wrapper regression covers the mutex-free local-state design. TODO-628 is closed by that change.
- **AEAD header-protection sample bypass**: `AesHp::apply` zero-pads short samples with `unwrap_or([0u8; 16])`. Tracked in TODO-629.
- **GHASH test override in production**: `src/crypto/gcm.rs` exposes an env-var-activated test override in release builds. Tracked in TODO-630.
- **TLS cover zero keys**: `src/stealth/parts/tls_cover_provider.rs` falls back to all-zero keys on RNG failure. Tracked in TODO-642.
- **Reality session map cleanup**: `src/reality.rs` now sweeps stale sessions on the owner timer as well as on probe traffic, so sustained probes cannot bypass `MAX_SESSIONS` cleanup. Resolved by TODO-570.
- **Probe and escalation history bounds**: `src/stealth/parts/probe_detector.rs` retains only a bounded `VecDeque<Instant>` with limit `max(threshold, 1)` and FIFO eviction inside its 60-second window; `src/stealth/parts/escalation.rs` aggregates epoch-millisecond probe buckets, maintains independent 60-/120-second counters, and enforces a 120,001-bucket hard bound. TODO-644 and TODO-808 are locally remediated; native runtime proof remains environment-specific.
- **SecretString UTF-8 invariant**: TODO-651 now stores UTF-8 secrets in a private `String` owner, removes the unchecked conversion, and adds a checked `SecretBytes -> SecretString` boundary that rejects malformed bytes before ownership transfer. `SecretString` transfers its string buffer to the existing zeroizing `SecretBytes` owner on drop, preserving erasure observation and exact initialized lengths. Focused tests cover valid construction, cloning, owned erasure, checked acceptance, and malformed-byte rejection; the caller audit confirms arbitrary byte secrets remain `SecretBytes`.
- **Privilege drop FFI boundary**: TODO-652 keeps libc status, null-result, and exact returned-pointer identity checks adjacent to `MaybeUninit::assume_init`, retains the lookup buffer until `passwd`/`group` names are copied, and adds deterministic status, `ERANGE`, null, pointer-mismatch, and unknown-account tests. TODO-653 replaces both raw account-name scans with a bounded buffer-range and NUL check before `CStr::from_bytes_with_nul`, covering normal, null, out-of-buffer, and unterminated records. The completed TODO-684 audit additionally found a forgeable public identity boundary, a Windows `CurrentIds` compile failure, incomplete filesystem-ID and partial-transition proof, warning-only process-lock failure, embedded lock-policy divergence, and first-wins TLS identity lifecycle gaps. TODO-849 through TODO-854 own the remaining remediation; native privilege proof remains environment-specific.
- **TUN unsafe read**: `src/interface.rs` now loads the BMI2 IP-header word with `std::ptr::read_unaligned`, and the local test surface adds an intentionally unaligned IPv4 subslice. Linux and macOS `fcntl` setup paths check their return values; TODO-654 owns this alignment proof, while TODO-843 through TODO-848 own the separate BMI2 feature-dispatch and platform-FFI findings from the completed TODO-683 audit.
- **PKI time contract**: TODO-656 closes the ambient PKI clock boundary in `src/pki/mod.rs`. `PkiTime` captures one canonical or injected `SystemTime`, rejects pre-epoch and unrepresentable values through typed `PkiError::ClockError`, and supplies the same checked instant to root, intermediate, and leaf validity, existing-chain validation, and quarantine naming. `checked_validity_window()` rejects overflow and non-positive intervals through `PkiError::InvalidValidity`; focused tests cover injected clock failure, one capture, epoch boundaries, interval ordering, and fixed-time regeneration.
- **Client profile persistence**: TODO-658 keeps `ProfileManager` explicitly standalone because no current `ClientRuntime`, CLI, or desktop/admin caller owns it. New `Profile::from_qkey()` IDs use 128 bits of fallible OS CSPRNG output and 32 lowercase hexadecimal characters; empty/duplicate IDs are rejected at `add()` and `load()`, while non-empty legacy IDs remain unchanged without automatic migration. `save()` serializes bearer-bearing profiles through TODO-662's atomic same-directory temporary publication with creation-time `0600`; TODO-671's permissive-umask mode regression keeps that sensitive-file contract covered.
- **Retry token aggregate-length claim reconciled**: TODO-618 raised `MAX_RETRY_TOKEN_LEN` to 192 and proves the exact 169-byte IPv6/20-byte-CID/64-byte-credential maximum. Current per-field checks reject oversized inputs before allocation and HMAC, so the post-HMAC aggregate check cannot reject an accepted input; TODO-659 is retained as stale audit history, not an open production DoS claim.
- **DNS failure result contract**: `src/dns/mod.rs` and the server TUN intercept preserve genuine upstream responses and synthesize SERVFAIL for upstream, configuration, and parse failures. Resolved by TODO-666; DNS module tests passed 22/22, the complete server test module passed 131/131, and Clippy Matrix run `30811429734` passed all eight feature lanes on revision `5b3b8c2`.
- **DNS TUN intercept admission**: `src/implementations/server/parts/dns_signals.rs` now bounds `spawn_blocking` DNS work with a global semaphore and rate caps, isolates source-IP token buckets, prunes idle buckets, and exports dropped-intercept telemetry. Resolved by TODO-611; admission tests passed 2/2, the metric test passed 1/1, the DNS module passed 22/22, and the complete server module passed 131/131. Clippy Matrix run `30812779253` passed all eight feature lanes on source revision `69e3511`. The optional response cache was evaluated but not added because a TTL-safe cache also needs an explicit transaction-ID and wire-question contract; TODO-669 and TODO-770 retain those boundaries. This admission result does not prove worker completion or shutdown ownership; TODO-650 remains open for the detached `JoinHandle`, panic/cancellation accounting, and late queue-publication boundary.
- **DNS TUN intercept worker ownership (TODO-650)**: `DnsInterceptWorkerOwner` retains every accepted `spawn_blocking` handle, serializes admission close with worker registration, tracks whether each blocking operation started, and gates MASQUE response publication on the same closed state. Standalone drain closes this owner before the live accept boundary closes, housekeeping reaps finished workers, final drain waits up to 500 ms, and stop/fault paths classify remaining queued cancellation or deliberately abandoned started work. Worker terminal response/queue outcomes, panic, queued/started cancellation, join failure, late publication, and shutdown expiry are exported through `quicfuscate_dns_intercept_worker_events_total`; `quicfuscate_dns_intercept_dropped_total` remains admission-only. Lifecycle tests cover a real single-thread blocking-pool queue, completion, panic, cancellation, bounded shutdown, the publication gate, and the standalone drain path. Local server coverage is 458/458; workspace checking and library strict Clippy pass; the full no-fail-fast matrix is library 2,225/2,227 and binary 41/43 due unchanged TODO-807, TODO-768, and TODO-800 baselines. TODO-669, TODO-770, and TODO-699 retain their separate forwarding, wire, and broader engine-runtime boundaries; native Linux/TUN proof and external publication remain unavailable.
- **DNS query wire semantics**: Resolved by TODO-770. The shared parser now enforces the supported query/header/question/name contract, rejects malformed reserved and compression encodings, preserves exact question wire plus raw QTYPE/QCLASS, and the server IPv4/IPv6 UDP/53 boundary enforces exact lengths, fragmentation, and applicable checksums. TODO-721 retains UDP transaction/question matching; native Linux/TUN, Omega, and live publication proof remain separate.
- **DNS client runtime wiring**: `ClientDnsRuntime` now owns localhost UDP/53, pre-pinned RFC 8484 DoH endpoint transport, platform resolver mutation, and restoration in the Engine and standalone TUN client. The Linux E2E harness exercises explicit TUN DNS, OS/application DNS, underlay capture, and restoration. Resolved by TODO-771; native macOS/Windows proof remains environment-specific.
- **Local close error kind**: `Connection::close()` now records structured `LocalApplicationClosed` or `LocalConnectionClosed` state matching the emitted frame, while preserving any earlier local root cause. `ClientConnection::close()` is the explicit application-close API; `close_transport()` covers transport errors and public accessors expose the local/remote split. Resolved by TODO-772.
- **fsutil TOCTOU race**: `src/implementations/server/fsutil.rs` now creates and secures the temporary file before the atomic rename, with post-rename defense-in-depth. Resolved by TODO-591; TODO-667 was a duplicate tracker.
- **MASQUE/DoH ownership**: TODO-597 retired the empty `stealth::MasqueManager`, its false-success send/legacy-varint path, and the unused stealth-local DoH resolver. Core H3/MASQUE now owns the active CONNECT-UDP/capsule carrier, buffers split DATA, rejects malformed or truncated FIN tails before event delivery, and covers all 1/2/4/8-byte varints including 16,384-byte payloads. Retired sources and the obsolete integration test remain recoverable under `archive/`; shared DoH primitives remain in `src/dns/mod.rs`, while `ClientDnsRuntime` owns the active client resolver path. The server's final DNS hop remains plain UDP by design. TODO-771 completed the runtime wiring.

### Resource and Performance Findings

- **Fountain decoder unbounded storage**: `src/fec/fountain_codes.rs` stores unique repair symbols without a cap. Tracked in TODO-634.
- **Adaptive FEC emitted_ids unbounded**: `src/fec/parts/adaptive_controller.rs` emitted ID tracking can grow without a hard cap. Tracked in TODO-635.
- **FEC decoder quadratic peeling**: `src/fec/parts/decoders.rs::try_peel_all` uses O(n^2) Vec remove/insert. Tracked in TODO-636.
- **Wiedemann solver repeated allocations**: column buffers are allocated per solve. Tracked in TODO-637.
- **ConnectionId cloning hot path**: `src/transport/connection/parts/impl_recv.rs` clones CIDs and tokens repeatedly. Tracked in TODO-638.
- **Metrics/optimize allocation hot spots**: metrics export and optimize module allocate per call. Tracked in TODO-587 and TODO-615.
- **DNS forwarding allocation surface**: the A/AAAA/NXDOMAIN response builders remain test-only in the current caller graph. Active forwarding allocations are bounded and measured separately for the DoH request body, streamed DoH response accumulator, UDP receive sentinel, and synthetic SERVFAIL response by `benches/dns_forwarding.rs`; no pooling or reuse change is claimed without a measured benefit. TODO-669 owns the resulting transport contract.

### Production-Readiness Gaps

- **Generic engine configuration reload and propagation**: `QuicFuscateEngine::reload_config_from_file()` now provides a complete parse/validate boundary. Created/stopped engines replace the full configuration; running clients synchronize the canonical Engine config with the `ClientRuntime` next-connection projection, preserve active non-FEC sessions, and reject startup-owned section changes. Running generic servers reject these mutations because the standalone SIGHUP/admin path is a separate, explicitly `NextConnectionOnly` reload with startup-owned fields and a non-transactional transport publication boundary. The standalone path reads `EngineConfig` only and does not rebuild `ServerConfig`, so server GeoIP, DDoS, auth, and blacklist policy remains construction-time state. TODO-645 owns the generic contract; TODO-724 owns standalone transactional publication; TODO-660 owns blacklist worker lifecycle rather than reload.
- **uring_batch admission and executor ownership**: `src/optimize/uring_batch.rs` has no cross-call pending queue. Public sender and worker methods reject batches above 256 packets or 524,288 aggregate payload bytes before owned copies; runtime async paths use one joined `UringBatchWorker` with a bounded queue, controlled deadline, quarantine, and typed no-replay failure. The generic client outbound path checks the trait-level `TunDevice::read_contract()` before direct reads; native backends declare nonblocking and custom backends default to an owned blocking-reader boundary. TODO-687 closed the unsafe/lifetime boundary, TODO-798 owns unordered partial-send disposition, and TODO-646 retains the blocked Linux compile/live-proof gate.
- **Admin HTTP admission and operation ownership**: `AdminHttpServer` owns a validated CLI-only connection capacity with default `16` and maximum `1024`, acquires admission immediately after `accept()` and before `tokio::spawn`, and drops excess sockets without a user-space pending connection queue. Each accepted request receives one bounded operation deadline configured by `--admin-web-operation-timeout-ms` (default `30000`, allowed range `50..=120000` ms). Body collection stays on the async path under `timeout_at`; synchronous authentication, registry, filesystem, logging, config, and handler work is transferred through a bounded command/result channel to an owned `spawn_blocking` `JoinSet`. A timed-out request receives HTTP `504` and closes its connection while a started blocking worker remains owned and reports completion after the deadline; worker panics become HTTP `500`, queue/receiver abandonment reports cancellation, and the server performs a bounded one-second worker drain on shutdown with `shutdown_expired` telemetry when Tokio cannot abort a started blocking task. `AdminHttpOperationSnapshot` is exposed under `admin_http` in runtime status and health. TODO-700 still owns the outer standalone service-task handle, TODO-712 request-body memory admission, TODO-699 the engine-thread lifetime, and TODO-787 credential durability.
- **Config write not validated**: `src/implementations/server/parts/config.rs` does not parse the temp config before atomic rename. Tracked in TODO-648.
- **Linux DNS resolver path and symlink ownership**: `LinuxResolverPaths` is the single owner of the legacy resolver path contract. `LinuxResolverPaths::standard()` retains `/etc/resolv.conf` with backup `/etc/resolv.conf.quicfuscate.bak` and derives the `.state` and `.lock` paths from that backup; `LinuxPlatform::new_with_resolver_paths()` provides the validated absolute, distinct path contract for alternate Linux construction and tests. Resolver state schema 3 records absent, regular-file, and valid-symlink source identity, raw and canonical symlink targets, target object identity, backup object identity/content digest, and the managed post-write identity. Create-only state/backup publication, atomic state replacement, broken-link rejection, target replacement detection, foreign backup/state refusal, and read-only-parent failure all fail closed without overwriting or removing unowned objects. Valid symlinks remain symlinks through restore, and backup deletion follows verified copy/read-back. TODO-623 retains absent-original and crash ownership; native Linux proof remains environment-specific.
- **DNS intercept worker lifecycle**: `spawn_dns_intercept()` receives a bounded admission permit but discards the `spawn_blocking` `JoinHandle`. There is no owner for accepted workers, no observation of panic or queued cancellation, no DNS-specific worker outcome metric, and no drain barrier before `finish_drain()` discards connection queues and `ServerRuntime::stop()` tears down resources. Tokio cannot abort a started blocking task, so TODO-650 must define a cooperative or bounded shutdown contract. The stale immediate pool-capacity-error claim is closed; TODO-611 owns admission, TODO-669 owns forwarding timeout/allocation, TODO-770 owns wire semantics, and TODO-699 owns the broader engine thread timeout boundary.
- **CLI probe parse contract**: `qf-e2e-client` and `qf-e2e-desktop` now return explicit errors for malformed or missing `--timeout-ms` and `--hold-ms` values. Omitted flags retain defaults, `0` remains valid, and duplicate flags preserve last-value-wins behavior. Bin unit tests and direct binary smokes cover both probes; the privilege probe and other E2E numeric flags already fail closed. TODO-657 records the completed local remediation.
- **qftls preloaded-key ownership**: `src/qftls.rs` now stores the key bytes in a zeroizing exact-range guard. The accepted identity remains process-lifetime-owned by `OnceLock`; rejected same-identity values are idempotent and conflicting identities fail closed, while any individually locked rejected value zeroizes before `munlock`. `lock_memory` is propagated from standalone and embedded server construction, and successful `mlockall(MCL_FUTURE)` ownership prevents redundant per-key unlocks. Lock failure remains best-effort but is returned as `TlsKeyLockStatus` and logged at startup. TODO-853 retains certificate/key correspondence and broader identity-output proof.
- **MemoryPool mlock without release**: `src/optimize/parts/memory_pool.rs` calls `mlock` on enabled allocations but has no matching `munlock` release path. Tracked in TODO-516 and the broader unsafe audit TODO-678.
- **Blacklist sync lifecycle**: `LiveServerState::maybe_sync_blacklist()` is the sole current production dispatch from the server housekeeping loop. `BlacklistSyncOwner` atomically claims due work under one mutex, retains the `JoinHandle` and cancellation flag, rejects concurrent claims, and owns completion observation. Successful publication schedules the configured interval; failures and cancellation schedule bounded exponential retry delays of `5`, `10`, `20`, `40`, `80`, `160`, then `300` seconds. HTTPS fetch and bounded body collection remain async; feed parsing, atomic last-known-good cache publication, and active-list replacement run in `spawn_blocking` after a pre-publication cancellation check. Drain closes the owner and awaits up to `500` ms; direct stop/drop aborts the owned task, and an expired drain join records `shutdown_expired`. Absolute caps are `300` seconds request timeout, `16777216` bytes body/cache, `250000` entries, and `604800` seconds for TTL/interval. Typed lifecycle counters, active-entry/in-flight gauges, freshness ages, stale state, Prometheus export, and admin health/status exposure are implemented. TODO-660 retains external controlled-feed, native Linux, full-matrix, and publication gates; broader DNS worker and engine-thread shutdown boundaries remain TODO-650 and TODO-699.
- **Admin HTTP operation deadline and cancellation**: The per-request deadline is configured by `--admin-web-operation-timeout-ms` and validated to `50..=120000` ms. `AdminHttpServer` starts one owned operation state at request entry, bounds body collection with `timeout_at`, sends synchronous authentication, registry, filesystem, logging, config, static-file, and handler work through a bounded command/result channel to an owned blocking `JoinSet`, and returns HTTP `504` on deadline expiry without pretending that Tokio can kill a started blocking closure. Body admission has a distinct `408` response; the operation deadline governs the handler result and the connection has a one-second response-publication grace period. The worker state remains owned after a client timeout, records late completion and panic/cancellation outcomes, and applies a one-second shutdown drain; an expired drain is observable in `shutdown_expired_total`. Effective timeout and lifecycle counters are present in `admin_http` status/health diagnostics. The direct test helper remains synchronous only to preserve unit coverage; production `AdminHttpServer::run()` uses the worker protocol. TODO-647 owns admission placement/capacity, TODO-700 direct runtime service-task shutdown, TODO-699 engine-thread lifetime, TODO-712 body memory, and TODO-787 credential durability.
- **DNS admission ownership**: TODO-668 closes the caller/admission contract at both retained production boundaries. `DnsAdmission` owns global PPS, per-identity PPS, in-flight permits, idle pruning, and a hard identity-state cap. The client listener uses localhost source-IP identity and the public `process_dns_query_with_admission()` wrapper makes identity explicit; the low-level `process_dns_query()` helper remains admission-free only for callers that already own admission. The live server callback propagates authenticated `SessionId`, removes session/source state on lifecycle transitions, shares one aggregate budget across sequential upstream fallback, and exports accepted/rejected outcomes by reason. TODO-650 owns accepted server worker lifecycle, TODO-669 owns forwarding bounds, TODO-721 owns UDP transaction matching, TODO-770 closes the shared query wire admission contract, and TODO-810 closes DoH semantic response validation.
- **DoH DNS response semantics**: TODO-810 closes the active DoH response boundary. After the shared 4,096-byte body cap, `resolve_via_doh_with_client()` requires QR, standard opcode, exactly one bounded question, and a canonical case-insensitive QNAME plus exact raw QTYPE/QCLASS and transaction-ID match. Question compression pointers are bounded and reject forward/reserved/looping references; answer, authority, and EDNS sections remain opaque. Deterministic local HTTP coverage exercises valid compressed-answer/EDNS responses, wrong question fields, QR/opcode/count/name failures, status/content-type failures, and oversized bodies. TODO-770 closes the shared query admission and synthetic-question wire contract; UDP response matching remains TODO-721.
- **Environment helper contract**: TODO-670 and TODO-811 now provide one immutable snapshot contract for shared runtime configuration. Invalid numerics and booleans warn and retain safe defaults; ordered aliases trim and skip invalid values; direct parser exceptions are typed startup boundaries or non-product test/OS variables. The external-process torn-read claim remains unproven.
- **Direct environment parser authorities**: TODO-811 is complete. Compression, memory-pool, optional zstd, Reality target, trusted-proxy, CLI socket, metrics, NUMA, SIMD, and io_uring paths use snapshot-backed typed policies. Dedicated server policy and QKey secret loaders remain documented validated exceptions with startup-time errors/warnings.
- **File permission umask reliance**: Resolved by TODO-671. Linux resolver targets use explicit `0o644`, resolver locks and backups use `0o600`, rotating operational logs use explicit `0o640` on create/reopen/truncate/rotation, and standalone bearer-bearing profile temporaries use `0o600` under TODO-662's atomic publication. Audit active files reassert `0o600` on direct reopen before append. Audit, registry, resolver-state, routing-state, and PKI private-key writers retain their restrictive contracts; public certificates and generated systemd units remain non-secret outputs.
- **Audit log blocking flush**: `src/audit/mod.rs` flushes synchronously with no timeout. Tracked in TODO-675.
- **AMX capability contract**: TODO-816 removed the former `static mut` tile config and unverified raw kernels from the active source. The production FEC path reports only scalar Wiedemann operations until TODO-818 proves a real AMX arithmetic backend; compiled/runtime eligibility, detector process bounds, and profile/documentation mapping remain tracked by TODO-676, TODO-817, and TODO-819.
- **Time-source and clock-domain contract**: the exhaustive inventory covers direct Rust monotonic/wall-clock producers, Tokio clocks, browser `Date.now()`/`performance.now()`, event-loop timers, implicit `.elapsed()`/`duration_since()` paths, and timestamp boundaries across transport, H3, core, engine, stealth, qftls, server, client, runtime, telemetry, audit, PKI, Tauri, Svelte, tests, probes, and scripts. TODO-677 is the umbrella audit; TODO-656 closes the PKI validity-time boundary; TODO-820 owns transport/stealth/core, TODO-821 owns server/client state, TODO-822 owns Tokio/OS/runtime clock boundaries, TODO-823 owns wall-clock provenance, TODO-824 owns Rust injection/test isolation, and TODO-825 owns frontend/browser clocks. Existing TODO-640, TODO-658, TODO-662, TODO-671, TODO-675, TODO-768, TODO-584, and TODO-588 remain narrower owners.
- **Memory and pooled-buffer ownership**: `src/optimize/unsafe.rs` has a non-TLS `UnsafeCell` cache behind manual `Send`/`Sync`, raw-pointer admission without runtime origin proof, mixed fallback ownership, and fixed-span prefetch arithmetic. The active safe `MemoryPool` can accept same-sized foreign blocks, mishandle ephemeral returns, and fail to make TLS-aware shrink progress. Plain `AlignedBox` drops on compression, TUN, transport-frame, and FEC error paths bypass pool accounting, and feature-gated `DatagramBuffer` has no pool-return Drop path. TODO-678 is the umbrella index; TODO-826 through TODO-833 own the split remediation boundaries, while TODO-516, TODO-646, TODO-682, TODO-683, TODO-687, TODO-689, TODO-730, TODO-734, and TODO-767 retain adjacent contracts.
- **SIMD unsafe surface**: TODO-679 completed the read-only audit of all 31 files in `src/simd/*` and `src/optimize/simd/*`, including 138 unsafe function declarations, 102 actual target-feature attributes, direct callers, tests, audit scripts, and history. TODO-834 completed the exact dispatch-owner audit and confirmed SVE2 decode, ACK AVX512VL, SHA-VNNI, AES/VAES, GF16, AVX-512 compression/pattern/histogram, neural FMA, optimization string, stale BMI2 profile, and scalar-claim boundaries. TODO-835 completed the release-boundary audit and confirmed the short-needle load, debug-only matrix/BMI2 checks, unchecked Berlekamp-Massey length, and caller-only private helper proofs; remaining vector tails were cross-checked. TODO-836 completed the proof-owner audit and confirmed the blanket safety-doc suppression, only four function-level `# Safety` sections, silent ISA-test returns, stale unsafe-surface matching, and missing native-ISA proof lane. Open remediation remains split into release-safe slice/dimension/short-load boundaries (TODO-835), safety documentation/proof guardrails (TODO-836), and the dispatch implementation gates retained by TODO-834.
- **Optimize brain/transport/stealth unsafe**: TODO-680's read-only audit covered all ten current Optimize source boundaries, CPU profile mapping, direct callers, vector tails, malformed-input fixtures, Linux/macOS UDP FFI, guardrail scripts, documentation claims, and relevant history. Open findings include P1f reductions dispatching AVX-only CPUs to AVX2, P4a moving-average dispatch without an AVX512F proof, test-only BMI2 bitmap selection/range arithmetic, SSE2 short-pattern overwrite, overflow-prone pattern positions, SVE2 base64 output coverage, unchecked packet-number lengths, VNNI truncation, Linux batch receive-length/sockaddr/count contracts, and percentile/profile proof gaps. Remediation remains open; no production implementation was made in the audit phase. Tracked in TODO-680, with completed transport audit evidence in TODO-682 and open transport remediation in TODO-837-TODO-842, plus adjacent dispatch and safety-proof ownership in TODO-834, TODO-689, and TODO-836.
- **Crypto unsafe primitives**: AES, AEGIS, MORUS, GCM, Poly1305, ChaCha lack safety docs and bounds. Tracked in TODO-681.
- **Transport unsafe**: TODO-682 completed the read-only pass over transport batching, shared UDP FFI, internal AF_XDP, frame/packet SIMD, public packet lengths, PMTU/prefetch, direct callers, tests, suites, guardrails, documentation, and history. Open remediation covers UDP result and fd ownership (TODO-837), AF_XDP UMEM/ring ownership (TODO-838), packet-number and public length contracts (TODO-839), frame malformed-input and batch cleanup (TODO-840), PMTU/prefetch (TODO-841), and malformed/native proof coverage (TODO-842). No production implementation or verification command was performed in the audit phase.
- **Interface/platform unsafe**: TODO-683 completed the read-only audit of
  `interface.rs`, Wintun, Linux/macOS/Windows platform backends, Windows WFP,
  every direct client/server TUN caller, platform gate, cleanup owner, test,
  CI/audit script, documentation claim, and relevant history. The initial
  blanket Linux/macOS syscall finding is stale. Open remediation covers CPU
  profile/BMI2 dispatch (TODO-843, with the unaligned load in TODO-654), the
  generic TUN read/write result contract (TODO-844), Unix syscall progress,
  lengths, kernel-name rollback, and close ownership (TODO-845), Wintun
  lifecycle and concurrency proof (TODO-846), WFP engine/transaction
  ownership (TODO-847), and negative proof/guardrails (TODO-848). No product
  implementation or verification command was performed for TODO-683.
- **Privilege/mlock/secret unsafe**: `privilege/drop.rs`, mlock, `qftls.rs`, `secret.rs` handle credentials unsafely. Tracked in TODO-684.
- **QKey/admin unsafe**: QKey registry and admin session blocks lack safety docs. Tracked in TODO-685.
- **FEC unsafe and boundary audit**: TODO-686 is complete as a read-only audit across FEC unsafe SIMD/AMX sites, direct core/runtime callers, decoder/matrix/wire/Fountain public inputs, feature gates, malformed tests, fuzz and shell/benchmark/netns proof, documentation, and history. Open remediation is split across TODO-634, TODO-636, TODO-637, TODO-690, TODO-715, TODO-832, and TODO-855 through TODO-860; no implementation or runtime closure is claimed.
- **io_uring/io_driver unsafe**: TODO-687 closed the SQE/CQE lifetime, raw socket buffer, receive-slot ownership, and eventfd ABI audit boundary. TODO-801 also closed the additional Linux zero-length-rearm and opt-in SendMsgZc evidence. TODO-646 now implements runtime executor ownership and bounded admission; its local Linux compile/live-proof gate remains blocked. TODO-798 owns unordered partial-send disposition.
- **Audit/limits unsafe**: TODO-688 completed the read-only audit of the complete audit implementation and tests, direct startup/runtime callers, audit probe, limits false positive, suites, guardrails, documentation, related owners, and history. The current inventory is three production FFI sites plus one Unix-only test guard. TODO-861 owns Windows interior-NUL rejection, local FFI safety contracts, security-hardening failure propagation, and platform-negative proof; TODO-671, TODO-675, TODO-726, TODO-728, TODO-813, and TODO-814 retain their separate mode, lifecycle, path-binding, and bound owners. TODO-815 now closes the shutdown admission-order owner. No production implementation or runtime verification was performed for TODO-688.
- **Remaining auxiliary unsafe audit**: TODO-689 completed the read-only audit of `cpu_dispatch`, the shared prefetch facade and direct callers, Windows NUMA FFI, global-pool/auto-tuner initialization, test-environment mutation, the test-only constant-buffer helper, telemetry, `lib.rs`, and the transport/config false-positive matches. Remediation is TODO-862 through TODO-865, with TODO-670/TODO-811, TODO-826/TODO-827, TODO-834/TODO-835/TODO-836, TODO-841, TODO-843, and TODO-752 retaining adjacent ownership.

### Follow-up Audit Findings (2026-08-02)

- **Server fan-out and MTU:** The shared broadcast/multicast queue finding is resolved by TODO-612; its bounded admission, drop telemetry, and housekeeping work budget are reconciled below. TODO-613 is closed: the selected contract returns IPv4 Fragmentation Needed for both DF states before either server TUN write and intentionally does not perform userspace fragmentation. The later native IPv4 TTL-expiry failure is closed by TODO-806; the independent backpressure-quiescence finding remains separate.
- **Rate and session contracts:** `src/implementations/server/limits.rs` now defines the byte burst as `ceil(max_bps * effective_burst / max_pps)`, preserving the packet-token burst duration while keeping `refill_interval` as refill cadence. TODO-614 retains the focused implementation and runtime-admission verification boundary. `src/implementations/server/session.rs` validates duplicate session IDs and IPv4/IPv6/remote lookup keys before mutation, and remote-address rebinding rejects a foreign owner without removing the old index. TODO-616 is closed with focused SessionManager and migration coverage plus full server/library and all-feature Clippy gates.
- **HTTP control surfaces:** TODO-615 closes the HealthServer, active MetricsServer, and retained test-only GlobalMetricsServer sequential-read gap with bounded incremental request framing, a five-second per-read deadline, an 8 KiB header cap, and a 32-worker connection limit. The separate telemetry server remains an independent active surface with its existing five-second read timeout, 32-connection semaphore, and `QUICFUSCATE_METRICS_ADDR` bind.
- **Unix admin socket:** TODO-617 is closed. `AdminServer` enforces mode `0600`, bounds command framing to 8 KiB with one five-second absolute read deadline, and accepts/removes only owner-matching socket identities after bounded liveness checks. Unsafe path types, owner mismatches, live sockets, ambiguous probes, and identity changes fail closed. Focused admin tests pass 13/13; the server module passes 135/135; the full library passes 2,176/2,176; all-target checking and strict all-feature Clippy pass.

### Build Verification

- `cargo check --all-targets --all-features` completed successfully.
- `cargo clippy --all-targets --all-features -- -D warnings` completed successfully.
- `cargo test --all-features` failed initially due to a corrupted `target/` cache (missing object files), recovered with `cargo clean` and rerun of `cargo check`/`cargo clippy`. No code-level build errors were produced.

## Deep Audit Reconciliation (2026-08-02, client and platform surfaces)

- **Retry admission:** TODO-618 is closed. `src/implementations/server/ddos.rs` sets `MAX_RETRY_TOKEN_LEN` to 192, and the real `issue_for_initial` plus `validate` path accepts the exact 169-byte bounded maximum for IPv6, 20-byte original and retry CIDs, and a 64-byte credential. The DDOS policy probe has no duplicate length constant. TODO-659 was fully reconciled and is stale under these active bounds: oversized fields already fail before allocation/HMAC, while every accepted combination fits.
- **Client runtime lifecycle:** TODO-619 is closed. `ClientRuntime::connect()` routes every failure after connection assignment, including missing runtime, UDP/socket, TUN, driver, and task-setup failures, through explicit transport rollback. The rollback shuts down and joins owned I/O tasks, closes and removes the QUIC connection, clears socket and driver state, and returns to `Running`. Focused client tests pass 5/5, the full library passes 2,179/2,179, and locked all-target checking, strict all-feature Clippy, format, and diff checks pass.
- **Client backend configuration:** TODO-620 is closed. `src/implementations/client/backend.rs::connect_inner()` resolves `tun_ip`, `tun_netmask`/`tun_subnet_prefix`, and `tun_gateway` through one effective-network path, validates family and contiguous-mask contracts, and installs family-matched split default routes. The legacy IPv4 `10.8.0.2/24` default remains unchanged. Focused backend tests pass 11/11, the full library passes 2,183/2,183, and locked all-target checking, strict all-feature Clippy, format, and diff checks pass. TODO-604 is closed as its duplicate.
- **Client TUN dual-stack projection:** TODO-663 closes the static generic-client boundary. `InterfaceConfig` now exposes canonical `tun_ip6`/`tun_prefix6` fields and resolves legacy IPv4/IPv6 pairs plus canonical IPv6 into `ClientTunnelAddresses`, which `ClientRuntime` projects into the native typed `TunConfig`. Config projection tests pass 3/3, generic client projection tests pass 5/5, and compatibility backend tests pass 6/6, covering IPv4-only, IPv6-only, dual-stack, round-trip, malformed, MTU, non-contiguous-mask, duplicate-source, and compatibility rejection cases. Format, library check, strict library Clippy, all-target checking, and the complete library test pass 2,295/2,295. The all-target test matrix passes 2,295/2,295 library tests and 41/43 binary tests; the two failures are the known runtime-reload assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`. All-target strict Clippy retains eight pre-existing diagnostics. The public compatibility `ClientBackend` remains explicitly single-family and rejects canonical IPv6 fields. No server-assigned IPv6 control-plane message exists in the generic client path; TODO-866 owns that separate authenticated assignment contract. The standalone CLI's parse-failure boundary remains TODO-731.
- **Linux resolver restoration:** TODO-623 remains the owner of absent-original, stale-ownership, and crash recovery semantics. TODO-649 now supplies the typed `LinuxResolverPaths` contract, schema-3 resolver/source/target/backup identities, create-only and atomic state publication, and fail-closed rollback for broken or replaced symlinks and foreign backup/state objects. The focused resolver suite passes 14/14; host workspace checking and library strict Clippy pass. The full local matrix reaches 2,259/2,261 library tests and 41/43 binary tests, with unchanged external-DNS/qftls and runtime-reload/PMTU baselines. The Linux target gate remains unavailable because this macOS host lacks the required Linux C compiler/sysroot (`x86_64-linux-gnu-gcc`, then `assert.h` under Clang); the configured Omega SSH path is also unavailable.
- **macOS pf activation:** TODO-624 closes the client activation rollback gap. `MacOSKillSwitch::ensure_pf_enabled()` now requires a successful `pfctl -sr` query with an exact QuicFuscate `anchor` statement or the approved wildcard, emits an actionable diagnostic when absent, and flushes/removes a just-loaded anchor when the later activation check fails. `KillSwitch::enable()` rolls back failed backend activation and exposes a fail-closed retained state only when rollback cannot be proven. The server routing manager rejects macOS before host mutation and retains only pure pf rule generation. Focused client tests pass 74/74 and routing tests pass 20/20; locked all-target checking and strict all-feature Clippy pass. The full local library covered 2,195 tests but remains red on the external-DNS DoH cache test and one intermittent Stealth Cover freshness assertion, which passed in isolation. The privileged live PF proof is exposed by `scripts/tests/macos-pf-anchor-proof.sh` but was not run because this session is UID 501 and must not mutate shared PF state. TODO-548 remains the owner of managed anchor installation and full privileged lifecycle proof.
- **Client FEC surface:** TODO-625 removes the uncompiled `src/implementations/client/pipeline.rs` adapter, its packet-id-zero `FecCodec` wrapper, and the unused `ClientSubsystems.fec` construction. Client tests pass 74/74; locked all-target checking, strict all-feature Clippy, format, diff, and source-reference gates pass. The full local library reached 2,193/2,195; TODO-768 and TODO-807 own the two unrelated failures. The active FEC wire/framing owner remains `QuicFuscateConnection`/`src/core.rs`; TODO-602 is closed as its duplicate.
- **Duplicate tracker closure:** TODO-621 was true-renamed to `docs/todo/done/` as an exact duplicate of TODO-662, and TODO-622 was true-renamed to `docs/todo/done/` as an exact duplicate of TODO-658. No product implementation changed.

## Deep Audit Reconciliation (2026-08-02, runtime and control surfaces)

- **Engine reload:** The generic `QuicFuscateEngine` now exposes validated `reload_config_from_file` and routes it through the same candidate publication boundary as `update_config`. Created/stopped engines replace the full config; running clients update the next-connection projection and keep active non-FEC sessions immutable, while startup-owned engine/interface/telemetry/logging/audit/crypto/optimization/security sections are rejected. Running generic servers reject these mutations. The standalone server has a separate validated file reload path with explicit `NextConnectionOnly` scope, startup-owned fields, and shared-policy publication before best-effort transport mutation. That path reads `EngineConfig` only and leaves construction-time `ServerConfig`, including blacklist/GeoIP/DDoS/auth policy, unchanged. TODO-645 owns the generic contract; TODO-660 owns blacklist worker lifecycle; TODO-724 owns standalone transactional publication.
- **io_uring:** `UringBatchSender` has no cross-call pending queue: scratch vectors are preallocated and submissions are chunked to SQ capacity. Every public sender call now rejects batches above 256 packets or 524,288 aggregate payload bytes before sender-owned copies. Payloads are staged in sender-owned slots; failed submissions quarantine the sender; SendMsgZc waits for every primary and every `CQE_F_MORE` notification; receive indices are checked and zero-length slots are re-armed. Client and standalone server runtime paths use one bounded `UringBatchWorker` per runtime, with one joined blocking thread, one queued request, a controlled 250 ms completion deadline, and typed failure without ambiguous replay. TODO-798 owns unordered partial-send disposition; Linux-target compilation and live io_uring proof remain environment gates for TODO-646.
- **Config writes:** The active `write_runtime_config` handler parses `AppConfig`, validates it, validates transport overrides, and only then calls `atomic_write_file`. TODO-648 is closed as stale; the earlier `config.rs` location was not the TOML write path.
- **Linux DNS backup:** Restore copies the backup before removing it, verifies source/target identity and restored bytes, and removes the backup only after successful read-back. TODO-649 now owns the typed standard/alternate source and backup contract, derives state/lock paths from the backup, records regular-file and symlink target identity, rejects broken or replaced links, and refuses foreign or pre-existing backup/state objects without clobbering them. TODO-623 owns absent-original and crash ownership; native Linux verification remains blocked by the local macOS cross-toolchain boundary.
- **DNS intercept worker shutdown:** The full caller and runtime audit confirms that `DnsInterceptAdmission` is local to one standalone server loop, while each accepted worker retains its queue and metrics `Arc`s after the caller returns. Existing parser, admission, metric, and admin-shutdown tests do not exercise a real worker, blocking-pool queue, panic, queued cancellation, or post-teardown queue publication. Tokio's local contract says `spawn_blocking` queues beyond its thread limit, returns a `JoinHandle`, cannot abort a started task, and makes ordinary runtime drop wait for started blocking tasks. TODO-650 owns the missing worker owner, outcome telemetry, bounded drain, and lifecycle tests; no production implementation was made in the audit phase.
- **TUN fcntl:** Linux and macOS check `F_GETFL` and `F_SETFL`, close only on the error path, and return before device publication. TODO-655 is closed as stale. TODO-654 now owns the alignment-safe BMI2 load and unaligned-subslice regression proof; the broader interface/platform remediation is TODO-843 through TODO-848.
- **Probe parsing:** `qf-privilege-probe`, `--initial-count`, and `--initial-interval-us` already return parse errors. TODO-657 now makes `--timeout-ms` and `--hold-ms` in `qf-e2e-client` and `qf-e2e-desktop` explicit and testable: malformed or missing values fail, omitted values retain defaults, zero is valid, and duplicates remain last-value-wins.
- **Retry token:** Per-field bounds already exist. TODO-618 owns the corrected 192-byte aggregate capacity and 169-byte worst-case round-trip. TODO-659 was reconciled as stale because accepted inputs cannot exceed the active aggregate limit and oversized fields fail before body allocation and HMAC.
- **Blacklist sync:** TODO-660 now owns one `BlacklistSyncOwner` per live server. The housekeeping path performs an atomic due/in-flight claim, stores the task and cancellation flag, observes completion, preserves last-known-good state on failure, and schedules bounded retry delays. Parsing, atomic cache publication, and active-list replacement run in `spawn_blocking` after a pre-publication cancellation check. Drain closes the owner and awaits up to `500` ms, while direct stop/drop abort the task and record cancellation; an expired join records `shutdown_expired`. Absolute caps are `300` seconds request timeout, `16777216` bytes body/cache, `250000` entries, and `604800` seconds for TTL/interval. Prometheus, health, and admin status expose lifecycle events, active entries, in-flight state, last-success/last-failure ages, and stale state. Local focused and server test gates pass; external controlled HTTPS-feed, native Linux, full-matrix, and publication proof remain separate gates. TODO-650 and TODO-699 retain the adjacent DNS worker and engine-thread shutdown boundaries.
- **Replay and session protection:** The admin session store uses a timestamped bounded `VecDeque` plus `HashSet`: fingerprints are rejected for five minutes, expired entries are pruned from the front, and one oldest entry is evicted per insertion beyond 4,096. The outer store admits at most 256 live sessions, rejects capacity-exceeding logins without evicting active sessions, exposes active/created/rejected/expired counters, and clears sessions after the admin server shutdown drain.
- **Environment parsing:** No supported external-process or safe concurrent mutation path establishes a torn-read defect. TODO-670 closes the shared helper's invalid/default/alias/whitespace contract, its active runtime snapshot wiring, and library test mutation coordination. TODO-811 closes the remaining direct parser authorities, records the validated server/QKey exceptions, and defines first-use versus construction-time snapshot timing.
- **File modes:** TODO-671 closes the remaining umask-dependent writers: Linux resolver targets are explicit `0o644`, resolver locks and backups are `0o600`, rotating operational logs are `0o640`, profile temporaries are `0o600`, and direct audit reopens reassert active-file mode `0o600` through the opened handle. `fsutil`, QKey registry, resolver ownership state, routing ownership state, and PKI private-key writers retain their restrictive creation modes; TODO-662 remains the profile atomic publication owner.
- **Log rotation:** TODO-672 is complete. `src/logging.rs` owns FIFO `Rotate` and `Reopen` commands with bounded acknowledgements. Authenticated `POST /api/logs/rotate` force-rotates through the writer owner and emits a typed admin audit event. Unix SIGHUP preserves the validated next-connection-only config reload, then independently reopens the file sink and audits/logs the result. External rename and copytruncate are supported by sending SIGHUP after the pathname operation; reopen refreshes tracked size from the current pathname. Failed logger-installation worker cleanup remains TODO-812.
- **CLI control protocol:** TODO-673 closes the request boundary. The registered Unix-only `quicfuscate-ctl` target builds typed commands, enforces exact arity before socket I/O, rejects empty/control-character/oversized values, canonicalizes IP and client identities through shared helpers, and serializes with `serde_json`. A custom `AdminCommand` deserializer rejects unknown fields and command names. The complete newline-terminated request frame is capped at 8 KiB, and the Unix server revalidates it before dispatch. TODO-617 retains socket identity and framing ownership; TODO-795 retains the bounded typed response contract.
- **Audit persistence:** `AuditLog::flush` bounds the producer acknowledgement wait, but the writer's `flush` and `sync_data` remain synchronous and uninterruptible. Flush/checkpoint failure classification, sticky shutdown errors, terminal admission after a writer error, and configuration maxima remain TODO-675, TODO-726, and TODO-813 respectively; TODO-814 closes producer-side payload bounds, and TODO-815 closes shutdown admission ordering.

## Deep Audit Reconciliation (2026-08-02, unsafe and protocol lifecycle)

This pass reconciled the remaining unsafe inventory and the next transport/FEC lifecycle surfaces against the current source. No product implementation was changed.

- **Crypto corrections:** TODO-631's blanket round-key zeroization claim is stale because the AES-NI schedule exists only on x86_64 and is zeroized in its target-specific `Drop`; key and IV zeroization remains cross-target. TODO-642's zero-key fallback claim is stale because TLS cover entropy failure returns a typed crypto error before derivation. TODO-627 closes the constructor key/IV boundary; TODO-629 and TODO-632 retain the independent header-protection and nonce-lifecycle contracts, while TODO-633 now owns the local exact 32-byte KDF boundary and its remaining full-matrix/native proof.
- **AMX:** TODO-816 removes the compile-time-absent production AMX branch from `src/fec/parts/decoders.rs`, restores scalar SpMV on every x86 build, and removes the uncalled raw kernels from `src/simd/amx.rs`. The current production path no longer claims AMX operations or allocates AMX scratch. TODO-676 retains the broader planner/runtime and concurrent ownership audit; TODO-817 owns detector execution, TODO-818 owns a future AMX proof lane, and TODO-819 owns profile/documentation truth.
- **Unsafe memory and pooled-buffer boundaries:** `src/optimize/unsafe.rs` calls a field named `tls_cache` through shared `UnsafeCell` state without actual thread-local storage, permits fallback allocations to desynchronize capacity/available counters, and performs block-size-independent prefetch pointer arithmetic. `UnsafeCompressor` exposes a shared mutable zstd context through `Sync`. The active safe `MemoryPool` can accept same-sized foreign blocks, mishandle ephemeral returns, and fail to make TLS-aware shrink progress. Plain `AlignedBox` drops on compression, TUN, transport-frame, and FEC error paths bypass pool accounting, and feature-gated `DatagramBuffer` has no pool-return Drop path. The historical `copy_to_block` inventory is absent from the current source. TODO-678 is the umbrella index; TODO-826 through TODO-833 own the split remediation boundaries, with TODO-516, TODO-646, TODO-682, TODO-683, TODO-687, TODO-689, TODO-730, TODO-734, and TODO-767 retaining their adjacent contracts.
- **SIMD:** The old AVX-512/GFNI Reed-Solomon delegation claim is stale for the active decoder. TODO-834's dispatch pass confirmed open SVE2 decode, ACK AVX512VL, SHA-VNNI, AES/VAES, GF16, AVX-512 compression/pattern/histogram, neural FMA, optimization string, stale BMI2 profile, and scalar-claim boundaries. TODO-835's completed boundary pass confirmed the critical `find_pattern_sse42_short` short-needle load, debug-only matrix and BMI2 output checks, unchecked Berlekamp-Massey length, and caller-only proofs for private key/XOR helpers; remaining vector tails were cross-checked. TODO-836's completed proof pass confirmed the blanket safety-doc suppression, only four function-level `# Safety` sections, silent ISA-test returns, stale unsafe-surface matching, and missing native-ISA proof lane. TODO-835 and TODO-836 retain their respective release-safe and proof remediations.
- **Optimize and UDP:** TODO-680's completed Optimize audit confirmed the P1f-to-AVX2 reduction route, P4a-to-AVX512 moving-average route, test-only BMI2 bitmap dispatch/range contract, SSE2 short-pattern overwrite, overflow-prone pattern position arithmetic, SVE2 base64 output-lane undercoverage, unchecked QUIC packet-number lengths, VNNI truncation beyond 64 samples, percentile input gaps, and Linux batch receive-length, sockaddr initialization, and syscall-count proof gaps. TODO-682 completed the direct transport owner pass and split its open remediation into TODO-837-TODO-842. Valid vector tails and the bounded active connection caller were cross-checked; remediation remains open under TODO-680, TODO-837-TODO-842, TODO-834, TODO-689, and TODO-836.
- **Interface and platform:** TODO-683 completed the full read-only source,
  caller, platform-gate, cleanup, test, script, documentation, and history
  pass. The current findings are broader than the initial P4-only note:
  P3a-P3e and P4a/P4b can reach the BMI2 parser without a matching BMI2
  predicate; the generic TUN trait does not bound read counts or require full
  writes; Linux/macOS retain zero-progress, vectored-result, kernel-name, and
  Drop-close gaps; Wintun can lose ownership after event/library or early Drop
  failure; and WFP engine/transaction failures are not retryable. TODO-654
  replaces the unaligned load with `read_unaligned` and owns its regression
  proof; TODO-843 through TODO-848 own the remaining remediation and proof
  boundaries. No implementation or verification command was performed for
  TODO-683.
- **Privilege and FFI:** TODO-684 completed the full privilege, memory-lock, qftls, secret, caller, platform, cleanup, test, script, documentation, related-TODO, and history pass. TODO-652 closes the returned-pointer identity boundary and TODO-653 closes the bounded account-name conversion boundary in `src/privilege/drop.rs`, both with local deterministic tests. Final-boundary identity validation, complete filesystem-ID verification, and a portable `CurrentIds` type remain open under TODO-849-TODO-850. Process-lock failure remains warning-only, the embedded engine does not propagate the CLI lock settings, and pool/key unlock ownership remains TODO-516/TODO-643; TODO-851-TODO-853 own the distinct policy and identity gaps. TODO-854 owns the missing negative proof and guardrails. Windows audit-file path FFI, local safety comments, and security-hardening failure semantics are TODO-861; Unix audit pathname TOCTOU remains TODO-728. Native privilege proof remains environment-specific.
- **FEC unsafe inventory:** TODO-686 completed the full FEC source, caller, public-input, feature, test, script, documentation, related-owner, and history audit. Active GF(256)/GF(16) wrappers clamp slice lengths before private vector calls; the old public raw-slice and SSSE3 claims are stale. The P4 GF16 threshold map can still select a VBMI2 threshold while the actual policy falls back to scalar when VBMI2 is unavailable. Direct decoder/matrix/wire/Fountain validation, FEC configuration/feedback, sequence arithmetic, negative proof, and documentation truth remain open under TODO-855 through TODO-860 and the linked existing owners. TODO-816 now closes the active AMX kernel-semantics boundary; TODO-676 and TODO-817-TODO-819 retain the broader tile, detector, proof, and profile owners. No implementation or runtime verification was performed for TODO-686 itself.
- **io_uring:** The current sender copies payloads into owned slots before publishing pointers and quarantines after submit/protocol errors; SendMsgZc tracks `CQE_F_MORE` and waits for every announced notification, including errored primaries. Receive completion metadata is range-checked, zero-length and error receives are re-armed, and ring destruction precedes pool-block return. Client eventfd reads require exactly eight bytes. TODO-687 closed the unsafe/lifetime boundary and TODO-801 closed the additional Linux kernel execution boundaries. TODO-646 now isolates synchronous submit/wait behind the bounded runtime worker and enforces admission, cancellation, shutdown, and generic-reader contracts; the local Linux compile/live-proof gate remains blocked. TODO-798 owns unordered partial-send retry disposition.
- **Auxiliary unsafe surface:** TODO-689 completed the read-only audit of the remaining `cpu_dispatch`, prefetch, Windows NUMA, global-pool/auto-tuner, test-environment, telemetry, crate-root, transport/config, and test-only constant-buffer surfaces. The non-iOS AArch64 fallback uses `read_volatile`, Windows `GetCurrentProcessorNumberEx` status is ignored, lazy and explicit pool initialization differ, test-environment locks are fragmented, and `ConstPacketPool<N>` exposes `N - 1` slots while documenting `N`. Remediation is TODO-862 through TODO-865. TODO-688's completed audit records the separate audit-file FFI boundary; TODO-861 owns its remediation.
- **FEC solver:** `solve_wiedemann_system` still returns a copy of `rhs` after constructing the Krylov sequence and minimal polynomial; the existing equation check and Gaussian fallback are containment, not a functional solver. The all-feature fixture also uses an inconsistent repair packet identity. TODO-690 owns both mathematical correctness and fixture separation.
- **HTTP/3 control and parser:** The local H3 constructor records a control stream and settings in memory without emitting the stream type or SETTINGS bytes, and the server skips initialization. The frame parser reads a one-byte type, ignores SETTINGS/unknown state, and does not enforce stream-specific legality or push ownership. TODO-691 and TODO-692 own wire initialization and varint/state validation.
- **Transport receive accounting:** STREAM flow control increments connection bytes before overlap/deduplication, so retransmitted bytes consume credit. `take_ack` clears pending ACK state before capacity/write success. Loss detection materializes and sorts a packet-number prefix, while terminal timeout clears connection counters without retiring per-space recovery state. TODO-693 through TODO-696 own these accounting and terminal-owner contracts.
- **Terminal close and queued sends:** Congestion-bypass control flushing can block a later CONNECTION_CLOSE behind an earlier ack-eliciting frame; TODO-606 now suppresses duplicate local close frames and TODO-772 preserves the selected local close kind in typed error state. FEC and DATAGRAM queues pop items before every serialization/seal stage has committed, so a later failure can lose local payload ownership. Server stop can report `Stopped` while a startup-timeout runtime thread remains live. TODO-697, TODO-698, and TODO-699 own priority, transactional send ownership, and server thread lifecycle.

The audit remains open. These reconciliations document current evidence and ownership; they do not constitute implementation or runtime closure of the listed TODOs.

## Implementation Reconciliation (2026-08-05, TODO-812 logger installation failure ownership)

- **Failure ownership:** `logging::init()` now retains the `qf-log-writer` `JoinHandle` after spawning the bounded writer. If `log::set_boxed_logger()` rejects the new owner, `shutdown_and_join_worker()` sends the existing `LogCommand::Shutdown` and joins the handle before returning `LogInitError::LoggerAlreadyInstalled`.
- **Success boundary:** Successful installation still publishes the existing `LoggerControl`, sets the maximum level, and leaves the worker handle detached exactly as before. No fallback logger, recursive log emission, or new global owner is introduced.
- **Regression proof:** The logging unit suite passes 19/19, including a real pre-installed global logger with a configured file sink and a deterministic helper test that holds worker cleanup until the join boundary is observed. The process-level logging integration suite passes 3/3, and the complete library passes 2,374/2,374. Default and optional workspace checks and strict library Clippy pass.
- **Global gate boundary:** The full workspace matrix passes every target except the two existing `quicfuscate` runtime-reload/PMTU fixture assertions at `src/main_parts/late_tests_and_mlock.rs:566,638` (`41/43` for that binary). Workspace all-target strict Clippy reports the eight pre-existing client/backend and blacklist-test diagnostics; none originate in TODO-812. Native, Omega, deployed, and external publication proof remain separate evidence boundaries.
- **Scope:** This reconciliation covers only temporary worker ownership when global logger installation fails. Successful runtime shutdown, duplicate probe initialization, rotation/reopen, queue admission, sink error telemetry, and audit persistence retain their existing owners under TODO-674, TODO-672, and the adjacent audit TODOs.

## Implementation Reconciliation (2026-08-05, TODO-814 audit event payload bounds)

- **Admission contract:** `AuditLog::log_typed()` measures source IP, client ID, reason, and message strings as their exact JSON-encoded UTF-8 size, including quotes and escapes, before cloning any dynamic field or touching the bounded queue. The individual ceilings are 128, 512, 512, and 8,192 bytes; the combined dynamic payload ceiling is 8,192 bytes.
- **Failure and observability:** An oversized field returns typed `AuditError::PayloadTooLarge` with the field and measured/maximum sizes. Rejections increment `AuditStats.payload_rejections` and `quicfuscate_audit_payload_rejections_total`, never increment queue drops, and never consume a queue slot. The probe exposes the counter and all five ceilings in its JSON output.
- **Regression proof:** Audit payload-boundary tests cover exact field limits, over-limit field errors, combined-payload rejection, UTF-8, control characters, and queue interaction. Existing typed schema-v1/v2 and hash-chain tests remain in the same audit suite; the exact pushed Omega source closes the full Rust gate while the local macOS full build remains disk-limited.
- **Final proof:** The exact pushed Omega checkout at `495d12d8f5ac4450fc281560298f9179bd4d5607` passes the complete library suite `2403/2403`, strict library Clippy with `-D warnings`, and the audit probe `3/3`; post-push Graphify remains explicitly fail-closed at `scripts/out/audits/graphify-20260805T165808Z/graphify-evidence.json`.

## Implementation Reconciliation (2026-08-05, TODO-815 audit shutdown admission)

- **Linearization contract:** `AuditLog` stores an atomic `Open`/`Closing`/`Closed` lifecycle state together with an in-flight admission count. `log_typed()` acquires an admission guard with a compare-and-swap increment only while the state is `Open`; `shutdown()` changes `Open` to `Closing`, waits for the admitted count to reach zero, sends the final flush barrier, joins the writer, and publishes `Closed`.
- **Producer outcome:** Producers that win admission remain counted until their bounded `try_send` completes and are therefore included before the acknowledged final barrier. Producers racing after the close linearization point receive typed `WorkerClosing` or `WorkerDisconnected` errors; these lifecycle rejections increment the existing dropped-event counters and Prometheus metric.
- **Regression proof:** The focused audit suite passes `28/28`, including the admission-close and concurrent producer/shutdown tests; the metrics test passes `1/1`; `qf-audit-probe` tests pass `3/3`; the local full library passes `2381/2381`; Omega passes the exact pushed source at `90decbc7d8543294fc57ef33a79f8fdfe3268a3c` with `2405/2405`; local and Omega strict library Clippy pass with `-D warnings`. Local format and diff checks pass. Omega lacks its `rustfmt` component, so the remote format check remains an environment limitation.
- **Scope boundary:** TODO-675 retains synchronous durability/cancellation and sticky shutdown-error semantics; TODO-726 retains terminal admission after writer failure; TODO-727 and TODO-728 retain existing-file reads and path binding; TODO-849 retains the broader privilege identity and cross-platform FFI contract.

## Implementation Reconciliation (2026-08-05, TODO-816 AMX kernel semantics)

- **Active arithmetic contract:** The production Wiedemann path now uses one checked scalar GF(256) SpMV implementation on every target. `WiedemannScratch` always owns bounded column buffers and an accumulator, and `multiply_gf256_with_scratch()` zeroes output, bounds vector and row copies, and applies the canonical GF(256) table multiplication without raw ISA operations.
- **AMX source boundary:** The former compile-time-absent decoder branch, scalar-after-tile-load/store GF(256) kernel, uncalled signed INT8 kernel, and global mutable tile configuration are removed from the active source. `src/simd/amx.rs` is now an explicit integration boundary for a future verified backend; no tile register, stride, shape, or output-capacity claim is made for the current production path.
- **Telemetry and scope:** `WIEDEMANN_SCALAR_OPS` records the active solver path. `WIEDEMANN_AMX_OPS` and `WIEDEMANN_AMX_SCRATCH_ALLOCS` remain reserved and zero until TODO-818 proves real AMX GF(256) arithmetic and its compiler/runtime lane. TODO-676 retains tile ownership and broader dispatch/race boundaries; TODO-817 retains detector execution bounds; TODO-819 retains profile/documentation mapping; TODO-690 retains Wiedemann equation correctness.
- **Regression proof:** The focused Wiedemann suite passes `4/4`, the complete FEC test group passes `80/80`, the complete local library passes `2383/2383`, strict library Clippy passes with `-D warnings`, and local format/diff checks pass. The parity test covers non-identity GF(256) SpMV at `16x64` and `17x65` matrix shapes; it is a scalar fallback proof, not native AMX execution proof.
- **Pushed-source proof:** The isolated Omega checkout at exact commit `afe1d17003464981ab67ca666e7e98ce55114fc6` passes the complete library suite `2407/2407` and strict library Clippy with `-D warnings`; its source inventory has no `static mut`, former AMX kernel, or `TILE_CONFIG` match. Remote `cargo fmt --all -- --check` is unavailable because `cargo-fmt` is not installed for toolchain `1.97.1-aarch64-unknown-linux-gnu`; native AMX execution remains TODO-818 evidence and is not claimed.

## Implementation Reconciliation (2026-08-05, TODO-813 audit persistence bounds)

- **Shared contract:** `src/audit/mod.rs::AuditOptions::validate()` is the canonical validation owner for queue capacity `1..=65,536`, active segment bytes `1..=128 MiB`, retained segments `1..=64`, and flush/shutdown timeout `1..=60,000 ms`. `AuditConfig::to_audit_options()` uses the same values, and `AuditLog::open_with_options()` validates before path inspection, recovery, file opening, channel allocation, or worker spawn.
- **Probe contract:** `qf-audit-probe` rejects event counts above 1,000,000 and producer counts above 64, accepts `--flush-timeout-ms`, applies the shared persistence validation, and emits the selected options, nominal retained-segment budget, and effective ceilings in machine-readable JSON.
- **Resource boundary:** The configured nominal retained-segment budget is at most 8 GiB. This is a rotation/retention threshold budget, not a hard per-file payload cap; producer-side event payload limits are closed by TODO-814, while TODO-727 owns bounded reads of already-existing files.
- **Regression proof:** Audit bound tests pass 24/24, the shared EngineConfig boundary test passes 1/1, and the probe boundary tests pass 3/3. A 10,000-event restart/verification probe passes with 17,965 durable events/s, zero drops, zero persistence errors, and `restart_verified=true`. The 1,000-event diagnostic attempt was below the probe's existing 10,000 events/s acceptance threshold and is retained as a parameter-sensitive negative result, not a code failure.

## Implementation Reconciliation (2026-08-05, TODO-673 CLI control request contract)

- **Command ownership:** `src/bin/quicfuscate-ctl.rs` now parses exact command arity into the shared `AdminCommand` enum. `status`, `clients`, `reload`, `qkey`, `shutdown`, and `help` accept no positional values; `kick`, `block`, and `unblock` accept exactly one value; unknown commands and extra arguments fail before socket I/O. The Unix-only binary is registered explicitly in `Cargo.toml` and has a non-Unix unsupported-platform entry point.
- **Value contract:** `src/implementations/server/admin.rs` owns `MAX_ADMIN_COMMAND_BYTES = 8192` for the complete newline-terminated request frame and `MAX_ADMIN_COMMAND_VALUE_BYTES = 256` for raw command values. Values are trimmed, non-empty, control-character-free, and command-specific: IPs parse to canonical `IpAddr` text and client identities parse to the canonical `ClientIdentity` form. Runtime and HTTP dispatch reuse the same normalizers.
- **Serialization and admission:** `AdminCommand` is serialized with `serde_json`; the custom deserializer rejects unknown command names, missing required fields, and unknown fields. The CLI encodes and bounds the complete frame before connecting, while `AdminServer` retains the five-second deadline and independently validates the decoded command before dispatch.
- **Regression surface:** CLI request-builder/encoder tests cover exact arity, valid canonical values, JSON escaping, control-character rejection, and oversized values. Unix admin tests cover typed bounded encoding, unknown-field rejection, canonical dispatch, and invalid commands. The CLI target passes 8/8 focused tests and strict binary Clippy; the serial server filter passes 490/490; the complete library passes 2,372/2,372; default and optional all-target checks pass; and default and optional strict library Clippy pass. The full workspace matrix executes the CLI target at 8/8 and every other target successfully except the two pre-existing `quicfuscate` runtime-reload/PMTU fixture failures at `src/main_parts/late_tests_and_mlock.rs:566,638`.
- **Boundary:** TODO-617 retains Unix socket identity and request-reader ownership; TODO-795 retains the 1 MiB newline-terminated typed response contract. No UI, Omega checkout, remote runtime, or live deployment state is changed by this reconciliation.

## Deep Audit Reconciliation (2026-08-02, target and scope contracts)

This read-only pass reconciled the current Cargo target inventory, runner references, CI feature lanes, and audit-register scope. No product or protected UI implementation was changed.

- **Cargo target inventory:** The root package declares 71 integration-test targets and every declared source path exists. The desktop/web-admin Rust validation suite invokes five current declared targets. The historical `it-masque-runtime-integration` source remains under `archive/tests/` as evidence only and is not an active Cargo target; TODO-774 closed the stale runner contract.
- **Feature-gated tests:** All 64 declared test targets with crate-level feature cfgs now declare matching Cargo `required-features`. The orchestrator target requires `rust-tests,orchestrator`, SIMD self-check requires `rust-tests,simd-selfcheck`, Linux io_uring targets require `rust-tests,io_uring`, and XDP requires `rust-tests,internal_af_xdp_experimental`. The common `run_cargo` helper retains baseline `rust-tests` injection, while target-specific runners pass the complete feature set explicitly.
- **Non-vacuous execution:** `scripts/tests/lib/lib-common.sh::qf_cargo_test_run_expect()` rejects zero executed tests, missing successful libtest output, and missing named test markers. The transport suite verifies one named body in each transport integration target and records non-Linux io_uring, kernel-hotpath, and XDP paths as explicit `SKIP` records. `scripts/tests/fast/test-dynamic-discovery-fail-closed.sh` proves that missing `rust-tests` or `orchestrator` is rejected by Cargo before any green zero-test result. The CI SIMD lane passes `rust-tests,simd-selfcheck` and requires `varint_roundtrip_and_consistency`; the default all-target feature lane passes `rust-tests`.
- **Example target:** `tun_factory_example` is selected by Cargo and its crate-level cfg only with `tun-tests`; `main()` now demonstrates the registered external factory without advertising unreachable `tun-windows` or `tun-ios` branches. The example proves factory wiring, not platform backend behavior. TODO-775 closed the target contract; TODO-443 remains the platform implementation owner.
- **CI and release:** The current workflow review confirms existing ownership under TODO-708, TODO-709, TODO-734, TODO-741, TODO-749, and TODO-758: masked benchmark-baseline failures, incomplete strict Clippy feature coverage, vacuous feature lanes, optional release artifact publication and updater activation, mutable dependency/toolchain inputs, and push-only fuzz coverage. No additional unowned workflow finding was created in this pass.
- **Audit register:** The current local corpus contains 709 tracker headings, 370 current detail files, and 374 archived detail files. A fresh raw Git path inventory classifies 910 tracked and 21,283 ignored paths with zero unclassified paths; the last recorded validator pass accounted for 902 tracked, 58,787 ignored, and zero non-ignored untracked paths, for 59,689 accounted paths, including exactly three `historical-archive` paths. The current validator run stops before those counts because it rejects the canonical `Blocked` tracker section; TODO-799 owns that schema mismatch. TODO-773 closed the tracked archive classifier boundary; TODO-777 closed the fast FEC smoke failure-propagation boundary; new runtime/configuration/evidence findings are owned by TODO-724, TODO-751, and TODO-788 through TODO-805. Therefore the broader whole-project audit remains open for its separately owned target, runtime, native, evidence, feature-contract, and frontend dependency boundaries.

## Implementation Reconciliation (2026-08-03, bounded client fan-out queue)

- **Shared admission owner:** `src/implementations/server/parts/live_auth.rs` now stores broadcast and multicast packets in one `ClientFanoutQueueState` shared by the MASQUE datagram callback and framed HTTP/3 uplink callback. Admission rejects before payload cloning when the queue reaches 256 entries or 384 KiB, or when one source reaches 32 entries or 64 KiB.
- **Bounded work and memory:** `LiveServerState::drain_client_fanout()` removes at most 64 packets per invocation with FIFO accounting for total and per-source bytes. It no longer materializes the complete backlog into a second `Vec`; housekeeping invokes the same bounded drain even when no UDP datagram arrived, so pending fan-out cannot wait indefinitely for input traffic.
- **Drop observability:** Admission drops increment `quicfuscate_client_fanout_dropped_total` and emit a debug-only reason. Existing normal-load routing and the source exclusion rule remain unchanged; downstream per-target TUN queues retain their independent bounds.
- **Local proof:** Four focused fan-out/metric tests passed, the complete server module passed 133/133, and the full library gate passed 2,156/2,156. `cargo check --locked --all-targets`, `cargo fmt --all -- --check`, and `git diff --check` passed. Strict local Clippy still stops only at the pre-existing `TlsCover::client_hello_custom` dead-code lint owned by TODO-709/TODO-752/TODO-787. Remote Clippy Matrix run `30815583508` passed all eight feature lanes on source revision `c216cc5`.

## Implementation Reconciliation (2026-08-03, explicit server IPv4 PTB disposition)

- **Pre-write boundary:** `src/implementations/server/parts/live_auth.rs::allow_client_uplink()` now emits IPv4 Fragmentation Needed for every IPv4 packet larger than the configured server TUN MTU, regardless of the DF flag. The shared decision returns before the MASQUE callback's `tun_sink.write()` and the framed HTTP/3 callback's `tun.write()`, so no platform backend receives an oversized packet.
- **Intentional contract:** Userspace RFC 791 fragmentation is not implemented. The server chooses explicit PMTU feedback for DF=0 as a fail-closed, backend-independent disposition rather than relying on unverified driver behavior. Existing IPv6 Packet Too Big and DF=1 IPv4 behavior remain unchanged.
- **Regression scope:** A crafted 1,428-byte IPv4 UDP packet over a 1,400-byte TUN MTU is checked for PTB in both DF states, including quoted bytes, MTU, router/source and destination addresses, IPv4 checksum, ICMP checksum, and `packet_too_big` routing telemetry. The focused regression `implementations::server::tests::oversized_ipv4_packets_get_ptb_before_any_tun_write_for_both_df_states` passed 1/1 locally; the complete server module passed 134/134 and the full library passed 2,157/2,157. `cargo check --locked --all-targets`, formatting, diff hygiene, and native-harness syntax passed. Strict local Clippy stops only at the pre-existing `src/stealth/tls_cover.rs:393` dead-code lint; no TODO-613 diagnostic was emitted.
- **Native probe gate:** `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh::prove_server_ptb_from_client()` sends DF=1 and DF=0 (`ping -M dont`) IPv4 probes plus an IPv6 probe while the client phase uses a separate 1472-byte transport budget and 1500-byte TUN ceiling, the server carrier uses the 1472-byte Ethernet payload ceiling, the server TUN remains at 1280, and the 1300-byte IPv4 echo payload produces a 1,328-byte inner packet. The carrier/TUN split is intentional: the inner probe must reach `allow_client_uplink()` whole so only the server TUN boundary owns the PTB decision. The two IPv4 probes use distinct destinations (`198.51.100.2` for DF=1 and `198.51.100.3` for DF=0) so the first server PTB cannot install a cached 1280-byte client PMTU that fragments the second probe before the server. The gate captures server-sourced IPv4 PTB for both DF states and server-sourced IPv6 Packet Too Big on the client TUN, then checks the server metric deltas. The `.github/workflows/ci.yml` `linux-traffic-analysis-native` job executes the complete multi-client harness with an isolated CA and dedicated `server-ipv4-ptb-native` artifact path. Exact run `30818265053` proved the earlier same-config probe was consumed by the client-local oversized-TUN path (`packet_too_big` stayed at zero and the client TUN capture was empty). Follow-up run `30819134933`, job `91704360063`, reached the harness with the corrected client/server PMTU values but failed earlier at the bidirectional framed-H3 assertion because the 1472-byte client budget leaves no packet range above its MASQUE datagram budget and below its tunnel MTU. Run `30819873718`, job `91706872150`, passed the isolated H3 preflight but exposed the remaining stale client-local PTB assertion. Run `30821179317`, job `91711269455`, reached the corrected server-owned assertion and retained zero server PTB on the client TUN while server `packet_too_big` stayed at zero. Run `30823185685`, job `91718100017`, enabled verbose server evidence and proved the 1,328-byte probe was truncated by the 1,280-byte server carrier receive buffer before routing, producing `MalformedPacket`; the harness now separates the 1,472-byte carrier from the 1,280-byte TUN boundary. Run `30823826169`, job `91720279895`, proved the corrected DF=1 and IPv6 server responses (`packet_too_big` delta 2 and `icmpv6` delta 1), but the same-destination DF=0 probe was fragmented by the client kernel after the DF=1 PMTU update and therefore never reached the server as one oversized packet; the harness now isolates the destinations. Run `30824438300`, job `91722362887`, passed the complete PTB gate: both IPv4 wire captures contain unfragmented 1,328-byte probes, both return `Frag needed and DF set (mtu = 1280)`, IPv6 returns `Packet too big: mtu=1280`, and the server metric deltas are `packet_too_big=3` and `icmpv6=1`. The overall job then stopped in the independent IPv4 TTL-expiry assertion; the corrected native wire proof is closed by TODO-806, and that later backpressure failure does not invalidate the completed TODO-613 PTB gate.

## Implementation Reconciliation (2026-08-03, IPv4 TTL expiry before ingress fingerprint normalization)

- **Root cause:** The native TTL probe uses the MASQUE datagram path. `core_parts/connection.rs::drain_masque_datagrams()` normalized the decoded IPv4 packet before dispatching it to the server callback, and `PacketNormalizer::normalize_ipv4_fields()` changed TTL 1 to the selected OS profile TTL. `allow_client_uplink()` therefore never saw the expiry value and could not enqueue `TIME_EXCEEDED`.
- **Correction:** All tunnel-ingress normalization paths now use the TTL-aware normalizer. A valid IPv4 packet with TTL 0 or 1 is passed through byte-for-byte until `allow_client_uplink()` evaluates routing; ordinary packets retain the existing fingerprint normalization, including IPv4 fields, TCP SYN options, ICMP policy, and buffer-capacity behavior.
- **Regression scope:** The fingerprint suite proves both owned-vector and caller-buffer tunnel-ingress paths preserve an expiring packet. The server regression then routes that packet through `allow_client_uplink()`, checks `time_exceeded` telemetry, validates the generated response profile TTL and ICMP type/code, and verifies the quoted original bytes. Focused tunnel tests passed 2/2, the complete server module passed 135/135, and the complete fingerprint module passed 46/46. Formatting, diff hygiene, and all-target Rust test compilation passed.
- **Native evidence closure:** `prove_icmp_boundaries()` retains the TTL ping output, a client-TUN pcap, a machine-readable verification result, and before/after server metrics. Native run `30827540460`, job `91733001327`, artifact `server-ipv4-ptb-native` (`8861606310`, SHA-256 `28eaf231afd5feb1f931a276d78e98f761b35a4ee6b4a39fa83542f1569e4e3c`) contains one captured request `10.0.1.2 -> 198.51.100.1`, TTL 1, ICMP echo type 8/code 0, and one server response `10.0.1.1 -> 10.0.1.2`, TTL 128, ICMP Time Exceeded type 11/code 0. Both IPv4 and ICMP checksums are valid; the verifier confirms an exact 28-byte quote matching the original request. Server `time_exceeded` increased from 0 to 1. The independent PTB probes in the same artifact retained `packet_too_big=0 -> 3` and `icmpv6=0 -> 1`. The native job later failed at the independent backpressure-quiescence gate with `quicfuscate_tun_downlink_backpressure_events_total{event="enqueued"}=6`; this does not reopen TODO-613 or TODO-806.

## Deep Audit Reconciliation (2026-08-03, io_uring ownership and completion contracts)

- **Sender ownership:** `src/optimize/uring_batch.rs` copies connected and unconnected send payloads into sender-owned slots before publishing `iovec` pointers. Standard SendMsg and SendMsgZc message metadata therefore cannot borrow the caller's batch after the call boundary.
- **Failed submissions:** A submit or completion-protocol error marks the sender quarantined, attempts synchronous cancellation for requests already accepted by the kernel, drains available CQEs, and prevents scratch reuse. If cancellation cannot prove quiescence at drop, pointer-bearing storage is leaked deliberately rather than released while a kernel request may still reference it.
- **Zero-copy lifetime:** SendMsgZc distinguishes primary CQEs from notification CQEs. `CQE_F_MORE` on the primary announces a follow-up `CQE_F_NOTIF`; the sender waits for every announced notification, including notifications attached to errored primary requests, and rejects stale, duplicate, or unannounced notification state. The kernel contract is documented by the upstream `io_uring_prep_sendmsg_zc(3)` semantics.
- **Receive slots:** `UringRecvBatch` validates every completion user-data value, tracks armed and pending state one-to-one, re-arms positive, negative, and zero-length receives, resets source-address storage on every consumed slot, and destroys the ring before returning pool blocks. The source contains a bounded Linux regression for a full receive depth of zero-length datagrams followed by a marker datagram, and `test-transport.sh` selects it through a bounded, fail-closed evidence command. CI run `30807353972`, job `91665699625`, executed it on Linux and recorded four zero-length CQEs plus the marker.
- **Client FFI:** `io_driver.rs` now documents eventfd `read`, `dup`, and `OwnedFd::from_raw_fd` ownership. An eventfd wakeup is accepted only for an exact eight-byte read; short positive reads fail before completion draining.
- **Separate owners:** Runtime async paths now isolate synchronous submit/wait/CQE draining behind the bounded `UringBatchWorker`; direct sender calls remain explicit synchronous compatibility primitives. The public contiguous-prefix result can retry a later packet after an unordered earlier error; TODO-798 owns the exact per-slot partial-send disposition and duplicate prevention.
- **Evidence boundary:** macOS client io_driver focused tests passed 12/12; the complete host library gate passed 2,144/2,144; `cargo check --all-targets --features rust-tests`, targeted Clippy with warnings denied and documented baseline suppressions, `cargo fmt --all -- --check`, and `git diff --check` passed. Remote Clippy Matrix run `30791153445`, job `91614771683`, passed the `io_uring` feature lane. Follow-up CI run `30807353972`, Linux fastpath job `91665699625`, passed on source revision `c4209ebba7f5b32dbb0400cbd94400271286b242`: `uring-rearm.json` and `uring-zc.json` both report `status=PASS`, `reason=kernel_executed`, and `command_status=0`; the rearm log records four zero-length CQEs and a delivered marker, while the opt-in ZC log records three primary sends, four notifications, three delivered payloads, and `error_outcome=cqe_error`. The regular lane passed 529 library tests, `rt-transport-uring` 14/14, and `rt-io-hotpath-kernel-integration` 1/1. The overall workflow remained red only on unrelated platform and native-lifecycle jobs. The local macOS host still cannot compile the Linux target because its GNU/Linux C sysroot is absent (`ring` cannot find `assert.h`).
- **Tracker gate:** `bash scripts/tests/audits/verify-audit-completeness.sh` currently fails before corpus validation with `unexpected tracker section 'Blocked'`; an independent filename/register reconciliation finds 709 tracker headings, 370 current detail files, and 340 archived filename-ID detail files with no filename-ID orphan or duplicate. The preceding section/status snapshot found Active `1`/`IN_PROGRESS`, Blocked `1`/`BLOCKED`, Queue `158` (`144` `OPEN`, `14` `QUEUED`), and Completed `549`; TODO-801 is now closed by the Linux evidence recorded above. TODO-799 owns alignment of the validator with the repository's canonical task lifecycle, and TODO-800 owns the stale macOS runtime-reload fixtures exposed by the same CI run. The legacy archive-schema observations remain unchanged.
- **Other CI failures:** The same completed CI run also fails the Windows core check at `src/privilege/drop.rs:676` because `CurrentIds` is unavailable (existing TODO-593/TODO-684 boundary), and strict macOS Clippy at `src/stealth/tls_cover.rs:393` plus `src/implementations/client/dns_runtime.rs:279,289` (existing TODO-709/TODO-752/TODO-787 lint boundary). These failures are recorded as existing owners and were not changed in this audit.
- **TODO-607 root cause:** `RoutingManager::teardown()` calls `recover_persisted_ownership()`, whose startup-only `reject_active_owner()` check rejects the current process PID before its graceful release. This exactly explains the native residue `/run/quicfuscate/routing/7174756e30.json`; current-owner release and stale-owner recovery must be separated before the lifecycle gate can close.
- **TODO-607 follow-up:** `RoutingManager::teardown()` removes the fixed firewall resource before the active-owner guard can succeed. On the current failure path this creates partial cleanup, and setup rollback reuses the same ordering. TODO-802 additionally tracks that fixed iptables/nftables identities are not bound to the per-TUN durable owner, so independent managers can replace or remove one another's firewall state.
- **TODO-607 evidence gap:** `scripts/tests/tun-e2e-netns.sh` checks only durable-record removal after graceful shutdown and then deletes the test namespaces; it does not directly prove pre-deletion cleanup of the managed TUN, address/link, forwarding, or selected firewall resources. The native zero-residue acceptance therefore remains open even after the current-owner teardown fix.
- **Audit-runner evidence:** `bash scripts/tests/audits/audit-runtime-guardrails.sh --output-dir /tmp/quicfuscate-audit-guardrails` completed with one Critical and one Warning. The Critical is a checker false negative: its exact-column regex misses the correctly indented `SERVER_PID=$!` assignment inside `start_server()`; the Warning is the known module-wide `dead_code` allowance in `src/simd/x86_ack.rs:3`, owned by TODO-752. TODO-730 owns the guardrail result-integrity repair.
- **Comprehensive audit evidence:** `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/quicfuscate-comprehensive-target bash scripts/tests/audits/audit-all-comprehensive.sh --strict --output-dir /tmp/quicfuscate-audit-comprehensive` completed on revision `1b91a55` with exit `1`, `4` Critical classifications, and `7` Warnings. The current strict log contains `1` `unwrap`, `20` `expect`, and `1` `panic` diagnostic; the older `68`-diagnostic result is historical scope evidence. TODO-730 owns result integrity and heuristic classification, TODO-676 retains the dispatch/runtime boundary, TODO-816 now closes the active kernel-semantics finding, TODO-817 owns detector process bounds, TODO-818 owns the AMX proof lane, TODO-819 owns profile/documentation truth, TODO-757 owns the strict panic/invariant cluster, and TODO-803 owns the two redundant clones. No product implementation was changed during that historical audit.
- **Readiness and analysis evidence:** On 2026-08-03 at revision `6b18d373da46242c47283ee5093d359e6a0792a0`, `audit-readiness-gates.sh` passed Clippy Strict, Cargo Audit, Cargo Deny, and deny-only Cargo Geiger; the explicit `--strict-geiger` rerun returned `1` because 31 dependency packages report unsafe usage, while the other three checks passed. The same revision's static coverage helper reported 7,029 functions and 2,575 test functions without executing coverage; the script-quality helper reported 122 scripts with 10 missing strict-mode cases, 21 missing descriptions, 14 missing help handlers, 24 naming violations, 10 missing usage lines, and 2 unknown-argument cases; the suite matrix found 28 suites, 21 invoked by the full-suite utility, and 7 omitted. The dead-code helper remains incomplete on Darwin because its BSD `sed` dependency scan fails and leaves unterminated JSON. TODO-730 owns these result and scope boundaries; TODO-799 owns the completeness validator's `Blocked` section failure. No product implementation was changed during this audit.
- **Suite exclusion evidence:** Direct `bash scripts/tests/suites/test-graceful-shutdown.sh --help` exits `1` on the missing default binary instead of returning usage. `test-fec-all.sh` is a dispatcher whose constituent modes are called directly; `test-linux-installer.sh` has the executable native CI lane and calls `test-linux-installer-guest.sh` inside systemd-nspawn. No executable `.github/workflows` or full-suite invocation is present for the DDoS admission, graceful-shutdown, QKey-auth, or QKey-registry process proofs. TODO-730 owns the missing inclusion/exclusion contract and live-lane ownership. No product implementation was changed during this audit.
- **Omega proof boundary:** Read-only inspection on 2026-08-03 found two remote `main` checkouts instead of one canonical proof surface. `omega:/home/ubuntu/SOFTWARE/QuicFuscate` is at `9b57474`, has 97 untracked status paths and 43,722 untracked files, and contains a running server; `omega:/home/ubuntu/CODE/QuicFuscate` is at `d36652d`, has 20 tracked modifications, and its diff inspection fails on missing Git object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1`. TODO-804 owns reconciliation. No remote state was modified during this audit.
- **Fast full-suite evidence:** `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/quicfuscate-full-suite-fast-target bash scripts/tests/utils/util-run-full-suite.sh --fast --output-dir /tmp/quicfuscate-full-suite-fast` passed the build check, 2,144/2,144 root library tests, Core Integration, Desktop/Admin validation, Stealth Fast, and Crypto Fast, then exited `1` in `test-optimization.sh` because the consumer passed malformed environment JSON with an extra closing brace to the shared writer. The traced field is `environment=json:${COMMAND_ENVIRONMENT_JSON:-{}}`; TODO-782 owns the three affected consumer call sites and TODO-730 owns aggregate result classification. No product implementation was changed during this audit.
- **Frontend dependency evidence:** The 2026-08-03 baseline `bun audit --json` exited `1` with `29` advisories across nine locked package keys: `@sveltejs/kit@2.55.0`, `cookie@0.6.0`, `devalue@5.6.4`, `esbuild@0.27.4`, `picomatch@4.0.3`, `postcss@8.5.8`, `svelte@5.53.12`, `undici@7.24.3`, and `vite@7.3.1`. `bun pm scan` was unavailable because no scanner was configured. TODO-805 owns the now-completed local reconciliation and retains the exact advisory inventory and dispositions.
- **Frontend dependency gate:** Before TODO-805, CI installed and built the Bun workspaces but invoked only Cargo dependency auditing. The baseline frontend advisory result therefore had no required CI failure lane. The implementation reconciliation below adds that lane and records the remaining hosted/native boundary.

## Deep Audit Reconciliation (2026-08-03, FEC complete audit)

- **Scope:** TODO-686 is complete as a read-only audit across every current FEC source and test module, all FEC `unsafe` sites and direct callers, public decoder/matrix/wire/Fountain boundaries, feature gates, malformed-input tests, fuzz and shell/benchmark/netns proof, documentation, related owners, and history.
- **Current evidence:** The validated product wire path has real profile, epoch, length, and repair-identity checks, while direct public constructors and helpers can be called outside those gates. Existing tests and scripts prove selected recovery, liveness, bounded telemetry, and live Linux transitions, but not all malformed metadata, matrix shapes, native feature intersections, repair semantics, or negative paths.
- **Open remediation:** TODO-634 retains Fountain storage/queue growth, TODO-636 peeling complexity, TODO-637 Wiedemann scratch reuse, TODO-690 solver correctness, TODO-715 GF16 PCLMUL mathematics, TODO-832 pooled-buffer ownership, and TODO-855 through TODO-860 own FEC SIMD contracts, public input validation, Fountain direct inputs, FEC-domain feedback validation, proof/documentation truth, and sequence arithmetic. Shared SIMD, AMX, transport, and environment owners remain in force.
- **Documentation truth:** The accepted product Fountain maximum is 128 sources and the example now uses 128. The steady-state GF16 inverse table is 65,536 `u16` entries, or 128 KiB; temporary exponent/logarithm build allocations are separate and are not represented as the retained table. Universal pool-return wording was narrowed because TODO-832 remains open.
- **Evidence boundary:** No production implementation, build, test, native probe, privileged network run, commit, or push was performed for TODO-686. Completion means the audit and ownership record is complete, not that the remediation or runtime gates are closed.

## Deep Audit Reconciliation (2026-08-03, audit-file FFI complete audit)

- **Scope:** TODO-688 is complete as a read-only audit across the complete current audit implementation and tests, the audit probe, direct startup/runtime callers, the limits false-positive source, audit suites and guardrails, documentation, related owners, and relevant history.
- **Current inventory:** The confirmed current inventory is three production FFI sites in `src/audit/mod.rs` (`geteuid`, `chown`, and Windows `MoveFileExW`) plus one Unix-only test guard. No production `unsafe` operation was found in `src/implementations/server/limits.rs`.
- **Open remediation:** TODO-861 owns local FFI safety contracts, Windows interior-NUL rejection, warning-only permission/ownership failure semantics, and platform-negative proof. TODO-671 owns direct existing-file mode; TODO-675 and TODO-726 own writer lifecycle and terminal admission; TODO-728 owns pathname-to-inode binding; TODO-813 and TODO-814 own configuration and payload bounds. TODO-815 closes shutdown admission ordering.
- **Evidence boundary:** The current source has no Windows-specific replacement success/failure or malformed-path test, and the root-dependent Unix permission failure test skips the privileged branch. No production implementation, build, test, native Windows/root probe, privileged network run, commit, or push was performed for TODO-688. Completion means audit coverage and ownership are recorded, not that the remediation or runtime gates are closed.

## Deep Audit Reconciliation (2026-08-03, auxiliary unsafe audit complete)

- **Scope:** TODO-689 is complete as a read-only audit across the remaining
  auxiliary source and test modules, all real unsafe operations and
  source-text false positives, direct prefetch callers, SIMD feature/profile
  intersections, Windows NUMA FFI, global-pool and auto-tuner initialization,
  test-environment mutation, the test-only constant-buffer helper,
  feature/platform gates, audit scripts, CI workflows, documentation, related
  TODO owners, and history.
- **Open remediation:** TODO-862 owns the shared portable prefetch facade and
  non-PMTU callers; TODO-863 owns Windows NUMA result and safety proof;
  TODO-864 owns global-pool/auto-tuner lifecycle and telemetry side effects;
  TODO-865 owns the test-only `ConstPacketPool` capacity and zero-size
  contract. TODO-670/TODO-811, TODO-826/TODO-827, TODO-834/TODO-835/TODO-836,
  TODO-841, TODO-843, and TODO-752 retain their separate boundaries.
- **Evidence boundary:** The whole-project source audit is read-complete
  through TODO-689, but TODO-754 remains active because the current
  `verify-audit-completeness.sh` invocation stops on the canonical `Blocked`
  section before validating the corpus. TODO-730 and TODO-799 retain the
  machine-checkable runner/schema boundary. No production implementation,
  build, test, native architecture probe, privileged run, commit, or push was
  performed for TODO-689. Completion means audit coverage and ownership are
  recorded, not that remediation or runtime proof is closed.

## Audit Register Reconciliation (2026-08-04, TODO-799 complete)

- TODO-799 repaired the completeness validator's canonical tracker contract. It now accepts and validates `Active`/`ACTIVE|IN_PROGRESS`, `Blocked`/`BLOCKED`, `Queue`/`OPEN|QUEUED|AUDIT_COMPLETE`, and `Completed`/`DONE|SCRAP|COMPLETE|COMPLETED|CLOSED|AUDIT_COMPLETE`, enforces section order and presence, and derives the global status allowlist from the same contract.
- The live validator passes with tracker `769` headings across Active `1`, Blocked `3`, Queue `190`, and Completed `575`; current details `411/411`; archived Markdown files `393` with `36` explicit exceptions; tracked paths `927`; ignored paths `37,803`; and zero non-ignored untracked paths. The fixture suite passes the valid blocked/audit-status corpus and fails closed for malformed sections, duplicate IDs, missing details, and status mismatches.
- TODO-754 is active again. This closes the register/schema/Git-scope gate only; the broader target, runtime, native, feature, Graphify, frontend, Omega, and external-evidence boundaries remain with their existing owners. No production Rust or UI code was changed.

## Implementation Reconciliation (2026-08-03, crypto key and IV constructor boundaries)

- **Typed boundary:** `src/crypto/aead.rs` owns `KeyMaterialError` plus exact-length helpers. `ChaCha20Poly1305` requires a 32-byte key and 12-byte IV; `AesGcm128`, AEGIS L/X4/X8 wrappers, and `MorusAead` require a 16-byte key and 12-byte IV. Public data-AEAD selection and the benchmark builder enforce the same 16/12 contract before copying into fixed arrays.
- **Header protection:** `AesHp::new` rejects secrets shorter than 16 bytes without a panic. Its documented raw-secret API still consumes the first 16 bytes of a longer secret; all packet setup paths derive the exact 16-byte header-protection key first and use the typed array constructor, so a 32-byte traffic secret is never silently installed as an HP key.
- **Propagation:** QKey registry encryption/decryption, TLS cover ciphers, packet initial/handshake/0-RTT/1-RTT setup, examples, runtime fixtures, property/security fixtures, and the retained backend benchmark all propagate or prove the fallible constructor boundary. No key/IV `unwrap_or(0)` construction fallback remains; QUIC traffic-secret derivation now enforces the exact 32-byte KDF boundary under TODO-633, while header-protection sample handling remains separately owned by TODO-629.
- **Verification:** Locked all-target/all-feature check and strict Clippy passed. Serial crypto tests passed 143/143, QKey registry storage 11/11, packet tests 25/25, baseline/property/security integration targets 6/6, 12/12, and 24/24, and all four retained backend benchmark smokes executed successfully. The Criterion benchmark target compiled with `--no-run`. The full local library passed 2,194/2,196; DNS resolution remains TODO-807 and rustls ClientHello readiness remains TODO-768. The fuzz manifest remains unbuildable at its pre-existing path boundary owned by TODO-758.

## Implementation Reconciliation (2026-08-03, header-protection sample and packet-number bounds)

- **Typed sample boundary:** The crypto and transport `HeaderProtector` traits now return errors. `AesHp` requires an exact 16-byte sample and exact 5-byte mask, while the Rustls-backed provider rejects every non-exact sample length and propagates mask-derivation failures as `ConnectionError::CryptoError`; no zero mask or zero-padded sample is synthesized.
- **Receive boundary:** `unprotect_and_decrypt_with_key()` requires the complete 16-byte sample window before reading or mutating the protected header, validates the decoded 1-4 byte packet-number range before mutation, and propagates failures through the 1-RTT fast path, fallback key path, and previous-key candidates. `remove_hp()` has the same sample and packet-number bounds.
- **Send boundary:** `protect_header()` validates packet-number length, offset, and buffer bounds before mutation. `apply_hp()` now propagates sample and packet-number-buffer errors. The short-header sealing path pads to the minimum sample-bearing ciphertext length before AEAD sealing and no longer silently emits an unprotected packet when the payload is short.
- **Regression proof:** The locked all-target/all-feature check and strict Clippy passed; 144/144 Crypto tests, 29/29 packet tests, and baseline/property/security integration targets 6/6, 12/12, and 24/24 passed. Format and diff checks passed. The full local library passed 2,199/2,201; the two unrelated failures remain TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness.
- **Scope boundary:** No UI or Omega state was changed. The TODO-633 KDF implementation is local-only until its full matrix and native/external proof gates close; fuzz-manifest dependency resolution remains TODO-758, and the broader project audit remains open under its existing task owners.

## Implementation Reconciliation (2026-08-03, GHASH dispatch configuration)

- **Test boundary:** `GHASH_TEST_OVERRIDE` and `__test_set_ghash_override` remain behind `cfg(test)` on x86_64; the prior claim that the test hook was compiled into production builds is not confirmed.
- **x86 dispatch:** `GHASH_OVERRIDE` stores a parsed `GhashOverride` in `OnceLock`. `QUICFUSCATE_GHASH` is read and interpreted once, while normal GHASH calls use the immutable enum without environment access, string allocation, or case normalization.
- **ARM dispatch:** `GHASH_PMULL_ENABLED` caches the startup value of `QUICFUSCATE_GHASH_PMULL`, removing the per-call environment read from the AArch64 GHASH path. CPU feature selection remains owned by the existing process-cached `FeatureDetector`.
- **Benchmark:** `examples/microbench.rs ghash-short` measures repeated 32-byte AAD plus 128-byte ciphertext GHASH calls; `scripts/benchmarks/micro/micro-ghash.sh` runs it before the configurable size matrix and retains the CSV/JSON/log evidence.
- **Regression proof:** Native all-target check and strict Clippy passed. The complete Crypto group passed 144/144, GCM passed 11/11 with `QUICFUSCATE_GHASH_PMULL=0` and `=1`, the release short-packet benchmark completed 1,000 packets, and the runner smoke completed with isolated artifacts. The x86_64-Apple cross-check remains blocked by pre-existing `avx10.1-*` feature-macro errors and the existing non-constant `_mm_prefetch` argument at `src/optimize/parts/cache_and_const.rs:54`; no x86 runtime proof is claimed on this ARM host.
- **Scope boundary:** No UI, Omega, or unrelated crypto backend behavior changed. The broader project audit remains open under its existing task owners.

## Implementation Reconciliation (2026-08-03, QUIC nonce and packet-number lifecycle)

- **Nonce contract:** `src/crypto/mod.rs::make_nonce16` remains a stateless QUIC-style nonce primitive. It XORs the full 64-bit packet number into bytes 4-12 of the 96-bit IV and leaves the final four bytes of the internal AES-GCM nonce zero. Its callers must provide a unique traffic-secret/IV epoch and a packet number within QUIC's 62-bit limit.
- **Connection owner:** `src/transport/connection/parts/types.rs` owns one monotonic outbound packet-number counter per Initial, Handshake, and Application space. `next_send_packet_number()` rejects values above `pnspace::PktNumSpace::MAX_PACKET_NUMBER`; `advance_send_packet_number()` uses checked arithmetic and rejects invalid state with `ConnectionError::AeadLimitReached` instead of wrapping.
- **Send coverage:** The Initial/Handshake send loop, the normal short-header path, the targeted path-control short-header path, and both 1-RTT sealing branches use the shared guard/advance helpers. Counters are reset only when a new connection/version or Retry Initial-key epoch is installed. `key_update()` derives the next 1-RTT traffic secret without resetting the Application packet number.
- **No history table:** Runtime nonce-history storage is not required at the connection boundary because the key/IV epoch plus monotonic packet-number invariant makes every `(traffic secret, IV, packet number)` tuple unique. The low-level AEAD wrappers remain usable as stateless primitives and do not pretend to enforce connection lifecycle state.
- **Regression coverage:** Connection tests prove that a 1-RTT key update preserves the packet number, the final valid 62-bit packet number advances to a fail-closed sentinel, u64 overflow cannot wrap, and an invalid outbound packet number is rejected before send-state mutation.
- **Verification:** Locked all-target/all-feature check, strict Clippy, format, and diff checks passed. The full Connection group passed 119/119, Crypto passed 144/144, Packet passed 28/28, and the baseline/property/security integration suites passed 6/6, 12/12, and 24/24. The full local library passed 2,203/2,205; the two unrelated environment failures remain TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness.

## Audit Infrastructure Reconciliation (2026-08-04, TODO-730)

- `scripts/tests/audits/audit-all-comprehensive.sh` is strict by default and accepts explicit `--advisory` reporting mode. It writes the `quicfuscate.audit-result-contract.v1` result contract, preserves raw command artifacts and return codes, and classifies every required check as `PASS`, `FAIL`, or `UNAVAILABLE`.
- The live strict run completed all sections with 32 result objects: 25 `PASS`, 3 `FAIL`, and 3 `UNAVAILABLE`, exit `1`, summary `FAIL`. The failed checks were strict runtime Clippy (`rc=101`) and runtime guardrails (`rc=1`, the existing PMTU contract finding). The unavailable checks were native PowerShell parsing and Cargo Audit/Cargo Deny advisory database access. The run did not modify production Rust or UI code.
- Structural scope is explicit: `scripts/tests/audits/audit-rust-scope.py` covers 232 production Rust files with 869 parsed `unsafe` locations and 4 leak-pattern locations; `audit-secret-scope.py` covers 403 executable/configuration surfaces, records 707 explicit exclusions, and reports zero secret findings. The test metric is `test_file_presence_percent` and means source-marker presence only, not executed coverage.
- `scripts/tests/analysis/analysis-dialect-validation.py` parses JSON/JSONC, TOML, YAML, Python, and Bash with consumer-compatible parsers. The local run checked 173 files and retained two PowerShell `UNAVAILABLE` records because the macOS host has no PowerShell parser.
- Supporting contracts are failable and machine-readable: dead-code analysis returns a 28-marker report, the 28-suite matrix has 21 primary invocations plus 7 explicit exclusions with zero unowned omissions, Scripts Quality returns strict `FAIL` with 116 findings, and benchmark-preflight, suite-environment, result-contract, scope, dialect, and runtime-PID negative fixtures pass.
- `scripts/tests/audits/audit-readiness-gates.sh` distinguishes deny-only from strict Geiger policy and retains the 31 dependency packages with unsafe usage. The current deny-only run is `UNAVAILABLE` because Cargo Audit and Cargo Deny cannot fetch the advisory database; strict Geiger is independently `FAIL` for the dependency-unsafe policy.
- Scope boundary: local structural and command-result integrity is implemented, but the project is not release-green. Product findings remain with their named TODO owners, and protected Omega checkout attribution remains TODO-804. External, native, privileged, and feature/Graphify boundaries are not inferred from this local run.
- Post-staging validator refresh: the current tracked/ignored scope is `956`/`28,123` with zero non-ignored untracked paths and the register validator passing. The earlier `927`/`37,803` counts in the TODO-799 snapshot predate the new audit-infrastructure files.

## Implementation Reconciliation (2026-08-04, QUIC KDF secret-length validation)

- **Exact secret boundary:** `src/crypto/quic_kdf.rs` validates every traffic-secret derivation against the exact 32-byte QUIC/TLS secret contract through one fixed-array helper. `derive_initial_secret()` remains separate because it consumes a destination connection ID, not a traffic secret. The former zero-padding/truncation behavior is gone.
- **Error propagation:** KDF functions return `KeyMaterialError`; transport packet helpers map it to `ConnectionError::CryptoError`. Initial/Handshake/0-RTT/1-RTT packet installation, Retry re-derivation, lifecycle setup, transport-owned key updates, and `KeyScheduleHooks` now return and propagate errors. Invalid material is rejected before the affected key slot is mutated.
- **Regression boundary:** The established previous-read-key AEAD window remains unchanged. A trial HP rotation was removed after it broke the existing packet fallback because that window does not retain previous HP keys.
- **Verification:** Local `cargo check --lib --features rust-tests`, strict library Clippy, 26 KDF tests, 29 packet tests, and 4 connection key-update tests pass. Full workspace/all-target tests completed with 2,204/2,206 passing; the two failures are the existing TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness boundaries. Full workspace/all-target strict Clippy reports only the existing backend type-complexity and DNS-runtime needless-borrow findings; no TODO-633 diagnostic was emitted.
- **Scope boundary:** No UI, Omega, remote checkout, or unrelated TODO owner was changed. TODO-633 is locally implemented but blocked by the unchanged workspace baseline failures and unavailable authorized native/external proof; it is not marked complete.

## Implementation Reconciliation (2026-08-04, bounded Fountain decoder state)

- **Wire admission:** Fountain keeps the global deterministic `meta.sequence` as the LT symbol ID, while `repair_index` remains the bounded per-window ordinal. Because `WireProfile::validate()` restricts Fountain to one interleave lane, `ReceiveWindow` binds each ordinal to exactly one global ID and rejects duplicate ordinals or duplicate IDs before repair-payload allocation. The existing non-Fountain anchor rule is not applied to the rateless ID contract.
- **Decoder limits:** `LTDecoder` now bounds retained repair equations by symbol count, retained payload bytes, degree-one queue length, and cumulative dependency-propagation work. Direct decoder construction defaults to `5*k+4` symbols; the validated wire path passes its profile repair capacity. FIFO eviction removes the oldest retained equation and increments `quicfuscate_fec_fountain_decoder_evictions_total`; invalid or over-budget input increments the admission-rejection metric. Propagation stops fail-closed when its per-window work budget is exhausted.
- **Propagation and state ownership:** `received_symbols`, `symbol_degrees`, queue membership, symbol order, and retained-byte accounting are updated together. Fully peeled equations release their retained state, and queue IDs are deduplicated so the explicit queue bound is also a hard cardinality bound. The repair ordinal admission state is separate from the non-Fountain repair dedup cache.
- **Regression proof:** Fountain decoder tests pass 25/25, wire tests pass 22/22, the complete FEC group passes 241/241, strict library Clippy passes, and `cargo check --workspace --all-targets --features rust-tests` passes. The full workspace/all-target test run passes 2,207/2,209; the two failures are the unchanged TODO-807 DNS endpoint-resolution and TODO-768 Rustls ClientHello baseline boundaries. Full all-target strict Clippy retains only the existing backend type-complexity and DNS-runtime needless-borrow findings.
- **Scope boundary:** No UI, Omega, remote checkout, or unrelated decoder family was changed. GF4/GF8/GF16 equation-store complexity remains TODO-636, and direct-public FEC input contracts remain with their existing owners. TODO-634 is locally implemented but remains blocked until the unchanged workspace baseline and authorized external/native proof gates close.

## Implementation Reconciliation (2026-08-04, linear FEC equation peeling)

- **Representation:** `Decoder8`, `Decoder4`, and `Decoder16` now retain equations in `VecDeque`. Each peeling pass snapshots its input length, pops each equation once, and appends unresolved equations at the back in original order. This removes the repeated `Vec::remove`/`Vec::insert` shifts without changing solver iteration order or the existing GF backend contracts.
- **Benchmark:** `benches/fec_pipeline.rs` adds an isolated k=256 GF8 peeling benchmark with 128 disjoint two-source equations and 128 systematic sources. With identical Criterion settings on this host, the old Vec path measured 17.598 ms and the new VecDeque path 16.080 ms per batch, an approximately 8.6% reduction. The benchmark initializes the same GF tables as production FEC construction and is available through the `benches` feature.
- **Regression proof:** Complete FEC tests pass 241/241, all-target workspace checking passes, strict library Clippy passes, format and diff checks pass, and the full workspace/all-target run passes 2,207/2,209. The two failures remain the unchanged TODO-807 DNS endpoint-resolution and TODO-768 Rustls ClientHello boundaries. Full all-target strict Clippy retains only the existing backend type-complexity and DNS-runtime needless-borrow findings; benchmark strict Clippy is additionally blocked by two pre-existing unrelated dead-code warnings.
- **Scope boundary:** No UI, Omega, remote checkout, solver algorithm, or decoder-family semantics were changed. The authorized Omega FEC matrix remains unavailable because the local SSH client fails with `No user exists for uid 501`; TODO-636 is locally implemented but remains blocked by that native gate and the unchanged global baseline failures.

## Implementation Reconciliation (2026-08-04, Wiedemann scratch ownership)

- **Scratch ownership:** `Decoder8::try_eliminate_wiedemann` now partitions payload-byte indices into worker-sized Rayon chunks and initializes `WiedemannScratch` through `map_init`, giving each chunk producer private coefficient columns and one scalar SpMV accumulator. The column dimensions are `n x min(equation_count, n)`, with `n` bounded by the decoder's GF8 source count; the accumulator is cleared before every scalar matrix-vector product.
- **Architecture boundary:** The Wiedemann scalar SpMV scratch is now present on every target, including ordinary x86_64 builds that do not compile AMX. This removes the former zero-filled Krylov-vector path when runtime metadata claimed AMX for a compile-time-disabled binary.
- **Allocation accounting:** Telemetry separates logical column-buffer, SpMV-accumulator, matrix/RHS, Krylov, per-iteration, candidate, and reserved AMX scratch counters. The active path increments only scalar operations; AMX operation and scratch counters remain zero until a verified backend exists.
- **Benchmark surface:** `fec_pipeline` now includes high-loss Wiedemann cases for `k=128` and `k=256` with a two-coefficient full system, zero-valued payload validation, latency measurement, and one-shot allocation-counter profile output. The benchmark is feature-gated and does not alter production decoder policy.
- **Measured profile:** On this host, the worker-sized implementation reduced logical column-buffer events from 4,096 to 1,024 at `k=128` and from 8,192 to 2,048 at `k=256`; scalar SpMV accumulator events fell from 32 to 8 in both cases. The same-session latency comparison was 39.946 ms to 40.603 ms at `k=128` and 121.71 ms to 122.44 ms at `k=256`, a stable result within approximately +2.2% and +0.6%, not a claimed speedup.
- **Verification:** The focused Wiedemann tests pass 2/2, the complete FEC group passes 242/242, the telemetry export test passes 1/1, `cargo check --all-targets --features rust-tests` passes, `cargo clippy --lib --features rust-tests -- -D warnings` passes, the benchmark target check passes, the high-loss k=128/256 benchmark runs successfully, and format/diff checks pass. The benchmark harness required explicit GF-table initialization, now provided through the production FEC constructor.
- **Global boundary:** The full workspace/all-target test run passes 2,208/2,210; the only failures are TODO-807 DoH endpoint DNS resolution and TODO-768 Rustls ClientHello construction. All-target strict Clippy retains only the three existing client backend/DNS-runtime diagnostics, and benchmark strict Clippy retains only the two existing dead-code diagnostics in TLS cover and server metrics. The authorized Omega/native matrix remains unavailable because the local SSH client fails with `No user exists for uid 501`; no native or remote proof is claimed.
- **Scope boundary:** Solver mathematics, validation, and Gaussian fallback remain owned by their existing boundaries and were not changed. No UI, Omega, remote checkout, or unrelated TODO owner was changed.

## Implementation Reconciliation (2026-08-04, receive-side Retry and destination-CID ownership)

- **Retry ownership:** `src/transport/connection/parts/impl_recv.rs` now consumes the owned pre-parsed Retry header after integrity verification. The client moves `Header::token` into `config.initial_token` instead of cloning it, while preserving Retry version filtering, integrity verification, SCID adoption, Initial secret derivation, header-protection installation, short-header reserve refresh, and Initial packet-number-space reset.
- **CID tracking:** `src/transport/pn.rs::cid::ConnectionIdSet` now stores `ConnectionId` values directly in `HashSet<ConnectionId>`. The fixed-size `Copy + Hash` identity remains unchanged and `set_destination_cid()` no longer converts each destination CID to a heap `Vec`; version-negotiation reset and all receive-side CID-learning callers retain the same set lifecycle.
- **Regression surface:** `src/transport/connection/parts/tests.rs` adds a valid Retry path test that verifies the moved token, adopted Retry SCID, retained set membership, and Initial packet-number reset. `scripts/benchmarks/ci_regression.rs` measures the complete authenticated Retry receive and separate insert/contains cases for 16 inline destination CIDs. The CID module test verifies duplicate insertion and value lookup.
- **Measured boundary:** The new Criterion cases on this host report `authenticated_retry` at `[10.840, 10.887, 10.912] us` per receive, `insert_inline_ids` at `[1.2300, 1.2365, 1.2461] us` per 16 inserts, and `contains_inline_ids` at `[251.56, 262.58, 277.34] ns` per 16 lookups with 10 samples, 1 s warm-up, and 2 s measurement. This is a focused ownership/performance surface; it is not presented as an absolute allocation count.
- **Verification boundary:** Focused Retry/CID tests, the 538-test transport filter, workspace all-target checking, library strict Clippy, benchmark compilation/execution, formatting, and diff hygiene pass. The full workspace/all-target run passes 2,210/2,212; the two unchanged failures are TODO-807 DoH endpoint DNS resolution and TODO-768 Rustls ClientHello construction. Workspace all-target Clippy retains the existing three client diagnostics, and benchmark Clippy retains the existing two dead-code diagnostics. Authorized Omega/native proof remains unavailable.
- **Scope boundary:** `ConnectionId::from_ref` remains the bounded inline stack copy owned by TODO-258. Header-parser allocations, Initial-send token reuse, pre-parsed-header reuse, UI, Omega state, remote state, and unrelated clone owners remain outside TODO-638.

## Implementation Reconciliation (2026-08-04, StealthShaper RNG seed lifecycle)

- **Policy:** `StealthShaper::new()` now treats the pacing-jitter seed as non-cryptographic runtime state that still must be fresh. `crate::rng::fill_secure()` failure returns a typed `StealthShaperInitError<T>` and never enters `Xoshiro256pp::from_seed()` with zero or deterministic replacement bytes.
- **Ownership:** The initialization error returns ownership of the original congestion controller. `Recovery::set_stealth_mode()` restores that controller before returning `StealthShaperError`, emits an operator-visible warning, and leaves the connection on its base BBR2, BBR3, or CUBIC path. No new configuration knob is introduced; the fixed policy is disable activation while preserving transport availability.
- **Runtime propagation:** `Connection::set_cc_stealth_profile()` and the Brain runtime-delta path now return the typed error. Brain-driven profile activation uses the same Recovery boundary as startup activation, so a later entropy failure cannot silently install a deterministic shaper or replace the active controller with the temporary `mem::replace` placeholder.
- **Reno boundary:** `StealthReno` uses an explicit RNG-free constructor because Recovery never invokes a randomized post-ACK path for Reno. The wrapper retains state continuity without requesting secure entropy or claiming pacing jitter.
- **Regression proof:** Forced-failure tests cover direct shaper construction, BBR2/BBR3/CUBIC Recovery retention, Reno activation without entropy, and Brain runtime propagation. The stealth-focused library group passes 266/266, the public CC/Recovery integration targets pass 20/20 and 2/2, workspace all-target checking passes, strict library Clippy passes, and format/diff hygiene passes. The full library run passes 2,214/2,216; the two unrelated failures remain TODO-807 DoH endpoint DNS resolution and TODO-768 Rustls ClientHello construction. The no-fail-fast workspace run also executes every target: the `quicfuscate` binary passes 41/43, with the two existing TODO-800 runtime-reload PMTU fixture failures.
- **Global gate boundary:** Workspace all-target strict Clippy reports only the three pre-existing client backend/DNS-runtime diagnostics. Omega/native proof remains unavailable because the authorized SSH path fails locally with `No user exists for uid 501`; GitHub push remains unavailable because DNS cannot resolve `github.com`.
- **Scope boundary:** This change covers only StealthShaper seed lifecycle and its transport/Brain propagation. Cryptographic key, token, nonce, padding/timing fast-RNG, configuration, UI, Omega, and remote-state ownership remain with their existing TODO boundaries.

## Implementation Reconciliation (2026-08-04, H3 masquerade cookie time source)

- **Runtime source:** `Http3Masquerade::generate_realistic_cookies()` now reads `crate::time_source::now_system()` and keeps `generate_realistic_cookies_at(timestamp)` as the pure rendering boundary. Direct `SystemTime::now()` is no longer used by the production cookie path.
- **Invalid-clock policy:** A pre-Unix-epoch value omits only the optional cookie. The remaining pseudo-headers and persona headers are still generated, and no zero timestamp is emitted as a silent fallback.
- **Regression surface:** Crate-local coverage installs a fixed `TimeSource` and verifies both normal timestamp propagation through `generate_headers()` and pre-Epoch cookie omission. The existing scalar/SIMD formatter and header-shape coverage remains unchanged.
- **Scope boundary:** The normal H3 masquerade caller path is covered. The independent cover-traffic scheduler and its direct monotonic cadence remain outside this task under TODO-677.
- **Test isolation:** The canonical RNG failure hook is thread-local under `cfg(test)`, so forced entropy tests cannot alter parallel tests that exercise normal secure randomness.
- **Verification status:** The focused H3 filter passes 9/9, the external persona-header target passes 13/13, and the complete stealth filter passes 268/268. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: the library passes 2,216/2,218, with unchanged TODO-807 DNS and TODO-768 Rustls failures, and the `quicfuscate` binary passes 41/43, with the two existing TODO-800 PMTU fixture failures.
- **Global gate boundary:** Workspace all-target strict Clippy reports only the three pre-existing client backend/DNS-runtime diagnostics. Authorized Omega/native proof remains unavailable because the local SSH client fails with `No user exists for uid 501`; the GitHub push remains unavailable because `github.com` DNS resolution fails.

## Implementation Reconciliation (2026-08-04, domain-fronting selection semantics)

- **Primary contract:** `DomainFrontingManager::get_fronted_domain()` now advances exactly one atomic sequence slot per non-empty call and returns strict round-robin order. Serial calls are deterministic; concurrent calls preserve slot coverage while completion order remains scheduler-dependent.
- **Random boundary:** `random_domain()` remains the explicit unpredictable selection method. No seed, jitter flag, engine field, standalone TOML field, environment variable, or runtime policy was added.
- **Empty input:** Both selection methods return `cdn.cloudflare.com` without panicking. The owned `String` return contract remains unchanged; nonexistent `_ref` and `set_domains` API claims were removed from the documentation.
- **Consumers:** Cover scheduler initialization, SNI/Host fronting, and WebTransport cover use manager round-robin. MASQUE proxy authority intentionally remains the first configured domain plus `:443` as a stable connection endpoint.
- **Regression surface:** Serial exact-sequence and concurrent-coverage tests replace the previous probabilistic jitter assertion. The focused domain-fronting filter passes 9/9, the complete stealth filter passes 269/269, the standalone stealth-config target passes 9/9, and the stealth-mode integration target passes 7/7. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: the library passes 2,217/2,219 with unchanged TODO-807 DNS and TODO-768 Rustls failures, and the `quicfuscate` binary passes 41/43 with the two unchanged TODO-800 runtime-reload PMTU fixture failures. Workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics.
- **External boundary:** Authorized Omega SSH proof remains unavailable because the local client reports `No user exists for uid 501`; GitHub publication remains unavailable because DNS cannot resolve `github.com`.

## Implementation Reconciliation (2026-08-04, preloaded TLS key lock ownership)

- **Key owner:** `PreloadedServerIdentity` keeps certificate bytes separate from `LockedKeyMaterial`; the private-key PEM remains `Zeroizing<Vec<u8>>`, and the guard records whether the configured policy disabled locking, a process-wide `MCL_FUTURE` owner covers the allocation, an individual `mlock` succeeded, or locking was unavailable.
- **Release order:** A rejected identity's guard zeroizes the exact live key range first and calls `munlock` only for its own successful individual lock. The accepted static identity intentionally remains process-lifetime-owned because active TLS providers borrow it until process exit; process-wide `mlockall` remains TODO-516-owned.
- **Duplicate/conflict policy:** Exact same certificate/key bytes are idempotent and return `AlreadyLoaded`; a different identity fails with a typed TLS error. The publication helper handles the `OnceLock::set` race and drops every rejected value through the guard.
- **Configuration wiring:** Standalone and embedded server identity loading pass `SecurityConfig.lock_memory` into qftls. Standalone startup reports successful `MCL_FUTURE` coverage to qftls; finite `MCL_CURRENT` protection leaves later key allocations on the individual-lock path.
- **Proof wiring:** An isolated child-process test generates real certificate/key fixtures, verifies first load, same-identity idempotence, and conflicting-identity rejection. A local publication test exercises accepted, same, and rejected values, including the guard drop path. Focused qftls lifecycle tests pass 2/2; the broader qftls filter passes 22/23 with only the unchanged TODO-768 Rustls ClientHello failure. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: the library passes 2,219/2,221 with TODO-807 DNS and TODO-768 Rustls failures, the `quicfuscate` binary passes 41/43 with the two TODO-800 runtime-reload PMTU fixture failures, and all other targets pass. Workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics. Native Linux and remote publication gates remain unavailable.

## Implementation Reconciliation (2026-08-04, TUN unaligned BMI2 header load)

- **Alignment contract:** `src/interface.rs::parse_ip_header_bmi2()` now uses `std::ptr::read_unaligned` for the four-byte IPv4 header word. No raw `*const u32` dereference remains in `src/interface.rs` or `src/interface/`.
- **Regression surface:** `write_packet_accepts_intentionally_unaligned_ipv4_slice` forces a non-four-byte-aligned subslice and verifies successful device output plus IPv4 telemetry. On x86-64 with BMI2 support, `bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported` calls the target-feature parser directly; unsupported x86-64 CPUs skip that optional hardware-specific invocation, while the portable write test still exercises the scalar dispatch path.
- **Scope boundary:** CPU-profile/BMI2 feature dispatch, generic TUN read/write result contracts, Unix syscall progress and close ownership, Wintun, WFP, and negative platform proof remain TODO-843 through TODO-848-owned boundaries.
- **Verification status:** `interface::tests::` passes 11/11 on this ARM64 macOS host and `rt-interface` passes 4/4. Workspace all-target checking passes, strict library Clippy passes, and workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics. The no-fail-fast workspace matrix executes every target: the library passes 2,220/2,222 with unchanged TODO-807 DNS and TODO-768 Rustls failures, the `quicfuscate` binary passes 41/43 with the two unchanged TODO-800 runtime-reload PMTU fixture failures, and all other targets pass. Formatting and diff hygiene pass. The x86-64 BMI2-specific test is target-gated and was not runnable on this ARM64 host; native x86/Linux and remote publication remain separate closure gates.

## Implementation Reconciliation (2026-08-04, reproducible dependency resolution)

- **Version ownership:** `config/tool-versions.env` is the source-owned version contract for Bun `1.3.14`, Rust `1.97.1`, the explicit nightly lane, Tauri CLI `2.11.4`, Cargo Audit `0.22.2`, Cargo Fuzz `0.13.2`, and Critcmp `0.1.8`. `rust-toolchain.toml` pins the default Cargo toolchain to `1.97.1`; this exact baseline is not an MSRV declaration.
- **Lock ownership:** CI and release workflows use `bun install --frozen-lockfile`; release-critical Cargo builds, checks, tests, Clippy, metadata, and Tauri packaging forward `--locked`. The Tauri host lockfile was reconciled against `apps/tauri/src-tauri/Cargo.toml` without an intentional dependency upgrade.
- **Action ownership:** Mutable `dtolnay/rust-toolchain@master` references were removed. Stable workflow lanes declare `1.97.1`, the fuzz lane declares `nightly`, and release-critical installed tools use exact versions plus `--locked`.
- **Reproducibility gate:** `scripts/audits/verify-reproducible-dependencies.sh` statically audits all workflow files, runs two locked Cargo metadata resolutions for each manifest, runs two frozen Bun dry-run resolutions with identical `bun pm hash`, and validates the active Bun/Rust versions. The local result is `RESULT: PASS - dependency and toolchain resolution is reproducible` with Bun lock hash `10111F769AB0DF7E-c8bf34ac712c2681-9B1E6056451B6CA1-bfc42866eebd8464`.
- **Native Tauri evidence:** On this ARM64 macOS host, `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml --locked`, `cargo clippy --manifest-path apps/tauri/src-tauri/Cargo.toml --locked --all-targets -- -D warnings`, and `cargo test --manifest-path apps/tauri/src-tauri/Cargo.toml --locked` pass; the host test target reports 41/41. The check emits only the three pre-existing library dead-code warnings.
- **External boundary:** This local pass does not claim GitHub-hosted CI, Linux/Windows native packaging, updater signing, or tagged release publication. `cargo tauri build --help` confirms the `-- --locked` runner-argument contract, but full signed release packaging remains an external platform/credential gate. No UI source or remote checkout was changed.

## Implementation Reconciliation (2026-08-04, feature-gated test target contract)

- **Cargo contract:** The root package retains 71 integration-test targets and every source path exists. All 64 sources with crate-level feature cfgs now declare the same feature prerequisites in `Cargo.toml`; the orchestrator disabled branch and the unsupported-host no-op tests were removed so a missing feature or platform cannot masquerade as coverage.
- **Runner contract:** `qf_cargo_test_run_expect()` requires a positive executed-test count and a named successful test marker. `test-transport.sh` passes `rust-tests,io_uring` for Linux io_uring and kernel-hotpath targets, `rust-tests,internal_af_xdp_experimental` for XDP, verifies one intended test in every transport integration target, and writes structured Linux-only `SKIP` records on macOS. Desktop/web-admin Rust integration invokes the orchestrator with `rust-tests,orchestrator` and verifies one real body in all five targets. The full-suite utility passes the exact Linux feature sets as well.
- **CI contract:** The SIMD self-check lane passes `rust-tests,simd-selfcheck` and requires the `varint_roundtrip_and_consistency` success marker. The default all-target feature-matrix lane passes `rust-tests`, and non-empty matrix entries append that baseline feature.
- **Negative proof:** `scripts/tests/fast/test-dynamic-discovery-fail-closed.sh` now runs real Cargo invocations with one required feature removed for SIMD and Orchestrator targets. Both must exit nonzero, identify Cargo's `required-features` contract, and contain neither `running 0 tests` nor a green test-result line.
- **Local proof:** Cargo metadata reports zero crate-feature-gated targets without matching `required-features`; `cargo check --all-targets` passes; SIMD self-check passes 14/14; Orchestrator integration passes 2/2; the dynamic-discovery negative contract passes; and the macOS transport suite passes 541/541 basic transport tests, 13/13 anti-replay and 20/20 congestion tests, all 11 target-scoped transport checks with their named markers, and explicit Linux-only `SKIP` records. The combined desktop/web-admin validation suite passes its desktop and web-admin checks with 0 errors/0 warnings, desktop unit tests 370/370, web-admin unit tests 285/285, and the five Rust targets with 5/3/2/1/7 tests. The broad workspace all-target gate reaches 2,308/2,308 library tests and 41/43 binary tests; its exit is still limited to the two unchanged runtime-reload assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`.
- **Resource boundary:** After the broad gate, the filesystem reports 11 GiB free and `target/` is 11 GiB, below the 13 GiB target ceiling used for this task.
- **Architecture boundary:** The five architecture-specific test targets no longer compile as empty crates. On this arm64 host, `rt-random-aes-ctr` executes 1/1, while the four x86_64-only targets emit one ignored test each with an explicit `SKIP: target requires x86_64` reason.
- **External boundary:** The Linux kernel, AF_XDP, and native io_uring runtime bodies remain CI/Omega-gated and are not claimed by this macOS run. No production or protected UI surface changed.

## Implementation Reconciliation (2026-08-04, Tauri dependency advisory closure)

- **Lockfile scope:** `apps/tauri/src-tauri/Cargo.lock` was intentionally reconciled without upgrading the pinned Tauri release line. The targeted changes are `crossbeam-epoch` 0.9.18 -> 0.9.20, `plist` 1.8.0 -> 1.10.0, `quick-xml` 0.38.4 -> 0.41.0, `quinn-proto` 0.11.13 -> 0.11.15, `rustls-webpki` 0.103.10 -> 0.103.13, `tar` 0.4.44 -> 0.4.46, `anyhow` 1.0.102 -> 1.0.103, `rand` 0.8.5 -> 0.8.6, and `rand` 0.9.2 -> 0.9.3. `rand` 0.7.3 remains because `phf_generator` 0.8 requires the `^0.7` line.
- **Advisory result:** `cargo audit --quiet --json --file apps/tauri/src-tauri/Cargo.lock` returns zero vulnerabilities. The original 10 actionable RustSec vulnerabilities are gone without adding an advisory ignore. The remaining inventory is 19 transitive warnings: 17 archived GTK3/URLPattern packages plus `glib` 0.18.5 and `rand` 0.7.3. `glib >=0.20.0` is incompatible with the pinned GTK3 0.18 ABI; `rand >=0.8.6` cannot satisfy the legacy `phf_generator` 0.8 `^0.7` requirement. `anyhow` and the patchable `rand` 0.8/0.9 lines were upgraded.
- **Reachability contract:** `scripts/audits/verify-tauri-dependencies.sh` parses locked Cargo metadata, computes reverse paths from each warning package to `quicfuscate-desktop`, rejects direct warning dependencies, verifies the exact 19-entry inventory and blocked patch ranges, rejects any vulnerability, and checks the lockfile hash before and after metadata and Cargo Deny. It emits one source-grounded path per advisory, distinguishing Tauri GTK3/WebKit runtime paths from URLPattern/parser and macro build paths.
- **Deny policy:** `config/deny-tauri.toml` keeps `ignore = []`, scopes unmaintained and unsound advisories to transitive dependencies with `workspace`, allows the already reachable `MPL-2.0` license, and records the intentional Tauri/GTK/legacy version splits in the multiple-version skip list without polluting the root graph's `deny.toml`. The Tauri binary manifest now declares its inherited `MIT` license. Locked Tauri `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`; four existing informational diagnostics remain for an unmatched `OpenSSL` allowance and three unnecessary skip entries.
- **CI and release:** `config/tool-versions.env` now owns Cargo Deny `0.19.0`. The reproducibility audit validates exact locked Cargo Deny installs. CI security and the release-version contract install Cargo Audit `0.22.2` plus Cargo Deny `0.19.0`, then run the locked Tauri dependency gate before release packaging. Existing Tauri check, Clippy, test, and packaging commands remain locked.
- **Local proof:** With `CARGO_BUILD_JOBS=2` and an isolated temporary target, locked Tauri check, all-target strict Clippy, and the desktop host test target pass; the test target reports 41/41. The check and Clippy output retains only the three pre-existing root-library dead-code warnings at `src/stealth/tls_cover.rs:393`, `src/transport/recovery.rs:441`, and `src/implementations/server/metrics.rs:1552`. The temporary target peaked at 3.8 GiB, was cleaned, and the repository target directory is absent afterward with 20 GiB free.
- **External boundary:** Hosted CI, native Linux GTK/WebKit packaging, Windows packaging, updater signing, and tagged publication were not run locally and remain required release evidence. No UI source, remote checkout, or Omega state was changed.

## Implementation Reconciliation (2026-08-04, frontend dependency advisory closure)

- **Current inventory:** The live 2026-08-04 `bun audit --json` baseline contained 35 advisories across `@sveltejs/kit`, `cookie`, `devalue`, `esbuild`, `picomatch`, `postcss`, `svelte`, `undici`, and `vite`. The complete ID, severity, vulnerable range, dependency path, runtime surface, and disposition table is maintained in `docs/todo/todo-805-frontend-dependency-advisories.md`.
- **Resolved graph:** The Bun lockfile now resolves `@sveltejs/kit@2.70.2`, `svelte@5.56.8`, `devalue@5.9.0`, `cookie@0.7.2`, `esbuild@0.28.1`, `picomatch@4.0.4`, `postcss@8.5.23`, `undici@7.29.0`, `vite@7.3.6`, and `vitest@4.1.10`. Root overrides own the reviewed patch pins for `cookie`, `esbuild`, `picomatch`, `postcss`, `undici`, and `vite`; no advisory ignore was added.
- **Exposure boundary:** Both applications remain `@sveltejs/adapter-static` builds with the existing static fallback and no installed `@sveltejs/adapter-node`. `undici` remains test-only through `jsdom@28`; the `jsdom@30` Node engine change was not introduced. Build, generated-static, browser-bundle, development-server, Tauri frontend, and test-only paths were separately revalidated.
- **Gate ownership:** `scripts/audits/verify-frontend-dependencies.sh` checks Bun `1.3.14`, frozen lock resolution, lock immutability, zero untrusted lifecycle scripts, zero `bun audit --json` advisories, the explicit `bun pm scan` unavailable state, and exact package contracts. It emits machine-readable JSON and fails closed. CI adds `frontend-dependency-security`; release-version-contract runs the same gate before release dependency and packaging operations.
- **Local proof:** The gate reports `result=PASS`, `audit.advisories=0`, `frozen_install=PASS`, `lifecycle_scripts=PASS`, and `package_contract=PASS`; `bun pm scan` is explicitly `UNAVAILABLE` because no scanner is configured. Admin and Desktop checks report zero errors and zero warnings, builds pass, unit tests pass 285/285 and 370/370, bounded loopback dev-server probes pass on ports 1430 and 4173, and the locked ARM64 macOS Tauri host check/Clippy/test lane passes with 41/41 tests.
- **Open evidence:** Hosted CI execution of the package-owned Playwright provisioning and full E2E jobs, Linux/Windows native packaging, updater signing, and tagged publication remain external gates. TODO-756 provides local fail-fast and full browser-run proof. Existing non-failing static-adapter, Vite, Svelte test-warning, and Rust dead-code diagnostics remain documented; none was suppressed. No frontend visual/UI source, remote checkout, or Omega state changed.

## Implementation Reconciliation (2026-08-04, frontend E2E browser prerequisite contract)

- **Version ownership:** `config/tool-versions.env` owns Playwright `1.58.2`; both frontend manifests and `bun.lock` use that exact `@playwright/test` version. The reproducibility and frontend dependency audits validate the version and lock contract.
- **Execution contract:** `apps/svelte-admin/package.json` and `apps/svelte-desktop/package.json` expose the same `test:e2e:install` and `test:e2e:preflight` contract. Their E2E, UI, and debug entrypoints run `scripts/tests/frontend/verify-playwright-browser.sh` before Playwright can start its preview server. The smoke runner uses the same preflight.
- **Browser readiness:** The shared preflight checks the exact CLI version and performs a real headless launch through Playwright `channel: "chromium"`, which matches the Chrome-for-Testing `chromium-1208` artifact. Missing or non-launchable browser state returns one actionable `UNAVAILABLE` environment result with exit code 2; a version mismatch returns `FAIL` with exit code 1.
- **CI alignment:** CI provisions Chromium through the package-owned install script with `--with-deps`, so local and CI use the same source-owned version and install path. The normal installer stalled during ZIP extraction on this host after downloading the complete artifact; local proof used that exact downloaded artifact in the expected cache and does not claim normal installer success here.
- **Local proof:** Empty-cache Admin and Desktop preflights fail closed before preview-server startup. With the declared browser available, Admin passes 70/70 E2E tests and Desktop passes 23/23, with no inventory reduction. Admin/Desktop checks are 0 errors and 0 warnings; unit suites pass 285/285 and 370/370. No frontend UI source, component, style, asset, route, or behavior file changed.
- **External boundary:** Hosted CI execution of the updated browser installation and E2E jobs remains open evidence. This is the only TODO-756 gate not proven in the current ARM64 macOS session.

## Implementation Reconciliation (2026-08-04, Graphify relationship evidence contract)

- **Entrypoint:** `scripts/audits/verify-graphify-evidence.sh` resolves the source-owned Graphify Python runtime and invokes `scripts/audits/verify-graphify-evidence.py`. The implementation refuses to reuse an output directory and writes run-scoped evidence under `scripts/out/audits/graphify-<UTC>/`.
- **Detection scope:** The current local run enumerates 725 files and 1,255,784 words: 672 code, 29 documents, 24 images, and 3 sensitive files accounted for as redacted. The detected code surface contains 332 Rust files, 139 shell/PowerShell scripts, 115 TypeScript files, and 50 Svelte files. Generated, dependency, agent-state, audit-output, and local-sensitive Git paths remain counted by the machine-readable Git scope without being treated as source inputs.
- **AST identity:** Graphify deterministic extraction runs sequentially to avoid macOS stdin/process-spawn partial-output behavior. Raw nodes and edges are preserved for diagnosis. The normalization layer collapses exact duplicate records, converts source paths to repository-relative paths, creates content-addressed stable node IDs, and retains every unresolved or ambiguous endpoint as an explicit external node with an `endpoint_status` instead of deleting relationship evidence.
- **Current result:** The latest local run produced 14,591 raw nodes and 39,348 raw edges, 12,981 normalized nodes and 39,348 normalized edges, zero normalized dangling edges, stable IDs, and relative source paths. Raw evidence still contains 1,478 dangling edges and 2,104 duplicate IDs; normalized evidence retains 350 ambiguous and 1,465 unresolved edge statuses. Six detected files have no AST nodes, so the extraction contract is `BLOCKED` rather than a relationship pass.
- **Semantic and legacy boundaries:** The run records 53 semantic content files, zero cached files, zero partial subagent results, and no `GEMINI_API_KEY` or `GOOGLE_API_KEY`, therefore semantic extraction is `UNAVAILABLE`. The legacy `graphify-out/graph.json` is explicitly stale because it was built at `57965230c92f1b741a0e52312191f93001897978`, contains 537 nodes and 1,616 links, and lacks current corpus, extraction, tool, and timestamp provenance.
- **Machine-readable contract:** Each run records `quicfuscate.graphify-evidence.v1`, source revision, source-scope SHA-256, extraction mode, Graphify version, timestamp, ignored/generated policy, sensitive policy, semantic cache state, unsupported surfaces, raw and normalized AST artifact paths, and a report path. `scripts/tests/audits/verify-audit-completeness.sh` validates the latest manifest, normalized non-dangling identity, semantic classification, artifact presence, and stale legacy attribution. `BLOCKED` and `UNAVAILABLE` are valid fail-closed outcomes and never count as project-green evidence.
- **Scope boundary:** This contract changes audit tooling and evidence only. It does not modify Rust product behavior, frontend source, UI surfaces, remote state, or Omega checkout state. Native runtime proof, hosted semantic credentials, and any remaining parser/relationship remediation stay explicit open gates under TODO-759.

## Implementation Reconciliation (2026-08-05, DNS query wire admission)

- **Shared parser contract:** `src/dns/mod.rs::parse_dns_query()` admits only supported query flags, exactly one question, bounded RFC 1035 labels and names, and backward-only compression pointers. Reserved prefixes, forward/header/self pointers, pointer loops, and overlong names fail closed.
- **Wire preservation:** Parsed queries retain expanded byte-preserving QNAME bytes for answer owner names and the exact original question section, including casing, compression bytes, non-UTF-8 labels, raw QTYPE, and QCLASS. Synthetic response builders preserve that representation and applicable RD/CD flags.
- **Packet integrity:** Server IPv4 UDP/53 admission enforces exact IP/UDP lengths, rejects all fragments, validates the IPv4 header and present UDP checksums, and retains the legal IPv4 zero-checksum case. IPv6 admission enforces exact lengths, immediate UDP framing, and a mandatory valid UDP checksum.
- **Targeted proof:** DNS parser tests passed 36/36 and the complete server module passed 147/147. Formatting and diff hygiene passed. Native Linux/TUN, Omega, external publication, and TODO-721 UDP transaction matching remain separate gates.
