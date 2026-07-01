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
| MASQUE manager | `compat-only` | retained outside canonical product path |
| XOR obfuscation | `compat-only` | not part of canonical product path |
| `transport::batch` | `experimental/internal` | rust-parity/test-only transport surface |
| `accelerate::*` parity helpers | `compat-only` | internal runtime owner plus explicit `rust-tests` parity surface |
| `accelerate::random` helpers | `compat-only` | heuristic/perf helper surface only |
| Packet-number decode dispatch | `active` | `transport::packet` calls `optimize::transport::decode_packet_number()` after header protection removal; BMI2/SVE2/NEON/scalar dispatch preserves QUIC reconstruction semantics |

## Runtime Complexity Layer Model

The retained complexity in this repository is intentional and should be read through four explicit layers. This is the canonical architectural interpretation after the owner-reduction programs.

| Layer | Purpose | Canonical examples |
|---|---|---|
| `canonical runtime/product path` | user-visible retained runtime behavior and stable product contract | `src/core.rs`, `src/transport/connection.rs`, `src/crypto/` product contract, `src/fec/` public `auto` / `off` contract |
| `adaptive policy/control` | runtime policy loops that tune retained capability without changing the product contract | `src/brain.rs`, `src/stealth/`, `src/fec/` target/family auto-controller |
| `platform acceleration` | hardware detection, SIMD dispatch, Linux fast paths, and owner-local hot-path helpers | `src/optimize/`, `src/simd.rs`, `src/optimize/udp.rs`, `src/optimize/uring_batch.rs` |
| `compat/test/experimental` | retained compatibility machinery, parity hooks, and explicitly gated internal surfaces | MASQUE compatibility, `internal_af_xdp_experimental`, `rust-tests`, `benches` |

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
- The io_uring server send path batches all outgoing packets from a connection into a single
  `io_uring_enter` call; client outbound path dispatches via `UringBatchSender` in `IoDriver`.
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
| Data-plane AEAD posture | `src/crypto/`, `src/simd.rs` | Product contract is `Aegis128L` or `Morus1280_128`; internal width variants remain backend machine room only | `scripts/tests/rust/rt-security-suite.rs`, `scripts/tests/rust/rt-property-suite.rs`, `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs` |
| TLS-visible handshake boundary | `src/qftls.rs` | rustls owns real TLS protocol semantics; TLS Cover is overlay/cover only | `docs/todo/done/todo-85-tls-cover-and-rustls-boundary-clarification.md`, `scripts/tests/audits/audit-runtime-guardrails.sh` |
| Packet protection ownership | `src/transport/packet.rs`, `src/transport/connection.rs` | Packet protection and data-plane AEAD are fork-specific transport decisions, not TLS cipher-suite claims | `docs/todo/done/todo-76-forked-aead-protocol-posture-clarification.md`, targeted transport rust-tests, `audit-runtime-guardrails.sh` |
| Unsafe SIMD / crypto machine room | `src/crypto/`, `src/simd.rs`, `src/optimize/` | Unsafe and SIMD stay internal or parity-scoped; product/runtime claims stay at owner boundaries only | `cargo clippy --all-targets --all-features -- -W clippy::all`, `scripts/tests/audits/audit-all-comprehensive.sh`, `scripts/tests/audits/audit-runtime-guardrails.sh` |
| Stealth/TLS-cover boundary | `src/stealth/`, `src/qftls.rs` | Stealth owns persona and cover policy; rustls still owns real TLS protocol semantics | `docs/todo/done/todo-81-stealth-capability-preservation-and-simplification.md`, `docs/todo/done/todo-85-tls-cover-and-rustls-boundary-clarification.md` |

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
| FEC empirical proof | `scripts/tests/suites/test-fec-auto-controller-proof.sh`, `scripts/tests/suites/test-fec-auto-controller-scenarios.sh` | clean-path efficiency, escalation, cadence, recovery, and backend-family evidence |
| Retained crypto performance evidence | `scripts/benchmarks/suites/bench-retained-crypto-backends.sh` | whether retained `Aegis128L` / `Aegis128X4` / `Aegis128X8` / `Morus1280_128` machine room earns its complexity |

### Evidence Limits

- The current evidence proves active regression resistance, retained-contract consistency, and meaningful runtime/benchmark coverage.
- It does not claim formal verification.
- It does not replace external security review of the retained custom data-plane crypto and SIMD machine room.

### Release Scope
- Distribution model: source-first release (open-source code distribution).
- Signed desktop binaries are not part of the shipped source artifact set.
- Updater integration exists in code and remains disabled in shipped source builds unless signed artifacts are provided.

### Current Release Checkpoint

- Last fully verified release checkpoint before this documentation sync: `09cb9f2` (`fix: stabilize CI and app backend gates`).
- GitHub `CI` run `28461670844`, `Clippy Matrix` run `28461670906`, and `Release Build` run `28461670799` are green on that checkpoint.
- The CI workflow now includes an `app-backend-checks` job that builds the desktop Svelte bundle for Tauri context, then runs `cargo check` and `cargo test` in `apps/tauri/src-tauri` on macOS.
- The Linux fastpath evidence job is green in the current CI checkpoint. This proves the current non-privileged CI fastpath suite, not a replacement for a privileged production deployment soak.
- TODO-412 (server deploy and real-world profiling baseline) is deferred until server SSH/access details, TLS certificate paths or an approved self-signed test setup, and a profiling target are available.
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
  - controls: Argon2 hashes, `HttpOnly` cookies, `SameSite=Strict`, secure-cookie behavior tied to HTTPS forwarding, per-IP failed-login throttling and lockout, password-change lock (`423`) paths, same-origin POST validation (`Origin` host+port must match `Host` header when present; dev proxies must not rewrite `Host` via `changeOrigin`), and per-session CSRF token checks on authenticated POST routes.
  - verification: `implementations::server::admin_http` tests for lockout, throttling, cookie flags, lock removal, and cross-origin POST rejection.
- QKey issuance and revocation surface:
  - controls: strict QKey parsing and canonicalization, stable token IDs, TTL normalization, revoke path validation, persisted registry constraints, revoked-key rejection during initial auth, SessionId-to-QKey runtime tracking, active-session close on admin revoke, pending-auth revocation race prevention, scheduled revocation processing, and runtime auth-state rebind on source-address churn by DCID/source-id matching.
  - verification: `implementations::server::qkey_registry` tests, admin HTTP QKey API tests, runtime revocation tests, and `qkey_auth_tests::engine_qkey_id_matches_registry_qkey_id`.
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
| low | Updater/signature enforcement not active in source-first release | no binary auto-update trust chain in shipped source artifacts | out of current artifact scope | desktop release |

Current release constraints:
- No signed desktop binaries are provided.
- Updater runtime is integrated but disabled in shipped source builds without signing.

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
- Signed update-channel threats are outside the current source-first artifact scope.

### Deployment Hardening Guide

Server hardening baseline:
- Bind admin HTTP only to trusted interfaces or localhost.
- Enforce firewall rules for QUIC and admin ports; deny all unused inbound paths.
- Run service under dedicated non-root user with minimal filesystem permissions.
- Restrict `config/` and persistent state paths to owner-only access.
- Configure log rotation and retention; avoid logging sensitive token material.
- Back up config and QKey registry on controlled intervals with encrypted storage.

Admin UI hardening baseline:
- Put admin UI behind HTTPS termination in production.
- Ensure forwarded-proto headers are set correctly by the trusted proxy.
- Rotate default admin credentials on first bootstrap.
- Operate IP blocklist with explicit review and rollback procedure.

Desktop hardening baseline:
- Keep updater disabled for source-first builds.
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

## Introduction & Purpose
QuicFuscate is a forked stealth transport and VPN runtime built around a custom QUIC-like transport/data-plane posture, hybrid adaptive FEC, and a cohesive stealth stack. The canonical runtime is designed for strong censorship resilience and high-throughput operation under this forked protocol contract. It is not a drop-in upstream QUIC implementation.

This document provides comprehensive technical documentation for the system architecture, modules, and implementation details in Rust.

### Quick Index (Fast Paths)
- Runtime architecture and module map: [Architecture at a Glance](#architecture-at-a-glance)
- Stealth behavior and mode matrix: [Obfuscation-Modes Overview](#obfuscation-modes-overview)
- TLS boundary and controls: [TLS Boundary: rustls protocol with optional cover overlay](#tls-boundary-rustls-protocol-with-optional-cover-overlay)
- FEC runtime controls and tuning: [FEC Operations Guide](#fec-operations-guide)
- CLI operation and server/client flows: [Usage](#usage)
- Full config schema and env overrides: [Configuration Reference (Full)](#configuration-reference-full)
- Embedded API contracts: [Engine Control Plane (embedded orchestration)](#engine-control-plane-embedded-orchestration)
- Script entrypoints and suites: [Scripts Reference (Authoritative)](#scripts-reference-authoritative)

### Architecture at a Glance
- Modular Rust crate with focused modules:
  - `src/core.rs`: QUIC I/O and session management; maintains rolling `ConnectionStats` including VNNI-accelerated congestion aggregation (`aggregate_congestion`) for cwnd, bytes-in-flight and loss score.
  - `src/crypto/`: AEAD and handshake glue
  - `src/fec/`: Encoder/decoder/adaptive/GF tables
- `src/stealth/`: DoH, HTTP/3 masquerading, TLS Cover, domain fronting, QPACK helpers, active probe detection, runtime Server Push cover coordination
  - `src/reality.rs`: Reality Fallback (Xray-style reverse proxy for active probe mitigation)
  - `src/interface.rs`: Cross-platform TUN interface
  - `src/transport.rs`: Transport module root with focused submodules in `src/transport/` (packet, recovery, frames, h3, xdp, udpfast, connection)
  - HTTP/3 streams: `fin_received` flag tracks stream completion for deterministic GC in `poll()`
  - UDP fast paths: runtime-owned sendmmsg/recvmmsg batching in `src/optimize/udp.rs`, narrowed `udpfast` compatibility coverage, and sendmsg_x batching (macOS)
- `src/brain.rs`: StealthBrain adaptive policy engine (ACK/FEC hints plus compatibility-only MASQUE hint channel), sensor-fusion logic, and Intelligent-mode runtime-policy delta emitter

- `src/profile.rs`: test/compat-only `Aegis128Profile` adapter mapped to `simd::CryptoAeadPlan`
- `src/engine/`: Embedded control plane (`QuicFuscateEngine`, `EngineConfig`, `EngineCommand`, `EngineEvent`, `EngineStats`) for programmatic runtime orchestration
- `src/compress.rs`: Compression manager (zstd-only) with adaptive policy, telemetry-backed decisions, and optional dictionaries
- `src/qftls.rs`: Boundary split between rustls real TLS protocol and optional TLS Cover overlay
  - `src/instrumentation.rs`: Global runtime metrics and health export surfaces (`/metrics`, `/health`)
  - `src/implementations/server/metrics.rs`: Server metrics runtime and HTTP endpoint wiring
  - `src/optimize/`: Optimization submodules now live under `src/optimize/*` and are re-exported through `src/accelerate.rs` to keep the public `accelerate::*` API stable.
  - TLS fingerprint sourcing follows the canonical "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".
  - Unified configuration via `config/quicfuscate.toml`; environment overrides through `QUICFUSCATE_*`
  - Modular script-based architecture with dedicated scripts for each functionality
- Organized script directories: `scripts/build/`, `scripts/install/`, `scripts/utils/`, `scripts/benchmarks/`, `scripts/tests/build/`, `scripts/tests/analysis/`, `scripts/tests/audits/`, `scripts/tests/frontend/`, `scripts/tests/fuzz/`, `scripts/tests/lib/`, `scripts/tests/rust/`, `scripts/tests/smoke/`, `scripts/tests/suites/`, and `scripts/tests/utils/`
- Individual scripts for specific tasks: build management, benchmarking, testing, auditing, and utilities

- Developer Harness: `src/harness.rs` provides a central CLI used by scripts. Unit tests still exist in the codebase, but the harness is the main entry point for scripted internal tooling.
- Desktop App: `apps/svelte-desktop` (SvelteKit + Svelte 5 + bits-ui + Tailwind v4, packaged through Tauri) is the canonical native desktop client with tunnel management, settings, logs, and hardware detection. State is persisted via Tauri `invoke` commands with debounced writes. The selected tunnel surface supports direct `Set QKey` / `Change QKey`, exposes compact live diagnostics (token, loss, recovered packets, policy source), and the shell restores keyboard shortcuts for navigation/tunnel actions plus a fatal-error recovery screen for true hard UI faults.
- Web admin: `apps/svelte-admin` (SvelteKit + Svelte 5 + bits-ui + Tailwind v4) is the canonical admin/control surface that builds into `assets/web-admin/` via `scripts/build/build-web-admin.sh`. It provides dashboard, configuration, QKey management, logging views, and an explicit route-level crash fallback for render/load failures.
- Shared UI packages: `packages/ui` (shared Svelte 5 components: Switch, Select, Toast, ConfirmDialog, Skeleton, GlassCard, ErrorBoundary, SettingRow, AboutContent; plus ripple action, cn utility, toast store, and `createCopyFeedback` hook for clipboard-write + timed visual feedback). `ErrorBoundary` is a real Svelte boundary wrapper that can catch child render failures and render a supplied fallback. `packages/ui` has its own vitest config with 82 unit tests (9 files) under `scripts/tests/frontend/shared-ui/unit/`. `packages/theme` provides the shared CSS layer (glass morphism, layout, tokens, buttons, animations, login, scrollbar).
- QKey: server-issued connection key string (`QKey-...`) that embeds connection parameters (remote, SNI), optional policy presets (stealth/FEC), and a bearer token. QKeys are generated in the Web Admin UI and must be treated like passwords.
- Raw QKeys are one-time reveal credentials: the server returns the full credential at issuance time, but registry/list surfaces remain metadata-only and do not reconstruct raw QKey material later.
- Admin control plane: `src/implementations/server/admin_http.rs` and `src/implementations/server/qkey_registry.rs` provide server-authoritative QKey issuance/revocation, persistence, and runtime policy enforcement surfaces.
- Standalone CLI server runtime: `src/implementations/server/mod.rs::ServerRuntime::new_standalone(...)` owns standalone UDP socket bootstrap, live-state bootstrap, accept-loop ownership, optional standalone TUN setup, and auxiliary shutdown/control-plane signal registration for metrics, Unix admin, and admin-web services.
- Standalone runtime config reload: the server module now also owns runtime reload normalization for stealth overrides, optimize normalization, and `transport.*` TOML overrides. `main.rs` only forwards reload intent and transport state into that server-owned path.
- Server listen-address normalization: standalone CLI and embedded `EngineMode::Server` now derive `ServerConfig.listen` through the same server-owned resolver, so both entry surfaces share one canonical listen-address interpretation for runtime ownership.
- Desktop: imports QKeys (paste/import), persists them per tunnel locally, and uses them for connect/disconnect. Existing tunnel shells can be upgraded in-place through `Set QKey` / `Change QKey`. The desktop UI does not generate server-issued QKeys and does not render them after import.

#### Engine Control Plane (embedded orchestration)
`quicfuscate::engine::QuicFuscateEngine` is the canonical embedding entrypoint for non-CLI integrations. It owns the aggregated `EngineConfig`, selects `ClientRuntime` or `ServerRuntime` via `engine.mode`, tracks lifecycle in `EngineState`, and emits `EngineStats` snapshots for host applications.

Control and observability are explicit through typed channels:

- `EngineCommand`: `Start`, `Stop`, `Connect`, `Disconnect`, `Reconnect`, runtime overrides (`SetStealthMode`, `SetFecMode`, `SetCongestionControl`, `SetTrafficPadding`, `SetTimingObfuscation`, `SetZeroRtt`), and diagnostics/state queries (`GetTunCapabilities`, `GetState`, `GetStats`).
- `EngineEvent`: `StateChanged`, `Connected`, `Disconnected`, `Error`, `StatsUpdated`, `StealthEscalated`.

This keeps CLI and embedded control planes aligned on one runtime mutation path.

### Cohesive Stealth Stack (Hard to Classify)
The stealth design is one coherent browser-like H3/MASQUE flow, not a pile of unrelated
stealth toggles. TODO-464 through TODO-471 are complete and define the production policy.

- Persona: one browser/OS/TLS/H3/QPACK persona is selected per connection and remains immutable for that connection. Profile sequences and interval rotation are next-connection/reconnect policies, not mid-session identity mutation.
- TLS: RealTLS via rustls with optional TLS Cover that generates ClientHello templates and TLS frames from the active profile (no external uTLS/FFI). The Engine client path now passes the uTLS/persona decision instead of hardcoding it off.
- HTTP/3/QPACK: ALPN, header sets, QPACK policy, and framing must align with the selected persona snapshot.
- Core H3/MASQUE: production VPN/TUN payloads use the core H3/MASQUE data plane. The `stealth::MasqueManager` surface is retained compatibility/experimental machinery, not the canonical hot path.
- Domain Fronting: useful only with explicit, vetted fronting configuration. Blind fronting defaults are disabled for Performance, Stealth, and clean Intelligent mode.
- DoH: DNS resolution stays inside the tunnel path and keeps the canonical stealth runtime free of payload-side XOR obfuscation.
- Active Probe Detection + Reality Fallback: probe-like traffic is detected and, when required, relayed via `RealityProxy` to preserve realistic upstream behavior under active scanning.
- Cover Traffic: Cover PING, cover stream, randomized bounded Server Push cover, and escalated WebTransport cover are valid layers.
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
- `stealth::Http3Masquerade` emits realistic `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile` and navigation headers `sec-fetch-{dest,mode,site,user}` plus `upgrade-insecure-requests: 1`.
- `sec-ch-ua` major versions are derived from the active `User-Agent` to maintain internal consistency per browser/OS profile.

### TLS Boundary: rustls protocol with optional cover overlay
- Real TLS: implemented via rustls in `src/qftls.rs` with `CombinedProvider` orchestrating a rustls protocol stack plus optional TLS Cover overlay - supports `--verify-peer`, `--ca-file`, and ALPN negotiation for HTTP/3.
- TLS Cover: cover provider in `qftls::CombinedProvider` is enabled by default and can be disabled with `QUICFUSCATE_TLS_COVER=0`. Generates synthetic QUIC `CRYPTO` frames during the TLS handshake phase only (correct QUIC behavior per RFC 9001 - CRYPTO frames do not appear post-handshake in real QUIC). Post-handshake cover is provided by three layers: Cover PINGs (QUIC PING frames at configurable intervals), Cover Stream injection (fake APPLICATION_DATA on stream 248), and Server Push Cover Traffic / TrafficPadding. The canonical runtime cover mode now comes from the active `StealthManager::runtime_tls_profile(...)`: `off`, `performance`, and `intelligent` drive the cover layer into performance mode, while stealth-heavy modes keep timing/jitter enabled. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) enables TLS Cover extras in the stealth manager (ticket manager and cert chain emulator) but does not control the cover provider itself. Cipher selection is automatic (`auto`) and prefers AES-128-GCM when hardware AES (AESNI/VAES/SVE AES) is available, otherwise falls back to ChaCha20-Poly1305. On x86 the ChaCha keystream dispatches AVX-512 -> AVX2 -> AVX -> SSE4.1/SSSE3 -> Scalar with telemetry (`CHACHA20_X4_AVX2_OPS`, `CHACHA20_X4_AVX_OPS`, `CHACHA20_X4_SSE41_OPS`, `CHACHA20_X4_SCALAR_OPS`). Override via `QUICFUSCATE_TLS_COVER_CIPHER=auto|chacha|aes`.
- Ownership split: `qftls::CombinedProvider` provides a single runtime interface that keeps rustls as the security-critical protocol owner and composes the cover layer for observable mimicry behavior where enabled.
- Fork boundary: rustls/TLS Cover governs the TLS-visible handshake story only. The custom 1-RTT data-plane AEAD posture in `src/crypto/` and `src/transport/*` is a separate fork-specific transport decision, valid only under the explicit full-fork assumption, and must not be interpreted as a TLS cipher-suite or upstream interoperability claim.
- Risk/Tradeoff: enabling TLS Cover increases cover-byte volume and per-packet processing work.
- Certificate tooling: development certificates enabled by feature `dev-certs` (rcgen); production uses PEM chain via `--cert/--key` (server) and CA bundle via `--ca-file` (client).
- Session management: internal session cache for 0-RTT resumption (size-limited, not user-configurable).
  - Anti-replay: 0-RTT data is protected by a SHA-256 strike register (`src/transport/anti_replay.rs`) per RFC 8446 Section 8 and RFC 9001 Section 9.2. The register uses a Bloom fast-negative in front of the full-fingerprint index and a FIFO ring for O(1) capacity eviction. Replayed 0-RTT packets are silently discarded; clients fall back to 1-RTT automatically. Configurable via `[anti_replay]` TOML section.

#### Fingerprint Source Model
- Primary runtime path: deterministic in-memory ClientHello synthesis via `TlsClientHelloSpoofer` from `BrowserProfile` and `OsProfile`.
- Optional external path: top-level `browser_profiles/*.chlo` or `*.chlo.b64` dumps for strict byte-level replay and audit/regression workflows.
- Injection path: selected ClientHello bytes are injected natively through transport configuration (`set_custom_tls`) and then cached in memory.
- Operational rule: external dumps are optional; runtime operation remains available without on-disk profile artifacts.

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
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - forward a ClientHello override template to TLS providers that support CH overrides.
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
  - `QUICFUSCATE_ZSTD_MODE=manual`
  - `QUICFUSCATE_ZSTD_LEVEL=<int>` (default 3)
  - `QUICFUSCATE_ZSTD_WORKERS=<int>` (default 2)
  - `QUICFUSCATE_ZSTD_TARGET_BLOCK=<bytes>` (default 65536)
- Optional tuning (FFI path only):
  - `QUICFUSCATE_ZSTD_STRATEGY=fast|dfast|greedy|lazy2|btopt`
  - `QUICFUSCATE_ZSTD_WINDOW_LOG=<int>`
  - `QUICFUSCATE_ZSTD_CHECKSUM=0|1`
  - `QUICFUSCATE_ZSTD_CONTENTSIZE=0|1`
- Additional initialization hints (FFI path; applied at compressor creation):
  - `ZSTD_c_nbWorkers` is also set from `QUICFUSCATE_ZSTD_WORKERS` if present.
  - `ZSTD_c_targetCBlockSize` is set from `QUICFUSCATE_ZSTD_TARGET_BLOCK` if present.
- Safe fallback behavior: If `compression_zstd_ffi` is OFF, the "unsafe" path transparently uses the safe `zstd` crate under the same headers/mode, so behavior stays consistent across builds.

##### Headers and Compatibility
- Basic frame (no dictionary): `0x5A` + 4B big-endian original length, followed by zstd data.
- Dictionary frame: `0x5D` + 2B dict hash + 2B dict version + 4B big-endian original length, followed by zstd data.
- The internal unsafe compressor/decompressor backend reads and writes the same headers as `compress.rs` helpers for full interchangeability.

##### Dictionary Training and Lookup
- Training: `compress.rs::maybe_train()` periodically builds dictionaries from submitted samples and persists them to `dict_cache/`.
- Lookup: `get_dict_by_id(hash, version)` resolves bytes at runtime; the unsafe decompressor prefers the supplied dictionary but falls back to cache lookup by id.

##### Streaming Compression API
- Internal unsafe FFI backend:
  - The internal compressor streams via `ZSTD_compressStream2` with `targetCBlockSize` to reduce end-to-end latency on large inputs.
  - It automatically selects between direct and streaming mode based on `QUICFUSCATE_ZSTD_STREAM_MIN` (default: 262,144 bytes).
  - Header semantics are identical to direct: `0x5A` (no dict) or `0x5D` (with dict-ID: 2B hash, 2B version, then 4B length).
- Safe path (`src/compress.rs`):
  - `CompressionManager::compress_to_pool()` writes zstd output directly into the caller-provided pool block after the `0x5A` header via `zstd::bulk::Compressor::compress_to_buffer`.
  - Dictionary compression writes directly into the body-pool block after the `0x5D` dictionary header via `zstd::bulk::Compressor::with_dictionary(...).compress_to_buffer(...)`.
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
| MASQUE Manager | compat-only | compat-only | compat-only | compat-only |
| MASQUE Preferred | off | off | off | off |
| Cover Traffic Interval | off | 5 s | 5 s (tightened on escalation) | off at Level 0; 5 s from Level 1 |

Notes:
- Active probing detection is enabled in Stealth, Anti-DPI, and Intelligent; Performance keeps overhead minimal with the detector disabled and no H3 cover-request scheduler. Intelligent starts like Performance at Level 0 and can escalate toward Stealth/Anti-DPI features on probe signals.
- `sec-ch-ua*` hints are emitted only for Chromium family (Chrome/Edge); Firefox and Safari typically omit them.
- `StealthManager` owns all preset baselines and the concrete Intelligent-mode runtime policy derivation for pacing, timing, padding, mimic bias, granularity, and CC profile. `StealthBrain` still adapts transport ACK policy globally, but its Intelligent-mode stealth steering now flows through a narrow runtime-policy delta instead of embedding raw per-actuator mapping logic inline.
- * TLS Cover provider is enabled by default across modes and can be disabled with `QUICFUSCATE_TLS_COVER=0`. Runtime cover performance mode is now driven by the active stealth mode profile rather than relying on ENV-only shadow state. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) only controls TLS Cover extras (ticket manager and cert emulator).
- Risk/Tradeoff: domain fronting behavior depends on current upstream provider policy and regional filtering rules. It is not a safe default cover signal on modern CDNs.
- Core H3/MASQUE is the production VPN/TUN carrier. The compatibility MASQUE manager inside `stealth/` is not the canonical data-plane owner.
- Per-packet MASQUE TX/downlink logs are `debug`-only in the production hot path. CONNECT-UDP lifecycle and peer-flow registration remain `info` for operator observability without packet-rate log amplification.

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
          | cover streams, bounded   |
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
- `StealthBrain` is attached via `CombinedObserver` and continuously translates transport signals into ACK/FEC hints plus an Intelligent-mode-only `StealthRuntimeDelta`.
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
- Gradual escalation (TODO-416): Probe detection uses `EscalationState` with a sliding-window probe counter. Escalation 0→1 requires ≥3 probes in 60s; 1→2 requires ≥8 probes in 120s. A single probe does NOT trigger escalation. De-escalation occurs after a configurable quiet period (default: 300s). Config knobs: `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (default 3), `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2` (default 8), `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (default 300), `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (default 50).
- Explicit transport overrides win over Brain steering. If an operator sets ACK, pacing, jitter, padding, granularity, or mimic-bias overrides, the corresponding Intelligent-mode Brain actuator is locked out for that connection instead of silently re-overriding the operator choice at runtime.
- FEC hints: updates the internal FEC interval and redundancy hint atomics to steer encoder cadence without hard coupling.
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

#### Global Hints System
The StealthBrain module retains a small internal atomic hint surface for cross-module coordination where lock-free reads are still useful:

- **FEC_INTERVAL_HINT_PKTS**: Internal streaming FEC interval hint in packets
- **FEC_REDUNDANCY_PPM**: Internal parts-per-million redundancy hint for FEC encoder cadence
- **INTELLIGENT_STEALTH_LEVEL_HINT**: Internal Intelligent-mode escalation level consumed by Stealth runtime logic

Timing jitter is no longer published through a separate global hint. The Brain now delivers timing updates only through the `StealthRuntimeDelta`, and the live connection uses its own updated runtime timing configuration directly.

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

- The canonical runtime does not route escalation through MASQUE.
- On active probing, the stealth stack escalates to a hardened window (~20 minutes):
  - Adds extra pacing (1-3 ms per packet; 3-7 ms in Anti-DPI) in addition to existing timing gates.
  - Tightens cover-traffic cadence (default 5 s to 2.5 s; 2.0 s in Anti-DPI) with realistic GET/HEAD mix.
  - Raises server-push cover intensity and keeps the HTTP/3 persona stable.
  - Automatically clears after the escalation window (interval reset to 5 s).
- MASQUE stays compiled in as a compatibility experiment and may only be enabled explicitly outside the canonical stealth plan.

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

#### DoH Multi-Provider Rotation

DNS-over-HTTPS now supports multiple providers with automatic round-robin rotation and fallback:
- **Providers**: Cloudflare (`cloudflare-dns.com`), Quad9 (`dns.quad9.net`), Google (`dns.google`), NextDNS (`dns.nextdns.io`).
- **Mechanism**: `DOH_PROVIDERS` array with `DOH_PROVIDER_INDEX` atomic counter for rotation; `resolve_doh_multi()` tries next on failure.
- **Telemetry**: `DOH_QUERIES_TOTAL`, `DOH_FAILURES_TOTAL` counters.

#### Async Stealth Scheduler (Non-Blocking)

The stealth timing system has been fully refactored to eliminate blocking `std::thread::sleep()`:
- `stealth::StealthManager::process_outgoing_packet()` returns `Option<Duration>` delay instead of blocking.
- `core::QuicFuscateConnection` is the single outbound timing owner via `next_packet_release: Option<Instant>`.
- `send()` checks `next_packet_release`; if `now < release_time`, returns `Ok(0)` (yield) without blocking the reactor.
- Transport stealth jitter (`stealth_timing_enabled` / `stealth_timing_max_jitter_us`) is merged into the same release deadline; `transport::Connection::send` no longer maintains a parallel gate.
- When delay expires, clears the block and proceeds to flush `outgoing_fec_packets`.

### Compression Module

The compression module (`src/compress.rs`) provides adaptive zstd payload compression with intelligent policy control:

#### Compression Core Components
- **`CompressionManager`**: Main compression orchestrator with CPU-profile aware zstd tuning (threads, target block sizes, long-distance matching)
- **`CompressionConfig`**: Configuration with minimum length thresholds and compression levels
- **`CompressionPolicy`**: Runtime policy control for adaptive compression decisions
- **`CompressionAnalysis`**: SIMD-powered preprocessing (ASCII/newline/null/high-bit counters + chunk hashing) feeding telemetry (`COMPRESS_PREPROC_*`) and influencing encoder tuning.
- Pool-backed compression writes compressed zstd frames directly into `MemoryPool` / body-pool blocks with `compress_to_buffer`, avoiding an intermediate compressed `Vec` copy while preserving H3 payload semantics and wire headers.

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
Centralized CPU feature detection with comprehensive SIMD support:
- **x86_64**: RDRAND, RDSEED, AES-NI, VAES, PCLMULQDQ, SSE2, SSSE3, AVX, AVX2, FMA, AVX512-F/CD/BW/DQ/VL, GFNI
- **aarch64**: AES, PMULL, SHA2, SHA3, NEON, SVE (autodetect), SVE2
- **Feature mapping to CPU profiles**:
  - `X86_P0`: SSE2, AESNI
  - `X86_P1a`: SSE2, AESNI, PCLMULQDQ
  - `X86_P1b`: +AVX, RDRAND, RDSEED
  - `X86_P1f`: +F16C
  - `X86_P2a`: +AVX2, BMI1/2, LZCNT
  - `X86_P2b`: +RDRAND, RDSEED, FMA
  - `X86_P3a`: +AVX512F/CD
  - `X86_P3b`: +AVX512_BW/DQ/VL
  - `X86_P3c`: +VAES, VPCLMULQDQ
  - `X86_P3d`: +GFNI, GFNI+VAES+PCLMUL
  - `X86_P3e`: +AMX-TILE, AMX-INT8
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
 - **FEC (large-window decode acceleration)**: Done - `simd::amx::matmul_gf256_amx` processes 16x64 GF(256) blocks for internal large-window decoder paths, planner gating & telemetry active, scalar fallback intact.
 - **Utility (RVV)**: Infrastructure for RISC-V Vector (`RVV`) and additional iterator backends are not active in the current build.

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
- **AVX2/AVX512 sorting networks**: 5x faster u32/f32 sorting with SIMD
- **Radix sort for large arrays**: Optimized for performance
- **Fast argsort**: Index-based sorting 3x faster

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
- **Matrix multiplication**: AMX/AVX512F on x86 and dedicated SVE2 Gather/`svmla` on ARM
- **Apple Silicon AMX**: optimized matrix operations
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

// Create a memory pool with configurable parameters
let pool = MemoryPool::new(1024, 65536)?; // 1024 blocks of 64KB each
```

#### Zero-Copy Memory Architecture

**Memory Pool:**
- Zero-copy memory pool with tunables (`--pool-capacity`, `--pool-block`)
- NUMA-aware allocation with node affinity
- Huge pages support (2MB/1GB) for TLB optimization
- Thread-local caching to minimize contention
- Minimum block size is clamped to 2048 bytes for safety; mismatch-sized blocks are dropped on return to preserve invariants.

**Compatibility/Test Utility Structures:**
- `ConstPacketPool` plus its `ConstBuffer` contract remain available only in test and `rust-tests` builds for external regression coverage.
- The old aligned-scratch and lock-free helper cluster in `src/optimize/` is removed from the retained optimize surface because it has no canonical runtime owner in this fork.
- `optimize::memory::transpose_matrix(...)` remains retained as explicit rust-test parity surface, while orphan memory/string utility exports with no runtime or external test owner have been removed.
- `optimize::memory::LockFreeRingBuffer` remains retained only because it still has explicit rust-test parity ownership; the old helper exports for random prefetching, cache-aligned scratch allocation, cache-line clearing, and NUMA-local scratch allocation are removed from the retained surface.
- In `optimize::stealth`, `AsciiSimdBackend` remains the runtime-owned ASCII formatting owner used by persona/header generation, while the old free wrapper functions and perf-smoke shell around it have been reduced or removed because they had no independent runtime or external rust-test owner.
- In `optimize::transport`, `aggregate_congestion(...)` remains the only retained runtime-owned entrypoint, while the old orphan ACK-range search and stream-frame parsing utility surface has been removed; the remaining bitmap/ECN/packet-number helpers stay only as explicit parity/test surface.
- In `optimize::brain`, `decay_histogram(...)` and `jensen_shannon_divergence(...)` remain runtime-owned through `src/brain.rs`, while moving-average, percentile, and activation helpers remain explicit parity/test surface; the old standalone statistics, correlation, and matrix-multiply helper shell has been removed from the retained optimize contract.
- `optimize::sort` is no longer part of the normal optimize product surface in non-test builds; `sort_u32(...)`, `sort_f32(...)`, and `argsort(...)` remain available only as explicit rust parity helpers through `cfg(any(test, feature = "rust-tests"))`.
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
- Legacy AF_XDP socket code is kept behind the internal feature gate `internal_af_xdp_experimental` and is not part of the default production runtime path.
- `OptimizationManager` no longer models live AF_XDP runtime availability as mutable instance state in this fork; there is no separate `available` or `enabled` XDP runtime query surface anymore.
- Optional io_uring UDP Fast Path (Linux, feature `io_uring`) via `UringBatchSender` in `src/optimize/uring_batch.rs` using the official `io-uring` crate (v0.7). Batch `SendMsg` SQE submission with single `submit_and_wait(N)`, graceful fallback to `sendmmsg` on init failure or send error.

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
- Linux outbound dispatch is deterministic: `OutboundDispatch::IoUringBatch` (when feature `io_uring` is enabled and `UringBatchSender` initialised successfully) submits the full batch via io_uring; on failure, runtime falls back to `sendmmsg` batching, then per-packet socket fallback.
- Linux `SystemIoHotpathAdapter` performs one-time batch socket capability initialization on first `sendmmsg` use via the hidden runtime helper `transport::init_socket_acceleration`, keeping runtime hotpath independent from the test-only `transport::batch::BatchProcessor` surface.

#### Platform-Specific Implementations

**Linux (`LinuxTun`):**
```rust
pub struct LinuxTun {
    name: Arc<str>,
    fd: RawFd,
    mtu: u16,
}
```
- TUN device creation via `ioctl(TUNSETIFF)` with IFF_TUN | IFF_NO_PI flags
- Direct file descriptor I/O via `libc::read`/`libc::write` with EINTR retry
- Automatic cleanup in Drop trait
- No intermediate buffering
- MTU configuration support

**macOS (`MacTun`):**
```rust
pub struct MacTun {
    fd: RawFd,
    name: Arc<str>,
    mtu: u16,
}
```
- utun device creation via `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
- 4-byte AF header handling with `libc::readv`/`libc::writev` using iovecs
- Scatter-gather I/O eliminates header copying
- Control socket configuration via `ioctl(CTLIOCGINFO)`
- Automatic cleanup in Drop trait

**Windows/iOS:**
- External TUN factory pattern via `OnceLock<Box<dyn TunDeviceFactory>>`
- Platform-specific implementation injected at startup
- Clear error messages if factory not registered

### Cryptography Design (AEAD-First, Efficient by Construction)
- Product-level data-plane AEAD posture: retained `Aegis128L` and `Morus1280_128` families with hardware-aware automatic selection.
- Constant-time glue and strict nonce/tag checks on hot paths
- Perfect Forward Secrecy via ephemeral X25519
- Runtime selection via FeatureDetector and `simd::planner` (CryptoAeadPlan) chooses the best internal implementation for the selected data-plane AEAD posture

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
- Performance evidence:
  - retained backend evidence is produced by `scripts/benchmarks/suites/bench-retained-crypto-backends.sh`
  - the suite records hardware profile, per-backend throughput, and per-size winners for `Aegis128L`, `Aegis128X4`, `Aegis128X8`, and `Morus1280_128`
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
  - AES-GCM tag derivation (`aes_gcm_tag_aad_only`) uses the selected GHASH seamlessly. `QUICFUSCATE_GHASH=auto|vpclmul|pclmul|sse|scalar` allows targeted backend verification (tests use `__test_set_ghash_override`).
  

### FEC Design (Stability Under Loss)

#### Core Architecture
- **Hybrid design**: Adaptive RLNC + Tetrys-like streaming with automatic mode switching
- **Auto-Mode**: Switches based on observed loss/RTT (bounded by `hysteresis`, smoothed by `lambda`)
- **Telemetry**: Track mode switches via `fec_mode`, `fec_mode_switch_total`

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
- Broderick ARM/AArch64 decode-batch reference after TODO-490: Normal clean `282 us`, Normal 10% loss `514 us`, Strong clean `278 us`, Strong 10% loss `17.5-18.5 ms`, Streaming clean `499 us`, Streaming 10% loss `623 us`.
- Broderick ARM/AArch64 decode-batch reference after TODO-491 lazy full-recovery gating: Normal clean `279 us`, Normal 10% loss `506 us`, Strong clean `200 us`, Strong 10% loss `195 us`, Streaming clean `447 us`, Streaming 10% loss `474 us`.
- Broderick ARM/AArch64 streaming decode reference after TODO-501 lazy tail-loss gating: Streaming clean 128-packet batch `211.75 us` (`-99.213%` time versus the stale full-recovery wakeup baseline) and Streaming deterministic 10% loss batch `307.97 us` (`-97.963%` time), while Tetrys-style tail-loss recovery remains green.
- Broderick ARM/AArch64 lazy-fast-path reference after TODO-498 source-buffer replay: zero passthrough `285.14 ns`, zero reuse `266.47 ns`, Normal no-loss `1.284 us`, Normal no-loss reuse `1.244 us`.
- Broderick ARM/AArch64 send-reuse-hotpath reference after TODO-499: Zero/1400B `233.37 ns`, Normal/1400B `1.1081 us`, Strong/1400B `408.48 ns`, Streaming/1400B `380.88 ns`.
- Broderick ARM/AArch64 data AEAD reference after TODO-500: MORUS wins every retained-backend packet trait path tested; 1400B single seal/open are `1.1944 us` / `1.1885 us` for MORUS versus best AEGIS `2.0736 us` / `2.1307 us`, and batch8 seal/open are `9.3550 us` / `9.4560 us` for MORUS versus best AEGIS `16.699 us` / `17.010 us`.
- Broderick server fastpath reference after TODO-502: `scripts/install/setup-netfilter-fastpath.sh` removes stale lower-priority UDP/4433 ACCEPT rules before reinserting at INPUT line 1, so QuicFuscate UDP bypasses `ts-input` and other prepended chains before the measured `nft_do_chain` path. Repeated Broderick runs leave exactly one UDP/4433 ACCEPT rule at line 1.

#### Connection Benchmark Coverage

- `scripts/benchmarks/ci_regression.rs` contains the CI Criterion hotpath groups for transport send/receive, ACK accounting, STREAM frame encoding, Brain policy application, and stealth padding decisions.
- `connection_1rtt_send_recv` and `connection_1rtt_stealth_compare` use Criterion `iter_batched(..., BatchSize::PerIteration)` so paired-connection construction, CID setup, and key installation are excluded from timed measurement.
- `transport_stealth_padding_decision` protects the real per-packet transport padding decision path. Adaptive padding uses a power-of-two remainder fastpath for the default 64-byte granularity while preserving modulo behavior for custom non-power-of-two granularities.
- The measured routine remains the real 1-RTT path: `stream_send -> send -> recv`.
- Broderick ARM/AArch64 reference after TODO-500 AArch64 MORUS auto-selection: `connection_1rtt_send_recv` is about `4.70 us` for 256B, `5.50 us` for 1024B, and `5.84 us` for 1400B; `connection_1rtt_stealth_compare` is about `5.48 us` stealth-off and `5.55 us` stealth-on.

#### Galois Field Implementations

**GF(2^8) - 8-bit Galois Field:**
- Bit-sliced implementation for cache efficiency
- SIMD-accelerated multiply-accumulate
- Large-window sparse solver support
- Lookup tables for small operations
- SSSE3 nibble LUT slice multiply covers x86 SSSE3 profiles (`FEC_SSSE3_OPS` telemetry); AVX2/GFNI paths record `FEC_AVX2_GF_OPS`/`FEC_GFNI_OPS`.
- VBMI2 nibble gather kernel (`gf16_mul_slice_vbmi2`) drives `FEC_GF16_VBMI2_OPS`; processes 32xu16 per iteration via `_mm512_permutex2var_epi16` tables. Planner selects it for `X86_P3c+`; scalar fallback remains for residual CPUs. Throughput characteristics remain hardware-dependent and are validated on target systems.
- AVX-512 GFNI matrix multiply (`matrix_multiply_avx512`) now streams 64-byte stripes via `_mm512_gf2p8mul_epi8`, recording `FEC_GFNI_OPS`; CPUs without GFNI fall back automatically to the AVX2 FMA kernel.
- NEON and SVE2 slice kernels share nibble tables with adaptive prefetch; `FEC_NEON_OPS` and `FEC_SVE2_OPS` counters expose runtime usage.

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

**Large-window sparse solver (internal strategy):**
- Internal block-iterative solver for large GF(2^8) recovery systems.
- Parallel per-byte solving via Rayon.
- Falls back to Gaussian elimination when the large-window strategy does not converge.

**Public contract vs internal machinery:**
- The canonical FEC runtime surface is intentionally narrow: `FecConfig`, `FecMode`, `FecPacket`, and `AdaptiveFec` runtime operations.
- Decoder selection, large-window solver choice, GF math kernels, and similar implementation details are internal policy rather than product-facing feature posture.
- Test-only harness surfaces such as `Encoder8` and `FecDecoder8` remain available for repo validation and fuzz/property paths, not as product contract.

#### Runtime Control Loop (Transport <-> FEC)

Runtime adaptation is applied continuously in the connection loop:

- `transport::Connection::take_fec_control_delta()` provides transport-level control deltas each tick.
- The connection updates `AdaptiveFec` (`set_stream_every`, `force_streaming_mode`, `set_redundancy_ppm`) before the next encode path.
- Loss accounting feeds `AdaptiveFec::report_loss()` from transport callback counters and connection statistics.

This is the convergence point where transport feedback, StealthBrain hints, and FEC policy remain synchronized during live traffic.

#### Congestion Control Architecture

QuicFuscate uses a pluggable congestion control framework in `src/transport/cc/`. Three algorithms are available, all implemented in-tree with zero external dependencies:

| Algorithm | File | Description |
|-----------|------|-------------|
| **Reno** | `cc/reno.rs` | TCP New Reno (RFC 6582). Conservative AIMD baseline. No pacing. |
| **BBR2** | `cc/bbr2.rs` | BBR v2 (IETF draft-ietf-ccwg-bbr). Loss-aware model-based CC with 4-state machine (Startup/Drain/ProbeBW/ProbeRTT), windowed bandwidth estimation, and pacing. |
| **BBR3** | `cc/bbr3.rs` | Stealth-optimized BBR v3. Same state machine as BBR2 but with overridable gain tables for browser-profile shaping. Default and recommended. |

All three implement the `CongestionController` trait (`cc/mod.rs`). Dispatch uses an enum wrapper (`CcImpl`) with six variants for zero-vtable hot-path performance: `Reno`, `Bbr2`, `Bbr3` (base variants created at startup) and `StealthReno`, `StealthBbr2`, `StealthBbr3` (stealth-wrapped variants, activated at runtime by `Recovery::set_stealth_mode()`). The macro `cc_dispatch!` handles all six uniformly.

**CLI Usage:**
```bash
quicfuscate client --remote server:4433 --cc-algorithm bbr3
quicfuscate server --listen 0.0.0.0:4433 --cc-algorithm reno
```

**Default:** `bbr3`. Only `reno`, `bbr2`, and `bbr3` are accepted; any other value is rejected.

#### StealthShaper Wrapper

`StealthShaper<T>` (`cc/stealth_shaper.rs`) is an optional decorator that wraps any `CongestionController` to inject stealth traffic shaping. It is **not user-selectable** - it activates automatically when the stealth mode is active (controlled by StealthBrain/StealthManager) and deactivates when stealth mode is off.

**What it does (when active):**
- **Browser-profile gain tables:** Overrides BBR3's ProbeBW gain cycle with browser-specific values (Chrome/Firefox/Safari/Edge) so congestion patterns resemble real browser HTTPS traffic.
- **Pacing jitter:** Injects randomized timing perturbations via Xoshiro256++ PRNG (+/- the profile's jitter window) to defeat statistical timing analysis.
- **Flow dampening:** Optional 2% pacing reduction for smoother traffic shape.

**Algorithm-specific behavior:**
- **BBR3 + Stealth:** Full effect - gain table injection + pacing jitter. This is the recommended stealth configuration.
- **BBR2 + Stealth:** Pacing jitter only (BBR2 uses its own gain cycle, not overridable). Still effective for timing obfuscation.
- **Reno + Stealth:** No effect - Reno does not pace, so there is no pacing rate to jitter. Other stealth features (TLS Cover, HTTP/3 masquerading, domain fronting, DoH) still operate independently at the connection layer.

**Lifecycle:** The user selects the CC algorithm (Reno/BBR2/BBR3) and the stealth mode (Off/Performance/Stealth/AntiDPI/Intelligent/Manual) independently. When stealth mode activates, `Recovery::set_stealth_mode(true, profile)` uses `std::mem::replace` to swap the current `CcImpl` variant in place - e.g. `CcImpl::Bbr3` becomes `CcImpl::StealthBbr3(StealthShaper::new(inner, profile))`. This is a zero-cost enum replacement, not an outer wrapper layer. When stealth mode deactivates, the shaper variant is swapped back to the base variant. No manual configuration needed.

### FEC Modes & Algorithms (Current)
- Modes: `Zero`, `Light`, `Normal`, `Medium`, `Strong`, `Extreme`, `Ultra`, `Fountain`, `Streaming`.
- RLNC (GF(2^8)/GF(2^16))
  - Encoder: sliding window, systematic; repair generation via linear combinations with non-zero deterministic coefficients.
  - GF(2^16) path uses nibble (4-bit) operations; coefficients stored big-endian (2 bytes each); Cauchy-style matrix ensures invertibility.
- Internal large-window decoder strategy
  - Bitsliced multi-lane MatVec with internal heuristics for projection/lanes.
  - Verification path checks `A_k * X == B` on a small sample and falls back to Gauss on mismatch.
- Streaming (Tetrys-like)
  - Emits 1 repair per `N` sources; `QUICFUSCATE_FEC_STREAM_EVERY` overrides cadence (min 1; default computed from CPU profile).
- Seamless transitions
  - Cross-fade over `cross_fade_packets` with a `transition_buffer`; maintains continuity while changing `k`/mode.

SIMD & Parallelism
- SIMD levels auto-detected: `SSE2`, `AVX2`, `AVX512`, `NEON` (fallback: scalar). Parallel chunking for large payloads.
- Runtime overrides are documented in the FEC Operations Guide.

Wire Format (DATAGRAM)
```text
[0xF1, 0xEC][is_systematic:1][base_id:8][coeff_len:2][coeffs:..][payload:..]
```
Coefficients encode GF width (1 byte for GF(2^8), 2 bytes for GF(2^16)); all buffers come from `MemoryPool` and are returned on drop.

Mode Selection & Hysteresis
- Selection heuristic (loss-driven):
  - avg_loss < 0.001 -> Zero (ZeroEncoder: absolute zero overhead, counter only, ~2ns/packet)
  - < 0.02 -> Light (GF4: ~4x faster than GF8, ~5% overhead)
  - < 0.10 -> Normal (GF8: balanced)
  - < 0.25 -> Strong (AdaptRS)
  - < 0.50 -> Extreme (GF16)
  - else -> Fountain (LT Codes)
- Hysteresis & stability:
  - Minimum dwell time between switches (`~200 ms` except for fast paths like Streaming/Normal)
  - Switch only if `|avg_loss - last_avg| >= switch_threshold` (relaxes for Streaming/Normal)
  - Cross-fade transitions over `cross_fade_packets` with a `transition_buffer` to preserve continuity

#### Transport Integration (DATAGRAM Ingress/Egress)
- Repairs are transported over QUIC DATAGRAM frames (`Frame::Datagram`) using a compact, self-describing wire format:

  ````text
  [0xF1, 0xEC]        // Magic for demultiplexing FEC payloads
  [is_systematic:1]   // 1 byte: 1=systematic, 0=repair
  [base_id:8]         // u64 BE: sender's current window anchor (e.g., last source id)
  [coeff_len:2]       // u16 BE: bytes following as coefficients
  [coeffs:coeff_len]  // optional, present iff coeff_len>0 (GF(2^8): k bytes; GF(2^16): 2*k bytes)
  [payload:..]        // raw packet payload (length = datagram_len - header)
  ````

- Egress
  - The encoder serializes repairs via `FecPacket::to_stream_raw()` and enqueues them as DATAGRAMs if size <= `dgram_send_max_size`.
  - Emission policy is adaptive: base interval from `QUICFUSCATE_FEC_STREAM_EVERY` (default computed from CPU profile), escalation under loss and ECN-CE.

- Ingress
  - The receiver recognizes FEC DATAGRAMs by the 2-byte Magic. Parsing uses `FecPacket::from_stream_raw()` with zero-copy buffers from the global `MemoryPool`.
  - Parsed packets are fed into the streaming decoder; reconstructed systematics are surfaced to the application as regular DATAGRAMs.
  - `FecMode::Zero` receive is a true ownership-preserving passthrough when no transition is active: the decoder does not retain an `Arc` clone of the pooled payload, allowing the QUIC core to decrypt and remove header protection in place without an extra copy.

- Semantics & Safety
  - `base_id` stabilizes window alignment across ends; `coeff_len` encodes bytes (GF-specific width must be respected by producers/consumers).
  - All buffers are owned and returned to the pool on drop; the transport avoids moving out of pooled buffers in hot paths (borrow-safe).

### Code Layout
QuicFuscate uses a consolidated Rust layout that keeps hot paths explicit and auditable while optimizing safety, performance, and maintainability.

#### Source File Coverage (Exact Path Index)
The sections above describe architecture and behavior. This index maps exact `src/` file paths to their concrete runtime responsibility to keep this document exhaustive and drift-resistant.

Core crate and entrypoints:
- `src/lib.rs` - crate root, module exports/re-exports, and public type surface.
- `src/main.rs` - CLI wiring, client/server runtime bootstrap, hidden diagnostic/bench commands, and process wiring around the centralized server/admin modules.
- `src/time_source.rs` - injectable time abstraction (`TimeSource`) with test install guard.
- `src/implementations/client/io_driver.rs` - client runtime I/O driver; its dispatch/fallback hotpath is isolated behind an internal `IoHotpathAdapter` seam for deterministic tests without real sockets or TUN devices.
- `apps/tauri/src-tauri/src/state_store.rs` - desktop native-host `StateStore` abstraction with file-backed production persistence and corrupt-state handling.

Binary entrypoints:
- `src/bin/harness.rs` - script-facing harness binary (3-line entry point); implementation is in `src/harness.rs` (~260 lines).
- `src/bin/qf-e2e-client.rs` - headless QKey-based E2E client for admin/web flows.
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
- `src/implementations/client/pipeline.rs` - legacy non-runtime adapter note; production packet I/O is owned by `io_driver.rs` and `core::QuicFuscateConnection`.
- `src/implementations/client/profile.rs` - profile persistence/load/save and profile manager.
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
- `src/implementations/server/fsutil.rs` - atomic file write helper (`atomic_write_file`) used by server persistence paths.
- `src/implementations/server/ip_pool.rs` - server-side tunnel IP allocation pool.
- `src/implementations/server/limits.rs` - rate limiting and connection limiting primitives.
- `src/implementations/server/metrics.rs` - runtime metrics registry and HTTP metrics server surface (`MetricsServer` active in CLI/runtime, `GlobalMetricsServer` retained for test/compat coverage).
- `src/implementations/server/qkey_registry.rs` - persistent QKey records, ids, token hash management.
- `src/implementations/server/routing.rs` - routing/NAT/forwarding integration and WAN interface detection.
- `src/implementations/server/session.rs` - session ids, session state and session manager.
- `src/implementations/server/systemd.rs` - systemd-oriented service/unit integration helpers.

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
  - Runtime-owned entrypoints: `aggregate_congestion(...)` for rolling congestion-window summarization in `src/core.rs`, and `decode_packet_number(...)` for packet-open PN reconstruction in `src/transport/packet.rs`.
  - Parity/test-only helpers: bitmap range ops, ECN popcount, ACK-range search, and stream-frame parsing acceleration are gated behind `cfg(any(test, feature = "rust-tests"))`.
- `src/optimize/udp.rs` - UDP fastpath helper layer.
- `src/optimize/unsafe.rs` - unsafe FFI backend for zstd compression.
- `src/optimize/uring_batch.rs` - io_uring batch sender (Linux-only, feature-gated).
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
- `src/transport/connection.rs` - core transport connection state machine and send/recv path. Includes in-order Stream fast path (sequential data bypasses recv_frags BTreeMap, copies directly to recv_buf) and hybrid ACK/loss range draining for sent-packet accounting: sparse/narrow ACK ranges use `BTreeMap::extract_if`, while large contiguous ACK ranges and loss prefixes use `BTreeMap::split_off`. Stored frames use `Frame<'static>` with `Cow::Owned`.
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

There is no external vendor workflow. All functionality (transport, stealth, FEC, crypto) is implemented under `src/` and built with Cargo. CI uses `.github/workflows/ci.yml` exclusively.

Build/runtime behavior for TLS fingerprint inputs is documented in the TLS boundary section; see "TLS Boundary: rustls protocol with optional cover overlay -> Fingerprint Source Model".

### Building Binaries (macOS, Linux, Windows)

Platform builds are executed from `src/` via consolidated scripts:

- `./scripts/build/build-pgo-release.sh` - PGO-optimized release build (optional `--features "io_uring zero_copy_dgram"`)
- `./scripts/build/build-server-bundle.sh` - Server deployment bundle
- `./scripts/tests/build/build-check.sh` - Format/Clippy/Compile/Test/Bench compilation
- `./scripts/tests/build/build-env-doctor.sh` - Toolchain diagnostics

Artifacts are written to `scripts/out/build/<run>/` by `build-pgo-release.sh`.

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
1. Install prerequisites: Rust stable with cargo.
2. Run the test script: `./scripts/tests/suites/test-crypto.sh`.
3. Manual invocation (in repo root):
   - `cargo test`
   - `cargo clippy -- -D warnings`

#### Integration Guidelines and Optimization Strategy
- Data-plane AEAD follows `CryptoAeadPlan` from `simd.rs` and is resolved once in `src/crypto/` into concrete packet dispatch wrappers.
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
- `src/simd.rs`
  - Acceleration planner (`planner::AccelerationPlanner`) with per-domain plans
  - CryptoAeadPlan (LAesni/LNeon/Morus by default; wider plans exist but are not selected by default)
  - QPACK Huffman encoding/decoding: runtime dispatch includes AVX2 (x86), NEON (ARM) and an SVE2 wrapper (encode/decode) with scalar fallback
  - QUIC varint encode/decode & header validation dispatch: SVE2 (VL-scalable predicates) -> NEON -> scalar; `transport::pn` uses these paths directly.
  - Bitstream pack/unpack: NEON fast paths for bit widths 1-8; SVE2 wrapper routes to NEON.
  - Core popcount: NEON (`vcntq_u8` + horizontal sum); SVE2 wrapper present.
- `src/accelerate.rs`
  - Thin re-export of `src/optimize/*` (transport_io, random, iter, sort, string, compress, brain, stealth, transport, memory). Implementations and telemetry live in optimize modules; accelerate paths remain stable.
- `src/fec/`
  - RLNC/Streaming encoders/decoders using `simd::galois` (GFNI/AVX2/NEON/SVE2/SSSE3)
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
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
}
```

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
- Crypto hotpaths use target-feature gated intrinsics (`aes`, `sse2`, `avx2`, `vaes`, `neon`); runtime dispatch via `cpufeatures` selects the best backend.
- AEGIS/MORUS implementations include unsafe blocks for SIMD lanes where necessary; all sensitive operations remain constant-time by design.
- Transport/H3 uses zero-copy iovecs, io_uring fast paths (feature `io_uring`, crate `io-uring` v0.7), pool-backed compression buffers, and aligned pools (`MemoryPool`) for minimal copies. The client `IoDriver` uses `UringBatchSender` (in `src/optimize/uring_batch.rs`) for batch `SendMsg` submission before falling back to `sendmmsg`, and uses pool-backed `UringRecvBatch` slots on Linux so inbound datagrams can enter FEC through `core::recv_pooled_block()` without an intermediate `Vec` copy. In FEC Zero mode, receive keeps the payload uniquely owned so the core avoids the copy-on-mutate fallback.
- Frame parsing is zero-copy: `Frame<'a>` uses `Cow<'a, [u8]>` for data fields, borrowing directly from the decrypted packet buffer in `from_bytes()`. Combined with the in-order Stream fast path (sequential data copies directly to recv_buf, skipping the recv_frags BTreeMap), the common-case receive path avoids heap allocation entirely. Vec-backed stream send flushes use `frames::write_stream_frame()` to encode directly from `send_buf` into the packet buffer, avoiding a temporary owned `Frame::Stream` payload allocation.
- ACK sent-byte accounting drains acknowledged and packet-threshold-lost ranges from `sent_packets_by_pn` without collect-then-remove passes. Sparse/narrow ACK ranges use `BTreeMap::extract_if`; large contiguous ACK ranges and packet-threshold loss prefixes use `BTreeMap::split_off`. ACK frames with many sparse ranges classify the packet-threshold prefix in one ordered drain pass, preserving largest-ACK RTT sampling and recovery/loss semantics while reducing repeated prefix walks.
- Stealth hotpaths (header/QPACK building and persona-driven shaping) prefer SIMD kernels with safe scalar fallback; mutex/atomic usage is minimized in hotpaths.

#### Feature Matrix (Crypto)
- Cargo features:
  - Product/default runtime:
    - `client`
    - `server`
  - Product/runtime opt-in:
    - `io_uring`
    - `zero_copy_dgram`
    - `compression_zstd_ffi`
  - Platform integration:
    - `tun-windows`
  - Test/validation:
    - `rust-tests`
    - `benches`
    - `simd-selfcheck`
    - `dev-certs`
    - `masque-tests`
    - `tun-tests`
  - Internal-only:
    - `internal_af_xdp_experimental`
    - `internal_avx10_preview`
    - `internal_wiedemann`
  - Backend/build knobs retained for dispatch or specialized integration:
    - `aes`
    - `aggressive_inline`
    - `avx2`
    - `avx512f`
    - `avx512vbmi2`
    - `crc`
    - `fma`
    - `gfni`
    - `neon`
    - `orchestrator`
    - `prefetch`
    - `rate_limiter`
    - `sse2`
    - `std`
    - `stream_ring_buffer`
    - `sve2`
    - `unsafe_rust`
    - `vaes`
- Product posture notes:
  - The canonical product contract is still the default `client`/`server` runtime.
  - Internal features must not be advertised as normal deployment knobs.
  - Decoder policy such as Wiedemann remains an internal FEC/runtime policy concern, not a top-level product identity.

Examples
```bash
cargo test
cargo build --release
```

#### Runtime Dispatch (Selector)

At runtime, the data-plane AEAD plan is selected based on CPU features and measured backend policy (via `cpufeatures`, the internal `FeatureDetector`, and `simd::planner`):

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
- Script: `./scripts/benchmarks/suites/bench-crypto.sh` - runs crypto micro-benchmarks across modes and exports results to `scripts/out/benchmarks/`.
- Optional (feature-gated): build with `--features benches` to run the `crypto-bench` subcommand.

#### Automated Build and CI/CD
- The general CI workflow `ci.yml` runs frontend checks, frontend E2E, security audit, TODO consistency, app backend checks, release build/test, fuzz target checks, feature-matrix tests, benchmark regression checks on pull requests, and Linux fastpath evidence.
- The `app-backend-checks` job validates the native desktop backend without UI source edits: it builds the existing `apps/svelte-desktop` bundle for Tauri context, then runs `cargo check` and `cargo test` in `apps/tauri/src-tauri`.
- `.github/workflows/clippy-matrix.yml` runs the Rust clippy feature matrix on stable Rust with `-D warnings`.
- `.github/workflows/release.yml` builds the release server binary, builds admin web assets, creates the server bundle, and uploads release artifacts.

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

#### MASQUE Handler Registration
The current fork retains MASQUE as a compatibility-only path inside the HTTP/3 stack. There is no
public `QuicFuscateConnection` setter surface such as `set_masque_capsule_handler(...)`,
`set_masque_datagram_handler(...)`, or `set_masque_control_handler(...)` in the active API.
Operational MASQUE behavior should therefore be read from `src/transport/h3.rs` rather than from
standalone connection-level callback registration.

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


## Deployment

### Linux Server Deployment

Step-by-step guide for deploying QuicFuscate on a Linux server.

#### System Requirements
- Linux server (Ubuntu 22.04+ / Debian 12+ / RHEL 9+ recommended)
- Minimum 2 CPU cores, 2 GB RAM (4+ cores recommended for production)
- Rust stable toolchain (for building from source)
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
User=quicfuscate
Group=quicfuscate
ExecStart=/opt/quicfuscate/bin/quicfuscate server --config /etc/quicfuscate/quicfuscate.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/quicfuscate

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

QKeys authenticate clients to the server. The server stores only SHA-256 hashes of tokens; the plaintext token is given to the client and never stored on the server.

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
```

For privacy-sensitive deployments, use `mode = "no-log"` for in-memory-only ring buffer with zero disk writes.

#### Common Operational Tasks
```bash
# Reload configuration
sudo systemctl reload quicfuscate

# View active connections
curl -s http://localhost:8080/api/status | jq .

# Check service health
sudo systemctl is-active quicfuscate
curl -sf http://localhost:8080/api/health || echo "Admin API unreachable"

# Follow logs
sudo journalctl -u quicfuscate -f

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
- web assets: `/usr/share/quicfuscate/admin-web`
- state (QKey registry): `/var/lib/quicfuscate/qkeys.json` (via `quicfuscate server --qkey-store`)

Installer flow is `scripts/install/install-server-linux.sh` together with `scripts/install/quicfuscate-server.service`.

Idempotency behavior of `scripts/install/install-server-linux.sh`:
- Existing `quicfuscate.toml` is preserved (created only if missing).
- Existing `quicfuscate.env` is preserved (created only if missing).
- Existing `qkeys.json` is preserved (created only if missing).
- Binary, assets, and unit template are reinstalled safely on reruns.
- `systemctl daemon-reload` is called on every install run.

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

### TUN interface example (feature-gated)
The TUN example is gated behind the Cargo feature `tun-tests` to avoid impacting default builds. Use the following command:
```bash
# Run example demonstrating factory registration
cargo run --features tun-tests --example tun_factory_example
```

Notes:
- The example integrates with `MemoryPool` to exercise zero-copy paths.

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

- `ProfileManager` (QKey-derived profile preferences and replay),
- zero-copy `MemoryPool`,
- optional `TunInterface`,
- `StealthManager`,
- `AdaptiveFec`,
- `IoDriver`,
- optional `KillSwitch`,
- shared Tokio runtime state.

`KillSwitch` is implemented in `implementations::client::killswitch` with platform-native firewall backends (Linux iptables, macOS pfctl, Windows netsh) and lifecycle hooks (`on_vpn_connected` / `on_vpn_disconnected`) to enforce fail-closed routing when configured.

Packet flow is unified across CLI and embedded paths:

- outbound: `TUN -> Stealth -> FEC -> QUIC`
- inbound: `QUIC -> FEC decode/recovery -> Stealth unwrap -> TUN`

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
Embedded `EngineMode::Server` is therefore a real headless live server runtime in the current codebase, not a bootstrap-only helper surface. It reuses the standalone listener loop and runtime ownership model, but does not expose the standalone admin service bundle by default.
Engine server-mode stats now follow the same runtime truth: bytes, packets, and active-client counts are projected from runtime-owned `implementations/server::Metrics`, while server-side RTT and loss remain `0` until explicit server-owned producers exist.
Admin orchestration helpers (`ServerAdminCore`, `AdminAction`) live in `implementations/server`, so admin, reload, metrics, and shutdown wiring no longer depend on a CLI-local server state island.
Within the live server path, ownership is now intentionally split only along one line:
- `LiveServerDomain` owns remote/session/IP-pool/connection-limiter/packet-rate-limiter/snapshot state.
- `LiveServerState` owns active QUIC connection objects, QKey auth tracking, runtime QKey revocation state, and the SessionId-to-QKey tracker used to terminate active sessions on revoke.
The standalone path also delegates DCID-based live path rebinding, closed-client reconciliation, control-plane shutdown registration, and runtime reload normalization to `implementations/server`, so runtime lifecycle and bookkeeping now converge on one canonical server model.
Session timeout is also part of that canonical lifecycle: standalone housekeeping reaps expired shared-domain sessions according to `client_timeout_secs`, while `QKEY_AUTH_TIMEOUT` remains a separate short pre-auth gate for unauthenticated handshakes rather than a replacement for session expiry.
 
Server Options (selected):

```
    --tun                   Enable TUN bridging (optional)
    --tun-name <name>       TUN interface name
    --tun-mtu <mtu>         TUN MTU (default 1500)
    --tun-ip <addr>         TUN IP address
    --tun-netmask <addr>    TUN netmask
    --admin-socket <path>   Unix admin socket (status/clients/kick/block/reload/qkey/shutdown)
    --admin-web <addr>      HTTP admin web bind address (e.g. 127.0.0.1:9000)
    --admin-web-root <dir>  Static root for the web admin bundle (default: assets/web-admin)
    --admin-web-user <user> Admin username (or env QUICFUSCATE_ADMIN_USER)
    --admin-web-password <pass> Admin password (or env QUICFUSCATE_ADMIN_PASSWORD, minimum 6 characters)
    --qkey-ttl-secs <secs> Default QKey TTL in seconds (0 disables expiration; env QUICFUSCATE_QKEY_TTL_SECS)
    --qkey-store <path> QKey registry store path (recommended: /var/lib/quicfuscate/qkeys.json)
    --metrics-port <port>   Metrics HTTP port (text format at /metrics)
```

### Admin CLI (quicfuscate-ctl)

`quicfuscate-ctl` talks to the Unix admin socket exposed by `--admin-socket`. It uses
`/var/run/quicfuscate/ctl.sock` by default and can be overridden via `QUICFUSCATE_CTL_SOCKET`.

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
    --cc-algorithm <alg>    Congestion control: reno|bbr2|bbr3 (default: bbr3)
```

### Client Options

```
    --local <addr>          Local UDP bind address (default: 0.0.0.0:0)
    --url <url>             URL used by the client (default: https://cloudflare-dns.com/)
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

Successful validated migrations increment the internal `PATH_MIGRATIONS` telemetry counter.

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
- Status poller (500 ms): fetches `engine_status` and updates tunnel state map via `tunnelsRef` (ref-based to avoid interval re-creation on tunnel list changes).
- Stats poller (900 ms): fetches `engine_stats` for the active tunnel (latency, loss, bytes, packets, uptime, stealth/FEC mode).
- Logs poller (350 ms): incremental log fetch via `engine_logs_since` with cursor tracking; ring-buffers at 2000 entries.

**Persistence:**
- State (tunnels, settings, selected tunnel) is loaded on startup via `invoke("load_state")` and saved on change via `invoke("save_state")` with a 450 ms debounce timer to avoid excessive disk writes.

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
- Tray menu exposes status, active tunnel summary, connect/disconnect, open/hide app, auto-connect-on-launch toggle, start-at-login preference toggle, and quit.
- Auto-connect-on-launch reads persisted desktop settings and attempts connection on startup when enabled.
- Start-at-login persists user preference and is wired to OS auto-start registration via the desktop runtime plugin.

**Updater Integration (source-first):**
- Updater plugin path is integrated but runtime-gated behind `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE`.
- Default is disabled; signed artifacts are required before enabling update delivery in shipped binaries.
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

The active web admin UI lives in `apps/svelte-admin/`. `scripts/build/build-web-admin.sh` builds the Svelte bundle and copies it into `assets/web-admin/`. Server startup with `--admin-web` is a separate runtime step:

```
scripts/build/build-web-admin.sh
```

The bundle output layout is the SvelteKit static adapter publish tree: `assets/web-admin/index.html`, `assets/web-admin/robots.txt`, and `assets/web-admin/_app/immutable/*` for hashed JS/CSS/assets.
Keep `--admin-web-root` pointing at `assets/web-admin` so `/_app/...` paths resolve correctly.

Admin HTTP contract notes:
- JSON endpoints respond with `AdminResponse { success, message, data }` and `/api/clients` is wrapped.
- Admin API failures return appropriate HTTP error statuses (`4xx`/`5xx`) while keeping the same `AdminResponse` envelope (`success: false`, optional `message`/`data`).
- `/api/qkey` is `POST` only, accepts `{ stealth, fec, ttl_seconds }` (presets + optional TTL), and returns `{ qkey, created_at, expires_at }` in `data`. The returned `qkey` is the one-time reveal point for the raw credential.
- `/api/qkeys` returns metadata-only entries (`id`, optional `name`, `created_at`, optional `expires_at`, optional policy hints). Expired entries are pruned and the endpoint does not expose or reconstruct raw QKey strings.
- QKey strings include the embedded token field and are validated at issuance/import boundaries rather than being replayed through the registry list contract.
- `/api/clients/{id}/kick` is supported as an alias for `/api/kick`.
- `/api/status` includes `config_writable` for UI gating.
- `/api/config/logging` (`GET`/`POST`): read and set logging mode (verbose/normal/minimal/no-log).
- `/api/logs?cursor=<n>` (`GET`): incremental log retrieval with cursor-based pagination.
- `/api/admin/auth` (`GET`/`POST`): authenticated users can query `requires_password_change` and rotate admin credentials (`current_password`, optional `new_username`, optional `new_password`); updates persist to `admin-auth.json`, clear active sessions, and rotate CSRF/session material.
- `QUICFUSCATE_TRUST_PROXY=1|true` makes admin HTTP resolve client IPs from `X-Forwarded-For`/`X-Real-Ip`; default remains socket peer address.
- Oversized admin HTTP payloads are rejected with 413.
- Auth uses `POST /api/login` to issue a session cookie and `POST /api/logout` to clear it.
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
- Active app unit harnesses run without file-level parallelism and with one Vitest worker per app. This avoids Bun/Vite/Svelte transform contention that can turn passing component assertions into false 5s timeout failures under full-suite load. The web-admin and desktop setup hooks clean up Svelte Testing Library state and restore real timers after each test.
- `apps/tauri` is a minimal wrapper package for the native Tauri host and delegates its frontend build/check path to `apps/svelte-desktop`.
- `packages/ui` uses package `exports` entries with explicit `svelte` conditions so the shared Svelte component package resolves cleanly without `vite-plugin-svelte` packaging warnings.
- On a fresh machine, install the Playwright browser runtime once before the first E2E run: `cd apps/svelte-admin && bunx playwright install chromium`.
- Playwright does not reuse an existing server by default. Set `PW_REUSE_SERVER=1` only when intentionally reusing a running preview instance during local debugging.
- The Svelte admin dev server runs on port 1430 (`bun run dev --port 1430`) and proxies `/api/*` to the backend on port 9000.

#### Server-Side Persistence

The admin HTTP server persists the following state to JSON files derived from the main config path:
- **Blocked IPs** (`<config>.blocked.json`): loaded on startup, written on every block/unblock action.
- **Logging mode** (`<config>.logging.json`): loaded on startup, written on every mode change. When set to `no-log`, the server immediately calls `log::set_max_level(LevelFilter::Off)` to suppress all runtime logging output including to stderr and syslog.
- **QKey registry** (`--qkey-store` or `<config>.qkeys.json`): loaded on startup, written on generate/revoke.
- **Admin auth** (`<config_dir>/admin-auth.json`): Argon2 PHC string (`password_phc`) with `updated_at` timestamp and `requires_password_change`. File permissions set to `0o600` on Unix. Loaded on startup; written on credential change.
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
- `--url`: URL to request (default: https://cloudflare-dns.com/)
- `--cc-algorithm`: Congestion control (reno, bbr2, bbr3) [default: bbr3]

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
- `--verify-peer` - validate server certificate
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

**Configuration:**
- `--config`: Path to unified TOML configuration

#### **`server`** - Runs the QuicFuscate server
**Required Options:**
- `--cert`: Certificate file path
- `--key`: Private key file path

**Network Options:**
- `--listen`: Listen address (default: 127.0.0.1:4433)
- `--cc-algorithm`: Congestion control (reno, bbr2, bbr3) [default: bbr3]

**Other options mirror the client subcommand**

#### Hidden Diagnostic Subcommands  
- **`cross-fade-sim`** - cross-fade simulation for FEC mode transitions
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

### Environment Variable Overrides

At runtime you can override selected stealth options without changing the config file. The following variables are recognized (case-insensitive values where applicable):

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

**Compression Module (current):**
- `QUICFUSCATE_COMPRESS`: `0|1|false|true` - Enable/disable compression
- `QUICFUSCATE_COMPRESS_MIN`: integer - Minimum payload size for compression (bytes)
- `QUICFUSCATE_COMPRESS_LEVEL`: `1-22` - zstd compression level
- `QUICFUSCATE_COMPRESS_ALLOW`: comma-separated content-types to allow (e.g., `text/*,application/json`)
- `QUICFUSCATE_COMPRESS_DENY`: comma-separated content-types to deny (e.g., `image/*,video/*`)
- `QUICFUSCATE_BODYPOOL_CAP`: integer - Body pool capacity (blocks)
- `QUICFUSCATE_BODYPOOL_BLOCK`: integer - Body pool block size (bytes)
- `QUICFUSCATE_DICT_DIR`: path - Dictionary cache directory

**MASQUE controls (compatibility-only):**
- `QUICFUSCATE_MASQUE_ENABLE`: `0|1|true|false` - Explicitly create the compatibility MASQUE manager.
- `QUICFUSCATE_MASQUE_PROXY`: hostname of the MASQUE proxy (e.g., `masque.example.com`).
- `QUICFUSCATE_MASQUE_DATAGRAM`: `0|1|true|false` - Override MASQUE DATAGRAM handling once the compatibility manager exists.

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
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - Forward ClientHello template override names to providers that support `supports_ch_override()`
- `QUICFUSCATE_TRACE_TLS=1` - Enable additional TLS handshake/key-change diagnostics in qftls/transport

**Global toggles:**
- `QUICFUSCATE_BRAIN=0|1|false|true` - Enable StealthBrain transport observer coupling (default: enabled)
- `QUICFUSCATE_ORCHESTRATOR=0|1|false|true` - Enable DeepIntegrationOrchestrator when feature is compiled (default: enabled)
- `QUICFUSCATE_RAYON_THREADS=<n>` - Cap Rayon global thread pool used for parallel FEC kernels

**Telemetry server:**
- `QUICFUSCATE_METRICS_ADDR` - `host:port` for the `--telemetry` HTTP endpoint (default: `127.0.0.1:9898`).

**Transport and IO (advanced):**
- `QUICFUSCATE_RATE_LIMIT_PPS` - integer `>=1`; overrides per-source packet rate limit in server runtime path (default: `10000`).
- `QUICFUSCATE_RATE_LIMIT_BPS` - integer; overrides per-source byte rate limit (`0` = unlimited, default: `0`).
- `QUICFUSCATE_RATE_LIMIT_REFILL_MS` - integer `>=1`; token-bucket refill interval in milliseconds (default: `1000`).
  - These overrides are active only when the binary is built with the `rate_limiter` feature.
- `QUICFUSCATE_FASTPATH` - `auto|off` (default: `auto`). Controls XDP/UDP fast-path selection.
- io_uring queue depth and SQPOLL are probed automatically at runtime with no env override needed.
  SQPOLL requires `CAP_SYS_ADMIN` on kernels < 5.12 and falls back to standard mode silently.
  SendMsgZc requires kernel 6.0+ and `QUICFUSCATE_IO_URING_ZC=1`; without that explicit opt-in,
  the production send path stays on batched SendMsg.
- `QUICFUSCATE_IO_URING_ZC` - `1|true|yes|on` enables experimental Linux `SendMsgZc` zero-copy
  after the runtime probe succeeds (default: disabled).

#### Memory Pool (Optimization) Environment Overrides

- `QUICFUSCATE_POOL_CAPACITY` - Initial pool capacity (blocks). Default: `512`.
- `QUICFUSCATE_POOL_BLOCK_SIZE` - Block size in bytes. Default: `65536` (64 KiB). A minimum of `2048` bytes is enforced.
- `QUICFUSCATE_POOL_HARD_MAX_CAP` - Hard upper limit for capacity growth (DoS guard). Default: unlimited.
- `QUICFUSCATE_POOL_AUTO_TUNE` - `0|1|false|true` to enable auto-tuner. Default: `true`.
- `QUICFUSCATE_POOL_MIN_CAP` - Minimum capacity for auto-tuner. Default: `64`.
- `QUICFUSCATE_POOL_MAX_CAP` - Maximum capacity for auto-tuner. Default: `4096`.
- `QUICFUSCATE_POOL_TICK_MS` - Auto-tuner tick duration in milliseconds. Default: `1000`.
- `QUICFUSCATE_POOL_UTIL_HIGH` - Utilization percent that triggers growth (default: `80`).
- `QUICFUSCATE_POOL_UTIL_LOW` - Utilization percent that triggers shrink (default: `30`).
- `QUICFUSCATE_TLS_HIGH` - TLS cache size under high utilization (default: `48`).
- `QUICFUSCATE_TLS_LOW` - TLS cache size under low utilization (default: `24`).
- `QUICFUSCATE_POOL_ADAPTIVE_BLOCK` - `0|1|false|true` to enable adaptive block sizing (default: `true`). If enabled, block size is selected from MTU hints: `<=1500 -> 4096`, `<=9000 -> 16384`, otherwise `65536`.
- `QUICFUSCATE_MTU_HINT` - Integer hint for typical link MTU used by adaptive block sizing (default: `1500`).
- `QUICFUSCATE_TLS_CACHE` - Per-thread TLS cache size for pooled blocks (default: `32`).
- `QUICFUSCATE_POOL_DEBUG_SLACK` / `QUICFUSCATE_POOL_DEBUG_GRACE` - Debug-only invariants slack to reduce spurious warnings under bursty workloads.
- `QUICFUSCATE_MADVISE_HUGEPAGE` - `0|1|false|true` to disable or enable MADV_HUGEPAGE hints on Linux (default: `true`).
- `QUICFUSCATE_NUMA_POLICY` - `local|interleave|preferred:<n>` for NUMA placement on Linux (default: `local`).

Notes:
- The pool growth is clamped by `QUICFUSCATE_POOL_HARD_MAX_CAP`. When the limit is reached,
  ephemeral blocks are allocated without mutating pool counters (prevents counter skew under DoS).
- Debug builds assert pool invariants (`in_use <= capacity`, `available <= capacity`).

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
    patterns: Vec<ProbePattern>,   // GFW_TLS_Probe, DPI_QUIC_Scan
    history: Arc<Mutex<Vec<ProbeEvent>>>,
    threshold: usize,
    response_mode: ProbeResponseMode,
}

// Detects and responds to DPI probes
let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
if let Some(mode) = detector.check_packet(&packet, source_addr) {
    // mode is Ignore | Fake | Switch | Block
}
```

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
The retained MASQUE tunnel state is internal compatibility machinery inside `src/stealth/` and
is compiled only for test or `rust-tests` coverage. There is no stable public
`MasqueTunnel::connect(...)` product API in the current runtime.

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
    ["chrome", "windows"],
    ["firefox", "macos"],
    ["safari", "ios"],
]
```

#### Rotation Modes
- **Fixed**: single profile, no rotation
- **Slots**: rotate through configured slots (up to 3)
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

QuicFuscate can bridge a TUN interface by encapsulating frames in HTTP/3 streams:

- Client: when `--tun` is set, a blocking reader thread forwards frames into an H3 stream; zero-copy pool integration minimizes allocations.
- Server: with `--tun`, authenticated MASQUE CONNECT-UDP datagrams carrying raw IP packets are written to a TUN interface (when available on the platform). Standalone server mode derives `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool from explicit `--tun-ip` / `--tun-netmask`, so runtime session routing and OS TUN addressing stay aligned.
- Server hotpath: after a TUN packet is queued as MASQUE downlink for one session, only that target client's connection is flushed. The server does not scan and flush all clients per TUN packet.
- Authentication: the client injects QKey auth into both encrypted QUIC transport parameters and the H3/MASQUE CONNECT-UDP header path. The server accepts either valid proof and gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state.
- Platform support (interface.rs):
  - Linux/Android: `/dev/net/tun` via `TUNSETIFF` (IFF_TUN | IFF_NO_PI)
  - macOS: `utun` (PF_SYSTEM/SYSPROTO_CONTROL), 4-byte AF header using readv/writev
  - Windows: pluggable via `register_tun_factory` (feature `tun-windows`)
  - Other Unix: external factory via trait injection
  - All use the shared `MemoryPool` for zero-copy slices where possible.

### Real TLS Fingerprints

This section is an operational view; canonical behavior is defined in "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".

QuicFuscate performs native TLS handshake profile injection using deterministic in-memory ClientHello synthesis selected by `--profile` and `--os`. Runtime operation does not require on-disk profile dumps.

Generated ClientHello bytes are cached in memory for reuse across connections.

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

TLS Cover is a lightweight synthetic exchange for stealth shaping and traffic realism. It derives ClientHello-like output from the active fingerprint profile and emits synthesized reply artifacts with shorter message sizing than a full handshake.

TLS Cover is optional and does not replace native TLS security semantics.

**Scope - handshake phase only:** TLS Cover generates synthetic QUIC `CRYPTO` frames during the handshake phase only. This is correct QUIC behavior: per RFC 9001, QUIC `CRYPTO` frames only appear during the handshake. After the handshake completes, injecting `CRYPTO` frames would be anomalous and detectable. Post-handshake cover traffic is provided by three complementary mechanisms described below.

**Post-handshake cover mechanisms (three layers):**

1. **Cover PINGs** (`StealthConfig.enable_cover_ping`, `cover_ping_interval_ms`): ack-eliciting QUIC `PING` frames injected at the configured interval (default 30 s for Stealth, 15 s for Anti-DPI). Wired in `core.rs` via `StealthManager::should_send_cover_ping()` -> `Connection::queue_cover_ping()`. Mimics idle browser/HTTP3 keepalive patterns.

2. **PacketNormalize padding** (`PaddingStrategy::PacketNormalize`): all 1-RTT packets are padded to `normalize_target_size` bytes so wire-visible packet sizes are uniform. Prevents length-based traffic analysis.

3. **Cover stream injection** (`StealthManager::COVER_STREAM_ID = 248`, enabled when `enable_cover_ping = true`): fake `APPLICATION_DATA` frames (16-64 random bytes) are injected on a dedicated client-initiated bidirectional stream (stream ID 248, ordinal 62) at 3x the cover_ping_interval. Wired in `core.rs` via `StealthManager::should_inject_cover_stream_frame()` -> `Connection::stream_send(COVER_STREAM_ID, data, false)`. Adds application-layer traffic variety that PING frames alone cannot provide.

The **Server Push Cover Traffic** system (HTTP/3 `PUSH_PROMISE` + `DATA` frames) provides an additional H3-level cover layer - see Server Push Cover Traffic below.

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

### MASQUE CONNECT-UDP (compatibility-only)

There are two MASQUE surfaces and they must not be confused:

- Production carrier: Core/H3 MASQUE is the canonical VPN/TUN data-plane carrier used by the live tunnel path.
- Compatibility manager: `stealth::MasqueManager` is retained experiment and compatibility machinery.

The details below describe the retained HTTP/3 CONNECT-UDP machinery and compatibility manager surface, not a separate replacement for the production TUN carrier.

- Streams: establishes CONNECT-UDP control streams; keeps them open for duration of the tunnel.
- DATAGRAM: registers Flow-ID/Context-ID; sends UDP payloads over QUIC DATAGRAM frames.
- Capsules: encodes/decodes MASQUE capsules using varints.
  - Common types observed in telemetry: `0x00` (DATAGRAM), `0x21`, `0x22` (implementation-specific control/data hints).
- QPACK: MASQUE headers use QPACK with dynamic table; preferred indexing keys are set via `set_qpack_index_policy()`.
- Telemetry: `MASQUE_BYTES_SENT`, `MASQUE_BYTES_RECEIVED`, and capsule counters per type.

Notes
- Canonical Stealth, Anti-DPI, Performance, and Intelligent modes use the production H3/MASQUE TUN carrier when TUN mode is active.
- The compatibility `stealth::MasqueManager` path is opt-in experiment machinery and should not be expanded as a second production tunnel stack.
- CONNECT-UDP compatibility paths are documented here because the code remains available for targeted experiments.
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

Additional helpers:
- __StealthManager::masque_preferred() -> bool__
  - Indicates whether the compatibility MASQUE path is currently preferred.
- __StealthManager::get_masque_connect_headers(proxy, target) -> Option<Vec<Header>>__
  - Builds CONNECT-UDP headers for use with a MASQUE proxy. Returns `None` when the compatibility MASQUE manager is absent.

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

### Domain Fronting API (allocation-free getters)

- __DomainFrontingManager::get_fronted_domain_ref(&self) -> &str__
  - Returns the current front domain as a string slice without allocation.
- __DomainFrontingManager::random_domain_ref(&self) -> &str__
  - Returns a random front domain as a string slice without allocation.

Notes:
- Existing methods (`get_fronted_domain`, `random_domain`) remain for backward compatibility.
- Internally, domains are stored as `Arc<[String]>` to reduce cloning and enable zero-copy access.


## Scripts Reference
This section is the authoritative build/packaging script reference in this document. Script-produced artifacts are written to `scripts/out/<category>/` (including build-release artifacts under `scripts/out/build/...`).
For the broader script inventory and repository-wide file index, use `docs/MAP.md`.

#### Build and Packaging (`scripts/build/`)
- `build-web-admin.sh` - Builds `apps/svelte-admin` and publishes bundle to `assets/web-admin/`.
- `build-server-bundle.sh` - Produces a server bundle into `scripts/out/build/` for deployment packaging.

#### Build (`scripts/tests/build/`)
- `build-check.sh` - Format, Clippy, compile checks, test/bench compilation
- `build-clippy-matrix.sh` - Clippy feature-matrix sweep (aligns with CI variants)
- `build-env-doctor.sh` - Environment/Toolchain diagnostics

#### Build (`scripts/build/`)
- `build-pgo-release.sh` - PGO-optimized release build (profile-guided optimization)
- `build-server-bundle.sh` - Server deployment bundle (binary + assets + systemd unit)
- `build-web-admin.sh` - SvelteKit admin UI static build to `assets/web-admin/`

#### Analysis (`scripts/tests/analysis/`)
- `analysis-coverage-summary.sh` - Coverage summary (JSON/text)
- `analysis-dead-code-report.sh` - Dead code report (JSON/text)
- `analysis-scripts-quality.sh` - Script quality/static consistency checks
- `analysis-suite-matrix.sh` - Test/benchmark suite matrix report generation

#### Library (`scripts/tests/lib/`)
- `lib-common.sh` - Shared helpers (logging, JSON, env detection)

#### Tests (`scripts/tests/`)
**Suites (`scripts/tests/suites/`)**
- `test-core.sh` - Core integration tests (CLI/telemetry/profile/qftls/reality/config)
- `test-profile-overrides.sh` - Deterministic profile override parity tests
- `test-profile-fuzz-parity.sh` - Fuzz-style parity tests (scalar vs SIMD) with forced profiles
- `test-fec.sh` - FEC suite (all modes + GF16/GF8/Wiedemann/Partial/Adaptive/Stress; add `--refactor` / `--refactor-only` for structural invariants)
- `test-fec-simulation.sh` - FEC simulation under varied loss/threads/mode matrices
- `test-fec-e2e-loss.sh` - Deterministic FEC E2E loss matrix using seeded `fec_sim` runs and explicit ratio thresholds
- `test-stealth.sh` - Stealth suite (browser/OS profiles, padding, DoH, H3 masquerade, rotation)
- `test-stealth-brain.sh` - StealthBrain ACK policy optimization tests
- `test-probe-detection.sh` - Active-probe validation (detector invariants, reality fallback rotation, optional stealth pressure path)
- `test-crypto.sh` - Crypto suite (AEGIS/MORUS/AES-GCM/ChaCha20/HKDF/CT operations)
- `test-transport.sh` - Transport suite (varint/frames/loss/BBR/0-RTT/validated migration/DATAGRAM; io_uring on Linux)
- `test-optimization.sh` - Optimize suite (MemoryPool/NUMA/HugePages/SIMD/prefetch/zero-copy) + SIMD/accelerate fixtures (`--features rust-tests,simd-selfcheck`; override via `CARGO_FEATURES`)
- `test-security-fuzzing.sh` - Security & fuzzing (ASAN/MSAN/UBSAN, fuzz targets, concurrency, `rt-property-suite` via proptest)
- `test-performance-regression.sh` - Performance regression with baseline comparison
- `test-e2e.sh` - End-to-end integration tests with real network scenarios
- `tun-e2e-netns.sh` - Linux network-namespace production smoke: real server/client TUN over authenticated H3/MASQUE CONNECT-UDP and a hard 0%-loss ping assertion through the tunnel
- `tun-e2e-dns-leak-netns.sh` - Linux network-namespace DNS leak proof: real server/client TUN over MASQUE, DNS query through the server TUN IP, and tcpdump assertion that the client underlay sees zero raw TCP/UDP port 53 packets
- `test-e2e-admin-web.sh` - Admin web E2E (login/status/config/qkey + headless QKey connect via `qf-e2e-client` and `qf-e2e-desktop`)
- `test-desktop-webadmin-rust-integration.sh` - Cross-surface desktop/web-admin/core integration contract checks
- `test-fec-all.sh` - Dispatcher: runs all FEC suites (test-fec, test-fec-simulation, test-fec-e2e-loss, auto-controller)
- `test-fec-auto-controller-scenarios.sh` - FEC auto-controller scenario-driven tests
- `test-fec-auto-controller-proof.sh` - FEC auto-controller proof orchestration
- `tun-e2e-fec-netns.sh` - Linux netns FEC smoke over the real tunnel with tc-netem loss. Ping gates are hard pass/fail; optional iperf3 TCP probes are skipped unless real throughput is measured.
- `tun-e2e-fec-burst-netns.sh` - Linux netns burst-loss FEC proof using correlated tc-netem loss patterns.
- `tun-e2e-fec-transition-netns.sh` - Linux netns live FEC mode transition proof across clean, lossy, and recovered phases.
- `tun-e2e-fec-netem-adversity.sh` - Linux netns broad adversity matrix: loss sweep, jitter, bandwidth, RTT+loss, mobile-network mix, and recovery.
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
- `test-fast-fec.sh` - Fast FEC sanity (GF8/GF16 + benches compile)

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
- `bench-orchestrator.sh` - Orchestrates benchmark matrix; writes `manifest.json`, `summary.txt`, and per-suite logs under `scripts/out/benchmarks/`
- `bench-fec.sh` - FEC benchmarks (encoder/decoder/Wiedemann/GF16/parallelization)
- `bench-fec-simulation.sh` - FEC performance under simulated network conditions
- `bench-crypto.sh` - Extended crypto benchmarks with all cipher suites
- `bench-transport.sh` - Transport benchmarks (packet/varint/frames/streams; io_uring on Linux)
- `bench-optimization.sh` - Runtime-owned SIMD sort/shuffle optimization benchmarks; memory microprimitives are rust-tests parity-only.
- `bench-stealth.sh` - Stealth module performance (padding, masquerading, obfuscation)
- `bench-stealth-brain.sh` - StealthBrain ACK policy optimization benchmarks
- `bench-compression.sh` - Compression microbenchmarks (`examples/compress_bench.rs`) for text and binary payloads with JSON output
- `bench-qpack-encode.sh` - QPACK encode benchmark harness
- `bench-profile-transport-fastpaths.sh` - Transport profiling (Tokio vs io_uring)
- `bench-linux-send-path-decision.sh` - Linux send-path decision benchmark
- `bench-retained-crypto-backends.sh` - Crypto backend comparison benchmark
- `bench-fec-all.sh` - Dispatcher: runs all FEC benchmarks
- `bench-ci-regression.sh` - CI regression benchmark gate (Criterion)

**Micro (`scripts/benchmarks/micro/`)**
- `micro-crypto-all.sh`, `micro-aes-block.sh`, `micro-aes-gcm.sh`, `micro-ghash.sh`, `micro-chacha-x4.sh`, `micro-udpfast-throughput.sh`
  - Micro JSON output: each script writes `<name>.json` with a `meta` object (e.g., `iters`, `sizes`, `batch`, `bind`, `remote`) plus per-command entries.

#### Audits (`scripts/tests/audits/`)
- `audit-runtime-guardrails.sh` - Fast runtime/docs/structure anti-drift gate for reachability, contract, and shadow-path regressions
- `audit-all-comprehensive.sh` - Consolidated audit (security/dependencies/quality/performance) with clear exit codes
- `audit-readiness-gates.sh` - Readiness gate checks for release and CI quality thresholds

Guardrail remediation playbook:
- `Critical` failure: treat as contract drift or structural regression. Fix code/docs first, then rerun `audit-runtime-guardrails.sh`.
- `Warning`: treat as a suspected owner/surface drift. Either tighten the code path or explicitly narrow/document the retained compat/test-only boundary.
- When a guardrail touches feature claims, update runtime truth and `docs/DOCUMENTATION.md` in the same change set.

#### Utils (`scripts/tests/utils/`)
- `util-run-full-suite.sh`
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

**JSON schema (suite results)**
```json
{
  "schema": "<suite-schema-id>",
  "tool": "quicfuscate",
  "suite": "test-crypto",
  "timestamp": "2026-01-25T12:34:56-08:00",
  "system": {
    "os": "Darwin",
    "arch": "arm64",
    "cpu_cores": 8,
    "memory_gb": "16.0"
  },
  "items": [
    {"cmd": "cargo test --release ...", "rc": 0, "duration_sec": 12}
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
  "system": { "os": "Darwin", "arch": "arm64", "cpu_cores": 8, "memory_gb": "16.0" },
  "items": [
    {"meta": {"iters": 1000, "sizes": "256B 1KiB 16KiB 1MiB"}},
    {"cmd": "cargo run --release ...", "rc": 0, "duration_sec": 3}
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
- `QUICFUSCATE_FEC_FOUNTAIN_WINDOW`: integer - window size when switching to Fountain (default: `2048`).
- `QUICFUSCATE_FEC_EXTREME_WINDOW`: integer - window size for extreme loss escalation (default: `1024`).
- `QUICFUSCATE_FOUNTAIN_SYMBOL`: integer bytes - fountain symbol size (default: `MTU_HINT-80`, fallback `1500`, clamp `600..16384`).
- `QUICFUSCATE_RS_LOSS`: float - loss hint for AdaptiveRS (default: `0.0`).
- `QUICFUSCATE_RS_LATENCY_MS`: float - latency hint for AdaptiveRS (default: `5.0`).
- `QUICFUSCATE_RS_BW_MBPS`: float - bandwidth hint for AdaptiveRS (default: `1000.0`).
- `QUICFUSCATE_KALMAN_Q`: float - process noise override (default: `0.001`).
- `QUICFUSCATE_KALMAN_R`: float - measurement noise override (default: `0.01`).
- `QUICFUSCATE_PROFILE`: `mobile|server|desktop` - transport profile override for FEC observer.
- `QUICFUSCATE_MTU_HINT`: integer - used by fountain symbol sizing and memory pool sizing.
- `QUICFUSCATE_RAYON_THREADS`: integer - cap Rayon thread pool used by parallel FEC paths.
- `QUICFUSCATE_FEC_KERNEL`: `scalar|avx512vbmi2|avx512|avx2|neon|sve2` - override SIMD kernel selection for GF16 bitslice.

Notes:
- The runtime may set `QUICFUSCATE_FEC_STREAM_BURST`, `QUICFUSCATE_FEC_PARALLEL`, `QUICFUSCATE_WM_BITSLICE`, `QUICFUSCATE_WM_LANE_PAR`, `QUICFUSCATE_WM_LANES`, and `QUICFUSCATE_WM_U` internally during auto tuning; there is no manual override read path in the current code.
- `QUICFUSCATE_FEC_DECODER` and `QUICFUSCATE_FEC_WIEDEMANN_K` are advanced/internal controls for diagnostics and compatibility. They do not widen the canonical product contract.
- Fountain symbol sizing, AdaptiveRS runtime hints, and Rayon thread-pool setup now also follow explicit owner boundaries: they are snapshotted or initialized during construction instead of being repeatedly resolved inside live adaptation logic.
- Rayon thread-pool setup is now represented explicitly as FEC global-resource policy (`Default` or `ThreadCap(n)`) before initialization, rather than a hidden optional env parse embedded in the side effect itself.
- Constructor and observer ambient policy is now centralized: `AdaptiveFec::new()` resolves explicit FEC ambient/runtime inputs once, stores the resulting `FecRuntimePolicy` on the instance, and reuses that same snapshot for internal runtime/transition builders; `FecTransportObserver` snapshots its profile/base-stream inputs once; its retained transport-profile heuristic is represented explicitly as observer policy (`Explicit(profile)` or `Ambient(profile)`); the remaining FEC mode-policy env overrides are read through one `FecRuntimePolicy` snapshot instead of scattered per-call environment reads.
- Deterministic regression coverage exists for the remaining allowed ambient FEC controls: stream cadence stays stable per `AdaptiveFec` instance, `FecTransportObserver` stream policy snapshots per observer instance, decoder policy snapshots per `Decoder8` instance, and Fountain symbol size snapshots per Fountain encoder/decoder construction.
- Lazy receive polling is gated by `recovery_needed()` and `full_recovery_needed()`: clean blocks return systematic packets without polling heavy recovery, gap-only systematic arrivals stay lazy while retaining bounded source context, flushed repairs or tail-loss repair availability replay buffered sources into the heavy decoder and trigger full recovery, and clean complete blocks prune their sequence tracker and source buffer so long-running stable links do not retain unbounded FEC source IDs.
- Interleaved lazy gap tracking is depth-aware: each lazy block normalizes source sequence numbers by interleave depth before gap detection, so clean streams such as `0,4,8,12` at depth `4` do not trigger false recovery polling.
- Zero-mode receive bypasses decoder retention entirely while no transition is active, preserving unique ownership of pooled payloads for in-place QUIC processing. Recovery-capable modes still retain decoder state as required for source reconstruction.
- Send-side hot paths should call `AdaptiveFec::on_send_into(packet, output)` with a reused output buffer. `AdaptiveFec::on_send(packet)` remains a compatibility wrapper, but `QuicFuscateConnection` and the Engine `FecCodec` use per-instance scratch vectors so clean-link sends do not allocate a fresh FEC output vector per packet.
- Receive-side hot paths should call `AdaptiveFec::on_receive_into(packet, output)` with a reused output buffer. `AdaptiveFec::on_receive(packet)` remains a compatibility wrapper and keeps the direct zero-mode passthrough fast path, while `QuicFuscateConnection` and the Engine `FecCodec` reuse per-instance receive scratch vectors.

Examples (manual tuning):

```bash
# Low-loss emphasis (efficient)
export QUICFUSCATE_FEC_STREAM_EVERY=3
export QUICFUSCATE_FEC_INTERLEAVE=1
export QUICFUSCATE_FEC_LAZY=1

# High-loss emphasis (robust)
export QUICFUSCATE_FEC_STREAM_EVERY=1
export QUICFUSCATE_FEC_INTERLEAVE_DEPTH=4
export QUICFUSCATE_FEC_FOUNTAIN_WINDOW=2048
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

#### Telemetry HTTP endpoints

Telemetry and metrics endpoints are exposed by different runtime surfaces:

- `GET /telemetry`: text snapshot from `telemetry::export_telemetry_text()` served by `src/metrics.rs` (`spawn_telemetry_server`, bind via `QUICFUSCATE_METRICS_ADDR`, default `127.0.0.1:9898`).
- `GET /metrics` and `GET /health`: server metrics/health exposed by `implementations::server::metrics::MetricsServer` when server metrics are enabled.

`GlobalMetricsServer` (same module) is currently retained only for test/compat coverage around global instrumentation export and is not part of the active CLI/runtime metrics path.

#### Server `/metrics` families (default server runtime)

The default server metrics endpoint (`implementations::server::metrics::Metrics::export`) includes:

- `quicfuscate_up`, `quicfuscate_uptime_seconds`
- `quicfuscate_clients_active`, `quicfuscate_clients_total`, `quicfuscate_connections_accepted`, `quicfuscate_connections_rejected`
- `quicfuscate_bytes_in_total`, `quicfuscate_bytes_out_total`, `quicfuscate_packets_in_total`, `quicfuscate_packets_out_total`
- `quicfuscate_stealth_http3_active`, `quicfuscate_stealth_tls13_active`
- `quicfuscate_fec_packets_encoded`, `quicfuscate_fec_packets_decoded`, `quicfuscate_fec_packets_recovered`
- `quicfuscate_auth_failed_total`, `quicfuscate_rate_limited_total`

Accepted connections are now produced by the standalone live runtime at the same point that `clients_total` is incremented, so the standalone admin/metrics surfaces report one consistent accept/reject/auth-failure story instead of mixing runtime counts with partial projections.
The standalone server runtime now also records accepted, rejected, rate-limited, ingress, and egress events through explicit `Metrics` methods rather than scattered raw atomic increments in the live loop and QKey-auth branches.
Engine server-mode stats now treat RTT and loss as unavailable unless a truthful server-owned producer exists. The engine no longer reuses global client transport RTT/loss instrumentation for embedded server stats.
For rejected/auth-failed/rate-limited events and ingress/egress traffic, those standalone `Metrics` producers now also mirror the event into `crate::instrumentation::global()` so the optional global instrumentation export does not drift away from the standalone server metrics story.
That mirror contract is covered by a dedicated regression test in `src/implementations/server/metrics.rs`.
QKey auth failures now route through one canonical rejection producer, so `quicfuscate_auth_failed_total` reflects:
- missing or invalid initial QKey auth material
- live HTTP/3 `x-qf-auth` rejects
- QKey auth timeout closes
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

#### Telemetry access and operational interpretation

- ACK delay buckets model browser-like ACK timing distributions and can be used to validate profile behavior under different network conditions.
- Choke counters (`choked_bytes`, `choke_sleep_ms`) quantify pacing pressure and allow correlation with throughput/latency trade-offs.
- FEC gauges/counters should be interpreted together (`mode`, `window`, `loss_rate`, switch counters) to distinguish stable operation from adaptation churn.
- Compression and SIMD counters provide backend-selection and efficiency visibility without changing data-plane behavior.

### Operational hints
- Rayon thread pool sizing (parallel repairs)
  - Parallel generation uses the global Rayon pool. To cap threads, set `QUICFUSCATE_RAYON_THREADS=<n>` before launch.
  - The constructor now resolves this as an explicit FEC global-resource policy step before initializing the one process-global Rayon pool.
  - There is no runtime toggle for parallel vs sequential in the current code; selection is internal.
  - In async deployments (Tokio), avoid oversubscription: choose `<n>` near the number of physical cores or the Tokio worker count when CPU contention is observed.
  - Measure with `--telemetry` and watch `quicfuscate_fec_window`, `quicfuscate_fec_mode_switches_total`, and throughput counters when adjusting.

- Hysteresis and loss smoothing (mode stability)
  - `hysteresis` dampens mode flapping; larger values reduce oscillation on jittery links. Typical range: `0.01-0.03`.
  - `lambda` (EMA factor) near `1.0` reacts quickly to current loss; smaller values increase smoothing. Tests use `lambda=1.0` to trigger fast path deterministically.

- Streaming cadence trade-off
  - Lower `QUICFUSCATE_FEC_STREAM_EVERY` improves recovery latency but increases overhead; default is computed from CPU profile (often 1-3). Tests often use `1` for clear recovery behavior.

- Disturbance handling
  - The controller reacts to change-points (CUSUM) by escalating to streaming and, when necessary, increasing the FEC window (`QUICFUSCATE_FEC_EXTREME_WINDOW`).
  - Auto-Mode resets to efficient profiles once stability returns (EMA/variance gates).

- Telemetry for tuning
  - Enable `--telemetry` and monitor `quicfuscate_fec_mode_switches_total`, `quicfuscate_fec_window`, `quicfuscate_fec_loss_rate`, and switch-reason counters (`quicfuscate_fec_switch_reason_*_total`) during tuning iterations.

Notes
- `QUICFUSCATE_FEC_STREAM_EVERY` is read once per `AdaptiveFec::new`. Use a new instance to pick up changes.
- Telemetry updates are no-ops unless telemetry is enabled at runtime; exporting is handled by the `telemetry` module.

### Test-only Environment Overrides
These env vars are only read under `#[cfg(test)]` or with the `rust-tests` feature; they are not part of the runtime contract:
- `QUICFUSCATE_MORUS` - force MORUS plan selection.
- `QUICFUSCATE_PROFILE_OVERRIDE` - override CPU profile selection in tests.
- `QUICFUSCATE_GF16_TEST_ITERS` - iteration count for GF16 consistency tests.
- `QUICFUSCATE_FEC_ADAPT_RS` - toggles adaptive RS fixtures in tests; no runtime read path.
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
- Integration: serve the snapshot via your own HTTP endpoint or exporter; call `telemetry::flush()` to emit a one-off snapshot to logs.

### AF_XDP Experimental Status
Status: `experimental/internal` for the retained AF_XDP socket code behind `internal_af_xdp_experimental`.

AF_XDP runtime wiring is not part of the canonical runtime in this fork. The retained AF_XDP socket code remains available only behind the internal feature gate `internal_af_xdp_experimental`, and the canonical Linux high-end send path is `io_uring`.

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

The codebase uses approximately 116 global `AtomicU64`/`AtomicU32`/`AtomicBool`/`AtomicUsize`/`AtomicI64` instances across modules. This section documents the rationale, ownership, and future direction.

### Why Global Atomics

Global atomics provide lock-free, zero-overhead cross-module coordination for a high-throughput data-plane runtime. They avoid mutex contention on hot paths (packet processing, FEC, AEAD selection) where even microsecond-level lock waits would degrade throughput. The trade-off is implicit coupling between subsystems - readers and writers are connected through shared global state rather than explicit interfaces.

### Ownership by Module

| Module | Count | Category | Purpose |
|---|---|---|---|
| `src/optimize/telemetry.rs` | 97 | Metrics/Counters | Telemetry counters for H3, stealth, FEC, SIMD usage, memory pool, io_uring, CPU features, I/O driver stats. Read-only observation surface for dashboards and diagnostics. |
| `src/brain.rs` | 3 | Hint channels | Cross-subsystem coordination hints: `FEC_INTERVAL_HINT_PKTS`, `FEC_REDUNDANCY_PPM`, `INTELLIGENT_STEALTH_LEVEL_HINT`. Written by StealthBrain and read by FEC/stealth runtime coordination paths. |
| `src/optimize/` | 5 | Runtime config | NUMA round-robin node, NUMA node count, profile override, TLS limit. Hardware-adaptive runtime state. |
| `src/transport/batch.rs` | 3 | Metrics | Batch send/recv/packet counters for transport telemetry. |
| `src/crypto/` | 2 | Runtime config | `DATA_AEAD_OVERRIDE_MODE` (AEAD selection), `ARM_AES_OK` (ARM AES capability cache). |
| `src/fec/` | 1 | Sequencing | `REPAIR_ID_COUNTER` - monotonic repair packet ID generator. |
| `src/stealth/` | 1 | Round-robin | `DOH_PROVIDER_INDEX` - DoH provider rotation index. |
| `src/qftls.rs` | 1 | Runtime gate | `TLS_OVERRIDE_REQUIRED` - TLS cover override flag. |
| `src/rng.rs` | 1 | Test gate | `TEST_FORCE_SECURE_ENTROPY_FAILURE` - test-only entropy failure injection. |
| `src/main.rs` | 1 | Sequencing | `NEXT_ID` - connection ID generator. |

### Trade-offs

**Performance benefit**: Zero-cost reads on hot paths. No lock contention. No allocation. Compiler can optimize `Relaxed` loads into single instructions.

**Coupling cost**: Implicit data flow between subsystems. A writer in `src/brain.rs` affects behavior in `src/fec/` without an explicit interface contract. Grep is required to trace data flow. Testing individual modules in isolation requires awareness of global state.

### Future Direction

- **Metrics/counters (97 of 116)**: These are read-only observation surfaces and are appropriate as globals. No change planned.
- **Hint channels (4 in brain.rs)**: Candidates for a structured `HintChannel<T>` abstraction that makes the writer-reader contract explicit while preserving lock-free performance.
- **Runtime config (7 across optimize/, crypto/, qftls.rs)**: Could migrate to a shared `RuntimeConfig` struct passed through the call chain, but current usage is stable and well-bounded.
- **Sequencing (2 in fec/, main.rs)**: Standard pattern for ID generation. No change needed.
- **Test gates (1 in rng.rs)**: Test-only, acceptable as-is.

The overall approach prioritizes runtime performance over architectural purity. A structured hint/message channel for the 4 brain.rs hint atomics would provide the highest return on coupling reduction without impacting performance.

## Troubleshooting

### Connection Failures

#### TLS Handshake Errors
**Symptoms:** Connection times out during handshake, "TLS failure" or "TLS alert" in logs.

**Common causes:**
- Certificate mismatch between client SNI and server certificate CN/SAN
- Expired or self-signed certificate without `verify_peer = false` on the client
- ALPN protocol mismatch

**Fixes:**
1. Verify certificate validity: `openssl x509 -in server.crt -noout -dates`
2. Check SNI matches: ensure `connection.sni` in client config matches the server certificate
3. For testing, set `connection.verify_peer = false` in client config
4. Verify ALPN alignment between client and server `connection.alpn` arrays

#### Connection Timeout
**Symptoms:** "Timeout" error after idle_timeout_ms.

**Fixes:**
1. Increase `connection.idle_timeout_ms` (default: 30000ms)
2. Check firewall allows UDP on the configured port (default: 4433)
3. Verify NAT/router does not drop long-lived UDP sessions
4. Check `transport.max_idle_timeout` is consistent on both sides

#### QKey Authentication Failure
**Symptoms:** "Connection refused" or "Invalid token" immediately after handshake.

**Fixes:**
1. Verify `qkey_id` is exactly 12 hex characters
2. Verify `qkey_token` matches what was registered on the server
3. Check the QKey has not been revoked on the server
4. For TUN/MASQUE failures, check both auth layers: the encrypted QUIC transport parameter and the H3 `x-qf-auth` CONNECT-UDP header. MASQUE DATAGRAM delivery to TUN is intentionally blocked until one current auth proof has validated.

### DNS Leak Detection and Prevention

#### Detecting DNS Leaks
```bash
# While connected, test DNS resolution path:
nslookup -type=A example.com
# The response should come from your configured VPN DNS servers, not your ISP
```

Linux root validation uses `scripts/tests/tun-e2e-dns-leak-netns.sh`. The gate creates server/client namespaces, opens a real QKey-authenticated TUN/MASQUE tunnel, runs a DNS query through the server TUN IP, and captures the client underlay with tcpdump. Passing evidence requires a DNS response plus `raw_port_53_packets=0`.

#### Common DNS Leak Causes
1. **Split-tunnel configuration:** Ensure all DNS traffic routes through the tunnel
2. **IPv6 DNS fallback:** Configure IPv6 DNS explicitly when IPv6 is enabled. The live server intercepts both IPv4 and IPv6 UDP/53 DNS packets that arrive through the MASQUE/TUN path, but local OS resolver bypass outside the tunnel still requires kill-switch enforcement.
3. **macOS:** DNS reset to "Empty" falls back to DHCP DNS (see platform-specific section)

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
- Atomic iptables-restore is used for rule application into a dedicated `QUICFUSCATE_KS` chain. If you still experience leaks, check that iptables-restore is available on your system and that no other firewall manager is interfering.

**Stale rules from crashed session:**
- Run `quicfuscate client --cleanup-firewall` to remove stale kill-switch rules
- This only flushes the `QUICFUSCATE_KS` chain and removes the jump rule from OUTPUT - it does NOT touch unrelated user firewall rules

#### macOS
**pf rules not loading:**
- Check pf status: `sudo pfctl -s info`
- Verify rules file: `sudo pfctl -s rules`
- If pf was already enabled, the enable command may fail silently; check system pf state before enabling

**Temp file conflicts:**
- Kill-switch config uses PID-scoped temp files (`/tmp/quicfuscate_killswitch_<pid>.conf`) to avoid multi-instance conflicts
- Stale rules can be cleaned with `quicfuscate client --cleanup-firewall`

#### Windows
**Firewall rules accumulate:**
- Old rules may not be cleaned up on disconnect; run periodic cleanup
- Manual cleanup: `netsh advfirewall firewall show rule name=all | findstr QuicFuscate`
- Delete stale rules: `netsh advfirewall firewall delete rule name="QuicFuscate*"`

### Heartbeat Watchdog

The engine includes a heartbeat watchdog that detects connection loss when no data is received from the server for a configurable timeout period. When triggered, it activates the kill switch (if enabled) and transitions the engine back to `Running` state.

**Configuration:**
```toml
[security]
kill_switch = true              # Enable kill switch
heartbeat_timeout_ms = 30000    # 30s default; 0 to disable
cleanup_firewall_on_start = false  # Clean stale rules on startup
```

**Usage:** Call `engine.check_heartbeat()` periodically (every 1–5 seconds) from your run loop. It returns `true` if connection loss was detected and handled.

### IPv6 Dual-Stack Support

The VPN server supports dual-stack IPv4/IPv6 operation. When IPv6 is enabled (default), the server:
- Assigns IPv6 addresses to the TUN interface via `ip addr add` / `ifconfig inet6`
- Allocates IPv6 addresses to clients from a dedicated `Ipv6Pool`
- Routes IPv6 packets via `get_by_client_ipv6()` session lookup
- Sets up ip6tables MASQUERADE / pf inet6 NAT / Windows NetNat v6

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
Three algorithms are available: Reno (conservative AIMD), BBR2 (loss-aware model-based), BBR3 (stealth-optimized, default). All are real implementations, selectable via CLI, config, or admin UI.

```toml
[transport]
cc_algorithm = "bbr3"   # Options: "reno", "bbr2", "bbr3"
```

When stealth mode is active, the StealthShaper automatically wraps BBR2/BBR3 with pacing jitter. Reno has no pacing and is unaffected by stealth shaping.

#### CPU Affinity and Thread Count
```toml
[optimization]
num_worker_threads = 0   # 0 = auto (uses default of 8 threads)
```

#### Memory Pool
The memory pool auto-scales to 5% of system RAM (clamped 16-256 MB). Override via environment variable:
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
- Set capability: `sudo setcap cap_net_admin+ep /opt/quicfuscate/bin/quicfuscate`
- Or run via systemd with `AmbientCapabilities=CAP_NET_ADMIN`

#### macOS
**utun interface creation fails:**
- Requires root or network extension entitlement
- Run with `sudo` for development/testing

#### Windows
**WinTUN adapter not found:**
- WinTUN driver must be installed separately from https://www.wintun.net/
- Create a TUN adapter named "QuicFuscate" and run QuicFuscate as Administrator

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
