# QuicFuscate Map

This document is the single combined **file map** and **architecture index** for the repository.
It is maintained as the current architecture and repository index, with a curated tracked-source tree snapshot included below for navigation.

## High-Level Architecture and Wiring

- Runtime core: Rust crate under `src/` with entrypoints in `src/main.rs` and `src/lib.rs`.
- Data path wiring: app or TUN ingress -> core/transport -> stealth shaping -> crypto -> FEC -> network I/O.
- Production VPN carrier: authenticated Core H3/MASQUE CONNECT-UDP carries TUN IP packets. The public QKey ID in the QUIC Initial selects the server record; the bearer is presented only through the encrypted H3 `x-qf-auth` header. The server gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state.
- Tunnel MTU ownership: `transport::PmtuState` discovers a validated 1280-1500 outer packetization budget; `core::QuicFuscateConnection` derives the FEC/QUIC/MASQUE datagram payload and a separate IPv6-safe inner tunnel MTU. The client applies live TUN MTU changes and returns local IPv4/IPv6 PTB above that boundary.
- Oversized tunnel carrier: raw IP packets within the effective tunnel MTU but above the MASQUE datagram payload use bounded `QFT1` length framing on the `/tun` HTTP/3 stream. `core.rs` reassembles arbitrary DATA-read segmentation per stream and rejects invalid magic, empty frames, non-IP payloads, and unbounded pending data.
- Reliable STREAM ownership: `transport::Connection` keeps a 16 MiB immutable range ledger, binds compact transmission IDs to packet numbers, retires exact ACKed ownership, and requeues packet-threshold/PTO loss before new data. A PMTU decrease byte-exactly splits queued transmissions to the new packet budget while late ACKs retire all derived segments once.
- Outbound pacing: `core::OutboundPacer` centrally gates congestion-controlled transport and FEC emissions from every socket path; ACK-only output is explicitly exempt.
- CUBIC wiring: engine config, CLI, client/server conversion, and TOML select `Algorithm::Cubic`; `Recovery` owns RTT-before-ACK delivery, recovery-episode loss collapse, and enum-dispatched `Cubic`/`StealthCubic` pacing without vtable indirection.
- Standalone TUN routing: explicit `--tun-ip` / `--tun-netmask` on the server updates `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool, keeping Linux namespace deployments and runtime session routing in the same subnet.
- DNS-through-tunnel: server MASQUE/TUN uplink intercepts IPv4/IPv6 UDP/53 packets before generic TUN egress, resolves through configured server DNS upstreams, and queues rebuilt DNS responses over MASQUE downlink.
- NAT traversal: optional `NatPathDiscovery` is default-off and reason-gated (`connectivity-fallback`, `roaming`, `mesh`, `always`). It feeds transport path discovery when explicitly enabled; it is not part of the baseline stealth path.
- TUN downlink hotpath: after one MASQUE downlink packet is queued, the server flushes only the owning client connection rather than sweeping all connected clients.
- MASQUE observability: CONNECT-UDP lifecycle and peer-flow registration stay at `info`; per-packet MASQUE TX/downlink TX lines are `debug` to avoid production log amplification.
- Packet crypto wiring: Initial/Handshake use boxed AES-GCM compatibility keys; normal 0-RTT/1-RTT data-plane AEAD uses `DataAead` enum dispatch; Rustls packet-key integrations use the explicit dynamic packet wrapper arm.
- FEC recovery wiring: Initial, Handshake, and stable Zero datagrams remain raw. Active 1-RTT output reserves the exact 34-byte maximum FEC overhead before QUIC serialization, then `src/fec/wire.rs` carries a fixed 32-byte versioned header plus the protected two-byte source length. The receiver validates transmitted epoch, window, codec, source/total counts, interleave lane, sequence, and repair ordinal before bounded decoder allocation; it reconstructs GF4/GF8/GF16 rows or Fountain source sets deterministically instead of receiving coefficient vectors. `InterleavedEncoder` assigns source/repair symbols to lanes and complete-block transitions advance the wire epoch. Only reconstructed systematic datagrams enter QUIC header protection and AEAD processing. GF8 remains the wire-canonical GF(256)/0x11D field; GF4 uses fused scalar/AVX2/NEON multiply-XOR, and GF16 uses carryless polynomial multiplication with exact odd-length recovery.
- Compression wiring: `src/compress.rs` writes safe-path zstd output directly into `MemoryPool` / body-pool blocks via `compress_to_buffer`; H3 compression semantics and `0x5A` / `0x5D` frame headers remain unchanged.
- Client packet I/O is owned by `src/implementations/client/io_driver.rs` plus `src/core.rs`; `src/implementations/client/pipeline.rs` is not part of the production module graph.
- Audit logging wiring (TODO-515): `src/audit/mod.rs` exposes a global `OnceLock<Arc<AuditLog>>` accessor initialized via `--audit-log <path>` in `run_server()`. Emitters cover server lifecycle and privilege drop in `src/main.rs`; QKey auth results and timeout, live/standalone connection acceptance, removal, and expiry, and admin actions in `src/implementations/server/`; QKey issuance in `qkey_registry.rs`; and routing/firewall setup and teardown in `routing.rs`. `verify-audit-log <path>` exposes hash-chain verification at the production CLI boundary. The audit file is mode `0o600`, chowned to the runtime user before privilege drop; its parent is chowned only if newly created. Mutex poisoning is recovered via `unwrap_or_else(|e| e.into_inner())` rather than panicking.
- Remote proof runbook: `docs/remote-proof-runbook.md` contains the exact commands, expected outputs, and close criteria for the three remaining `OPEN (prepared)` TODOs (510 Docker validation, 512 Broderick soak, 513 signed release proof) that require remote infrastructure.
- Memory locking wiring (TODO-516): `src/main.rs::run_server()` calls `mlockall(MCL_CURRENT | MCL_FUTURE)` when `[security] lock_memory = true` (default) before key material is loaded. `src/optimize/mod.rs` `MemoryPool::set_lock_blocks()` gates per-block `mlock()` in `alloc_numa_block()` when `lock_blocks = true` (default). Both require `LimitMEMLOCK=infinity` in systemd or `CAP_IPC_LOCK`.
- Graceful shutdown wiring (TODO-448): `ServerRuntime` owns the shared `GracefulShutdown` lifecycle consumed by the UDP loop and admin handlers. SIGINT/SIGTERM/admin drain stop `AcceptLoop` admission, wait for established clients or `[engine] shutdown_timeout_ms`, flush final QUIC close packets, then stop control-plane services and host resources. SIGHUP uses the canonical runtime reload path. `implementations/server/systemd.rs` emits READY, RELOADING, STOPPING, STATUS, and watchdog notifications.
- Control plane wiring: CLI + engine + admin surfaces + metrics/telemetry endpoints.
- UI wiring: `apps/svelte-desktop` (Svelte 5 desktop frontend) and `apps/svelte-admin` (SvelteKit/Svelte 5 admin frontend) are the active UI surfaces. The retained native desktop host/runtime bridge lives in `apps/tauri/src-tauri`. Shared UI primitives live in `packages/ui` (Svelte components) and `packages/theme` (CSS).
- Automation wiring: scripts in `scripts/` orchestrate build/test/benchmark/audit tasks; GitHub workflows own cross-platform core checks and signed release packaging; generated local artifact directories are intentionally outside this map.

## Stealth Mode Architecture Notes (Session 22)

### StealthMode Enum (src/engine/config.rs)
6-variant: `Off | Performance | Stealth | AntiDpi | Manual | Auto` (default).
`Auto` serde alias: `intelligent`. `AntiDpi` serde: `anti-dpi`, alias `antidpi`/`max` (QKey compat only).
All call sites map `Auto` -> `StealthMode::Intelligent` in `stealth/mod.rs`.

### StealthManager Runtime Overrides (src/stealth/mod.rs)
Three `AtomicU8` rate fields are retained: `runtime_padding_rate`, `runtime_timing_rate`, `runtime_rotation_rate`.
`escalate_to_level(n)` sets padding/timing only (L0=0%, L1=50% configurable padding and 0% timing, L2=100% padding/timing).
Padding and timing rates flow through `StealthRuntimePolicy` → `StealthRuntimeDelta` → connection config.
`compute_stealth_padding()` uses `stealth_padding_rate` for probabilistic packet padding.
`transport_stealth_jitter_delay()` uses `stealth_timing_rate` to scale jitter magnitude.
`runtime_rotation_rate` stays 0 for active sessions; `maybe_rotate_fingerprint()` now defers persona movement to future sessions only.

### Stealth Stack Coherence Wave (2026-06-30)
- Engine client uses `stealth.use_utls` and no longer hardcodes `use_utls=false`.
- Connection persona is frozen for the session: Browser/OS/uTLS/QPACK/header identity does not mutate mid-connection.
- Domain fronting defaults off in Performance, Intelligent clean path, and Stealth; Anti-DPI keeps the aggressive built-in list.
- Server Push cover uses bounded seed-varied resource plans.
- WebTransport cover is H3 application cover only, active for Anti-DPI or Intelligent level 2, never a competing VPN carrier.
- Core H3/MASQUE remains the production VPN/TUN data plane; `stealth::MasqueManager` remains compatibility/experiment machinery.

### Linux Production E2E Evidence (2026-06-30)
- `broderick` release build: `cargo build --release --bin quicfuscate` passes on Linux.
- All TUN/netns E2E scripts acquire a shared `flock` guard (`/tmp/quicfuscate-tun-e2e.lock` by default) because they intentionally share namespace names, process cleanup, logs, admin sockets, and generated config/cert state.
- `scripts/tests/tun-e2e-netns.sh`: real server/client netns TUN over authenticated H3/MASQUE, 5/5 ping, 0% tunnel loss.
- `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh`: isolated three-client IPv4/IPv6 routing, source ownership, spoof rejection, fan-out, PTB, NAT, throughput, and explicit client-to-client policy proof.
- `scripts/tests/tun-e2e-dns-leak-netns.sh`: DNS query through server TUN IP returns a response and tcpdump observes `raw_port_53_packets=0` on the client underlay.
- `scripts/tests/tun-e2e-fec-netns.sh`: 0%, 5%, and 10% loss ping gates pass; optional iperf3 TCP-to-server-TUN probes skip unless real throughput is measured.
- `scripts/tests/tun-e2e-fec-burst-netns.sh`: correlated burst-loss gates pass.
- `scripts/tests/tun-e2e-fec-transition-netns.sh`: clean -> lossy -> recovered live transition gate passes.
- `scripts/tests/tun-e2e-fec-netem-adversity.sh`: broad adversity matrix passes with 25 passed, 0 failed.

### Omega DPLPMTUD and Multi-Client Evidence (2026-07-23)

- Exact run35 source archive SHA-256: `b3140e9c14300af3416d021de6e81476ec41e3b57b775c7b1605a9fcaaf2ce3e`; exact AArch64 binary SHA-256: `d985c254fb55792afc9d2e1bc88d14b68b8737a3bfcb7507961fc8b1a1c09888`.
- Local and native full Rust tests and strict all-target/all-feature Clippy pass. Deterministic coverage includes loss/PTO requeue, PMTU-aware 1500-to-1280 retransmission splitting, and late-original-ACK retirement of every derived segment.
- Three isolated clients prove IPv4/IPv6 allocation, routing/NAT, source ownership, spoof rejection, default-deny and explicit opt-in unicast, authenticated fan-out, client/server PTB, and all six zero-loss ping streams.
- All three clients and the server discover 1500. The 20-second egress black-hole trial detects failure in 3 seconds, falls back to 1280, transfers 17,039,360 bytes, and re-confirms 1500.
- Three 1280-floor trials have 6.454 Mbit/s median; three confirmed-1500 trials have 8.961 Mbit/s median. Every regular five-second run has exactly five positive intervals, and the median gain is 38.85%.
- Evidence root: `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo534/evidence/run35`. Cleanup leaves no product process, heartbeat failure, or network namespace.

### Omega CUBIC Conformance and Performance Evidence (2026-07-23)

- Exact run06 build-source archive SHA-256: `df1aed74696ed45ca1bb66e06556cf39b8298620fc60878570427dbcda4d0837`; compile-input digest: `423cb07e9b4f64c3605ba28034257edcfb4124a4e5ccd86850908d6c5109a680`; exact AArch64 binary SHA-256: `2dc42fd87b77f50eaef96c0244a15adf8126f19d4593c5497f26acdb048483eb`.
- Local and native full Rust tests and strict all-target/all-feature Clippy pass. Deterministic tests cover RFC 9438 precision below `1e-6`, RFC 9406 HyStart++, recovery episodes, application-limited epochs, CUBIC-over-Reno memory below 200 bytes, paced stealth behavior, and all selectable CC paths.
- The deterministic shared drop-tail model records CUBIC `13,389,600` bytes, Reno `14,367,600` bytes, and Jain fairness `0.998760`.
- The live shared 2 Mbit/s bottleneck records CUBIC 0.961 Mbit/s, Reno 0.951 Mbit/s, and Jain fairness `0.999974`.
- Three clean and three 5% random-loss CUBIC trials on a shared 5 Mbit/s bottleneck record median throughput of 3.001 Mbit/s clean and 2.862 Mbit/s under loss, retaining 95.38%.
- Evidence root: `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo535/evidence/run06`. Cleanup leaves no product process, network namespace, or test qdisc.

### Omega FEC Wire Integrity Evidence (2026-07-22)

- Exact proof source: `15570abf772766c76959f6aae6ba16b2b9c26fd7`; native ARM64 bundle SHA-256 `5406170b4175d91722d2169c8c21adc9721e61fe995a513299fc4f52eff9d8fe`; binary SHA-256 `9b4144a85e452ef37102ac255b0c8c976f1145ad04941c594d07d4fc6130cf5b`.
- Isolated runtime: `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-15570ab`; historical runtime directories remain untouched and test cleanup leaves no process or network namespace behind.
- `scripts/tests/tun-e2e-fec-netns.sh`: 1,000 packets at each 0/5/10/25% uniform-loss level, `4 passed, 0 failed`.
- `scripts/tests/tun-e2e-fec-burst-netns.sh`: 1,000 packets in each correlated-burst scenario, `2 passed, 0 failed`; both 10%/25%-correlation and 20%/50%-correlation cases finish with 2% residual tunnel loss.
- Retained client/server logs prove TLS, H3/MASQUE, and NEON FEC without AEAD, decrypt, or panic errors. Local deterministic tests separately prove 1,000/1,000 unique byte-exact interleaved recovery with zero duplicates and bounded latency.

### EscalationState (src/stealth/mod.rs) - TODO-416
Probe-count-based escalation state machine on `StealthManager`.
- `record_probe()`: records timestamp, checks thresholds (≥3 in 60s → L1, ≥8 in 120s → L2).
- `check_de_escalation()`: drops one level after configurable quiet period (default 300s).
- `on_probe_detected()` uses `EscalationState` instead of immediate binary escalation.
- `sync_intelligent_level()` calls `check_de_escalation()` on each tick.
- Config knobs: `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (3), `_L2` (8),
  `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (300), `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (50).
- `on_probe_detected` only escalates when `config.dynamic_enabled` is true (Intelligent mode).

### IntelligentStealthInputs.level_hint (src/stealth/mod.rs)
Brain reads `INTELLIGENT_STEALTH_LEVEL_HINT` (a `HintChannel<AtomicU32>` with an explicit writer/reader contract at the declaration site, TODO-517) after hysteresis and passes as `level_hint: u8` (0/1/2) to `derive_intelligent_runtime_policy`.
Level 0 (clean path): padding disabled (near-zero Intelligent-mode overhead). Level 1/2: padding active.
Jitter under pressure (CE>5% or rtt_spike>4): 85% of budget (was wrongly 20% - direction fixed).

### Preset Values (src/stealth/mod.rs)
- `performance()`: QPACK on (real Chrome always sends QPACK), domain fronting off
- `stealth()`: Server Push Cover enabled (intensity 0.25, 60s interval)
- `anti_dpi()`: fingerprint_rotation_interval retained for next-session policy, not active-session mutation
- `jitter_max_us` default in `StealthBrainConfig`: 5000 us (was 1500)

### Optimization + FEC + Transport - Test Coverage (Session 36, 2026-03-26)
10 previously untested modules received inline tests (+215 tests total):
- `optimize/simd.rs` (51): dispatch correctness, fallback parity, boundary conditions
- `optimize/brain.rs` (34): sensor fusion, threshold logic, moving average, histograms
- `optimize/string.rs` (31): SIMD search, edge cases, multi-match, scalar parity
- `transport/config.rs` (18): defaults audit, CC parsing, ALPN wire format, stealth config
- `stealth/tls_cover.rs` (16): ClientHello format, browser-specific generation, GREASE, extensions
- `fec/gf_tables.rs` (16): GF multiply properties, exhaustive inverse (all 255), GF16
- `optimize/transport.rs` (14): congestion aggregation, bitmap, ECN popcount, pn decode
- `optimize/sort.rs` (13): radix sort, f32 sort, argsort, duplicates, large input
- `fec/internal.rs` (18): ZeroEncoder/Decoder, LazyDecoder flush-on-gap, clean-block pruning, ModeManager
- `optimize/udp.rs` (5): GSO config, send_batch single/multi/IPv6

### Stealth Components - Test Coverage (Session 23, 2026-03-24)
All 15 stealth technologies in `src/stealth/mod.rs` have unit test coverage in `src/stealth/tests.rs`:
- RateChoker: token-bucket shape(), full-bucket=ZERO, deficit=positive-wait
- DomainFrontingManager: get_fronted_domain() membership + ultra_stealth() smoke
- Http3Masquerade: generate_headers() pseudo-headers, browser-profile UA divergence
- FingerprintRotation (via StealthManager): Fixed mode stable, All-mode no-panic guard path
- ActiveProbeDetector: GFW_TLS_Probe, DPI_QUIC_Scan masked, benign-ignored
- ServerPushState: observe_server_push_burst resets interval, disabled=None plan
- FlowShaper: jitter range, min-clamp, variation (existing)
- TlsCover: ClientHello structure, Firefox no-session-id, Chrome session-id (existing)
- TLS Cover key lifecycle: `TlsCoverProvider` fresh OS entropy -> profile/role-domain-separated HKDF -> `CryptoContext::install_tls_cover_cipher` -> active/retired material identity and monotonic per-direction record counters; cover generation encrypts only through the constructor-installed state and fails closed if it is absent.
- CoverPing: interval gate, disabled preset (existing)
- CoverStream: disabled_when_cover_ping_off, disabled_when_interval_zero, fires_once_then_suppressed, data_length_in_range (Session 31)
- PaddingStrategy: PacketNormalize distinct, serde roundtrip, defaults-per-mode (existing)

### CC + StealthShaper - Test Coverage (Session 24, 2026-03-25)
`src/transport/cc/bbr3.rs` - 15 total tests (was 7):
- State machine: starts_in_startup, exits_startup_on_plateau, drain_exits_to_probebw, probe_rtt_floor_holds
- Mechanics: bytes_in_flight, can_send, send_quantum, loss_rate, fec_callbacks, pacing_rate
- BBR3-specific: custom_gains_applied, btlbw_updates, set_pacing_rate_overrides, convergence

`src/transport/cc/cubic.rs` - 20 tests:
- RFC 9438: epoch K, cubic window, stateful Reno-friendly estimate, bounded target, recovery episodes, application-limited epoch suspension, and memory bound.
- RFC 9406: sampled-round entry, one-quarter CSS growth, spurious-exit recovery, and five-round exit.

`src/transport/cc/stealth_shaper.rs` - 16 total tests:
- Core: `stealth_wraps_reno`, `stealth_wraps_paced_cubic`, `stealth_wraps_bbr2`, `stealth_wraps_bbr3`, `profile_switch`, `disabled_stealth_no_jitter`
- Flow shaper: bounded CUBIC pacing jitter plus optional 2% dampening, BBR3 pacing reduction, and BBR2 pacing reduction
- Post-ack guard: `disabling_stealth_restores_cubic_pacing`, `apply_stealth_post_ack_disabled_is_noop_bbr3`, `apply_stealth_post_ack_disabled_is_noop_bbr2`
- Profile: edge_uses_chrome_jitter, inner_mut_access, jitter_produces_variation

### init_stealth() (src/implementations/client/subsystems.rs)
Uses `StealthConfig::from_mode(runtime_mode)` - was silently using `..Default::default()` which locked mode=Stealth for all modes.

## Critical Wiring Paths

1. Client CLI -> runtime init: `src/main.rs` -> `src/core.rs` -> `src/transport/connection.rs`
2. TLS handshake path: `src/qftls.rs` (`CombinedProvider`, release verification mandatory) -> rustls keys/errors -> `src/transport/connection.rs` TLS-bound application readiness -> `src/core.rs` terminal error propagation -> `src/transport/packet.rs`
3. Stealth shaping path: `src/stealth/` (`StealthManager`) -> `src/transport/config.rs` -> `src/transport/connection.rs`
4. FEC encode/decode path: `src/core.rs` raw handshake/Zero gate -> safe block-boundary mode transition -> `src/fec/` (`AdaptiveFec`) -> `InterleavedEncoder` lane distribution -> `src/fec/wire.rs` versioned MTU-bounded envelope -> packet loss -> receiver-owned epoch/window decoder -> `InterleavedDecoder` lane routing -> rank-checked and byte-validated systematic recovery -> `src/transport/connection.rs` authenticated QUIC receive -> transport observer hooks
5. Linux client zero-copy inbound path: `src/implementations/client/io_driver.rs` -> pool-backed `src/optimize/uring_batch.rs` `UringRecvBatch` -> `src/core.rs` `recv_pooled_block()` -> `src/fec/mod.rs` -> `src/transport/connection.rs`
6. Packet-number decode path: `src/transport/packet.rs` header-protection removal -> `src/optimize/transport.rs` `decode_packet_number()` -> BMI2/SVE2/NEON/scalar dispatch
7. Compression pool path: `src/transport/h3.rs` payload policy -> `src/compress.rs` direct zstd `compress_to_buffer` into `MemoryPool` / body-pool blocks -> H3 compressed body bytes
8. Probe mitigation path: `src/stealth/` detector -> `src/reality.rs` fallback proxy -> upstream targets
9. Engine embedding path: `src/engine/engine.rs` -> `src/implementations/{client,server}/` runtimes
10. Admin control plane path: `src/implementations/server/admin_http.rs` -> `qkey_registry.rs` -> live server policy enforcement
11. Desktop frontend path: `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts` -> Tauri invoke -> engine/control runtime
12. 0-RTT anti-replay path: `src/transport/anti_replay.rs` (`StrikeRegister` with SHA-256 fingerprints, Bloom fast-negative, FIFO ring eviction) -> `src/transport/config.rs` (attached at server startup) -> `src/transport/connection.rs` `recv()` gate -> silent discard on replay
13. Desktop native host path: `apps/tauri/src-tauri/src/main.rs` -> Tauri commands -> engine/control runtime
14. Web-admin path: `apps/svelte-admin/src/lib/api.ts` -> Vite dev proxy (`/api` -> `127.0.0.1:9000`) -> admin HTTP endpoints -> server runtime state
15. Build publish path: `scripts/build/build-web-admin.sh` -> `assets/web-admin/` consumed by `--admin-web-root`
16. Shared packages path: `packages/ui` (Svelte 5 components) + `packages/theme` (CSS tokens/glass/layout) -> consumed by both Svelte apps
17. GitHub CI app backend gate: `.github/workflows/ci.yml` `app-backend-checks` -> `apps/svelte-desktop` build output -> `apps/tauri/src-tauri` `cargo check` / `cargo test`
18. NAT traversal path discovery: `src/engine/config.rs` `[nat_traversal]` -> `src/transport/config.rs` `NatTraversalConfig` -> `src/transport/nat.rs` `NatPathDiscovery` -> path-management consumers when policy permits discovery.
19. Audit logging path: `src/main.rs::run_server()` `--audit-log <path>` -> `src/audit/mod.rs::init_audit_log()` (global `OnceLock<Arc<AuditLog>>`) -> `crate::audit::audit()` calls at lifecycle, privilege, authentication, QKey, admin, connection, configuration, and firewall boundaries -> `src/main.rs` `verify-audit-log <path>` -> `AuditLog::verify_chain()`.
20. Memory locking path: `src/engine/config.rs` `[security] lock_memory/lock_blocks` -> `src/main.rs::run_server()` `RLIMIT_MEMLOCK` gate -> unlimited `mlockall(MCL_CURRENT | MCL_FUTURE)` or finite-limit `MCL_CURRENT` -> `src/optimize/mod.rs` `MemoryPool::set_lock_blocks()` -> best-effort `mlock_block()` in `alloc_numa_block()`.
21. Windows core CI gate: `.github/workflows/ci.yml` `windows-core-checks` -> native `windows-latest` `cargo check --lib` -> parallel `cargo test --lib --features rust-tests` -> `cargo clippy --lib --features rust-tests -- -D warnings`; exact proof job `88909613077` is green on `15570abf772766c76959f6aae6ba16b2b9c26fd7`.
22. Windows signed release path: `scripts/audits/verify-release-version.sh` -> `.github/workflows/release.yml` `release-version-contract` -> `desktop-windows` Tauri MSI build -> `.msi` plus `.msi.sig` verification -> required `publish-release` dependency -> `latest.json` `windows-x86_64` entry.
23. Reliable tunnel fallback path: `src/core.rs` `QFT1` packet framing -> `src/transport/connection.rs` immutable STREAM ledger -> confirmed-PMTU packetization -> centralized `OutboundPacer` -> ACK/loss/PTO retirement and requeue -> byte-exact PMTU fallback splitting -> peer `core.rs` bounded packet reassembly.

## ASCII Repository Tree (curated tracked-source snapshot)

This snapshot intentionally excludes gitignored paths and local generated directories. `assets/web-admin/` remains included because it is a tracked publish artifact consumed directly by the server runtime.

```text
.
|-- .cargo
|   |-- audit.toml
|   `-- config.toml
|-- .gitattributes
|-- .github
|   `-- workflows
|       |-- ci.yml
|       |-- clippy-matrix.yml
|       `-- release.yml
|-- .gitignore
|-- AGENTS.md
|-- Cargo.lock
|-- Cargo.toml
|-- README.md
|-- SECURITY.md
|-- apps
|   |-- tauri
|   |   |-- package.json
|   |   `-- src-tauri
|   |   |   |-- Cargo.lock
|   |   |   |-- Cargo.toml
|   |   |   |-- build.rs
|   |   |   |-- gen
|   |   |   |   `-- schemas
|   |   |   |       |-- acl-manifests.json
|   |   |   |       |-- capabilities.json
|   |   |   |       |-- desktop-schema.json
|   |   |   |       `-- macOS-schema.json
|   |   |   |-- icons
|   |   |   |   |-- 128x128.png
|   |   |   |   |-- 128x128@2x.png
|   |   |   |   |-- 32x32.png
|   |   |   |   |-- 64x64.png
|   |   |   |   |-- Square107x107Logo.png
|   |   |   |   |-- Square142x142Logo.png
|   |   |   |   |-- Square150x150Logo.png
|   |   |   |   |-- Square284x284Logo.png
|   |   |   |   |-- Square30x30Logo.png
|   |   |   |   |-- Square310x310Logo.png
|   |   |   |   |-- Square44x44Logo.png
|   |   |   |   |-- Square71x71Logo.png
|   |   |   |   |-- Square89x89Logo.png
|   |   |   |   |-- StoreLogo.png
|   |   |   |   |-- icon.icns
|   |   |   |   |-- icon.ico
|   |   |   |   |-- icon.png
|   |   |   |   |-- tray_black.png
|   |   |   |   `-- tray_white.png
|   |   |   |-- src
|   |   |   |   |-- main.rs
|   |   |   |   |-- secrets.rs
|   |   |   |   `-- state_store.rs
|   |   |   `-- tauri.conf.json
|   |-- svelte-admin
|   |   |-- .npmrc
|   |   |-- package.json
|   |   |-- playwright.config.ts
|   |   |-- svelte.config.js
|   |   |-- src
|   |   |   |-- app.css
|   |   |   |-- app.d.ts
|   |   |   |-- app.html
|   |   |   |-- lib
|   |   |   |   |-- api.ts
|   |   |   |   |-- assets
|   |   |   |   |   |-- favicon.png
|   |   |   |   |   `-- favicon.svg
|   |   |   |   |-- components
|   |   |   |   |   |-- layout
|   |   |   |   |   |   `-- Sidebar.svelte
|   |   |   |   |   |-- LoginModal.svelte
|   |   |   |   |   |-- panels
|   |   |   |   |   |   |-- AdminSettingsPanel.svelte
|   |   |   |   |   |   |-- QKeyPanel.svelte
|   |   |   |   |   |   |-- ReferenceGuide.svelte
|   |   |   |   |   |   `-- StealthPanel.svelte
|   |   |   |   |   |-- ui
|   |   |   |   |   |   |-- FatalErrorScreen.svelte
|   |   |   |   |   |   |-- Sparkline.svelte
|   |   |   |   |   |   `-- TextInput.svelte
|   |   |   |   |   `-- views
|   |   |   |   |       |-- AboutView.svelte
|   |   |   |   |       |-- ConfigurationView.svelte
|   |   |   |   |       |-- DashboardView.svelte
|   |   |   |   |       |-- KpiCard.svelte
|   |   |   |   |       |-- LogsView.svelte
|   |   |   |   |       `-- SmoothTrafficValue.svelte
|   |   |   |   |-- blocked-ips.ts
|   |   |   |   |-- config-helpers.ts
|   |   |   |   |-- format.ts
|   |   |   |   |-- stores
|   |   |   |   |   `-- app.svelte.ts
|   |   |   |   |-- types.ts
|   |   |   |   `-- use-anchor-sync.ts
|   |   |   `-- routes
|   |   |       |-- +error.svelte
|   |   |       |-- +layout.svelte
|   |   |       `-- +page.svelte
|   |   |-- static
|   |   |   `-- robots.txt
|   |   |-- tsconfig.json
|   |   |-- vite.config.ts
|   |   `-- vitest.config.ts
|   |-- svelte-desktop
|   |   |-- .npmrc
|   |   |-- package.json
|   |   |-- playwright.config.ts
|   |   |-- svelte.config.js
|   |   |-- src
|   |   |   |-- app.css
|   |   |   |-- app.d.ts
|   |   |   |-- app.html
|   |   |   |-- data
|   |   |   |   `-- countries.ts
|   |   |   |-- lib
|   |   |   |   |-- assets
|   |   |   |   |   |-- favicon.png
|   |   |   |   |   `-- favicon.svg
|   |   |   |   |-- clipboard.ts
|   |   |   |   |-- components
|   |   |   |   |   |-- layout
|   |   |   |   |   |   `-- Sidebar.svelte
|   |   |   |   |   |-- tunnel
|   |   |   |   |   |   |-- AddTunnelDialog.svelte
|   |   |   |   |   |   |-- EditQKeyDialog.svelte
|   |   |   |   |   |   |-- ImportQKeyDialog.svelte
|   |   |   |   |   |   |-- ThroughputChart.svelte
|   |   |   |   |   |   |-- TunnelConfigDialog.svelte
|   |   |   |   |   |   |-- TunnelList.svelte
|   |   |   |   |   |   |-- TunnelListItem.svelte
|   |   |   |   |   |   `-- TunnelStats.svelte
|   |   |   |   |   |-- ui
|   |   |   |   |   |   |-- ConnectButton.svelte
|   |   |   |   |   |   |-- CountrySelect.svelte
|   |   |   |   |   |   |-- ErrorBanner.svelte
|   |   |   |   |   |   |-- FatalErrorScreen.svelte
|   |   |   |   |   |   `-- TextInput.svelte
|   |   |   |   |   `-- views
|   |   |   |   |       |-- AboutView.svelte
|   |   |   |   |       |-- LogsView.svelte
|   |   |   |   |       |-- SettingsView.svelte
|   |   |   |   |       `-- TunnelsView.svelte
|   |   |   |   |-- domain-fronting-policy.ts
|   |   |   |   |-- format.ts
|   |   |   |   |-- pill-styles.ts
|   |   |   |   |-- policy-display.ts
|   |   |   |   |-- qkey-utils.ts
|   |   |   |   |-- stores
|   |   |   |   |   |-- app.svelte.ts
|   |   |   |   |   `-- tauri-bridge.svelte.ts
|   |   |   |   |-- tunnel-validators.ts
|   |   |   |   |-- updater.ts
|   |   |   |   `-- types.ts
|   |   |   `-- routes
|   |   |       |-- +error.svelte
|   |   |       |-- +layout.svelte
|   |   |       `-- +page.svelte
|   |   |-- tsconfig.json
|   |   |-- vite.config.ts
|   |   `-- vitest.config.ts
|-- assets
|   |-- logo
|   |   |-- QuicFuscate.png
|   |   |-- QuicFuscate_clean.png
|   |   `-- QuicFuscate_hf.png
|   `-- web-admin
|       |-- _app
|       |   |-- env.js
|       |   |-- immutable
|       |   |   `-- ...
|       |   `-- version.json
|       |-- index.html
|       `-- robots.txt
|-- build.rs
|-- bun.lock
|-- config
|   |-- admin-auth.json.example
|   |-- local
|   |   `-- .gitkeep
|   |-- quicfuscate.toml
|   |-- server-linux.default.logging.json
|   |-- server-linux.default.qkeys.json
|   `-- server-linux.default.toml
|-- deny.toml
|-- docs
|   |-- CONTRIBUTING.md
|   |-- DOCUMENTATION.md
|   |-- LICENSE
|   |-- MAP.md
|   |-- remote-proof-runbook.md
|   |-- todo.md
|   `-- todo/
|       `-- done/          (completed detail files)
|-- examples
|   |-- brain_probe.rs
|   |-- compress_bench.rs
|   |-- crypto_backend_bench.rs
|   |-- engine_basic.rs
|   |-- fec_sim.rs
|   |-- microbench.rs
|   |-- rng_bench.rs
|   |-- shuffle_bench.rs
|   `-- tun_factory_example.rs
|-- package.json
|-- packages
|   |-- theme
|   |   |-- animations.css
|   |   |-- buttons.css
|   |   |-- glass.css
|   |   |-- index.css
|   |   |-- layout.css
|   |   |-- login.css
|   |   |-- package.json
|   |   |-- scrollbar.css
|   |   `-- tokens.css
|   `-- ui
|       |-- AboutContent.svelte
|       |-- ConfirmDialog.svelte
|       |-- ErrorBoundary.svelte
|       |-- GlassCard.svelte
|       |-- Select.svelte
|       |-- SettingRow.svelte
|       |-- Skeleton.svelte
|       |-- Switch.svelte
|       |-- Toast.svelte
|       |-- cn.ts
|       |-- index.ts
|       |-- package.json
|       |-- ripple.ts
|       |-- toast-store.svelte.ts
|       |-- use-copy-feedback.svelte.ts
|       `-- vitest.config.ts
|-- rust-toolchain.toml
|-- rustfmt.toml
|-- scripts
|   |-- benchmarks
|   |   |-- bench-ci-regression.sh
|   |   |-- ci_regression.rs
|   |   |-- micro
|   |   |   |-- micro-aes-block.sh
|   |   |   |-- micro-aes-gcm.sh
|   |   |   |-- micro-chacha-x4.sh
|   |   |   |-- micro-crypto-all.sh
|   |   |   |-- micro-ghash.sh
|   |   |   `-- micro-udpfast-throughput.sh
|   |   |-- suites
|   |   |   |-- bench-compression.sh
|   |   |   |-- bench-crypto.sh
|   |   |   |-- bench-fec-simulation.sh
|   |   |   |-- bench-fec.sh
|   |   |   |-- bench-fec-all.sh
|   |   |   |-- bench-optimization.sh
|   |   |   |-- bench-orchestrator.sh
|   |   |   |-- bench-profile-transport-fastpaths.sh
|   |   |   |-- bench-qpack-encode.sh
|   |   |   |-- bench-stealth-brain.sh
|   |   |   |-- bench-linux-send-path-decision.sh
|   |   |   |-- bench-retained-crypto-backends.sh
|   |   |   |-- bench-stealth.sh
|   |   |   `-- bench-transport.sh
|   |-- audits
|   |   `-- verify-release-version.sh
|   |-- build
|   |   |-- build-pgo-release.sh
|   |   |-- build-server-bundle.sh
|   |   `-- build-web-admin.sh
|   |-- install
|   |   |-- install-server-linux.sh
|   |   `-- quicfuscate-server.service
|   |-- tests
|   |   |-- analysis
|   |   |   |-- analysis-coverage-summary.sh
|   |   |   |-- analysis-dead-code-report.sh
|   |   |   |-- analysis-scripts-quality.sh
|   |   |   `-- analysis-suite-matrix.sh
|   |   |-- audits
|   |   |   |-- allowlists
|   |   |   |   `-- critical-allowlist.txt
|   |   |   |-- audit-all-comprehensive.sh
|   |   |   |-- audit-readiness-gates.sh
|   |   |   `-- audit-runtime-guardrails.sh
|   |   |-- build
|   |   |   |-- build-check.sh
|   |   |   |-- build-clippy-matrix.sh
|   |   |   `-- build-env-doctor.sh
|   |   |-- fast
|   |   |   |-- test-fast-crypto.sh
|   |   |   `-- test-fast-fec.sh
|   |   |-- frontend
|   |   |   |-- desktop
|   |   |   |   |-- e2e
|   |   |   |   |   |-- app.pw.ts
|   |   |   |   |   |-- dialog-centering.pw.ts
|   |   |   |   |   |-- full-ui.pw.ts
|   |   |   |   |   `-- smoke-ui.pw.ts
|   |   |   |   `-- unit
|   |   |   |       |-- setup.ts
|   |   |   |       |-- testing-library.ts
|   |   |   |       `-- src
|   |   |   |           |-- app-persistence.test.ts
|   |   |   |           |-- components
|   |   |   |           |   |-- layout
|   |   |   |           |   |   `-- sidebar.test.ts
|   |   |   |           |   |-- tunnel
|   |   |   |           |   |   |-- add-tunnel-dialog.test.ts
|   |   |   |           |   |   |-- edit-qkey-dialog.test.ts
|   |   |   |           |   |   |-- import-qkey-dialog.test.ts
|   |   |   |           |   |   |-- throughput-chart.test.ts
|   |   |   |           |   |   |-- tunnel-config-dialog.test.ts
|   |   |   |           |   |   |-- tunnel-list-item.test.ts
|   |   |   |           |   |   |-- tunnel-list.test.ts
|   |   |   |           |   |   `-- tunnel-stats.test.ts
|   |   |   |           |   `-- ui
|   |   |   |           |       |-- connect-button.test.ts
|   |   |   |           |       |-- country-select.test.ts
|   |   |   |           |       |-- error-banner.test.ts
|   |   |   |           |       |-- fatal-error-screen.test.ts
|   |   |   |           |       |-- select.test.ts
|   |   |   |           |       |-- switch.test.ts
|   |   |   |           |       |-- text-input.test.ts
|   |   |   |           |       `-- toast.test.ts
|   |   |   |           |-- lib
|   |   |   |           |   |-- clipboard.test.ts
|   |   |   |           |   |-- domain-fronting-policy.test.ts
|   |   |   |           |   |-- format.test.ts
|   |   |   |           |   |-- policy-display.test.ts
|   |   |   |           |   |-- qkey-utils.test.ts
|   |   |   |           |   |-- tunnel-validators.test.ts
|   |   |   |           |   `-- updater.test.ts
|   |   |   |           |-- routes
|   |   |   |           |   `-- error-page.test.ts
|   |   |   |           `-- views
|   |   |   |               |-- about-view.test.ts
|   |   |   |               |-- logs-view.test.ts
|   |   |   |               |-- settings-view.test.ts
|   |   |   |               `-- tunnels-view.test.ts
|   |   |   |-- shared-ui
|   |   |   |   `-- unit
|   |   |   |       |-- about-content.test.ts
|   |   |   |       |-- cn.test.ts
|   |   |   |       |-- confirm-dialog.test.ts
|   |   |   |       |-- glass-card.test.ts
|   |   |   |       |-- ripple.test.ts
|   |   |   |       |-- setting-row.test.ts
|   |   |   |       |-- setup.ts
|   |   |   |       |-- skeleton.test.ts
|   |   |   |       |-- testing-library.ts
|   |   |   |       |-- toast-store.test.ts
|   |   |   |       `-- use-copy-feedback.test.ts
|   |   |   `-- web-admin
|   |   |       |-- e2e
|   |   |       |   |-- app.pw.ts
|   |   |       |   |-- button-semantics.pw.ts
|   |   |       |   |-- dialog-centering.pw.ts
|   |   |       |   |-- overlay-notifications.pw.ts
|   |   |       |   `-- smoke-ui.pw.ts
|   |   |       `-- unit
|   |   |           |-- api-error-parsing.test.ts
|   |   |           |-- config-helpers.test.ts
|   |   |           |-- format.test.ts
|   |   |           |-- ip-access-control.test.ts
|   |   |           |-- setup.ts
|   |   |           |-- testing-library.ts
|   |   |           |-- use-anchor-sync.test.ts
|   |   |           `-- src
|   |   |               |-- components
|   |   |               |   |-- error-boundary.test.ts
|   |   |               |   |-- fixtures
|   |   |               |   |   |-- error-boundary-host.svelte
|   |   |               |   |   `-- throwing-child.svelte
|   |   |               |   |-- layout
|   |   |               |   |   `-- sidebar.test.ts
|   |   |               |   |-- login-modal.test.ts
|   |   |               |   |-- panels
|   |   |               |   |   |-- admin-settings-panel.test.ts
|   |   |               |   |   |-- qkey-panel.test.ts
|   |   |               |   |   |-- reference-guide.test.ts
|   |   |               |   |   `-- stealth-panel.test.ts
|   |   |               |   |-- ui
|   |   |               |   |   |-- select.test.ts
|   |   |               |   |   |-- sparkline.test.ts
|   |   |               |   |   |-- switch.test.ts
|   |   |               |   |   |-- fatal-error-screen.test.ts
|   |   |               |   |   `-- text-input.test.ts
|   |   |               |   `-- views
|   |   |               |       |-- about-view.test.ts
|   |   |               |       |-- configuration-view.test.ts
|   |   |               |       |-- dashboard-view.test.ts
|   |   |               |       |-- kpi-card.test.ts
|   |   |               |       |-- logs-view.test.ts
|   |   |               |       `-- smooth-traffic-value.test.ts
|   |   |               `-- routes
|   |   |                   `-- error-page.test.ts
|   |   |-- fuzz
|   |   |   |-- .gitignore
|   |   |   |-- Cargo.lock
|   |   |   |-- Cargo.toml
|   |   |   |-- fuzz_targets
|   |   |   |   |-- connection_handling.rs
|   |   |   |   |-- crypto_operations.rs
|   |   |   |   |-- fec_encoding.rs
|   |   |   |   |-- frame_decoding.rs
|   |   |   |   |-- packet_parsing.rs
|   |   |   |   `-- varint_parsing.rs
|   |   |   `-- seeds                    (gitignored - binary blobs regenerated by cargo-fuzz)
|   |   |       |-- connection_handling
|   |   |       |-- crypto_operations
|   |   |       |-- fec_encoding
|   |   |       |-- frame_decoding
|   |   |       |-- packet_parsing
|   |   |       `-- varint_parsing
|   |   |-- lib
|   |   |   `-- lib-common.sh
|   |   |-- rust
|   |   |   |-- integration
|   |   |   |   |-- engine_control_plane.rs
|   |   |   |   |-- interface_capabilities.rs
|   |   |   |   |-- masque_runtime_integration.rs
|   |   |   |   |-- orchestrator_runtime_activation.rs
|   |   |   |   |-- qkey_auth_integration.rs
|   |   |   |   `-- stealth_mode_matrix.rs
|   |   |   |-- rt-ack-merge-parity.rs
|   |   |   |-- rt-admin-http-contract.rs
|   |   |   |-- rt-anti-replay.rs
|   |   |   |-- rt-argsort-parity.rs
|   |   |   |-- rt-base64-decode-parity.rs
|   |   |   |-- rt-baseline-oracles.rs
|   |   |   |-- rt-bitmap-range-parity.rs
|   |   |   |-- rt-bitstream-parity.rs
|   |   |   |-- rt-brain-activation-parity.rs
|   |   |   |-- rt-brain-histogram.rs
|   |   |   |-- rt-cc-algorithms.rs
|   |   |   |-- rt-chacha-x16-parity.rs
|   |   |   |-- rt-chacha-x4-parity.rs
|   |   |   |-- rt-cli-help.rs
|   |   |   |-- rt-compress-preprocessor.rs
|   |   |   |-- rt-core-connection-basics.rs
|   |   |   |-- rt-ecn-popcount.rs
|   |   |   |-- rt-fake-hmac.rs
|   |   |   |-- rt-ghash-sse-parity.rs
|   |   |   |-- rt-harness-cli.rs
|   |   |   |-- rt-harness-udpfast.rs
|   |   |   |-- rt-header-validate-parity.rs
|   |   |   |-- rt-interface.rs
|   |   |   |-- rt-io-hotpath-kernel-integration.rs
|   |   |   |-- rt-iter-reduction-telemetry.rs
|   |   |   |-- rt-iter-reductions.rs
|   |   |   |-- rt-moving-average-parity.rs
|   |   |   |-- rt-packet-number-parity.rs
|   |   |   |-- rt-pnspace-ack-policy.rs
|   |   |   |-- rt-probe-detection.rs
|   |   |   |-- rt-profile-aegis-selection.rs
|   |   |   |-- rt-profile-fuzz-parity.rs
|   |   |   |-- rt-profile-overrides.rs
|   |   |   |-- rt-property-suite.rs
|   |   |   |-- rt-qftls-profiles.rs
|   |   |   |-- rt-random-aes-ctr.rs
|   |   |   |-- rt-reality-targets.rs
|   |   |   |-- rt-ring-buffer-parity.rs
|   |   |   |-- rt-security-suite.rs
|   |   |   |-- rt-shuffle-parity.rs
|   |   |   |-- rt-simd-selfcheck.rs
|   |   |   |-- rt-stealth-ascii-count.rs
|   |   |   |-- rt-stealth-config-toml.rs
|   |   |   |-- rt-stealth-persona-headers.rs
|   |   |   |-- rt-telemetry-counters.rs
|   |   |   |-- rt-telemetry-http.rs
|   |   |   |-- rt-tls-cover-cipher.rs
|   |   |   |-- rt-transport-batch-processor.rs
|   |   |   |-- rt-transport-config.rs
|   |   |   |-- rt-transport-connection.rs
|   |   |   |-- rt-transport-frames-roundtrip.rs
|   |   |   |-- rt-transport-h3.rs
|   |   |   |-- rt-transport-packet-headers.rs
|   |   |   |-- rt-transport-recovery.rs
|   |   |   |-- rt-transport-udpfast.rs
|   |   |   |-- rt-transport-uring.rs
|   |   |   |-- rt-transport-xdp.rs
|   |   |   |-- rt-transpose-parity.rs
|   |   |   |-- rt-udp-batch-send.rs
|   |   |   |-- rt-varint-roundtrip.rs
|   |   |   |-- rt-xor-repeating-parity.rs
|   |   |   |-- rt-xor-parity.rs
|   |   |   `-- rt-xor-sse2-parity.rs
|   |   |-- smoke
|   |   |   |-- smoke-avx10.sh
|   |   |   |-- smoke-sve2.sh
|   |   |   `-- smoke-ui-frontends.sh
|   |   |-- suites
|   |   |   |-- test-core.sh
|   |   |   |-- test-crypto.sh
|   |   |   |-- test-desktop-webadmin-rust-integration.sh
|   |   |   |-- test-e2e-admin-web.sh
|   |   |   |-- test-e2e.sh
|   |   |   |-- test-fec-all.sh
|   |   |   |-- test-fec-e2e-loss.sh
|   |   |   |-- test-fec-simulation.sh
|   |   |   |-- test-fec.sh
|   |   |   |-- test-optimization.sh
|   |   |   |-- test-performance-regression.sh
|   |   |   |-- test-probe-detection.sh
|   |   |   |-- test-profile-fuzz-parity.sh
|   |   |   |-- test-profile-overrides.sh
|   |   |   |-- test-security-fuzzing.sh
|   |   |   |-- test-stealth-brain.sh
|   |   |   |-- test-fec-auto-controller-proof.sh
|   |   |   |-- test-fec-auto-controller-scenarios.sh
|   |   |   |-- test-runtime-soak-chaos.sh
|   |   |   |-- test-security.sh
|   |   |   |-- test-stealth.sh
|   |   |   `-- test-transport.sh
|   |   `-- utils
|   |       |-- util-e2e-decode-all-profiles.sh
|   |       |-- util-e2e-verify-all.sh
|   |       |-- util-e2e-verify-current.sh
|   |       |-- util-fuzz-seed-curate.sh
|   |       |-- util-run-full-suite.sh
|   |       |-- util-tls-diff-profiles.sh
|   |       |-- util-tls-export-active-profile.sh
|   |       |-- util-tls-generate-sha256-sidecars.sh
|   |       |-- util-tls-list-profiles.sh
|   |       |-- util-tls-profile-head.sh
|   |       `-- util-tls-show-active-env.sh
|   `-- utils
|       |-- dev.sh
|       |-- util-analyze-codebase.sh
|       |-- util-check-quality.sh
|       |-- util-cleanup-workspace.sh
|       |-- util-dev-uis-start.sh
|       |-- util-dev-uis-stop.sh
|       |-- util-release-source-package.sh
|       |-- util-run-local-admin-web.sh
|       |-- util-run-local-ui.sh
|       |-- util-stop-local-admin-web.sh
|       `-- util-stop-local-ui.sh
`-- src
    |-- accelerate.rs
    |-- bin
    |   |-- harness.rs
    |   |-- qf-e2e-client.rs
    |   |-- qf-e2e-desktop.rs
    |   `-- quicfuscate-ctl.rs
    |-- brain.rs
    |-- compress.rs
    |-- core.rs
    |-- crypto
    |   |-- aead.rs
    |   |-- aegis.rs
    |   |-- aes.rs
    |   |-- chacha.rs
    |   |-- gcm.rs
    |   |-- hkdf.rs
    |   |-- mod.rs
    |   |-- morus.rs
    |   |-- poly1305.rs
    |   |-- quic_kdf.rs
    |   `-- tests.rs
    |-- engine
    |   |-- config.rs
    |   |-- engine.rs
    |   |-- mod.rs
    |   `-- qkey.rs
    |-- fec
    |   |-- adaptive_reed_solomon.rs
    |   |-- fec_stream_tests.rs
    |   |-- fountain_codes.rs
    |   |-- gf16_tests.rs
    |   |-- gf_tables.rs
    |   |-- internal.rs
    |   |-- mod.rs
    |   |-- test_support.rs
    |   |-- tests.rs
    |   |-- transition_tests.rs
    |   `-- wire.rs
    |-- env_utils.rs
    |-- harness.rs
    |-- implementations
    |   |-- client
    |   |   |-- backend.rs
    |   |   |-- connection.rs
    |   |   |-- integration.rs
    |   |   |-- io_driver.rs
    |   |   |-- killswitch.rs
    |   |   |-- mod.rs
    |   |   |-- pipeline.rs
    |   |   |-- platform
    |   |   |   |-- linux.rs
    |   |   |   |-- macos.rs
    |   |   |   |-- mod.rs
    |   |   |   |-- traits.rs
    |   |   |   `-- windows.rs
    |   |   |-- profile.rs
    |   |   |-- quality.rs
    |   |   |-- runtime.rs
    |   |   `-- subsystems.rs
    |   |-- mod.rs
    |   `-- server
    |       |-- accept.rs
    |       |-- admin.rs
    |       |-- admin_http.rs
    |       |-- admin_logs.rs
    |       |-- fsutil.rs
    |       |-- ip_pool.rs
    |       |-- limits.rs
    |       |-- metrics.rs
    |       |-- mod.rs
    |       |-- qkey_registry.rs
    |       |-- routing.rs
    |       |-- session.rs
    |       `-- systemd.rs
    |-- instrumentation.rs
    |-- interface.rs
    |-- lib.rs
    |-- main.rs
    |-- metrics.rs
    |-- optimize
    |   |-- brain.rs
    |   |-- compress.rs
    |   |-- crypto
    |   |   |-- aegis.rs
    |   |   |-- mod.rs
    |   |   |-- morus.rs
    |   |   `-- planner.rs
    |   |-- iter.rs
    |   |-- memory.rs
    |   |-- mod.rs
    |   |-- random.rs
    |   |-- simd.rs
    |   |-- sort.rs
    |   |-- stealth.rs
    |   |-- string.rs
    |   |-- telemetry.rs
    |   |-- transport.rs
    |   |-- udp.rs
    |   |-- unsafe.rs
    |   |-- uring_batch.rs
    |   `-- x86_sse2.rs
    |-- profile.rs
    |-- qftls.rs
    |-- reality.rs
    |-- rng.rs
    |-- simd
    |   |-- arm_stream.rs
    |   |-- arm_varint.rs
    |   |-- x86_ack.rs
    |   `-- x86_header.rs
    |-- simd.rs
    |-- stealth
    |   |-- mod.rs
    |   |-- tests.rs
    |   `-- tls_cover.rs
    |-- time_source.rs
    |-- transport
    |   |-- anti_replay.rs
    |   |-- batch.rs
    |   |-- cc/
    |   |   |-- mod.rs             (CongestionController trait, Algorithm enum, CcImpl dispatch)
    |   |   |-- reno.rs            (TCP New Reno - RFC 6582)
    |   |   |-- bbr2.rs            (BBR v2 - IETF draft, loss-aware model-based)
    |   |   |-- bbr3.rs            (BBR v3 - stealth-optimized)
    |   |   `-- stealth_shaper.rs  (StealthShaper<T> wrapper, BrowserProfile, jitter)
    |   |-- config.rs
    |   |-- connection.rs
    |   |-- frames.rs
    |   |-- h3.rs
    |   |-- packet.rs
    |   |-- pn.rs
    |   |-- recovery.rs
    |   |-- udpfast.rs
    |   `-- xdp.rs
    `-- transport.rs
```

## IPv6 Dual-Stack Architecture (Review Fix Session)

### Components
- `Ipv6Pool` (`src/implementations/server/ip_pool.rs`): Allocate/release IPv6 addresses from ULA range (default fd00::2–fd00::fe).
- `Session::new_dual_stack()` (`src/implementations/server/session.rs`): Creates session with both IPv4 and IPv6 client addresses.
- `RoutingManager::new_dual_stack()` (`src/implementations/server/routing.rs`): Configures dual-stack NAT (ip6tables MASQUERADE / pf inet6 / Windows NetNat v6).
- `TunConfig.ip6` / `TunConfig.prefix6` (`src/interface.rs`): IPv6 TUN interface address fields, now wired to CLI flags `--tun-ip6` / `--tun-prefix6`.

### Wiring
- `SharedServerDomain` (`src/implementations/server/mod.rs`):
  - Holds `ipv6_pool: Option<Arc<Mutex<Ipv6Pool>>>` created from `ServerConfig.ipv6_pool_start/end`.
  - `accept()` → `accept_session_in_domain()` allocates from both IPv4 and IPv6 pools, creates dual-stack session.
  - `remove()` / `reap_expired()` → release IPv6 address back to pool.
- `ServerHostResources::start()` (`src/implementations/server/mod.rs`):
  - Calls `RoutingManager::new_dual_stack()` when `server_config.ipv6_server_ip.is_some()`.
  - `RoutingManager::setup()` assigns TUN interface addresses via `ip addr add` / `ifconfig inet6` before NAT.
- `main.rs`:
  - Client: `--tun-ip6` / `--tun-prefix6` → `TunConfig.ip6` / `TunConfig.prefix6`.
  - Standalone server: `TunConfig` populated from `ServerConfig.ipv6_server_ip` / `ipv6_prefix_len`.

## Kill Switch Architecture

### Policy and Platform Boundary
- `VpnFirewallPolicy` (`src/implementations/client/killswitch.rs`): Validates one TUN name, the exact primary VPN UDP endpoint, an optional opposite-family endpoint, and up to eight deduplicated VPN DNS addresses.
- `KillSwitch`: Owns four states: disabled, block-only, endpoint-only connecting, and connected TUN/DNS policy. `Drop` deliberately retains enabled rules; explicit shutdown or stale cleanup removes them.
- Linux nftables: `inet quicfuscate_ks` is replaced with one `nft -f -` transaction. The output chain permits loopback, exact endpoint, selected TUN DNS, and TUN traffic in that order under a default-drop policy.
- Linux iptables: Dedicated `QUICFUSCATE_KS` chains and OUTPUT jumps exist for IPv4 and IPv6. Cleanup removes only owned jumps/chains. TODO-530 owns explicit backend wiring and a fully atomic fallback replacement.
- macOS: PF policy is available only when the main ruleset exposes the QuicFuscate anchor. TODO-548 owns managed installation and privileged proof.
- Windows: Runtime activation fails with `NotSupported`; stale legacy rule cleanup remains. TODO-528 owns a WFP-backed implementation because broad `netsh` block rules cannot be safely overridden by endpoint/TUN allow rules.

### Automatic Loss Ownership
- `Connection::last_activity_elapsed()` (`src/transport/connection.rs`): Exposes time since the last inbound datagram.
- `ClientRuntime::start_loss_watchdog()` (`src/implementations/client/mod.rs`): Owns one 50 ms remote-close/inactivity loop, records the first `DisconnectReason`, stops the I/O driver, and invokes the loss transition callback once.
- `QuicFuscateEngine::connect()` (`src/engine/engine.rs`): Applies endpoint-only policy before handshake, connected policy after handshake, and installs the runtime watchdog. Callback and event snapshots avoid holding callback locks during user code.
- `run_client()` (`src/main.rs`): Owns the standalone select-loop equivalent and distinguishes clean signal shutdown from remote close, socket failure, and heartbeat timeout.
- `QuicFuscateEngine::check_heartbeat()`: Compatibility query only; it never drives a duplicate watchdog.
- `scripts/tests/tun-e2e-killswitch-netns.sh`: Privileged Linux process proof for nftables state, selected VPN DNS, direct DNS and IPv6 leakage, timeout latency, retained fail-closed state, stale cleanup, and clean SIGTERM cleanup.

## ICMP Server Architecture (Review Fix Session)
- `build_echo_reply()` (`src/implementations/server/icmp.rs`): Sets fresh TTL=64 for locally-originated echo replies (RFC 1812 §5.3.1), not decremented from original request.
