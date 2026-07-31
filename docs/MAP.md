# QuicFuscate Map

This document is the single combined **file map** and **architecture index** for the repository.
It is maintained as the current architecture and repository index, with a curated tracked-source tree snapshot included below for navigation.

## High-Level Architecture and Wiring

- Runtime core: Rust crate under `src/` with entrypoints in `src/main.rs` and `src/lib.rs`.
- Data path wiring: app or TUN ingress -> core/transport -> stealth shaping -> crypto -> FEC -> network I/O.
- QUIC version wiring: Engine and standalone CLI config default to ordered v2/v1 support; `transport::version` owns selection, greasing, type mapping, and authenticated Version Information; `transport::packet` owns v1/v2 Initial and Retry material plus stateless VN; standalone server ingress bypasses VN for the FEC magic before existing-session dispatch; `transport::Connection` owns strict CID validation and one bounded fresh-state restart.
- Production VPN carrier: authenticated Core H3/MASQUE CONNECT-UDP carries TUN IP packets. The public QKey ID in the QUIC Initial selects the server record; the bearer is presented only through the encrypted H3 `x-qf-auth` header. The server gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state.
- QKey auth abuse-policy wiring: `ServerConfig.auth_policy` resolves and validates bounded environment controls -> `LiveServerState` owns one monotonic `AuthRateLimiter` -> new Initial admission allocates one attempt ID before registry lookup -> the same ID survives pending H3 authentication -> QUIC/TLS establishment starts the bounded encrypted-bearer deadline exactly once -> success, failure, timeout, pre-auth close, and internal abandonment complete the attempt at most once. Constant-size per-IP state applies capped exponential backoff, explicit block expiry, pending/state capacity bounds, and periodic idle pruning; admission outcomes remain wire-indistinguishable while Prometheus and typed audit events remain distinct.
- Sustained DDoS admission wiring: validated environment policy -> interval-delta accepted PPS -> monotonic EWMA activation/clear windows -> ordered global, GeoIP, blacklist, and per-IP admission -> normal-cost cryptographically established traffic or enhanced-cost half-open/new traffic -> source/IP/CID/credential/time-bound stateless QUIC Retry for supported Initial packets -> validated public QKey credential restoration plus RFC 9001 Initial keys from the Retry SCID. Stateless Version Negotiation remains behind the admission caps. Strict HTTPS blacklist refresh supports a bounded pre-parsed custom CA bundle, applies timeout/body/UTF-8/format/entry bounds, and atomically persists a versioned last-known-good cache before replacing active state.
- Idle-session lifecycle wiring: `transport::Connection` derives idle expiry from configured `max_idle_timeout`, treats zero as disabled, and marks an expired connection terminal without emitting CONNECTION_CLOSE -> standalone housekeeping reconciles the closed transport owner -> `LiveServerDomain` releases the session, IPv4/IPv6 pool addresses, connection-limit ownership, QKey association, bandwidth state, and pending policy state. The independent `client_timeout_secs` expiry remains a longer shared-domain safety boundary.
- Per-session bandwidth wiring: validated `QUICFUSCATE_CLIENT_*` defaults -> `SharedServerDomain` constructs one `PerClientBandwidthManager` -> session admission creates independent uplink/downlink token buckets plus shared UTC daily/monthly quotas -> encrypted QKey authentication optionally replaces the effective policy -> authenticated admin read/update/reset has final live precedence. MASQUE and framed-H3 uplink boundaries admit bytes directly. Unshaped TUN/fan-out downlinks with no session backlog use direct admission; shared shaping, rate backpressure, or transport backpressure enters the existing bounded pending owner, whose optional validated shared token bucket defines aggregate service capacity before weighted byte-deficit round robin applies FIFO-preserving per-session shares. Session close, expiry, revoke, and kick remove the same state; metrics and deduplicated audit expose typed rate/daily/monthly outcomes.
- Tunnel MTU ownership: `transport::PmtuState` discovers a validated 1280-1500 outer packetization budget; `core::QuicFuscateConnection` derives the FEC/QUIC/MASQUE datagram payload and a separate IPv6-safe inner tunnel MTU. The client applies live TUN MTU changes and returns local IPv4/IPv6 PTB above that boundary.
- Windows Wintun and kill-switch ownership: `src/interface.rs` selects the built-in backend only with `tun-windows` -> `src/interface/wintun.rs` securely loads the upstream DLL, creates one adapter/session, captures its LUID and session-owned read event, configures addresses and active MTU, and serializes packet operations against one shutdown event and one exactly-once teardown -> `src/implementations/client/killswitch/windows.rs` resolves the live alias to its LUID and transactionally replaces fixed persistent WFP provider/sublayer/filter identities across IPv4/IPv6 outbound transport layers, which also classify third-party transports and raw packets while preserving the exact UDP tuple -> ignored native tests prove data-plane lifecycle, observe exact IPv4/IPv6 WFP packet absence or presence at the Wintun ring, retain block policy across child-process exit, and prove exact stale cleanup -> `scripts/utils/provision-wintun.ps1` pins archive/DLL hashes plus Authenticode -> CI and Tauri MSI paths provision the untracked DLL beside their executable. Run `30508948149`, job `90764941801` proves the native adapter/WFP lifecycle and zero residue; release run `30533862566`, Windows job `90842338800`, proves the signed MSI plus byte-exact packaged DLL; Windows-Omega runs `30535603045` and `30536002374` prove encrypted QKey/MASQUE connected policy with five IPv4 and five IPv6 tunnel pings twice against unchanged server PID `1158967`, followed by zero WFP/adapter residue.
- Oversized tunnel carrier: raw IP packets within the effective tunnel MTU but above the MASQUE datagram payload use bounded `QFT1` length framing on the `/tun` HTTP/3 stream. `core.rs` reassembles arbitrary DATA-read segmentation per stream and rejects invalid magic, empty frames, non-IP payloads, and unbounded pending data.
- Reliable STREAM ownership: `transport::Connection` keeps a 16 MiB immutable range ledger, binds compact transmission IDs to packet numbers, retires exact ACKed ownership, and requeues packet-threshold/PTO loss before new data. A PMTU decrease byte-exactly splits queued transmissions to the new packet budget while late ACKs retire all derived segments once.
- Outbound pacing: `core::OutboundPacer` centrally gates congestion-controlled transport and FEC emissions from every socket path; ACK-only output is explicitly exempt. BBR2 and BBR3 own a congestion-window/initial-RTT Startup pacing floor that cannot collapse on a transient slow delivery sample; measured pacing becomes authoritative after Startup.
- Traffic-analysis defense wiring: canonical `[transport.traffic_analysis]` plus independent QKey and Intelligent ceilings -> `transport::Config` validated policies -> `transport::Connection` one `TrafficAnalysisScheduler` deadline and one pending slot -> `QuicFuscateConnection::next_send_deadline()` merged with pacing, stealth release, and recovery -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted PING plus PADDING chaff at path-bounded size. Due cover packets consume a slot, but only application STREAM or DATAGRAM traffic extends the idle lifecycle. Idle timeout, ramp-down, reactivation, and shutdown cancellation remain connection-owned. QKey and Intelligent upgrades stay inert until encrypted bearer authentication and cannot exceed their operator ceilings.
- CUBIC wiring: engine config, CLI, client/server conversion, and TOML select `Algorithm::Cubic`; `Recovery` owns RTT-before-ACK delivery, recovery-episode loss collapse, and enum-dispatched `Cubic`/`StealthCubic` pacing without vtable indirection.
- Validated migration wiring: `[connection]` reduction/cooldown/probe-target policy -> `transport::Config::migration_policy` -> exact PATH_CHALLENGE/PATH_RESPONSE candidate validation -> `Recovery::on_path_change()` path epoch and typed `PathChangeEvent` -> Reno/CUBIC/BBR2/BBR3/StealthShaper state transition. `SendInfo::path_control` routes validation datagrams ahead of buffered FEC output without FEC, outer-pacer, or stealth delay; standalone server DCID routing commits a candidate peer tuple only after validation, while simultaneous peer PATH_RESPONSE ownership remains queued independently.
- Standalone TUN routing: explicit `--tun-ip` / `--tun-netmask` on the server updates `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool, keeping Linux namespace deployments and runtime session routing in the same subnet.
- DNS-through-tunnel: server MASQUE/TUN uplink intercepts IPv4/IPv6 UDP/53 packets before generic TUN egress, resolves through configured server DNS upstreams, and queues rebuilt DNS responses over MASQUE downlink.
- NAT traversal: optional `NatPathDiscovery` is default-off and reason-gated (`connectivity-fallback`, `roaming`, `mesh`, `always`). It feeds transport path discovery when explicitly enabled; it is not part of the baseline stealth path.
- TUN downlink hotpath: after one MASQUE downlink packet is queued, the server flushes only the owning client connection rather than sweeping all connected clients.
- MASQUE observability: CONNECT-UDP lifecycle and peer-flow registration stay at `info`; per-packet MASQUE TX/downlink TX lines are `debug` to avoid production log amplification.
- Packet crypto wiring: Initial/Handshake use boxed AES-GCM compatibility keys; normal 0-RTT/1-RTT data-plane AEAD uses `DataAead` enum dispatch; Rustls packet-key integrations use the explicit dynamic packet wrapper arm.
- FEC recovery wiring: Initial, Handshake, product Auto startup, and stable Zero datagrams remain raw; active 1-RTT framing is also deferred while any Initial/Handshake PTO probe is pending. Active 1-RTT output reserves the exact 36-byte maximum FEC overhead before QUIC serialization. The encoder stores `[outer FEC source length | inner QUIC length | QUIC]`; systematic wire frames omit only the outer length, while repairs retain both layers. The receiver validates transmitted epoch, window, codec, source/total counts, interleave lane, sequence, and repair ordinal before bounded decoder allocation; it reconstructs GF4/GF8/GF16 rows or Fountain source sets deterministically instead of receiving coefficient vectors. Both accepted systematic sources and recovered sources validate then remove the exact inner QUIC length before entering QUIC header protection and AEAD processing. `InterleavedEncoder` assigns source/repair symbols to lanes and complete-block transitions advance the wire epoch. Fountain rescue is bounded to 128 sources and at most 512 repairs at the current 5x total code rate. Other transitions remain block-boundary safe; only a return to raw Zero after 32 transport-classified clean ACKs may retire an incomplete repair-only encoder window immediately. GF8 remains the wire-canonical GF(256)/0x11D field; GF4 uses fused scalar/AVX2/NEON multiply-XOR, and GF16 uses carryless polynomial multiplication, exact odd-length recovery, and one process-wide 128 KiB inverse table that removes exponentiation from deterministic row-cache construction without changing coefficients.
- Active FEC policy wiring: `QuicFuscateEngine::set_fec_mode()` returns a typed requested/configured/effective acknowledgement with active-versus-next-connection scope. `ClientRuntime` retains accepted construction policy for reconnect. The existing connection mutex serializes active commands with all I/O and controller inputs; `QuicFuscateConnection` preserves queued sources, retires queued repairs, resets wire state, and replaces all adaptive/codec/recovery state at Zero. Hard-Off framed receive uses source-only parsing with no recovery window. Standalone reload reports `NextConnectionOnly`, is serialized with connection construction by the single live loop, and records the unchanged active-session count.
- Compression wiring: `src/compress.rs` writes safe-path zstd output directly into `MemoryPool` / body-pool blocks via `compress_to_buffer`; H3 compression semantics and `0x5A` / `0x5D` frame headers remain unchanged.
- Client packet I/O is owned by `src/implementations/client/io_driver.rs` plus `src/core.rs`; `src/implementations/client/pipeline.rs` is not part of the production module graph.
- Audit logging wiring (TODO-515, TODO-525): `src/main_parts/late_tests_and_mlock.rs` resolves `[audit]` bounds and initializes the global `OnceLock<Arc<AuditLog>>` owner before privilege reduction -> typed lifecycle, privilege, authentication, QKey, admin, connection, configuration, and routing emitters call non-blocking producer APIs -> one bounded `qf-audit-writer` assigns order and owns schema-v2 serialization, SHA-256 chaining, file I/O, deterministic rotation, retention, and atomic checkpoint durability -> Prometheus exposes rejected-event and persistence-error counters -> acknowledged shutdown flush joins the worker -> `verify-audit-log <path>` validates the checkpoint-declared ordered segment set with schema-v1 compatibility. All audit artifacts are mode-`0o600` regular files owned by the runtime identity; special files and symlinks are rejected.
- Memory locking wiring (TODO-516): `src/main.rs::run_server()` applies `mlockall(MCL_CURRENT | MCL_FUTURE)` when `[security] lock_memory = true` (default), but defers it until after a configured Linux UID/GID transition so glibc never broadcasts setxid across pre-locked runtime stacks. The preloaded TLS private-key allocation and `src/optimize/mod.rs` `MemoryPool` blocks use individual `mlock()` before the transition. `LimitMEMLOCK=infinity` in systemd enables full process locking; finite limits retain explicit failure reporting and the individually locked boundary.
- Retained-secret erasure wiring (TODO-526): `src/secret.rs` zeroizing byte/string owners -> `src/engine/qkey.rs` typed `QKeyToken` plus zeroizing JSON/base64 parse/generate temporaries -> server issuance and registry decode/hash -> client profile/config/live connection ownership. `src/qftls.rs` and `src/transport/config.rs` zeroize session-cache ticket/master owners, ticket copies, test-bound ticket/session owners, and private-key PEM read buffers; `src/transport/packet.rs` wraps QuicFuscate's copied 1-RTT secrets, `src/crypto/aead.rs` wipes AES header-protection keys, and `src/crypto/aegis.rs` wipes L/X4/X8 wrapper key/IV/initialized state on drop without changing per-packet reinit or SIMD dispatch.
- QKey registry persistence wiring (TODO-539): standalone startup -> `qkey_registry.rs::QKeyRegistry::open()` -> `qkey_registry_storage.rs` protected current/previous keyring -> authenticated `QFQREG` version-1 ChaCha20-Poly1305 envelope. Startup propagates typed missing-key, wrong-key, corruption, version, permission, and I/O failures. Admin issue/revoke mutations serialize into zeroizing buffers and publish durable state before updating memory. Plaintext migration writes encrypted recovery before encrypted primary; an existing encrypted backup anchors plaintext-downgrade rejection; legacy/current-key rotation retains encrypted recovery and never interprets failed ciphertext as plaintext.
- Linux privilege-boundary wiring (TODO-527): CLI `--drop-user`/`--drop-group` -> `src/privilege/drop.rs::resolve_identity()` reentrant NSS or numeric-ID resolution -> pre-setup `try_check_capabilities()` and operation-specific capability gate -> TLS identity preload plus privileged UDP/TUN/routing initialization -> blocking-thread `drop_privileges_resolved()` clears supplementary groups, transitions all real/effective/saved IDs, and clears ambient/effective/permitted/inheritable capability sets -> `verify_process_privilege_state()` validates every Linux thread has the target IDs, empty groups, zero capability sets, and `PR_SET_NO_NEW_PRIVS` -> process-wide memory locking is applied after setxid while the TLS key and MemoryPool allocations are individually locked before it. The isolated `qf-privilege-probe` alone performs the destructive root-regain attempt. `quicfuscate capabilities --json` exposes the same identity, capability, target, and readiness state; systemd root-starts with only bounded setup capabilities and owns confinement plus post-drop host cleanup.
- Memory-pool growth wiring: `src/engine/config.rs` bounds automatic engine pools to 16-64 MiB; `MemoryPool` derives a per-instance hard ceiling of at least its explicit initial capacity and otherwise 64 MiB by effective block size. The global auto-tuner defaults to 1,024 blocks and cannot bypass that instance ceiling. Per-thread caching is opt-in and keyed by pool identity; the default lock-free shared queue prevents cross-thread cache stranding.
- Graceful shutdown wiring (TODO-448): `ServerRuntime` owns the shared `GracefulShutdown` lifecycle consumed by the UDP loop and admin handlers. SIGINT/SIGTERM/admin drain stop `AcceptLoop` admission, wait for established clients or `[engine] shutdown_timeout_ms`, flush final QUIC close packets, then stop control-plane services and host resources. SIGHUP uses the canonical runtime reload path. `implementations/server/systemd.rs` emits READY, RELOADING, STOPPING, STATUS, and watchdog notifications.
- Control plane wiring: CLI + engine + admin surfaces + metrics/telemetry endpoints. Embedded Engine server startup constructs `ServerRuntime` and its Tokio-bound socket inside the dedicated runtime thread, then transfers shutdown and metrics handles through a bounded readiness acknowledgement before reporting `Running`.
- UI wiring: `apps/svelte-desktop` (Svelte 5 desktop frontend) and `apps/svelte-admin` (SvelteKit/Svelte 5 admin frontend) are the active UI surfaces. The retained native desktop host/runtime bridge lives in `apps/tauri/src-tauri`. Shared UI primitives live in `packages/ui` (Svelte components) and `packages/theme` (CSS).
- Automation wiring: scripts in `scripts/` orchestrate build/test/benchmark/audit tasks; `scripts/tests/suites/test-qkey-registry-encryption.sh` owns the process-real encrypted-registry migration, rejection, rotation, secrecy, and cleanup contract; `scripts/tests/suites/test-linux-installer.sh` owns signature-checked AlmaLinux 9 build plus AlmaLinux 9/Debian 12 `systemd-nspawn` install, preflight, identity, permission, systemd, rerun, failure/recovery, exact-artifact, and residue proof; GitHub workflows own cross-platform core checks, the same native installer contract, and signed release packaging; generated local artifact directories are intentionally outside this map.
- Native traffic-analysis proof: `scripts/tests/tun-e2e-traffic-analysis-netns.sh` supplies exact baseline policy files to `scripts/tests/tun-e2e-netns.sh` -> immediate-mode buffered `tcpdump` capture with an exact measured window and post-window libpcap drain -> outbound cadence/size plus reverse control analysis -> cost-warning, CPU, bandwidth, binary-hash, process-set, and namespace-residue gates. `.github/workflows/ci.yml` runs the same proof against its freshly built Linux release artifact.
- Native fingerprint proof: `scripts/tests/fingerprint-runtime-proof-netns.sh` -> `scripts/tests/tun-e2e-netns.sh` with explicit server `--profile`/`--os` forwarding -> `fingerprint-runtime-proof-hook.sh` captures both TUN directions, runs p0f 3.09b and Nmap 7.94SVN, and invokes `utils/verify-fingerprint-pcap.py` -> exact profile/checksum/passthrough/downlink-scope evidence. Omega run `evidence-fingerprint-20260731i` passes all five capture and p0f profiles against binary SHA-256 `37c4ac6f7c79cd53e3e6f327dc9fcbff780b3d072eee73818110843b42d51dfa`; Nmap remains recorded evidence, not an exact closure claim, because arbitrary active probes remain outside the server-side SYN-only uplink boundary.

## Stealth Mode Architecture Notes (Session 22)

### StealthMode Enum (src/engine/config.rs)
6-variant: `Off | Performance | Stealth | AntiDpi | Manual | Auto` (default).
`Auto` serde alias: `intelligent`. `AntiDpi` serde: `anti-dpi`, alias `antidpi`/`max` (QKey compat only).
All call sites map `Auto` -> `StealthMode::Intelligent` in `stealth/` (config/manager parts).

### StealthManager Runtime Overrides (src/stealth/)
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
- Post-handshake application cover uses H3-framed cover requests, Server Push, and WebTransport only. QUIC Cover PING stays transport-owned; no raw fixed-stream payload or configuration-dependent H3 ignore path exists.
- Server Push cover uses bounded seed-varied resource plans.
- WebTransport cover is H3 application cover only, active for Anti-DPI or Intelligent level 2, never a competing VPN carrier.
- Core H3/MASQUE remains the production VPN/TUN data plane; `stealth::MasqueManager` remains compatibility/experiment machinery.

### Linux Production E2E Evidence (2026-06-30)
- `broderick` release build: `cargo build --release --bin quicfuscate` passes on Linux.
- All TUN/netns E2E scripts acquire a shared `flock` guard (`/tmp/quicfuscate-tun-e2e.lock` by default) because they intentionally reuse namespace and veth names. The base and specialized FEC/loss harnesses capture and reap only exact child PIDs, track namespace/link/qdisc ownership, refuse pre-existing product processes or colliding network resources, and keep generated certificates, QKey stores, and logs inside guarded per-run runtime directories. The CUBIC harness keeps its owned admin socket at a checked short `/tmp` path so a caller-selected evidence directory cannot exceed the Unix-domain socket limit, refuses existing artifact paths and colliding topology, and returns explicitly from a clean `set -e` preflight. `scripts/tests/test-specialized-tun-e2e-ownership.sh` owns the exit/signal/keep-on-failure and unrelated-resource survival regression. TODO-555 closed lifecycle ownership, TODO-558 closed FEC policy and observability, and TODO-557 closed specialized quantitative acceptance.
- `scripts/tests/tun-e2e-netns.sh`: real server/client netns TUN over authenticated H3/MASQUE, 5/5 ping, 0% tunnel loss, exit-scoped owned-PID cleanup, and fail-closed pre-existing-runtime isolation.
- `scripts/tests/fingerprint-runtime-proof-netns.sh`: exact-artifact five-profile privileged capture matrix with non-overwriting evidence paths, explicit `--profile`/`--os` forwarding, p0f/Nmap recording, protected-process identity, and namespace-residue gates.
- `scripts/tests/fingerprint-runtime-proof-hook.sh` plus `scripts/tests/utils/verify-fingerprint-pcap.py`: synchronous capture/classifier hook and pure pcap/checksum/vector verifier. Normalized client SYNs are checked against each profile; ordinary server downlink SYN-ACKs are checked for integrity and retained as passthrough.
- `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh`: isolated three-client IPv4/IPv6 routing, source ownership, spoof rejection, fan-out, PTB, NAT, throughput, and explicit client-to-client policy proof. It uses an owned checked short admin socket, generates a per-run leaf certificate when no explicit certificate pair is supplied, records the exact binary SHA-256 in retained evidence, and explicitly deletes every host veth after namespace teardown. It now uses a paced IPv6 TCP probe that fails closed on sender/receiver byte or SHA-256 mismatch and measures receiver time, replacing the unstable `iperf3` process. Earlier PMTU comparisons, including exact ARM64 binary `ee0243f6…61e95e88` with a 4.81% result, did not measure 1500-byte TUN payloads because both phases hard-coded the TUN ceiling to 1280 and route setup reset it. The harness now propagates the phase PMTU ceiling to server and clients, preserves client-side confirmed-MTU synchronization, and keeps the 15% gate. It fetches metrics after both TCP phases and fails unless pending-depth gauges plus both TUN/MASQUE event-counter families are present and zero. `core::next_send_deadline()` includes outer pacing for generic I/O-driver polling. Exact final-source ARM64 proof closes TODO-559 with 6.939/11.326 Mbit/s medians, 63.21% PMTU gain, receiver-valid black-hole recovery, bounded CPU/RSS/latency/allocations, zero queue or rate-limit events, and clean teardown.
- The multi-client harness offers `QF_E2E_EXTERNAL_EGRESS_CAPTURE=1` as an external-only diagnostic. It captures client 1 underlay UDP only on host veth `qf523h1`, only during each three-trial throughput phase, and emits bounded per-trial count/gap summaries using wall-clock intervals emitted by the TCP probe. Exact ARM64 source `8ed1cbc` passed the full gate against binary `c54d2d5e1c600790fcc0c2d437fdb5f3942e8337dadd2138896f0bf958ac6a2e`: 8.176 to 9.965 Mbit/s, 21.89% gain, 3-second black-hole detection, 6,356,992 bytes in 28.769 seconds, zero queue events, and clean teardown. Per-trial maximum gaps were default 65,372/78,915/52,858 us and opt-in 67,156/105,044/104,909 us. Successful trials therefore prove that a single roughly 100-ms egress gap is not the prior clean-path collapse mechanism. It does not change the product binary, runtime, payload handling, credentials, or normal gate.
- `scripts/tests/tun-e2e-multi-client-dual-stack-stability.sh` invokes that full gate three times with forced external capture and isolated child artifacts. `scripts/tests/utils/aggregate-dual-stack-stability.py` revalidates exact binary identity, six receiver results per child, positive per-child PMTU gain, an unchanged 15% median gain across three complete children, black-hole bounds, and six ordered per-trial egress summaries before final acceptance. Any failed or incomplete child makes the aggregate fail while retaining all raw child artifacts.
- External throughput capture records client-1 UDP at both host-side boundaries: `qf523h1` ingress and matching `qf523hs` server-veth observation with bidirectional capture direction filtering. The shared summarizer correlates both observations to the same receiver wall-clock intervals, retains packet counts and gap distributions without reading payloads, and fails only on missing capture evidence rather than inferring product loss from capture-count variance. Native exact-artifact evidence is pending.
- Exact source `259ed60` validates both capture boundaries against fresh binary `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`: completed default/opt-in throughput measured 7.193/10.136 Mbit/s and 40.91% gain, while client egress and server-veth ingress were exactly equal at 24,817/31,276 packets and every receiver-trial interval count matched. The later deliberate black-hole phase still hit a 13-packet run PN 37207-37221 over 108 ms against a 79-ms period before recovery evidence. The bridge boundary is now proved for completed clean phases; black-hole recovery remains the current TODO-559 blocker.
- The root-target `c54d2d5e1c600790fcc0c2d437fdb5f3942e8337dadd2138896f0bf958ac6a2e` stability control is stale: it omitted the current persistent-congestion provenance strings and cannot prove source `24c4a92`. Fresh `cargo clean` and Release build from `24c4a92` produced `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`; its forced-capture stability aggregate failed all three children. Children 1/3 reached default medians 7.308/7.551 Mbit/s, then opt-in persistent-congestion runs PN 14639-14652 (12 losses, 78-ms period, 107-ms run) and PN 17889-17902 (12, 87 ms, 121 ms) before receiver evidence. Child 2 reached 7.833 to 10.287 Mbit/s and 31.33% gain, then the deliberate black-hole phase reached PN 38527-38541 (13, 87 ms, 99 ms) before recovery evidence. All children cleaned up owned runtime resources. TODO-559 remains blocked by this current-source live transport failure.
- Exact ARM64 source `47e0a82` then tested the reverted standalone runtime against binary SHA-256 `a884a6f9e930fc6c64d0641cac88eedf91dbd6414e7e3caa36930f3061cd87f5`. It did not reproduce a heartbeat timeout, but the third opt-in throughput receiver did not produce an artifact, so the harness failed closed before a PMTU comparison. Default receiver trials were 2.536/7.789/8.210 Mbit/s; completed opt-in trials were 9.393/10.337 Mbit/s. One client entered persistent congestion at 0.20% loss, while failure metrics still showed zero TUN/MASQUE backpressure events. Cleanup was clean. TODO-559 remains open.
- `src/transport/recovery.rs`: Persistent-congestion runs include only ack-eliciting non-PMTU losses sent after the first RTT sample. The active candidate retains packet-number-space-scoped lost packet numbers so a reordered ACK after loss, as well as a later tracked ACK, resets the run. Focused regressions prove collapse, ACK invalidation, reordered-loss ACK invalidation, pre-sample exclusion, and ACK-only exclusion before native validation.
- Exact ARM64 source `9633afc` proved the corrected recovery path still has a separate live transport issue: default 1280-byte receiver trials completed at 8.859/9.270/9.439 Mbit/s, but the first 1500-byte receiver failed after client persistent congestion at 0.11% loss and cwnd 6000. The server recorded zero loss and no TUN/MASQUE backpressure events. TODO-559 remains open for ACK/loss-level instrumentation and correction.
- `src/transport/recovery.rs` carries `PersistentCongestionEvidence` through `AckOutcome`; `src/transport/connection/` emits bounded provenance only on a cwnd collapse, including trigger ACK delay, largest-ACKed packet age, per-threshold loss counts, exact-microsecond RTT/loss/period timings, and run-start/terminal packet numbers. The next native failure can distinguish an actual loss run from ACK progression or loss-accounting defects.
- Exact ARM64 source `3e64eaa` completed all receiver-verified trials without a collapse: default median 9.157 Mbit/s, opt-in median 9.582 Mbit/s. The fixed gate rejected the 4.64% gain before black-hole recovery. The comparison subsequently proved invalid as a 1500-byte payload measurement because the harness held both TUN interfaces at 1280; the corrected harness awaits exact ARM64 proof. TODO-559 is no longer an ACK/loss evidence gap.
- Exact ARM64 source `8808c7f` raised the client TUN to 1400 and then failed opt-in throughput after an application-space persistent-congestion run of 90 ms against a 78-ms period at 0.09% observed loss. The root boundary is now L3 versus UDP-payload size: the 1500-byte selected QUIC packet is passed directly to the IPv4 UDP socket, exceeding the 1500-byte veth L3 MTU after headers. The harness now qualifies the same 1500-byte L3 path at a 1472-byte QUIC UDP-payload ceiling, with the 15% gate retained; TODO-559 still requires exact ARM64 evidence.
- `src/transport/connection/` and `src/transport/recovery.rs`: a dedicated PMTU PING+PADDING probe may bypass a closed congestion gate only when `PmtuState`'s configured interval is at least `Recovery::rtt`; the bypass excludes queued control, STREAM, and DATAGRAM data. Only a probe that actually uses that bypass is ack-eliciting and loss-tracked outside bytes in flight, CC loss, and persistent-congestion runs; a regular PMTU probe retains normal congestion-control accounting.
- Exact ARM64 source `bfe8bd9`, binary SHA-256 `f6e3ecdeeac887478e12c0612cf990f3f2295c90a0b63a1df544b43818a4e129`, passed the three-client dual-stack PMTU gate: 7.757 to 10.186 Mbit/s, 31.31% gain; 2-second black-hole detection; 18,022,400-byte receiver-valid transfer in 20.732 seconds; zero TUN/MASQUE queue events and zero product-process, namespace, qf523-link, or qdisc teardown residue.
- Exact ARM64 source `12da3cc`, binary SHA-256 `d137ce40157d2669ce01f101604c0018b68f795a30f04b0405182e4e19a36f26`, confirmed that the reordered-ACK recovery correction is not the remaining native blocker. The default phase had a 7.281 Mbit/s receiver-valid median; opt-in trial one failed before a receiver result after a 12-packet application-space persistent-congestion run (PN 10177-10191, 108 ms, 80-ms period, ACK largest PN 10193) at 0.12% observed loss. TUN/MASQUE queue metrics and cleanup were zero. TODO-559 remains open for root-cause diagnosis of the real burst loss.
- Exact ARM64 source `82c954c` reused the `88a12ae` binary with FEC Off and reproduced the failure, excluding active-FEC wire admission. The three failed children retained positive server `quicfuscate_rate_limited_total` exactly at each stalled interval: 49 in black-hole recovery, 37 in a clean opt-in timeout, and 52 in a default trial that needed 27.103 seconds. Clean comparison phases retained zero. The server's 1,000-PPS per-source limiter was dropping legitimate tunnel datagrams before `Connection::recv`; the resulting absent ACKs drove persistent congestion and inner TCP retransmission timeout. `src/implementations/server/limits.rs` restores the documented 10,000-PPS default, and the dual-stack gate now requires bounded duration and zero rate-limit events.
- Exact ARM64 source `f392f45`, binary `781fbe6ddb988d1ae1f91f3d1e252d3e700fbd8e00b283af82adf41d597646c0`, completed all 18 clean receiver-valid TCP trials under Auto FEC with zero rate-limit events and zero UDP socket drops. Children two and three fully passed at 41.98% and 55.49% gain with 17,694,720 and 19,595,264 black-hole recovery bytes. Child one recorded a positive 12.70% gain but the child-local threshold stopped it before black-hole evidence, exposing a repeated-test design error. The stability wrapper now retains all three complete children, requires every gain to remain positive, and enforces the unchanged 15% threshold on the three-child median; standalone execution still requires 15% per run.
- Exact harness source `b2a08d3` reran that binary through three complete Auto-FEC children. All passed at 35.93%, 43.95%, and 56.09% gain, with an enforced 43.95% median; black-hole detection was 3/3/2 seconds and delivered 18,284,544/27,656,192/18,808,832 receiver-valid bytes. All 12 phase metric snapshots had zero rate-limit events, all UDP drop deltas were zero, and cleanup left no owned runtime residue.
- Exact ARM64 source `d9149d0`, binary SHA-256 `a4c31c030ffcdb6db05cf468723873dc7b1c7135fe73b10b1ab05e4aebeef7cb`, failed two children only in deliberate black-hole IPv6 recovery; their raw client logs then recorded application-space persistent congestion after the 1472-to-1280 reset, but the harness did not retain a dedicated event artifact on that early path. The third child passed at 7.640/10.509 Mbit/s, 37.55% gain, 3-second detection, and 7,929,856 receiver bytes in 26.299s. Source and owned runtime cleanup were clean. The repeated black-hole recovery contract remains the TODO-559 blocker.
- The black-hole failure branch now retains that client event and `PersistentCongestionEvidence` includes the effective PMTU plus minimum/maximum packet sizes across the completed loss run. The next native failure can distinguish stale oversized flight loss from continued floor-sized loss without changing recovery policy.
- Exact ARM64 source `4a63c3b` retained `pmtu_effective=1280`, `run_min_packet_size=40`, and `run_max_packet_size=1280` for a failed black-hole recovery. The collapse continued at the floor, and the existing Core FEC path already reserves outer datagram overhead before transport packetization. The root cause is therefore still unproven.
- The external encrypted-boundary diagnostic now also spans black-hole recovery. It creates one non-overwriting recovery window and summarizes client egress, server ingress, server return, and client ingress before either recovery-failure report or successful transfer validation. Transport behavior is unchanged.
- Exact ARM64 source `e47d3bf` validated that black-hole path. Its three-child aggregate failed closed only on child one's recovery timeout, but all four host-veth observations matched exactly: 6,662 forward and 5,374 reverse packets. That child still recorded persistent congestion at the 1280-byte floor with a 40-to-1280-byte run lasting 119,988 us against an 89,489-us period. Children two and three recovered after 2 seconds and transferred 18,481,152 bytes in 20.689 seconds and 7,667,712 bytes in 23.803 seconds. The bridge is not the demonstrated loss point; root cause remains open.
- At the 1280-byte floor, Core accepts the IPv6 minimum but the effective MASQUE payload is 1180 bytes, so a 1280-byte TUN frame uses the existing H3 STREAM fallback. `PersistentCongestionEvidence` now reports independent control, STREAM, and DATAGRAM loss-run counts, including co-carriage, to qualify that boundary on the next exact native run without changing recovery policy or scheduling.
- Exact ARM64 source `7d866f6`, binary `70af5f218b611b5f0bad1ce18df3a9ffabb9b1afdba6b9fa4e2c90e9dccd7d79`, failed closed in stability children one and three. Child three established 1280-floor persistent congestion with 11 STREAM, 2 control, and 0 DATAGRAM carriers across its 13-packet loss run. The fallback is therefore the active collapse path, but the missing STREAM acknowledgements still require a source-grounded correction. Child two passed at 43.91% gain with 17,170,432 recovery bytes in 22.086 seconds; cleanup was zero process, namespace, link, and qdisc residue.
- `PersistentCongestionEvidence` now splits STREAM loss-run carriers into fresh and retransmitted ranges, so the next exact native run can distinguish first-delivery loss from retransmission-loop behavior without changing runtime policy.
- Current local `cargo test --lib --features rust-tests --quiet` passes all 2,008 library tests; the broader workspace, all-target, `rust-tests` release gate also exits successfully.
- `scripts/tests/tun-e2e-dns-leak-netns.sh`: DNS query through server TUN IP returns a response and tcpdump observes `raw_port_53_packets=0` on the client underlay.
- `scripts/tests/tun-e2e-fec-netns.sh`: exact-artifact uniform-loss gate whose `UNIFORM_PING_SCENARIOS` and `UNIFORM_IPERF_SCENARIOS` are the single source for printed and executed cases. A new absolute artifact path retains the binary SHA-256, contract, endpoint handshakes, raw ping and iperf JSON, receiver-verified results, and zero panic/decryption/runtime-liveness evidence.
- `scripts/tests/tun-e2e-fec-burst-netns.sh`: exact-artifact correlated burst-loss gate whose `BURST_SCENARIOS` owns profiles, repetition count, median bounds, and worst-sample bounds. It retains every raw trial, aggregate, endpoint handshake, binary identity, and runtime-log result without overwriting prior evidence.
- `scripts/tests/tun-e2e-fec-transition-netns.sh`: exact-artifact clean -> moderate/severe loss -> recovered policy gate whose `TRANSITION_SCENARIOS` owns each profile's netem loss, phase sample counts and bounds, recovery settle, maximum recovery duration, and Fountain policy. It exports six client/server telemetry snapshots; Off remains Zero with no repairs, switches, or wire overhead, while Auto has zero clean-link overhead, positive lossy wire overhead, and returns to Zero within the declared monotonic-time recovery bound. Every phase requires source/repair wire-byte, overhead, and recovery counters, and rejects panic, decryption, heartbeat, internal, and TUN-send failures.
- Exact source `b52add5edfac34e6407efee6f4116a1a9eb2c1ae` passed the complete quantitative Omega transition matrix using the successful ARM64 Release Build bundle from run `30317521105`: bundle SHA-256 `dc6e91c1c04d0afd059441b630c87257870cf19a010c064c207a507c371fe507`, binary SHA-256 `ee0243f6aae50ee66115ba9f11d596004c3f057e240654e9a4bf340461e95e88`. Auto/moderate was 0/22/0% with 35,379 ms recovery, Off/moderate was 0/16/0% with 35,427 ms recovery, and Auto/severe was 0/37/0% with 35,426 ms recovery. Every result was within the 5/35/10% or 5/60/10% loss limits and the scenario-owned 40,000 ms bound, recorded one handshake per endpoint with zero panic/decryption failures, passed the quantitative telemetry assertions, and left no process, namespace, or veth residue.
- `scripts/tests/tun-e2e-fec-netem-adversity.sh`: exact-artifact 25-scenario ping/liveness matrix whose six declared contracts own every qdisc input, phase timing, and loss bound. Each scenario reads both telemetry endpoints for active-FEC, observed/lost packets, repairs, and mode switches; the manifest records measurements, bounds, binary identity, and a zero runtime-failure count. `QF_ADVERSITY_PING_COUNT` permits a larger declared sample without duplicating thresholds.
- Isolated loss repeat `a81f7ad` was 5/6 and failed 25% netem loss at 54% tunnel loss against 40%, while 50% passed at 46% against 65%. High-loss liveness is therefore unstable across runs, not a single 50% outlier.
- Diagnostic source `ae59a97` completed one clean exact-artifact Omega loss matrix at 0/2/2/6/24/50% tunnel loss for 0/1/5/10/25/50% netem, within 15/16/20/25/40/65% bounds. Client telemetry at 25/50% reported 16/28 observed losses, 2/18 repairs, and two mode switches. This proves live feedback and repairs, but one passing run does not clear the earlier high-loss variance blocker.
- `scripts/tests/tun-e2e-fec-loss-stability.sh`: serial three-trial wrapper for the exact adversarial loss contract using 200 packets per level. It preserves raw manifests and telemetry, aggregates results into `summary.tsv`, and rejects child failure, runtime failure, wrong sample count, missing or duplicate scenarios, binary mismatch, or a bound violation.
- TODO-557 closure proof used ARM64 binary SHA-256 `e09cad15…2f580`. Uniform passed 6/6, Burst passed both three-trial aggregates, Transition passed Auto/moderate, Off/moderate, and Auto/severe within 35,512 ms, Adversity passed 25/25, and the strengthened loss-stability matrix passed 18/18. The matched CUBIC control recorded Auto 2.989 Mbit/s and 99.60% retention versus Off 2.849 Mbit/s and 94.94%, with Jain fairness 0.999931. All manifests reported zero runtime failures and teardown left no product process, namespace, link, qdisc, or admin socket.
- TODO-555 final evidence: commit `222ebdc0c91a887e480dc6697f82e45e4c9d417c`, native ARM64 artifact `8571739901`, bundle SHA-256 `5bf7ce43748301a7720520590db9c61e0cb0660ced4e6eb464b9869f217d551f`, binary SHA-256 `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`, and isolated Omega root `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo555-222ebdc`.
- TODO-558 final evidence: implementation commit `b7db20443bb070d97686975034ebd9656ca3f98e`; CI `30155084370`; Clippy Matrix `30155084377`; Release Build `30155084369`; GitHub source archive SHA-256 `64a8fae24a1143ab9715b78c0075dfcf570c51432682f5c1383077d5309be678`; native ARM64 artifact `8618776310`, bundle SHA-256 `0fb66cb66b48475cb578eccadeb1d9f8da17273f98939ab60931b0dd8ebdeecb`, and packaged binary SHA-256 `ea93bc10af7fc205da41b2acf02b5b6a0b25702113c7d8900390c12e99e516fb`; isolated Omega root `/home/ubuntu/SOFTWARE/QuicFuscate/candidate-todo558-7c8907e-d3d0ffea7751`.

### Omega DPLPMTUD and Multi-Client Evidence (2026-07-23)

- Exact run35 source archive SHA-256: `b3140e9c14300af3416d021de6e81476ec41e3b57b775c7b1605a9fcaaf2ce3e`; exact AArch64 binary SHA-256: `d985c254fb55792afc9d2e1bc88d14b68b8737a3bfcb7507961fc8b1a1c09888`.
- Local and native full Rust tests and strict all-target/all-feature Clippy pass. Deterministic coverage includes loss/PTO requeue, PMTU-aware 1500-to-1280 retransmission splitting, and late-original-ACK retirement of every derived segment.
- Three isolated clients prove IPv4/IPv6 allocation, routing/NAT, source ownership, spoof rejection, default-deny and explicit opt-in unicast, authenticated fan-out, client/server PTB, and all six zero-loss ping streams.
- All three clients and the server discover 1500. The 20-second egress black-hole trial detects failure in 3 seconds, falls back to 1280, transfers 17,039,360 bytes, and re-confirms 1500.
- Three historical 1280-floor trials have 6.454 Mbit/s median and three historical confirmed-1500 trials have 8.961 Mbit/s median. Their 38.85% gain is not PMTU payload-efficiency evidence because the harness then hard-coded and reset both TUN interfaces to 1280.
- Evidence root: `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo534/evidence/run35`. Cleanup leaves no product process, heartbeat failure, or network namespace.
- Exact commit `c609c68` ARM64 binary SHA-256 `322060acffd79abe30ed7d8e4238933b0106c2df1ab3e116793e62073da8d32b` passed the historical three-client harness, including a 20.136-second black-hole transfer of 525,496 bytes and clean namespace teardown. Its 15.32% PMTU gain is not payload-efficiency proof because that harness still fixed both TUN interfaces at 1280.

### Omega CUBIC Conformance and Performance Evidence (2026-07-23)

- Exact run06 build-source archive SHA-256: `df1aed74696ed45ca1bb66e06556cf39b8298620fc60878570427dbcda4d0837`; compile-input digest: `423cb07e9b4f64c3605ba28034257edcfb4124a4e5ccd86850908d6c5109a680`; exact AArch64 binary SHA-256: `2dc42fd87b77f50eaef96c0244a15adf8126f19d4593c5497f26acdb048483eb`.
- Local and native full Rust tests and strict all-target/all-feature Clippy pass. Deterministic tests cover RFC 9438 precision below `1e-6`, RFC 9406 HyStart++, recovery episodes, application-limited epochs, CUBIC-over-Reno memory below 200 bytes, paced stealth behavior, and all selectable CC paths.
- The deterministic shared drop-tail model records CUBIC `13,389,600` bytes, Reno `14,367,600` bytes, and Jain fairness `0.998760`.
- The live shared 2 Mbit/s bottleneck records CUBIC 0.961 Mbit/s, Reno 0.951 Mbit/s, and Jain fairness `0.999974`.
- Three clean and three 5% random-loss CUBIC trials on a shared 5 Mbit/s bottleneck record median throughput of 3.001 Mbit/s clean and 2.862 Mbit/s under loss, retaining 95.38%.
- Evidence root: `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo535/evidence/run06`. Cleanup leaves no product process, network namespace, or test qdisc.
- Exact commit `c609c68` ARM64 binary SHA-256 `322060acffd79abe30ed7d8e4238933b0106c2df1ab3e116793e62073da8d32b` passes the active-FEC CUBIC matrix after FEC framing is exempted from stateless Version Negotiation: CUBIC 1.075 Mbit/s, Reno 1.049 Mbit/s, Jain 0.999846; Auto baseline 3.001 Mbit/s; controlled 5% loss 2.988 Mbit/s; retained throughput 99.56%.
- Harness source `046a567` keeps the CUBIC control safe for caller-selected long evidence paths by using an owned, checked short `/tmp` admin socket. The exact ARM64 bundle from run `30319765868`, SHA-256 `c597ffb4e28b63c97a8858b7f38452d5a5f046de57eb951e160e014880a70983`, contains the already live-verified binary SHA-256 `ee0243f6aae50ee66115ba9f11d596004c3f057e240654e9a4bf340461e95e88`. Three clean and three controlled-5%-loss trials per policy recorded Auto 3.001/2.984 Mbit/s, 99.45% retained; FEC-off 3.001/2.857 Mbit/s, 95.20% retained; delta 0.128 Mbit/s and 4.25 percentage points. Fairness was CUBIC/Reno 1.045/1.080 Mbit/s, Jain 0.999726. No product process, namespace, bridge, or test veth remained.
- Exact ARM64 binary `8fb60531841e5575aef557720950b452a43006fb658419c28bc84f75e127220a` passes the expanded runtime-performance control from candidate `6965cc9a…b79cd3c`: Auto 3.001/2.986 Mbit/s and 99.52% retention; Off 3.001/2.868 Mbit/s and 95.56%; Jain `0.999983`; 297.2-298.9 MiB combined RSS; 12.48-17.10% one-core CPU; 34.8-73.2-ms p95 latency; 16,637-53,023 fallback allocations; and zero pending queue/rate-limit events. The harness owns the metrics service, samples exact PIDs every 200 ms, waits explicitly for TUN creation, and retains `/tmp/qf-ff9d316-tight-performance-20260729-0048`.
- Exact final-source ARM64 binary `e09cad15ef86ea79a074bf1daff93615a97e9078d8786e346ac77b6f5d82f580` includes byte-bounded pools, standalone heartbeat keepalive, and metric-coupled bounded overload admission. Its TCP matrix retained `/tmp/qf-ff9d316-final-tcp-20260729-0145` with 6.939/11.326 Mbit/s medians, 63.21% PMTU gain, and 26,017,792-byte black-hole recovery. Its UDP matrix retained `/tmp/qf-ff9d316-final-udp-20260729-0148` with Auto/Off loss retention of 99.71%/94.94%, 284.3-284.4 MiB combined RSS, 12.70-17.21% one-core CPU, 35.3-59.3-ms p95 latency, 16,469-52,663 fallback allocations, zero queue/rate-limit events, clean runtime logs, and exact teardown.

### Omega FEC Wire Integrity Evidence (2026-07-22)

- Exact proof source: `15570abf772766c76959f6aae6ba16b2b9c26fd7`; native ARM64 bundle SHA-256 `5406170b4175d91722d2169c8c21adc9721e61fe995a513299fc4f52eff9d8fe`; binary SHA-256 `9b4144a85e452ef37102ac255b0c8c976f1145ad04941c594d07d4fc6130cf5b`.
- Isolated runtime: `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-15570ab`; historical runtime directories remain untouched and test cleanup leaves no process or network namespace behind.
- `scripts/tests/tun-e2e-fec-netns.sh`: 1,000 packets at each 0/5/10/25% uniform-loss level, `4 passed, 0 failed`.
- `scripts/tests/tun-e2e-fec-burst-netns.sh`: 1,000 packets in each correlated-burst scenario, `2 passed, 0 failed`; both 10%/25%-correlation and 20%/50%-correlation cases finish with 2% residual tunnel loss.
- Retained client/server logs prove TLS, H3/MASQUE, and NEON FEC without AEAD, decrypt, or panic errors. Local deterministic tests separately prove 1,000/1,000 unique byte-exact interleaved recovery with zero duplicates and bounded latency.

### EscalationState (src/stealth/parts/escalation.rs) - TODO-416
Probe-count-based escalation state machine on `StealthManager`.
- `record_probe()`: records timestamp, checks thresholds (≥3 in 60s → L1, ≥8 in 120s → L2).
- `check_de_escalation()`: drops one level after configurable quiet period (default 300s).
- `on_probe_detected()` uses `EscalationState` instead of immediate binary escalation.
- `sync_intelligent_level()` calls `check_de_escalation()` on each tick.
- Config knobs: `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (3), `_L2` (8),
  `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (300), `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (50).
- `on_probe_detected` only escalates when `config.dynamic_enabled` is true (Intelligent mode).

### IntelligentStealthInputs.level_hint (src/stealth/parts/manager.rs)
Brain reads `INTELLIGENT_STEALTH_LEVEL_HINT` (a `HintChannel<AtomicU32>` with an explicit writer/reader contract at the declaration site, TODO-517) after hysteresis and passes as `level_hint: u8` (0/1/2) to `derive_intelligent_runtime_policy`.
Level 0 (clean path): padding disabled (near-zero Intelligent-mode overhead). Level 1/2: padding active.
Jitter under pressure (CE>5% or rtt_spike>4): 85% of budget (was wrongly 20% - direction fixed).

### Preset Values (src/stealth/parts/config.rs)
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
All 15 stealth technologies in `src/stealth/` have unit test coverage in `src/stealth/tests.rs`:
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

1. Client CLI -> runtime init: `src/main.rs` -> `src/core.rs` -> `src/transport/connection/`
2. TLS handshake path: `src/qftls.rs` (`CombinedProvider`, release verification mandatory) -> rustls keys/errors -> `src/transport/connection/` TLS-bound application readiness -> `src/core.rs` terminal error propagation -> `src/transport/packet.rs`
3. Stealth shaping path: `src/stealth/` (`StealthManager`) -> `src/transport/config.rs` -> `src/transport/connection/`
4. FEC encode/decode path: `src/core.rs` raw handshake/Zero gate -> safe block-boundary mode transition -> `src/fec/` (`AdaptiveFec`) -> `InterleavedEncoder` lane distribution -> `src/fec/wire.rs` versioned MTU-bounded envelope -> standalone server FEC-magic bypass before stateless VN -> receiver-owned epoch/window decoder -> `InterleavedDecoder` lane routing -> rank-checked systematic recovery -> exact inner-length validation and removal for systematic or recovered sources -> `src/transport/connection/` authenticated QUIC receive -> transport observer hooks
5. Linux client zero-copy inbound path: `src/implementations/client/io_driver.rs` -> pool-backed `src/optimize/uring_batch.rs` `UringRecvBatch` -> `src/core.rs` `recv_pooled_block()` -> `src/fec/` -> `src/transport/connection/`
6. Packet-number decode path: `src/transport/packet.rs` header-protection removal -> `src/optimize/transport.rs` `decode_packet_number()` -> BMI2/SVE2/NEON/scalar dispatch
7. Compression pool path: `src/transport/h3.rs` payload policy -> `src/compress.rs` direct zstd `compress_to_buffer` into `MemoryPool` / body-pool blocks -> H3 compressed body bytes
8. Probe mitigation path: `src/stealth/` detector -> `src/reality.rs` fallback proxy -> upstream targets
9. Engine embedding path: `src/engine/engine.rs` -> `src/implementations/{client,server}/` runtimes
10. Admin control plane path: `src/implementations/server/admin_http.rs` -> `qkey_registry.rs` -> `qkey_registry_storage.rs` durable fail-closed commit -> live server policy enforcement
11. Desktop frontend path: `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts` -> Tauri invoke -> engine/control runtime
12. 0-RTT anti-replay path: `src/transport/anti_replay.rs` (`StrikeRegister` with SHA-256 fingerprints, Bloom fast-negative, FIFO ring eviction) -> `src/transport/config.rs` (attached at server startup) -> `src/transport/connection/` `recv()` gate -> silent discard on replay
13. Desktop native host path: `apps/tauri/src-tauri/src/main.rs` -> Tauri commands -> engine/control runtime
14. Web-admin path: `apps/svelte-admin/src/lib/api.ts` -> Vite dev proxy (`/api` -> `127.0.0.1:9000`) -> admin HTTP endpoints -> server runtime state
15. Build publish path: `scripts/build/build-web-admin.sh` -> `assets/web-admin/` consumed by `--admin-web-root`
16. Shared packages path: `packages/ui` (Svelte 5 components) + `packages/theme` (CSS tokens/glass/layout) -> consumed by both Svelte apps
17. GitHub CI app backend gate: `.github/workflows/ci.yml` `app-backend-checks` -> `apps/svelte-desktop` build output -> `apps/tauri/src-tauri` `cargo check` / `cargo test`
18. NAT traversal path discovery: `src/engine/config.rs` `[nat_traversal]` -> `src/transport/config.rs` `NatTraversalConfig` -> `src/transport/nat.rs` `NatPathDiscovery` -> path-management consumers when policy permits discovery.
19. Audit logging path: `src/main_parts/late_tests_and_mlock.rs` pre-resolves the privilege target plus `[audit]` queue/segment/flush bounds -> `--audit-log <path>` -> `src/audit/mod.rs::init_audit_log_with_options()` creates the global owner and mode-`0o600` active file -> typed producer calls enqueue without hashing or file I/O -> bounded `qf-audit-writer` assigns sequence/timestamp, writes schema-v2 NDJSON, rotates immutable sequence-ranged segments, atomically advances the retained checkpoint, and exposes dropped/persistence counters -> shutdown barrier flushes and joins -> `src/main.rs` `verify-audit-log <path>` validates ordered retained continuity, restart state, and checkpoint tail -> `src/bin/qf-audit-probe.rs` proves concurrent durable throughput and restart verification.
20. Memory locking path: `src/engine/config.rs` `[security] lock_memory/lock_blocks` -> `src/main.rs::run_server()` `RLIMIT_MEMLOCK` gate -> unlimited `mlockall(MCL_CURRENT | MCL_FUTURE)` or finite-limit `MCL_CURRENT` -> `src/optimize/mod.rs` `MemoryPool::set_lock_blocks()` -> best-effort `mlock_block()` in `alloc_numa_block()`.
21. Windows core CI gate: `.github/workflows/ci.yml` `windows-core-checks` -> two-job native `windows-latest` `tun-windows,rust-tests` check/test compile -> `scripts/utils/provision-wintun.ps1` verified DLL beside the test executable -> ordinary unit tests -> serial ignored privileged dual-stack adapter, bidirectional UDP, blocked-read close, repeated-lifecycle, WFP packet-outcome, process-exit retention, and stale-cleanup tests -> exact WFP-object/adapter/firewall residue inspection plus evidence upload -> strict library Clippy. Run `30508948149`, job `90764941801` proves the complete native lifecycle; manual workflow runs `30535603045` and `30536002374` prove authenticated dual-stack Wintun/WFP traffic twice against one unchanged Omega server process.
22. Windows signed release path: `scripts/audits/verify-release-version.sh` -> `.github/workflows/release.yml` `release-version-contract` -> verified Wintun provisioner -> `apps/tauri/src-tauri/tauri.windows.conf.json` resource beside the Windows executable -> `desktop-windows` Tauri MSI build -> `.msi` plus `.msi.sig` verification -> administrative MSI extraction and exact Wintun DLL hash verification -> required `publish-release` dependency -> `latest.json` `windows-x86_64` entry. Release run `30612996058`, job `91099832490`, publishes `QuicFuscate_0.4.4_x64_en-US.msi` with SHA-256 `eba3a9b59b05474e887ed0491f66998523573cae675a44c4469394ee4a9c025f` plus its signature and Wintun provenance.
23. Reliable tunnel fallback path: `src/core.rs` `QFT1` packet framing -> `src/transport/connection/` immutable STREAM ledger -> confirmed-PMTU packetization -> centralized `OutboundPacer` -> ACK/loss/PTO retirement and requeue -> byte-exact PMTU fallback splitting -> peer `core.rs` bounded packet reassembly.
24. QUIC version negotiation path: `src/engine/config.rs` or `src/main.rs` ordered v2/v1 policy -> `src/transport/version.rs` selectable versions and grease -> `src/transport/packet.rs` stateless server VN -> `src/transport/connection/` strict CID/original-version gate and single restart -> `src/qftls.rs` version-matched rustls handshake plus authenticated Version Information downgrade validation.
25. Base Linux TUN proof lifecycle: `scripts/tests/tun-e2e-netns.sh` shared `flock` -> fail-closed pre-existing process/namespace check -> exact server/client PID capture -> TLS/H3/MASQUE TUN assertions -> exact child reap and owned namespace teardown; `scripts/tests/audits/audit-runtime-guardrails.sh` rejects global product-name process reapers on this path.
26. FEC operator-policy and observability path: `src/main.rs` / `src/implementations/server/mod.rs` engine `FecMode` -> `src/fec/` `FecConfig::apply_engine_mode()` -> independent `FecControlPolicy::{Off, Auto}` with Zero bootstrap -> `src/transport/connection/` independent recovery send/loss callback counts, transport-classified ACK counts, and congestion-controller smoothed loss -> `src/core.rs` typed `FecCallbackFeedback` transfer that admits only ACK/loss-bearing feedback to `AdaptiveFec::report_transport_loss()` -> recent-window-confirmed adaptive target or 32-clean-ACK Zero proof -> committed codec state -> actual wire send and `src/fec/wire.rs` accepted receive/recovery reports -> connection-local `FecTelemetrySnapshot` plus explicit process aggregates in `src/optimize/telemetry.rs` -> read-only server metric projections in `src/implementations/server/metrics.rs`. Active Engine commands follow `EngineCommand::SetFecMode` -> typed `FecPolicyCommandResult` -> existing `ClientConnection` mutex -> `QuicFuscateConnection::set_fec_control_policy()` -> queued-source preservation/repair retirement -> fresh Zero controller and wire receive state; accepted policy persists into `ClientRuntime` reconnect configuration.
27. Client TUN uplink pressure path: `src/main.rs` TUN reader channel -> event-loop drain with `tun_backpressure_frame` retry ownership -> `src/core.rs::send_tunnel_packet()` -> `src/transport/h3.rs::send_masque_datagram()` -> QUIC DATAGRAM queue (`ConnectionError::DgramQueueFull` backpressure) or oversized-packet framed H3 carrier -> socket flush and peer TUN delivery. Packets are not consumed from the TUN reader channel until the carrier accepts them.
28. Server TUN downlink pressure and fairness path: `src/implementations/server/mod.rs` TUN reader or authenticated client fan-out -> direct admission and transport enqueue when shared shaping is disabled and that session has no backlog, otherwise bounded `LiveServerState::pending_tun_downlinks` (256 packets, 384 KiB, 32 per session, 5-second expiry) -> optional shared token bucket reserves aggregate service capacity -> weighted byte-deficit round robin preserves per-session FIFO and proportional saturated shares -> front-packet-derived visit budget returns immediately when every active session is deferred -> `SessionManager::check_bandwidth()` performs one downlink admission/accounting decision -> `send_masque_downlink()` -> path-aware retry or socket flush. Shared or per-session rate denials stay bounded and retryable; already admitted transport retries do not double-charge the session; failed transport admission refunds the shared reservation; daily/monthly quota denials are terminal for the packet; queue, scheduler, bandwidth, audit, and exact terminal-drop metrics retain the outcome.
29. Server-generated MASQUE response pressure path: ICMP routing responses and asynchronous DNS interception -> `core::MasqueDownlinkQueue` (128 packets, 192 KiB per connection) -> `drain_masque_downlink_responses()` -> connection-owned retry slot on `ConnectionError::DgramQueueFull` -> subsequent housekeeping or packet pass; Prometheus telemetry reports retry, packet-capacity, byte-capacity, terminal-send, and shutdown outcomes.
30. Standalone dual-stack TCP diagnostic path: `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh` receiver trial boundary -> persisted start/end window plus client exit status -> `scripts/tests/utils/summarize-throughput-boundaries.py` observes encrypted client-to-server and server-to-client UDP at `qf523h1` and `qf523hs` -> per-window counts and gaps, including explicit zero return traffic. `scripts/tests/utils/udp-socket-evidence.py` snapshots `/proc/net/udp` before/after each trial and fails on a nonzero drop delta: server socket selected by local port 4433, client socket selected by remote port 4433 with local and remote endpoint continuity required.
    Exact ARM64 harness `57a2eed` has a clean full-run proof for all four observed boundaries and zero server socket drops. Its retained clean opt-in timeout also has equal forward counts of 7,086 and equal reverse counts of 6,072 at both host-veth boundaries with a zero server socket-drop delta. Exact ARM64 source `681705d` adds 18 zero-delta client socket summaries across all completed clean trials; child one passed the full gate, while children two and three later failed only in their deliberate black-hole recovery. On a future heartbeat failure, the harness-specific `QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS=1` path records socket receipt, outer Core receive result, and transport `last_activity` advancement without changing ordinary runtime behavior. Exact source `a3ced4d` reproduced a clean opt-in TCP timeout before that heartbeat path, after a 12-packet application-space persistent-congestion run; matching encrypted boundary counts and zero client/server socket drops remain retained. Exact source `36a97d0` shows that all three reproduced client decisions had one triggering ACK, twelve declared losses, and a terminal time-threshold loss, with retained runs of 133, 219, and 107 ms. The next diagnostic boundary is ACK progression and time-threshold loss provenance before its transport-side decision.

31. Telemetry resource-sampling path: every connection's one-second maintenance -> `src/optimize/telemetry.rs::refresh_resource_metrics_if_due()` -> disabled fast return or process-wide lock-free one-second admission -> current-PID memory-only `sysinfo` refresh plus global-pool gauges. Explicit shutdown `flush()` remains unthrottled. Feature-gated orchestrator sampling returns before system access when its runtime owner is absent; otherwise the connection-retained current-PID sampler refreshes CPU, process memory, and host RAM -> `DeepIntegrationOrchestrator`.
32. Production logging path: CLI `--config` -> pre-runtime `EngineConfig::from_file()` plus `validate()` -> `LoggingConfig::effective()` -> one `logging::init()` global facade owner -> bounded `qf-log-writer` queue -> rotating file, stderr, RFC 5424 UDP, and admin-buffer sinks -> acknowledged `FlushGuard` shutdown barrier; persisted admin modes adjust the facade filter only and never replace sink ownership.
33. Retained-secret erasure path: server or desktop token input -> `QKeyToken`/`SecretBytes` owner -> QKey serialization or zeroizing decoded JSON -> zeroizing binary decode -> SHA-256 verifier only in `QKeyRegistry`; client import -> typed config/profile -> live connection -> drop wipe. TLS installation/cache -> zeroizing private-key read, copied 1-RTT secret, ticket, and master owner -> replacement/eviction/drop wipe; AES header protection and AEGIS wrapper key/IV/derived state wipe before their owner is released. Test-only observers inspect the zeroed live ranges before clear/deallocation.
34. QKey auth abuse-policy path: validated `QUICFUSCATE_AUTH_*` environment -> `ServerConfig.auth_policy` -> `LiveServerState.auth_rate_limiter` -> pre-registry Initial admission -> pending `QKeyAuthState` attempt ID -> established QUIC/TLS connection starts the one-shot encrypted-H3 bearer deadline -> success/failure, timeout, connection close, or internal abandonment -> exactly-once completion -> backoff/block state, metrics, audit, and bounded housekeeping prune.
35. QKey auth process-proof path: `scripts/tests/suites/test-qkey-auth-policy.sh` refuses existing output and product processes -> validates fail-closed pre-resource startup -> creates an isolated CA/leaf/QKey state -> exercises CA-verified H3 auth, exact backoff/block/expiry/reset, secondary-loopback isolation, and idle prune -> runs exactly 100 real Initial attempts -> verifies metric/audit/resource/secret/UI/process contracts -> retains only caller-owned evidence.
36. DDoS admission process-proof path: `scripts/tests/suites/test-ddos-admission.sh` refuses existing evidence -> validates a pinned real MaxMind country database through `src/bin/qf-ddos-policy-probe.rs` -> serves a locally controlled certificate-verified HTTPS feed through the bounded custom-CA path -> proves atomic cache restart and failed-refresh last-known-good preservation -> completes a pre-activation no-Retry handshake and continuously exchanges ack-eliciting PING/ACK traffic on that connection -> drives a low baseline plus 800-packet sustained Initial spike -> observes one activation while the established client remains live -> completes one real Retry-protected QKey handshake -> observes one clear -> requires the original client to remain established with positive bidirectional packet counts and no additional Retry -> enforces CPU/RSS, secret, protected-UI, and process-residue bounds.
37. Per-session bandwidth control path: authenticated HTTP `GET|POST /api/clients/{session|remote|assigned-ip}/bandwidth` and `POST /api/clients/{id}/quota/reset` -> `ServerAdminCore` -> `SessionManager` live policy/quota owner. QKey issuance accepts the same complete `BandwidthPolicy`; persisted QKey policy overrides global defaults only after bearer authentication, while later admin mutation overrides the live session without resetting usage.
38. Traffic-analysis policy and timer path: standalone TOML baseline plus QKey and Intelligent ceilings -> validated `TrafficAnalysisPolicy` -> pending QKey request stored before authentication -> encrypted bearer success authorizes the bounded effective policy -> one `TrafficAnalysisScheduler` deadline participates in the Core wakeup minimum -> at most one due slot -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted path-MTU-bounded chaff emission -> idle ramp, reactivation, or terminal cancellation. FullPadding costs use the maximum UDP payload; ConstantRate costs and packet sizes use the configured target capped by that payload.
39. Network-stack fingerprint path: server config or `QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION` plus `QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE` -> one frozen `StealthConfig` snapshot -> TLS/H3 persona and `PacketNormalizer` created together in `QuicFuscateConnection::new_server()` -> decoded MASQUE DATAGRAM, raw capsule, compressed capsule, or `QFT1` framed-H3 packet -> one allocation-free IPv4 and SYN-only TCP normalization pass -> PMTUD-safe ICMP disposition -> authenticated server TUN/fanout callback. Client connections, Off mode, sealed QUIC datagrams, fragments, and ordinary downlink retain their explicit passthrough boundaries. `scripts/tests/fingerprint-runtime-proof-netns.sh` proves the five profile vectors; active nmap remains a recorded limitation until bidirectional probe normalization exists.

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
|   |   |   |-- test-ddos-admission.sh
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
|   |   |   |-- test-qkey-registry-encryption.sh
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
    |   |-- qf-ddos-policy-probe.rs
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
    |       |-- admin_http_parts/
    |       |-- admin_logs.rs
    |       |-- fsutil.rs
    |       |-- ip_pool.rs
    |       |-- limits.rs
    |       |-- parts/
    |       |-- metrics.rs
    |       |-- mod.rs
    |       |-- qkey_registry.rs
    |       |-- qkey_registry_storage.rs
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
    |-- secret.rs
    |-- reality.rs
    |-- rng.rs
    |-- simd
    |   |-- mod.rs
    |   |-- amx.rs
    |   |-- arm.rs
    |   |-- arm_stream.rs
    |   |-- arm_varint.rs
    |   |-- bitstream.rs
    |   |-- core.rs
    |   |-- crypto.rs
    |   |-- fec.rs
    |   |-- galois.rs
    |   |-- h3.rs
    |   |-- planner.rs
    |   |-- qpack.rs
    |   |-- scalar.rs
    |   |-- string.rs
    |   |-- transport.rs
    |   |-- x86.rs
    |   |-- x86_ack.rs
    |   |-- x86_extended.rs
    |   |-- x86_header.rs
    |   |-- tests.rs
    |   |-- tests_arm.rs
    |   `-- tests_dispatched.rs
    |-- stealth
    |   |-- mod.rs
    |   |-- fingerprint.rs
    |   |-- tls_cover.rs
    |   |-- tests.rs
    |   |-- test_support.rs
    |   `-- parts/
    |       |-- browser_profiles.rs
    |       |-- chaff.rs
    |       |-- config.rs
    |       |-- cover_traffic.rs
    |       |-- doh.rs
    |       |-- domain_fronting.rs
    |       |-- escalation.rs
    |       |-- flow_shaping.rs
    |       |-- http3_masquerade.rs
    |       |-- manager.rs
    |       |-- masque_manager.rs
    |       |-- probe_detector.rs
    |       |-- stealth_coverage_tests.rs
    |       |-- tls_client_hello.rs
    |       `-- tls_cover_provider.rs
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
    |   |-- connection/
    |   |   |-- mod.rs
    |   |   `-- parts/
    |   |-- frames.rs
    |   |-- h3.rs
    |   |-- packet.rs
    |   |-- pn.rs
    |   |-- recovery.rs
    |   |-- udpfast.rs
    |   |-- version.rs
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
- Linux backend selection: `firewall::resolve_backend()` probes nftables and the complete dual-stack iptables toolchain once at startup. Standalone and embedded client/server paths retain the selected enum through setup, policy transitions, teardown, and diagnostics; explicit unavailable requests fail closed.
- Linux nftables: `inet quicfuscate_ks` is replaced with one `nft -f -` transaction. The output chain permits loopback, exact endpoint, selected TUN DNS, and TUN traffic in that order under a default-drop policy.
- Linux iptables: `iptables-restore --noflush` and `ip6tables-restore --noflush` atomically rebuild dedicated `QUICFUSCATE_KS` chains. Shared OUTPUT chains contain only one exact jump; cleanup removes only owned jumps/chains.
- Server routing: nftables owns only `inet quicfuscate_rt`; iptables owns only `QUICFUSCATE_RT` and `QUICFUSCATE_NAT` plus exact FORWARD/POSTROUTING jumps. Setup, stale cleanup, and teardown use the same retained backend.
- Owned cleanup contract (`src/firewall/cleanup.rs`): Exact nftables table, iptables chain/rule, PF anchor, Windows firewall-rule, and NetNat identities share bounded three-attempt removal and a mandatory absent-resource postcondition. Injectable inspection/removal closures prove transient, permanent, command-result, and postcondition outcomes. Linux cross-backend stale inspection skips a tool only when its version probe proves it unavailable; explicit selection remains fail-closed. Runtime callers propagate permanent failure rather than reporting successful shutdown.
- Client resource ledger (`src/implementations/client/backend.rs`): Records TUN, exact route, and DNS ownership immediately after each mutation; failed setup rolls back in reverse order. Linux/macOS descriptor closure owns TUN destruction and verifies interface absence. Failed DNS and route cleanup remains retained for retry; every cleanup failure is aggregated.
- macOS: PF policy is available only when the main ruleset exposes the QuicFuscate anchor. Cleanup touches only `com.quicfuscate.killswitch` or `com.quicfuscate.vpn` and never disables shared PF. TODO-548 owns managed installation and privileged proof.
- Windows: `src/implementations/client/killswitch/windows.rs` owns one fixed persistent WFP provider/sublayer plus eight fixed filter slots. Each state replacement transaction deletes and recreates only those identities, then installs higher-weight loopback, exact endpoint, and optional live Wintun-LUID permits before a lower-weight catch-all block at IPv4/IPv6 outbound transport layers. Those layers also classify third-party transports and raw packets without widening the endpoint beyond its UDP address/port tuple. Engine/session/transaction guards close or abort exactly once; failed replacement preserves the previous committed policy; explicit disable and stale cleanup delete the complete identity set plus the two exact legacy `netsh` rules. The legacy `WindowsPlatform` adapter path still fails before host mutation. `src/interface/wintun.rs` remains the only valid native data-plane owner and its WFP test observes the adapter ring instead of treating socket acceptance as packet delivery. Run `30508948149`, job `90764941801` is native-green for Wintun lifecycle, all WFP packet-policy states, process-exit retention, stale cleanup, and zero residue; release run `30533862566` is green for the signed packaged boundary; Windows-Omega runs `30535603045` and `30536002374` are green for the authenticated connected-policy data plane and exact cleanup.

### Automatic Loss Ownership
- `Connection::last_activity_elapsed()` (`src/transport/connection/`): Exposes time since the last inbound datagram.
- `ClientRuntime::start_loss_watchdog()` (`src/implementations/client/mod.rs`): Owns one 50 ms remote-close/inactivity loop, records the first `DisconnectReason`, stops the I/O driver, and invokes the loss transition callback once.
- `QuicFuscateEngine::connect()` (`src/engine/engine.rs`): Applies endpoint-only policy before handshake, connected policy after handshake, and installs the runtime watchdog. Callback and event snapshots avoid holding callback locks during user code.
- `run_client()` (`src/main.rs`): Owns the standalone select-loop equivalent and distinguishes clean signal shutdown from remote close, socket failure, and heartbeat timeout. Its existing 5 ms housekeeping path queues an ack-eliciting QUIC keepalive every third of a nonzero heartbeat window so a responsive idle peer advances inbound activity before the fail-closed deadline.
- `QuicFuscateEngine::check_heartbeat()`: Compatibility query only; it never drives a duplicate watchdog.
- `scripts/tests/tun-e2e-killswitch-netns.sh`: Privileged Linux process proof for explicit/automatic selection, unavailable-backend failure, rollback-safe nftables and iptables replacement, real TUN traffic, selected VPN DNS, direct DNS and IPv6 leakage, timeout latency, retained fail-closed state, stale recovery, and client/server SIGTERM cleanup.

## ICMP Server Architecture (Review Fix Session)
- `build_echo_reply()` (`src/implementations/server/icmp.rs`): Sets fresh TTL=64 for locally-originated echo replies (RFC 1812 §5.3.1), not decremented from original request.
- Live local echo handling selects the connection's frozen network profile before the reply enters the bounded MASQUE response queue. Optional unreachable suppression never removes IPv4 Fragmentation Needed or ICMPv6 Packet Too Big.

## Deep Audit Update (2026-08-04)

A full source-audit sweep produced TODO-626 through TODO-657 and augmented TODO-570, TODO-584, TODO-587, TODO-592, TODO-615, and TODO-576. The new findings affect the following wiring surfaces and should be reconciled before treating those areas as production-proven:

- **Crypto data plane**: constant-time tag comparison (TODO-626), key/IV length validation (TODO-627), AEGIS `unwrap` panics (TODO-628), AEAD header-protection sample validation (TODO-629), GHASH test override removal (TODO-630), round-key zeroization (TODO-631), nonce/IV uniqueness (TODO-632), and QUIC KDF input validation (TODO-633).
- **FEC recovery**: unbounded fountain-decoder storage (TODO-634), adaptive emitted-ID cap (TODO-635), decoder peeling complexity (TODO-636), and Wiedemann buffer reuse (TODO-637).
- **Transport/Stealth**: ConnectionId clone hot path (TODO-638), StealthShaper RNG fallback logging (TODO-639), H3 masquerade time source (TODO-640), domain fronting jitter (TODO-641), TLS cover zero-key fallback (TODO-642), qftls `munlock` (TODO-643), probe detector history cap (TODO-644), Reality session map timer-driven cleanup (TODO-570), and brain escalation/histogram/config correctness (TODO-584).
- **Optimize/Engine/Admin**: engine config reload (TODO-645), uring_batch backpressure (TODO-646), admin HTTP connection limit (TODO-647), config write validation (TODO-648), memory-pool unsafe bounds (TODO-587), metrics export allocations (TODO-587, TODO-615), and TUN interface unaligned/fcntl safety (TODO-654, TODO-655).
- **Client/Server/DNS/PKI**: DNS backup path (TODO-649), DNS intercept spawn failure (TODO-650), PKI timestamp fallback (TODO-656), and CLI probe parse errors (TODO-657).
- **Privilege and secrets**: SecretString UTF-8 safety (TODO-651), privilege `assume_init`/`CStr` validation (TODO-652, TODO-653).

`cargo check --all-targets --all-features` and `cargo clippy --all-targets --all-features -- -D warnings` pass after a `cargo clean` recovered a corrupted `target/` cache.
