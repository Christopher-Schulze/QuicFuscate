# QuicFuscate Map

This document is the single combined **file map** and **architecture index** for the repository.
It is maintained as the current architecture and repository index, with a curated tracked-source tree snapshot included below for navigation.

## High-Level Architecture and Wiring

- Native IPv4 TTL-expiry proof: `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh::prove_icmp_boundaries()` captures the client-TUN request and server `TIME_EXCEEDED` response into a pcap, then `scripts/tests/utils/verify-icmp-time-exceeded-pcap.py` checks endpoints, TTLs, ICMP type/code, IPv4 and ICMP checksums, and the exact 28-byte quoted request; before/after metrics require a positive `time_exceeded` delta. Run `30827540460`, job `91733001327`, artifact `8861606310`, proves one request, one server response, the exact 28-byte quote, valid checksums, and `time_exceeded=0 -> 1`. The native job later failed at the independent backpressure-quiescence gate; TODO-806 is closed and TODO-559 owns that queue evidence.
- Runtime core: Rust crate under `src/` with entrypoints in `src/main.rs` and `src/lib.rs`.
- Unified configuration boundary: `config/quicfuscate.toml` -> strict `EngineConfig` parse -> complete section validation -> dedicated transport/client/server projections. `AppConfig` retains only validated FEC, stealth, optimization, and anti-replay runtime state; transport policies and startup-owned sections remain on their canonical owners, and invalid or unknown submitted values fail before admin persistence or runtime construction.
- Data path wiring: app or TUN ingress -> core/transport -> stealth shaping -> crypto -> FEC -> network I/O.
- QUIC version wiring: Engine and standalone CLI config default to ordered v2/v1 support; `transport::version` owns selection, greasing, type mapping, and authenticated Version Information; `transport::packet` owns v1/v2 Initial and Retry material plus stateless VN; standalone server ingress bypasses VN for the FEC magic before existing-session dispatch; `transport::Connection` owns strict CID validation and one bounded fresh-state restart.
- Production VPN carrier: authenticated Core H3/MASQUE CONNECT-UDP carries TUN IP packets for standalone, embedded generic, and live server paths. One registered Flow-ID (`0`) is checked against the active CONNECT-UDP stream before decoded MASQUE DATAGRAM payloads reach TUN; oversized/unavailable datagrams use the bounded `QFT1` length-framed H3 fallback. `src/control_plane.rs` owns the bounded versioned assignment capsule; the client sets a reconnect generation in the CONNECT request, waits for the authenticated assignment before opening TUN, and uses one bounded H3/MASQUE ingress owner for downlink. The public QKey ID in the QUIC Initial selects the server record; the bearer is presented only through the encrypted H3 `x-qf-auth` header. The server gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state and emits the assignment from the authenticated session allocation. TODO-866 owns assignment lifecycle; TODO-867 owns the remaining carrier integration and native/authenticated evidence gates. The retired stealth manager and stealth-local DoH resolver are archived, not compiled.
- Frontend request lifecycle wiring: the Svelte admin dashboard, configuration, logging, credential, and QKey resources share per-resource serialized request coordinators with generation checks and teardown invalidation, so interval, initial, manual-refresh, and mutation reconciliation responses cannot commit stale state. Desktop Tauri status, stats, and log pollers own one in-flight request per resource; a poller owner generation, status-state version, and log cursor epoch reject delayed teardown, tunnel-state, cursor-regression, and log-clear responses.
- TUN provisioning proof: `src/interface.rs`, `src/interface/wintun.rs`, and `src/implementations/client/platform/{linux,macos}.rs` enforce the shared address/prefix/MTU contract; Linux server routing in `src/implementations/server/routing.rs` recovers persisted ownership before a new TUN is opened, rejects addresses owned by another interface, records exact ifindex/config ownership before mutation, verifies exact postconditions, and performs bounded owned rollback and stale recovery; `scripts/tests/tun-provisioning-negative-netns.sh` owns the privileged negative/retry/residue proof and `scripts/tests/tun-e2e-netns.sh` owns the process-loss and graceful-removal lifecycle proof.
- QKey auth abuse-policy wiring: `ServerConfig.auth_policy` resolves and validates bounded environment controls -> `LiveServerState` owns one monotonic `AuthRateLimiter` -> new Initial admission allocates one attempt ID before registry lookup -> the same ID survives pending H3 authentication -> QUIC/TLS establishment starts the bounded encrypted-bearer deadline exactly once -> success, failure, timeout, pre-auth close, and internal abandonment complete the attempt at most once. Constant-size per-IP state applies capped exponential backoff, explicit block expiry, pending/state capacity bounds, and periodic idle pruning; admission outcomes remain wire-indistinguishable while Prometheus and typed audit events remain distinct.
- QKey revocation wiring: explicit admin revoke persists the registry mutation -> `LiveServerState` records the single revocation state and atomically drains the SessionId-to-QKey tracker -> affected transports queue authenticated QUIC CONNECTION_CLOSE frames -> the next live flush delivers the close before closed-client reconciliation releases the session/domain state. Pending authentication checks the same revocation owner before and during commit. Revoked records use the validated 90-day default retention, are pruned at most every five minutes from housekeeping, and expose `quicfuscate_revocation_pruned_total`; no automatic QKey-rotation scheduler or external revocation callback remains in the housekeeping path.
- Brain observer wiring: transport receive callbacks update packet count, reorder state, and size bins through lock-free atomic accumulators and sample inter-arrival bins every eighth packet -> `StealthBrain::apply_policy` drains those accumulators under its consolidated mutation lock. Transport control producers route through one bounded queue admission helper that coalesces the latest `MAX_DATA` and per-stream `MAX_STREAM_DATA` update and preserves terminal close frames under saturation. `Connection::close()` is first-close-wins under TODO-606 and records structured local application/transport errors under TODO-772; terminal close priority remains open under TODO-697.
- Sustained DDoS admission wiring: validated environment policy -> interval-delta accepted PPS -> monotonic EWMA activation/clear windows -> ordered global, GeoIP, blacklist, and per-IP admission -> normal-cost cryptographically established traffic or enhanced-cost half-open/new traffic -> source/IP/CID/credential/time-bound stateless QUIC Retry for supported Initial packets -> validated public QKey credential restoration plus RFC 9001 Initial keys from the Retry SCID. GeoIP activation validates the country policy, fully verifies a regular MaxMind country database before readiness, rejects valid non-country databases, propagates configured activation failure through every server constructor, exposes actual disabled/active state through health/admin/metrics, and drops lookup/decode failures fail-closed with explicit counters. Stateless Version Negotiation remains behind the admission caps. Strict HTTPS blacklist refresh is owned by `BlacklistSyncOwner`, which claims one due task, retains completion/cancellation state, applies bounded retry, isolates feed parsing, atomic cache publication, and active-list replacement in `spawn_blocking` after a pre-publication cancellation check. Absolute timeout/body/entry/TTL/interval caps and lifecycle/freshness metrics are exposed through Prometheus, health, and admin status.
- Idle-session lifecycle wiring: `transport::Connection` derives idle expiry from configured `max_idle_timeout`, treats zero as disabled, and marks an expired connection terminal without emitting CONNECTION_CLOSE -> standalone housekeeping reconciles the closed transport owner -> `LiveServerDomain` releases the session, IPv4/IPv6 pool addresses, connection-limit ownership, QKey association, bandwidth state, and pending policy state. The independent `client_timeout_secs` expiry remains a longer shared-domain safety boundary. Error ownership preserves the first local root cause separately from the first peer close, including peer close code, frame type, and reason bytes. TLS provider failures queue a CRYPTO_ERROR close with the 0x0100 alert base before termination; received peer closes remain receive-only terminal events.
- Per-session bandwidth wiring: validated `QUICFUSCATE_CLIENT_*` defaults -> `SharedServerDomain` constructs one `PerClientBandwidthManager` -> session admission creates independent uplink/downlink token buckets plus shared UTC daily/monthly quotas -> encrypted QKey authentication optionally replaces the effective policy -> authenticated admin read/update/reset has final live precedence. MASQUE and framed-H3 uplink boundaries admit bytes directly. Unshaped TUN/fan-out downlinks with no session backlog use direct admission; shared shaping, rate backpressure, or transport backpressure enters the existing bounded pending owner, whose optional validated shared token bucket defines aggregate service capacity before weighted byte-deficit round robin applies FIFO-preserving per-session shares. Session close, expiry, revoke, and kick remove the same state; metrics and deduplicated audit expose typed rate/daily/monthly outcomes.
- Tunnel MTU ownership: `transport::PmtuState` discovers a validated 1280-1500 outer packetization budget; `core::QuicFuscateConnection` derives the FEC/QUIC/MASQUE datagram payload and a separate IPv6-safe inner tunnel MTU. The client applies live TUN MTU changes and returns local IPv4/IPv6 PTB above that boundary. The server's `allow_client_uplink()` returns IPv4 Fragmentation Needed for both DF states before either MASQUE or framed-H3 TUN write, intentionally avoiding platform-dependent oversized writes and userspace fragmentation. The Linux CI native job first runs a separate 1280-byte carrier phase for bidirectional framed-H3 fallback, then gives its PTB phase a 1472-byte carrier on both ends, a 1500-byte client TUN ceiling, and a 1280-byte server TUN ceiling so the 1,328-byte probe crosses only the server TUN boundary; `prove_server_ptb_from_client()` captures the server-sourced PTB for both IPv4 DF states and IPv6 and retains the exact wire and metric evidence. The two IPv4 probe destinations are isolated to prevent the client's learned PMTU from fragmenting the later DF=0 probe. Run `30823185685` proved that keeping the server carrier at 1280 truncated the probe before routing and produced `MalformedPacket`; run `30823826169` exposed same-destination PMTU-cache contamination; run `30824438300`, job `91722362887`, passed the complete PTB gate with unfragmented 1,328-byte DF=1 and DF=0 probes, server-generated IPv4 PTB for both, IPv6 Packet Too Big, and metric deltas `packet_too_big=3` plus `icmpv6=1`. Tunnel-ingress fingerprint normalization now preserves valid IPv4 TTL 0/1 packets until routing can emit `TIME_EXCEEDED`; the native proof of that correction is closed under TODO-806, while the independent queue failure remains separate.
- Windows Wintun and kill-switch ownership: `src/interface.rs` selects the built-in backend only with `tun-windows` -> `src/interface/wintun.rs` securely loads the upstream DLL, creates one adapter/session, captures its LUID and session-owned read event, configures addresses and active MTU, and serializes packet operations against one shutdown event and one exactly-once teardown -> `src/implementations/client/killswitch/windows.rs` resolves the live alias to its LUID and transactionally replaces fixed persistent WFP provider/sublayer/filter identities across IPv4/IPv6 outbound transport layers, which also classify third-party transports and raw packets while preserving the exact UDP tuple -> ignored native tests prove data-plane lifecycle, observe exact IPv4/IPv6 WFP packet absence or presence at the Wintun ring, retain block policy across child-process exit, and prove exact stale cleanup -> `scripts/utils/provision-wintun.ps1` pins archive/DLL hashes plus Authenticode -> CI and Tauri MSI paths provision the untracked DLL beside their executable. Run `30508948149`, job `90764941801` proves the native adapter/WFP lifecycle and zero residue; release run `30533862566`, Windows job `90842338800`, proves the signed MSI plus byte-exact packaged DLL; Windows-Omega runs `30535603045` and `30536002374` prove encrypted QKey/MASQUE connected policy with five IPv4 and five IPv6 tunnel pings twice against unchanged server PID `1158967`, followed by zero WFP/adapter residue.
- Oversized tunnel carrier: raw IP packets within the effective tunnel MTU but above the MASQUE datagram payload use bounded `QFT1` length framing on the `/tun` HTTP/3 stream. `core.rs` reassembles arbitrary DATA-read segmentation per stream and rejects invalid magic, empty frames, non-IP payloads, and unbounded pending data.
- Reliable STREAM ownership: `transport::Connection` keeps a 16 MiB immutable range ledger, binds compact transmission IDs to packet numbers, retires exact ACKed ownership, and requeues packet-threshold/PTO loss before new data. Readable/writable membership uses O(1)-average HashSet admission beside ordered VecDeque scheduling; front removals are O(1), while priority changes retain their explicit reorder scan. A PMTU decrease byte-exactly splits queued transmissions to the new packet budget while late ACKs retire all derived segments once. Bounded flow-control notifications coalesce to one current `DataBlocked` frame per connection window and one `StreamDataBlocked` frame per stream window. Low-level 1-RTT write key updates are provider-owned when TLS is configured and fail closed without a raw transport fallback.
- Outbound pacing: `core::OutboundPacer` centrally gates congestion-controlled transport and FEC emissions from every socket path; ACK-only output is explicitly exempt. Partial burst accounting decays at the configured pacing rate over elapsed time before new bytes are admitted, preventing stale idle bytes from creating false pacing blocks. BBR2 and BBR3 own a congestion-window/initial-RTT Startup pacing floor that cannot collapse on a transient slow delivery sample; measured pacing becomes authoritative after Startup. Reno, BBR2, and BBR3 use saturating in-flight accounting, BBR2 keeps send-side rounds separate from its ACK delivery clock, and both BBR filters expire stale minimum-RTT samples through the shared `QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS` window.
- Traffic-analysis defense wiring: canonical `[transport.traffic_analysis]` plus independent QKey and Intelligent ceilings -> `transport::Config` validated policies -> `transport::Connection` one `TrafficAnalysisScheduler` deadline and one pending slot -> `QuicFuscateConnection::next_send_deadline()` merged with pacing, stealth release, and recovery -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted PING plus PADDING chaff at path-bounded size. Due cover packets consume a slot, but only application STREAM or DATAGRAM traffic extends the idle lifecycle. Idle timeout, ramp-down, reactivation, and shutdown cancellation remain connection-owned. QKey and Intelligent upgrades stay inert until encrypted bearer authentication and cannot exceed their operator ceilings.
- CUBIC wiring: engine config, CLI, client/server conversion, and TOML select `Algorithm::Cubic`; `Recovery` owns RTT-before-ACK delivery, recovery-episode loss collapse, and enum-dispatched `Cubic`/`StealthCubic` pacing without vtable indirection.
- Validated migration wiring: `[connection]` reduction/cooldown/probe-target policy -> `transport::Config::migration_policy` -> exact PATH_CHALLENGE/PATH_RESPONSE candidate validation -> `Recovery::on_path_change()` path epoch and typed `PathChangeEvent` -> Reno/CUBIC/BBR2/BBR3/StealthShaper state transition. `SendInfo::path_control` routes validation datagrams ahead of buffered FEC output without FEC, outer-pacer, or stealth delay; standalone server DCID routing commits a candidate peer tuple only after validation, while simultaneous peer PATH_RESPONSE ownership remains queued independently.
- Standalone Linux TUN routing: explicit `--tun-ip` / `--tun-netmask` on the server updates `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool, keeping Linux namespace deployments and runtime session routing in the same subnet. Server TUN mode rejects macOS, Windows, and other platforms before host mutation until a native routing owner and proof exist.
- DNS-through-tunnel: `src/implementations/client/dns_runtime.rs` owns the supported client TUN resolver lifecycle, binds localhost UDP/53, pre-pins RFC 8484 DoH endpoint addresses before resolver/firewall mutation, and restores the prior platform resolver before teardown; the server MASQUE/TUN uplink separately intercepts IPv4/IPv6 UDP/53 packets before generic TUN egress, resolves through configured plain-UDP server DNS upstreams, and queues rebuilt DNS responses over MASQUE downlink. `DnsInterceptWorkerOwner` retains every accepted blocking worker, closes admission before standalone drain closes the live data-plane boundary, serializes response publication against that close, reaps finished handles during housekeeping, and classifies queued cancellation, panic, terminal response/queue outcomes, late publication, and started-operation shutdown expiry through `quicfuscate_dns_intercept_worker_events_total`; the existing `quicfuscate_dns_intercept_dropped_total` remains admission-only. Client listener admission remains TODO-668; forwarding deadlines, body/input/UDP response bounds, and measured allocations remain TODO-669; DoH semantic response validation beyond transaction ID is TODO-810; UDP response matching is TODO-721; shared query admission and wire preservation are TODO-770.
- NAT traversal: optional `NatPathDiscovery` is default-off and reason-gated (`connectivity-fallback`, `roaming`, `mesh`, `always`). It feeds transport path discovery when explicitly enabled; it is not part of the baseline stealth path.
- TUN downlink hotpath: after one MASQUE downlink packet is queued, the server flushes only the owning client connection rather than sweeping all connected clients.
- TUN data-plane fault wiring: typed `DataPlaneFault` outcomes cover reader termination, channel disconnect, TUN write, transport send, and transport receive failures -> client `ClientRuntime` and standalone client first-wins fault slots -> watchdog/exit reason, driver shutdown, and bounded cleanup -> `EngineStats.data_plane_ready`/`data_plane_faults` plus server `Metrics` readiness and fault counters. Cooperative shutdown is published before receiver drop, owned reader joins are awaited, and deliberate shutdown remains outside fault health.
- MASQUE observability: CONNECT-UDP lifecycle and peer-flow registration stay at `info`; per-packet MASQUE TX/downlink TX lines are `debug` to avoid production log amplification.
- Packet crypto wiring: Initial/Handshake use boxed AES-GCM compatibility keys; normal 0-RTT/1-RTT data-plane AEAD uses concrete `DataAead` enum dispatch with local per-packet or per-batch AEGIS state and no wrapper mutex; Rustls packet-key integrations use the explicit dynamic packet wrapper arm.
- PKI identity wiring (TODO-577, TODO-656): `ensure_pki()` captures one checked `PkiTime` from the canonical or injected clock and passes it unchanged to existing leaf/intermediate/root validation, quarantine naming, and fresh root/intermediate/leaf generation. Rustls/WebPKI verifies hostname, validity, trusted chain, and leaf/private-key match before reuse; invalid or incomplete material moves to a unique quarantine directory before a fresh hierarchy is written. Pre-epoch, unrepresentable, overflowed, and non-positive validity timestamps fail through typed PKI errors.
- FEC recovery wiring: Initial, Handshake, product Auto startup, and stable Zero datagrams remain raw; active 1-RTT framing is also deferred while any Initial/Handshake PTO probe is pending. Active 1-RTT output reserves the exact 36-byte maximum FEC overhead before QUIC serialization. The encoder stores `[outer FEC source length | inner QUIC length | QUIC]`; systematic wire frames omit only the outer length, while repairs retain both layers. The validated product receiver checks transmitted epoch, window, codec, source/total counts, interleave lane, sequence, and repair ordinal before its bounded wire-path decoder allocation; direct public decoder, matrix, wire-helper, and Fountain constructors remain separate audit boundaries under TODO-856 and TODO-857. It reconstructs GF4/GF8/GF16 rows or keyed Fountain source sets deterministically instead of receiving coefficient vectors. Fountain seeds derive from the matching QUIC 1-RTT traffic secret through HMAC-SHA-256 and are applied before the first protected window. Both accepted systematic sources and recovered sources validate then remove the exact inner QUIC length before entering QUIC header protection and AEAD processing. `InterleavedEncoder` assigns source/repair symbols to lanes and complete-block transitions advance the wire epoch. The validated product Fountain rescue policy is bounded to 128 sources and at most 512 repairs at the current 5x total code rate. Every retained receive window caps duplicate-repair state at its profile repair capacity and evicts oldest keys through a bounded FIFO. Decoder equation, solver, timing, success, and eviction counters flow to `src/optimize/telemetry.rs`. Other transitions remain block-boundary safe; only a return to raw Zero after 32 transport-classified clean ACKs may retire an incomplete repair-only encoder window immediately. GF8 remains the wire-canonical GF(256)/0x11D field; GF4 uses fused scalar/AVX2/NEON multiply-XOR, and GF16 uses carryless polynomial multiplication and exact odd-length recovery. The inverse/log/exponent table footprint, native SIMD intersection, and proof claims remain under TODO-855 and TODO-859.
- Active FEC policy wiring: `QuicFuscateEngine::set_fec_mode()` returns a typed requested/configured/effective acknowledgement with active-versus-next-connection scope. `ClientRuntime` retains the canonical Engine projection for reconnect. The existing connection mutex serializes active commands with all I/O and controller inputs; `QuicFuscateConnection` preserves queued sources, retires queued repairs, resets wire state, and replaces all adaptive/codec/recovery state at Zero. Hard-Off framed receive uses source-only parsing with no recovery window. Other generic Engine setters and `reload_config_from_file()` are next-connection/reconnect controls for clients, with startup-owned sections requiring a stopped engine; standalone reload reports `NextConnectionOnly`, is serialized with connection construction by the single live loop, and records the unchanged active-session count.
- Compression wiring: `src/compress.rs` writes safe-path zstd compression and decompression directly into caller-owned `MemoryPool` blocks via bulk buffer APIs; successful callers must return those `AlignedBox` blocks through `MemoryPool::free()` because direct drop bypasses pool accounting. Error-path cleanup remains TODO-831; exact decompression length remains TODO-603. H3 centralizes MIME allow/deny evaluation with deny precedence, and `0x5A` / `0x5D` frame headers remain unchanged.
- Client packet I/O is owned by `src/implementations/client/io_driver.rs` plus `src/core.rs`; no parallel client pipeline adapter or client-local `FecCodec` is retained.
- Client IO ownership: inbound flushes reuse caller-owned 65,535-byte buffers, Linux outbound dispatch reuses one batch-reference vector per loop, and the client TUN reader transfers pool-backed `interface::TunPacket` blocks through its bounded channel so backpressure preserves ownership without a per-packet `Vec` allocation. `TunDevice::read_contract()` distinguishes native nonblocking descriptors from custom blocking backends before the generic async outbound loop starts. Admin HTTP auth/session state uses `parking_lot`; its login limiter is a 10,000-key LRU with all-attempt accounting, and session replay uses a `HashSet` plus bounded FIFO eviction. The FIFO is count-based rather than time-based (TODO-665), while the outer live-session map has no explicit count cap (TODO-809).
- Linux outbound dispatch wiring (TODO-578, TODO-646): `OutboundDispatch::IoUringBatch` is admitted only when a runtime-owned `UringBatchWorker` initialised successfully. The worker owns one synchronous sender on one joined blocking thread, has one queued request, admits at most 256 packets and 524,288 aggregate payload bytes before copying, disables SendMsgZc, and turns timeout or hard completion failures into typed data-plane faults. A busy worker falls back to `sendmmsg`/socket sends; the shared `try_sendmmsg_batch()` match rejects accidental io_uring fall-through explicitly instead of silently returning zero sends, while `SendmmsgBatch` remains bounded by the payload count. Direct `UringBatchSender` calls remain synchronous compatibility primitives. TODO-798 continues to own partial-send semantics.
- Audit logging wiring (TODO-515, TODO-525): `src/main_parts/late_tests_and_mlock.rs` resolves `[audit]` bounds and initializes the global `OnceLock<Arc<AuditLog>>` owner before privilege reduction -> typed lifecycle, privilege, authentication, QKey, admin, connection, configuration, and routing emitters call non-blocking producer APIs -> one bounded `qf-audit-writer` assigns order and owns schema-v2 serialization, SHA-256 chaining, file I/O, deterministic rotation, retention, and atomic checkpoint durability -> Prometheus exposes rejected-event and persistence-error counters -> acknowledged shutdown flush joins the worker -> `verify-audit-log <path>` validates the checkpoint-declared ordered segment set with schema-v1 compatibility. All audit artifacts are mode-`0o600` regular files owned by the runtime identity; special files and symlinks are rejected.
- Memory locking wiring (TODO-516): `src/main.rs::run_server()` applies `mlockall(MCL_CURRENT | MCL_FUTURE)` when `[security] lock_memory = true` (default), but defers it until after a configured Linux UID/GID transition so glibc never broadcasts setxid across pre-locked runtime stacks. qftls receives the same `lock_memory` policy from standalone and embedded server identity loading. Its accepted TLS identity is process-lifetime-owned; rejected values use an exact-range zeroize-before-`munlock` guard, and a successful process-wide `MCL_FUTURE` owner prevents redundant individual unlock ownership. The `MemoryPool` blocks use individual `mlock()` before the transition. Successful pool locks are tracked by `BlockLockLedger`; `MemoryPool::free()`, queue shrink, full-queue disposal, pool `Drop`, and TLS-cache `Drop` zeroize and `munlock()` before allocation release, while direct `AlignedBox` drops remain outside this owner boundary. `LimitMEMLOCK=infinity` in systemd enables full process locking; finite limits retain explicit failure reporting and the individually locked boundary. The process caller currently logs and continues after `mlockall` failure, so readiness and fail-closed policy remain TODO-852. A fresh native proof of the post-change source is blocked by the unavailable Omega SSH path. TODO-853 retains certificate/key correspondence and identity-output proof.
- Retained-secret erasure wiring (TODO-526): `src/secret.rs` zeroizing byte/string owners -> `src/engine/qkey.rs` typed `QKeyToken` plus zeroizing JSON/base64 parse/generate temporaries -> server issuance and registry decode/hash -> client profile/config/live connection ownership. `src/qftls.rs` and `src/transport/config.rs` zeroize session-cache ticket owners, ticket copies, test-bound ticket/session owners, and private-key PEM read buffers; `src/transport/packet.rs` wraps QuicFuscate's copied 1-RTT secrets, `src/crypto/aead.rs` wipes AES header-protection keys, and `src/crypto/aegis.rs` wipes L/X4/X8 wrapper key/IV plus local derived state on drop while concurrent packet operations remain mutex-free.
- QKey registry persistence wiring (TODO-539): standalone startup -> `qkey_registry.rs::QKeyRegistry::open()` -> `qkey_registry_storage.rs` protected current/previous keyring -> authenticated `QFQREG` version-1 ChaCha20-Poly1305 envelope. Startup propagates typed missing-key, wrong-key, corruption, version, permission, and I/O failures. Admin issue/revoke mutations serialize into zeroizing buffers and publish durable state before updating memory. Plaintext migration writes encrypted recovery before encrypted primary; an existing encrypted backup anchors plaintext-downgrade rejection; legacy/current-key rotation retains encrypted recovery and never interprets failed ciphertext as plaintext.
- QKey replay-window maintenance wiring (TODO-578): standalone housekeeping -> `QKeyRegistry::prune_replay_window()` -> current Unix-epoch timestamp -> `ReplayWindow::prune(now)` -> stale-slot removal and logical-base advancement, including an empty quiet window.
- Linux privilege-boundary wiring (TODO-527): CLI `--drop-user`/`--drop-group` -> `src/privilege/drop.rs::resolve_identity()` reentrant NSS or numeric-ID resolution -> pre-setup `try_check_capabilities()` and operation-specific capability gate -> TLS identity preload plus privileged UDP/TUN/routing initialization -> blocking-thread `drop_privileges_resolved()` clears supplementary groups, transitions all real/effective/saved IDs, and clears ambient/effective/permitted/inheritable capability sets -> `verify_process_privilege_state()` validates every Linux thread has the target IDs, empty groups, zero capability sets, and `PR_SET_NO_NEW_PRIVS` -> process-wide memory locking is applied after setxid while the TLS key and MemoryPool allocations are individually locked before it. The current proof omits filesystem UID/GID fields, the public identity type is trusted at the final drop boundary, and the non-Unix `CurrentIds` configuration fails the Windows core check; TODO-849 and TODO-850 own those gaps. The isolated `qf-privilege-probe` alone performs the destructive root-regain attempt. `quicfuscate capabilities --json` exposes the same identity, capability, target, and readiness state; saved UID/GID fields are optional and remain null on Unix targets without a reliable query instead of copying effective IDs; systemd root-starts with only bounded setup capabilities and owns confinement plus post-drop host cleanup.
- Memory-pool growth wiring: `src/engine/config.rs` bounds automatic engine pools to 16-64 MiB; `MemoryPool` derives a per-instance hard ceiling of at least its explicit initial capacity and otherwise 64 MiB by effective block size. The global auto-tuner defaults to 1,024 blocks and cannot bypass that instance ceiling. Its stop flag, wakeup, and join handle are owned by `MemoryPool::shutdown_auto_tuner()`. Per-thread caching is actual TLS and keyed by pool identity, but TLS lifetime, capacity shrink, same-sized foreign-block rejection, ephemeral returns, and exact counter invariants remain open under TODO-827. The separate `UnsafeMemoryPool` cache and raw-pointer contract remain open under TODO-826; its copies are not production proof.
- Graceful shutdown wiring (TODO-448): `ServerRuntime` owns the shared `GracefulShutdown` lifecycle consumed by the UDP loop and admin handlers. SIGINT/SIGTERM/admin drain stop `AcceptLoop` admission, wait for established clients or `[engine] shutdown_timeout_ms`, flush final QUIC close packets, then stop control-plane services and host resources. SIGHUP uses the canonical runtime reload path. `implementations/server/systemd.rs` emits READY, RELOADING, STOPPING, STATUS, and watchdog notifications.
- Control plane wiring: CLI + engine + admin surfaces + metrics/telemetry endpoints. Embedded Engine server startup constructs `ServerRuntime` and its Tokio-bound socket inside the dedicated runtime thread, then transfers shutdown and metrics handles through a bounded readiness acknowledgement before reporting `Running`.
- UI wiring: `apps/svelte-desktop` (Svelte 5 desktop frontend) and `apps/svelte-admin` (SvelteKit/Svelte 5 admin frontend) are the active UI surfaces. The retained native desktop host/runtime bridge lives in `apps/tauri/src-tauri`. Shared UI primitives live in `packages/ui` (Svelte components) and `packages/theme` (CSS).
- Automation wiring: scripts in `scripts/` orchestrate build/test/benchmark/audit tasks; `scripts/tests/suites/test-qkey-registry-encryption.sh` owns the process-real encrypted-registry migration, rejection, rotation, secrecy, and cleanup contract; `scripts/tests/suites/test-linux-installer.sh` owns signature-checked AlmaLinux 9 build plus AlmaLinux 9/Debian 12 `systemd-nspawn` install, preflight, identity, permission, systemd, rerun, failure/recovery, exact-artifact, and residue proof; `scripts/tests/tun-provisioning-negative-netns.sh` owns the fail-closed Linux TUN negative/retry/rollback/residue contract and `.github/workflows/ci.yml` runs it with root on the native Linux runner; GitHub workflows own cross-platform core checks, the same native installer contract, and signed release packaging; generated local artifact directories are intentionally outside this map.
- Native traffic-analysis proof: `scripts/tests/tun-e2e-traffic-analysis-netns.sh` supplies exact baseline policy files to `scripts/tests/tun-e2e-netns.sh` -> immediate-mode buffered `tcpdump` capture with an exact measured window and post-window libpcap drain -> outbound cadence/size plus reverse control analysis -> cost-warning, CPU, bandwidth, binary-hash, process-set, and namespace-residue gates. `.github/workflows/ci.yml` runs the same proof against its freshly built Linux release artifact.
- Native fingerprint proof: `scripts/tests/fingerprint-runtime-proof-netns.sh` -> `scripts/tests/tun-e2e-netns.sh` with explicit server `--profile`/`--os` forwarding -> `fingerprint-runtime-proof-hook.sh` captures both TUN directions, runs p0f 3.09b and Nmap 7.94SVN, and invokes `utils/verify-fingerprint-pcap.py` -> exact profile/checksum/passthrough/downlink-scope evidence. The active vector manifest covers client-originated SYN responses, closed-port TCP reset, ICMP echo, closed-UDP ICMP port unreachable, sequence fields, checksum, and IP-ID behavior. Omega run `evidence-fingerprint-20260731i` remains the TODO-543 baseline against binary SHA-256 `37c4ac6f7c79cd53e3e6f327dc9fcbff780b3d072eee73818110843b42d51dfa`; completed TODO-765 retains the five-profile response-contract matrix at `/home/ubuntu/SOFTWARE/QuicFuscate/candidate-todo765-20260801c/evidence-todo765-20260801c` against binary SHA-256 `f8c8f1e811edd4e9a47f54521c4a893e309e41fb42c02bdb6654d93189ff5b59`. The matrix proves 82 client and 82 server response packets per profile, all required vectors/checksums, disabled byte-exact passthrough, and enabled non-SYN transport plus consecutive IP-ID evidence. p0f passes all five primary signatures; Nmap reports no exact OS match for enabled profiles, so no exact active classifier result is claimed.

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

### StealthRuntimeOwner (src/stealth/parts/runtime.rs, TODO-570)
One owner is created per client/server runtime generation, including `main_parts/runtime.rs::run_client`, and passed into production `StealthManager` and `QuicFuscateConnection` construction.
- Shared `RealityConfig` and `CoverHandshakeCache`: at most one refresh worker per owner, never one worker per connection.
- `watch` cancellation plus named `JoinHandle` registry: Reality refresh, timer-driven proxy cleanup, and next-connection profile rotation are explicitly joined with a bounded shutdown timeout.
- `RealityProxy` registration uses weak references, so proxy sessions do not keep an old runtime generation alive after connection teardown.
- Compatibility constructors without an owner create no background worker and preserve direct-test/legacy behavior.
- `StealthRuntimeOwner::start()` and `spawn_owned()` require an active Tokio runtime and return an explicit error otherwise; `StealthManager::new()` remains a non-spawning compatibility constructor.
- TLS profile jitter is represented as a provider-local readiness deadline; `RustlsProviderImpl::flush_handshake_io()` gates CRYPTO emission without synchronous executor blocking.

### Stealth Stack Coherence Wave (2026-06-30)
- Engine client uses `stealth.use_utls` and no longer hardcodes `use_utls=false`.
- Connection persona is frozen for the session: Browser/OS/uTLS/QPACK/header identity does not mutate mid-connection.
- Domain fronting defaults off in Performance, Intelligent clean path, and Stealth; Anti-DPI keeps the aggressive built-in list.
- Post-handshake application cover uses H3-framed cover requests, Server Push, and WebTransport only. QUIC Cover PING stays transport-owned; no raw fixed-stream payload or configuration-dependent H3 ignore path exists.
- Server Push cover uses bounded seed-varied resource plans.
- WebTransport cover is H3 application cover only, active for Anti-DPI or Intelligent level 2, never a competing VPN carrier.
- Core H3/MASQUE is the sole active production VPN/TUN data plane; the retired `stealth::MasqueManager`, stealth-local DoH resolver, and obsolete integration test are preserved under `archive/` and are not compiled.

### Linux Production E2E Evidence (2026-06-30)
- `broderick` release build: `cargo build --release --bin quicfuscate` passes on Linux.
- All TUN/netns E2E scripts acquire a shared `flock` guard (`/tmp/quicfuscate-tun-e2e.lock` by default) because they intentionally reuse namespace and veth names. The base and specialized FEC/loss harnesses capture and reap only exact child PIDs, track namespace/link/qdisc ownership, refuse pre-existing product processes or colliding network resources, and keep generated certificates, QKey stores, and logs inside guarded per-run runtime directories. The CUBIC harness keeps its owned admin socket at a checked short `/tmp` path so a caller-selected evidence directory cannot exceed the Unix-domain socket limit, refuses existing artifact paths and colliding topology, and returns explicitly from a clean `set -e` preflight. `scripts/tests/test-specialized-tun-e2e-ownership.sh` owns the exit/signal/keep-on-failure and unrelated-resource survival regression. TODO-555 closed lifecycle ownership, TODO-558 closed FEC policy and observability, and TODO-557 closed specialized quantitative acceptance.
- `scripts/tests/tun-e2e-netns.sh`: real server/client netns TUN over authenticated H3/MASQUE, pre-open durable routing recovery, durable routing-record publication, SIGKILL/restart stale recovery, 5/5 ping, 0% tunnel loss, graceful record removal, exit-scoped owned-PID cleanup, and fail-closed pre-existing-runtime isolation.
- `scripts/tests/fingerprint-runtime-proof-netns.sh`: exact-artifact five-profile privileged capture matrix with non-overwriting evidence paths, explicit `--profile`/`--os` forwarding, p0f/Nmap recording, protected-process identity, and namespace-residue gates.
- `scripts/tests/fingerprint-runtime-proof-hook.sh` plus `scripts/tests/utils/verify-fingerprint-pcap.py`: synchronous capture/classifier hook and pure pcap/checksum/vector verifier. Client-to-server decoded packets, including active-probe responses, receive one frozen IPv4-layer normalization pass with SYN-only TCP rewriting; server-generated control ICMP uses the frozen profile TTL or hop limit; ordinary server downlink SYN-ACKs, sealed QUIC, and unrelated raw-IP downlink remain passthrough. The verifier records the active response vectors without equating vector coverage with an exact Nmap OS match.
- `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh`: isolated three-client IPv4/IPv6 routing, source ownership, spoof rejection, fan-out, PTB, TTL expiry, NAT, throughput, and explicit client-to-client policy proof. It uses an owned checked short admin socket, generates a per-run leaf certificate when no explicit certificate pair is supplied, records the exact binary SHA-256 in retained evidence, and explicitly deletes every host veth after namespace teardown. It now uses a paced IPv6 TCP probe that fails closed on sender/receiver byte or SHA-256 mismatch and measures receiver time, replacing the unstable `iperf3` process. Earlier PMTU comparisons, including exact ARM64 binary `ee0243f6…61e95e88` with a 4.81% result, did not measure 1500-byte TUN payloads because both phases hard-coded the TUN ceiling to 1280 and route setup reset it. The harness now propagates the phase PMTU ceiling to server and clients, preserves client-side confirmed-MTU synchronization, and keeps the 15% gate. It fetches metrics after both TCP phases and fails unless pending-depth gauges plus both TUN/MASQUE event-counter families are present and zero. The TTL assertion exercises the server-generated IPv4 Time Exceeded contract; its native closure is recorded under TODO-806, while the separate backpressure-quiescence failure remains with the queue/runtime backlog. `core::next_send_deadline()` includes outer pacing for generic I/O-driver polling. Exact final-source ARM64 proof closes TODO-559 with 6.939/11.326 Mbit/s medians, 63.21% PMTU gain, receiver-valid black-hole recovery, bounded CPU/RSS/latency/allocations, zero queue or rate-limit events, and clean teardown.
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
- `scripts/tests/tun-e2e-dns-leak-netns.sh`: explicit TUN DNS and a normal OS-resolver query return responses through a private resolver mount, client DNS restoration is logged after shutdown, and tcpdump observes `raw_port_53_packets=0` on the client underlay.
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
- `record_probe()`: records epoch-millisecond probe buckets, checks the ladder thresholds (≥3 in 60s → L1, then ≥8 in 120s → L2), aggregates same-millisecond probes, and enforces a maximum of 120,001 retained timestamp buckets; a fresh level-0 state cannot jump directly to L2.
- `check_de_escalation()`: drops at most one level per configurable quiet period (default 300s), measured from the latest probe or level change.
- `on_probe_detected()` uses `EscalationState` instead of immediate binary escalation.
- `sync_intelligent_level()` calls `check_de_escalation()` on each tick.
- Config knobs: `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (3), `_L2` (8),
  `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (300), `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (50).
- `on_probe_detected` only escalates when `config.dynamic_enabled` is true (Intelligent mode).
- `probe_timestamps` is a bounded `ProbeHistory` with independent 60-/120-second counters, same-millisecond aggregation, and a hard maximum of 120,001 millisecond buckets; it remains separate from the detector history (TODO-644).

### IntelligentStealthInputs.level_hint (src/stealth/parts/manager.rs)
Brain and `EscalationState` publish separate connection-local levels through `IntelligentLevelHints`; consumers use the maximum and pass it as `level_hint: u8` (0/1/2) to `derive_intelligent_runtime_policy`.
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
- DomainFrontingManager: strict serial round-robin, concurrent coverage,
  explicit random fallback, and ultra_stealth() smoke
- Http3Masquerade: generate_headers() pseudo-headers, browser-profile UA divergence
- FingerprintRotation (via StealthManager): Fixed mode stable, All-mode no-panic guard path
- ActiveProbeDetector: GFW_TLS_Probe detection; legacy DPI_QUIC_Scan response selector retained without a matching pattern; benign-ignored; bounded `VecDeque<Instant>` with `max(threshold, 1)` FIFO history limit and 60-second retention. `EscalationState` owns a separate bounded 120-second millisecond-bucket history (TODO-808)
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
7. Compression and H3 receive-buffer path: `src/transport/h3.rs` payload policy -> `src/compress.rs` direct zstd `compress_to_buffer` into `MemoryPool` / body-pool blocks -> H3 compressed body bytes; dictionary decompression requires the supplied pool block to cover the declared original length and rejects mismatches; one caller-owned 64 KiB STREAM receive buffer is reused across polls, while the one-per-connection MASQUE receive buffer follows `Connection::max_recv_udp_payload_size()`
8. Probe mitigation path: `src/stealth/` detector -> `src/reality.rs` fallback proxy -> upstream targets
9. Engine embedding path: `src/engine/engine.rs` -> complete `EngineConfig::validate()` -> `src/implementations/{client,server}/` runtimes; client/server pools, FEC, stealth, and transport policies use the same validated projections.
10. Admin control plane path: `src/implementations/server/admin_http.rs` -> `qkey_registry.rs` -> `qkey_registry_storage.rs` durable fail-closed commit -> live server policy enforcement
11. Desktop frontend path: `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts` -> Tauri invoke -> engine/control runtime
12. 0-RTT anti-replay path: `src/transport/anti_replay.rs` (`StrikeRegister` with SHA-256 fingerprints, Bloom fast-negative, FIFO ring eviction) -> `src/transport/config.rs` (attached at server startup) -> `src/transport/connection/` `recv()` gate -> silent discard on replay
13. Desktop native host path: `apps/tauri/src-tauri/src/main.rs` -> Tauri commands -> engine/control runtime
14. Web-admin path: `apps/svelte-admin/src/lib/api.ts` -> Vite dev proxy (`/api` -> `127.0.0.1:9000`) -> admin HTTP endpoints -> server runtime state
15. Build publish path: `scripts/build/build-web-admin.sh` -> `assets/web-admin/` consumed by `--admin-web-root`
16. Shared packages path: `packages/ui` (Svelte 5 components) + `packages/theme` (CSS tokens/glass/layout) -> consumed by both Svelte apps
17. GitHub CI app backend gate: `.github/workflows/ci.yml` `app-backend-checks` -> `apps/svelte-desktop` build output -> `apps/tauri/src-tauri` `cargo check` / `cargo test`
18. NAT traversal path discovery: `src/engine/config.rs` `[nat_traversal]` -> `src/transport/config.rs` `NatTraversalConfig` -> `src/transport/nat.rs` `NatPathDiscovery` -> path-management consumers when policy permits discovery.
19. Audit logging path: `src/main_parts/late_tests_and_mlock.rs` pre-resolves the privilege target plus `[audit]` queue/segment/flush bounds -> `--audit-log <path>` -> `src/audit/mod.rs::init_audit_log_with_options()` creates the global owner and mode-`0o600` active file -> typed producer calls enqueue without hashing or file I/O -> bounded `qf-audit-writer` assigns sequence/timestamp, writes schema-v2 NDJSON, rotates immutable sequence-ranged segments, atomically advances the retained checkpoint, and exposes dropped/persistence counters -> shutdown barrier flushes and joins -> `src/main.rs` `verify-audit-log <path>` validates ordered retained continuity, restart state, and checkpoint tail -> `src/bin/qf-audit-probe.rs` proves concurrent durable throughput and restart verification. TODO-675 retains synchronous durability/cancellation and failure-state gaps; TODO-671 retains direct public reopen mode; TODO-726, TODO-727, TODO-728, TODO-813, TODO-814, and TODO-815 retain admission, read, path, bound, payload, and shutdown-order gaps.
20. Memory locking path: `src/engine/config.rs` `[security] lock_memory/lock_blocks` -> standalone `src/main.rs::run_server()` `RLIMIT_MEMLOCK` gate -> unlimited `mlockall(MCL_CURRENT | MCL_FUTURE)` or finite-limit `MCL_CURRENT` -> `src/optimize/parts/memory_pool.rs` `MemoryPool::set_lock_blocks()` -> successful `mlock_block()` registration in `BlockLockLedger` -> `MemoryPool::free()`, queue shrink, pool `Drop`, and TLS-cache `Drop` zeroization plus `munlock()` before allocation release. The process caller currently continues after lock failure and the embedded engine does not yet apply the same settings, tracked in TODO-852 and TODO-851. A fresh native proof of the post-change source is blocked by the unavailable Omega SSH path; qftls key ownership remains TODO-643.
21. Windows core CI gate: `.github/workflows/ci.yml` `windows-core-checks` -> two-job native `windows-latest` `tun-windows,rust-tests` check/test compile -> `scripts/utils/provision-wintun.ps1` verified DLL beside the test executable -> ordinary unit tests -> serial ignored privileged dual-stack adapter, bidirectional UDP, blocked-read close, repeated-lifecycle, WFP packet-outcome, process-exit retention, and stale-cleanup tests -> exact WFP-object/adapter/firewall residue inspection plus evidence upload -> strict library Clippy. Run `30508948149`, job `90764941801` proves the complete native lifecycle; manual workflow runs `30535603045` and `30536002374` prove authenticated dual-stack Wintun/WFP traffic twice against one unchanged Omega server process.
22. Windows signed release path: `scripts/audits/verify-release-version.sh` -> `.github/workflows/release.yml` `release-version-contract` -> verified Wintun provisioner -> `apps/tauri/src-tauri/tauri.windows.conf.json` resource beside the Windows executable -> `desktop-windows` Tauri MSI build -> `.msi` plus `.msi.sig` verification -> administrative MSI extraction and exact Wintun DLL hash verification -> required `publish-release` dependency -> `latest.json` `windows-x86_64` entry. Release run `30612996058`, job `91099832490`, publishes `QuicFuscate_0.4.4_x64_en-US.msi` with SHA-256 `eba3a9b59b05474e887ed0491f66998523573cae675a44c4469394ee4a9c025f` plus its signature and Wintun provenance.
23. Reliable tunnel fallback path: `src/core.rs` `QFT1` packet framing -> `src/transport/connection/` immutable STREAM ledger -> confirmed-PMTU packetization -> centralized `OutboundPacer` -> ACK/loss/PTO retirement and requeue -> byte-exact PMTU fallback splitting -> peer `core.rs` bounded packet reassembly.
24. QUIC version negotiation path: `src/engine/config.rs` or `src/main.rs` ordered v2/v1 policy -> `src/transport/version.rs` selectable versions and grease -> `src/transport/packet.rs` stateless server VN -> `src/transport/connection/` strict CID/original-version gate and single restart -> `src/qftls.rs` version-matched rustls handshake plus authenticated Version Information downgrade validation.
25. Base Linux TUN proof lifecycle: `scripts/tests/tun-e2e-netns.sh` shared `flock` -> fail-closed pre-existing process/namespace check -> pre-open stale routing recovery -> exact server PID and durable routing-record capture -> SIGKILL/restart stale recovery -> TLS/H3/MASQUE TUN assertions -> graceful shutdown record removal -> exact child reap and owned namespace teardown; `scripts/tests/audits/audit-runtime-guardrails.sh` rejects global product-name process reapers on this path.
26. FEC operator-policy and observability path: `src/main.rs` / `src/implementations/server/mod.rs` engine `FecMode` -> `src/fec/` `FecConfig::apply_engine_mode()` -> independent `FecControlPolicy::{Off, Auto}` with Zero bootstrap -> `src/transport/connection/` independent recovery send/loss callback counts, transport-classified ACK counts, and congestion-controller smoothed loss -> `src/core.rs` typed `FecCallbackFeedback` transfer that admits only ACK/loss-bearing feedback to `AdaptiveFec::report_transport_loss()` -> recent-window-confirmed adaptive target or 32-clean-ACK Zero proof -> committed codec state -> actual wire send and `src/fec/wire.rs` accepted receive/recovery reports -> connection-local `FecTelemetrySnapshot` plus explicit process aggregates in `src/optimize/telemetry.rs` -> read-only server metric projections in `src/implementations/server/metrics.rs`. Active Engine commands follow `EngineCommand::SetFecMode` -> typed `FecPolicyCommandResult` -> existing `ClientConnection` mutex -> `QuicFuscateConnection::set_fec_control_policy()` -> queued-source preservation/repair retirement -> fresh Zero controller and wire receive state; accepted policy persists into `ClientRuntime` reconnect configuration.
27. Client TUN uplink pressure and fault path: `src/main.rs` TUN reader channel -> event-loop drain with `tun_backpressure_frame` retry ownership -> `src/core.rs::send_tunnel_packet()` -> `src/transport/h3.rs::send_masque_datagram()` -> QUIC DATAGRAM queue (`ConnectionError::DgramQueueFull` backpressure) or oversized-packet framed H3 carrier -> socket flush and peer TUN delivery. Packets are not consumed from the TUN reader channel until the carrier accepts them; channel disconnect, reader termination, and non-retryable transport errors become typed data-plane faults and wake the owner.
28. Server TUN downlink pressure, fairness, and fault path: `src/implementations/server/mod.rs` TUN reader or authenticated client fan-out -> shared `ClientFanoutQueueState` admission (256 entries, 384 KiB, 32 entries/64 KiB per source, 64-item drain batch) -> direct admission and transport enqueue when shared shaping is disabled and that session has no backlog, otherwise bounded `LiveServerState::pending_tun_downlinks` (256 packets, 384 KiB, 32 per session, 5-second expiry) -> optional shared token bucket reserves aggregate service capacity -> weighted byte-deficit round robin preserves per-session FIFO and proportional saturated shares -> front-packet-derived visit budget returns immediately when every active session is deferred -> `SessionManager::check_bandwidth()` performs one downlink admission/accounting decision -> `send_masque_downlink()` -> path-aware retry or socket flush. Shared or per-session rate denials stay bounded and retryable; already admitted transport retries do not double-charge the session; failed transport admission refunds the shared reservation; daily/monthly quota denials are terminal for the packet; TUN reader/channel/write/send faults stop the owner and reach server readiness/health; queue, scheduler, bandwidth, audit, and exact terminal-drop metrics retain the outcome.
29. Server-generated MASQUE response pressure path: ICMP routing responses and asynchronous DNS interception -> `core::MasqueDownlinkQueue` (128 packets, 192 KiB per connection) -> `drain_masque_downlink_responses()` -> connection-owned retry slot on `ConnectionError::DgramQueueFull` -> subsequent housekeeping or packet pass; Prometheus telemetry reports retry, packet-capacity, byte-capacity, terminal-send, and shutdown outcomes.
30. Standalone dual-stack TCP diagnostic path: `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh` receiver trial boundary -> persisted start/end window plus client exit status -> `scripts/tests/utils/summarize-throughput-boundaries.py` observes encrypted client-to-server and server-to-client UDP at `qf523h1` and `qf523hs` -> per-window counts and gaps, including explicit zero return traffic. `scripts/tests/utils/udp-socket-evidence.py` snapshots `/proc/net/udp` before/after each trial and fails on a nonzero drop delta: server socket selected by local port 4433, client socket selected by remote port 4433 with local and remote endpoint continuity required.
    Exact ARM64 harness `57a2eed` has a clean full-run proof for all four observed boundaries and zero server socket drops. Its retained clean opt-in timeout also has equal forward counts of 7,086 and equal reverse counts of 6,072 at both host-veth boundaries with a zero server socket-drop delta. Exact ARM64 source `681705d` adds 18 zero-delta client socket summaries across all completed clean trials; child one passed the full gate, while children two and three later failed only in their deliberate black-hole recovery. On a future heartbeat failure, the harness-specific `QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS=1` path records socket receipt, outer Core receive result, and transport `last_activity` advancement without changing ordinary runtime behavior. Exact source `a3ced4d` reproduced a clean opt-in TCP timeout before that heartbeat path, after a 12-packet application-space persistent-congestion run; matching encrypted boundary counts and zero client/server socket drops remain retained. Exact source `36a97d0` shows that all three reproduced client decisions had one triggering ACK, twelve declared losses, and a terminal time-threshold loss, with retained runs of 133, 219, and 107 ms. The next diagnostic boundary is ACK progression and time-threshold loss provenance before its transport-side decision.

31. Telemetry resource-sampling path: every connection's one-second maintenance -> `src/optimize/telemetry.rs::refresh_resource_metrics_if_due()` -> disabled fast return or process-wide lock-free one-second admission -> current-PID memory-only `sysinfo` refresh plus global-pool gauges. Explicit shutdown `flush()` remains unthrottled. Feature-gated orchestrator sampling returns before system access when its runtime owner is absent; otherwise the connection-retained current-PID sampler refreshes CPU, process memory, and host RAM -> `DeepIntegrationOrchestrator`.
32. Production logging path: CLI `--config` -> pre-runtime `EngineConfig::from_file()` plus `validate()` -> `LoggingConfig::effective()` -> one `logging::init()` global facade owner -> bounded `qf-log-writer` queue -> rotating file, stderr, RFC 5424 UDP, and admin-buffer sinks -> acknowledged `FlushGuard` shutdown barrier; persisted admin modes adjust the facade filter only and never replace sink ownership. `qf-logging-probe` currently calls `logging::init()` twice and is audited under TODO-674; failed global logger installation sends worker shutdown without a join boundary under TODO-812.
33. Retained-secret erasure path: server or desktop token input -> `QKeyToken`/`SecretBytes` owner -> QKey serialization or zeroizing decoded JSON -> zeroizing binary decode -> SHA-256 verifier only in `QKeyRegistry`; client import -> typed config/profile -> live connection -> drop wipe. TLS installation/cache -> zeroizing private-key read, copied 1-RTT secret, ticket, and master owner -> replacement/eviction/drop wipe; AES header protection and AEGIS wrapper key/IV plus local derived state wipe before their owner is released. Test-only observers inspect the zeroed live ranges before clear/deallocation.
34. QKey auth abuse-policy path: validated `QUICFUSCATE_AUTH_*` environment -> `ServerConfig.auth_policy` -> `LiveServerState.auth_rate_limiter` -> pre-registry Initial admission -> pending `QKeyAuthState` attempt ID -> established QUIC/TLS connection starts the one-shot encrypted-H3 bearer deadline -> success/failure, timeout, connection close, or internal abandonment -> exactly-once completion -> backoff/block state, metrics, audit, and bounded housekeeping prune.
35. QKey auth process-proof path: `scripts/tests/suites/test-qkey-auth-policy.sh` refuses existing output and product processes -> validates fail-closed pre-resource startup -> creates an isolated CA/leaf/QKey state -> exercises CA-verified H3 auth, exact backoff/block/expiry/reset, secondary-loopback isolation, and idle prune -> runs exactly 100 real Initial attempts -> verifies metric/audit/resource/secret/UI/process contracts -> retains only caller-owned evidence.
36. DDoS admission process-proof path: `scripts/tests/suites/test-ddos-admission.sh` refuses existing evidence -> validates pinned real MaxMind country and city databases through `src/bin/qf-ddos-policy-probe.rs` -> rejects missing, permission-denied, corrupt, invalid-country, and valid non-country activation cases with typed errors -> starts the server with GeoIP enabled -> asserts exact active=1, disabled=0, and failed=0 Prometheus state plus health and Unix-admin truth -> restarts the server with the same verified database and reasserts all three surfaces -> serves a locally controlled certificate-verified HTTPS feed through the bounded custom-CA path -> proves atomic cache restart and failed-refresh last-known-good preservation -> completes a pre-activation no-Retry handshake and continuously exchanges ack-eliciting PING/ACK traffic on that connection -> drives a low baseline plus 800-packet sustained Initial spike -> observes one activation while the established client remains live -> completes one real Retry-protected QKey handshake -> observes one clear -> requires the original client to remain established with positive bidirectional packet counts and no additional Retry -> enforces CPU/RSS, secret, protected-UI, and process-residue bounds.
37. Per-session bandwidth control path: authenticated HTTP `GET|POST /api/clients/{session|remote|assigned-ip}/bandwidth` and `POST /api/clients/{id}/quota/reset` -> `ServerAdminCore` -> `SessionManager` live policy/quota owner. QKey issuance accepts the same complete `BandwidthPolicy`; persisted QKey policy overrides global defaults only after bearer authentication, while later admin mutation overrides the live session without resetting usage.
38. Traffic-analysis policy and timer path: standalone TOML baseline plus QKey and Intelligent ceilings -> validated `TrafficAnalysisPolicy` -> pending QKey request stored before authentication -> encrypted bearer success authorizes the bounded effective policy -> one `TrafficAnalysisScheduler` deadline participates in the Core wakeup minimum -> at most one due slot -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted path-MTU-bounded chaff emission -> idle ramp, reactivation, or terminal cancellation. FullPadding costs use the maximum UDP payload; ConstantRate costs and packet sizes use the configured target capped by that payload.
39. Network-stack fingerprint path: server config or `QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION` plus `QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE` -> one frozen `StealthConfig` snapshot -> TLS/H3 persona and `PacketNormalizer` created together in `QuicFuscateConnection::new_server()` -> decoded MASQUE DATAGRAM, raw capsule, compressed capsule, or `QFT1` framed-H3 packet -> one allocation-free IPv4 and SYN-only TCP normalization pass -> PMTUD-safe ICMP disposition -> authenticated server TUN/fanout callback. Server-generated routing, MTU, and time-exceeded ICMP uses the same frozen profile TTL or hop limit. Client connections, Off mode, sealed QUIC datagrams, fragments, and ordinary server-to-client downlink retain their explicit passthrough boundaries. The active hook records five-profile response vectors and fails closed on missing direction, checksums, IP-ID progression, or transport-byte evidence; it does not imply an exact Nmap classifier match.

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
|-- archive
|   |-- stealth
|   |   |-- doh.rs
|   |   `-- masque_manager.rs
|   `-- tests
|       `-- masque_runtime_integration.rs
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
|   |   |-- profiling-baseline.sh
|   |   |-- profiling-common.sh
|   |   |-- profiling-tun-mode.sh
|   |   |-- profiling-zc.sh
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
|   |   |   |-- verify-audit-completeness.sh
|   |   |   |-- test-verify-audit-completeness.sh
|   |   |   `-- audit-runtime-guardrails.sh
|   |   |-- build
|   |   |   |-- build-check.sh
|   |   |   |-- build-clippy-matrix.sh
|   |   |   `-- build-env-doctor.sh
|   |   |-- fast
|   |   |   |-- test-dynamic-discovery-fail-closed.sh
|   |   |   |-- test-fast-crypto.sh
|   |   |   |-- test-fast-fec-fail-closed.sh
|   |   |   |-- test-fast-fec.sh
|   |   |   |-- test-benchmark-fast-mode-contract.sh
|   |   |   |-- test-harness-argument-safety.sh
|   |   |   |-- test-profiling-evidence-contract.sh
|   |   |   `-- test-shared-artifact-writer-contract.sh
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
    |   |   |-- dns_runtime.rs
    |   |   |-- integration.rs
    |   |   |-- io_driver.rs
    |   |   |-- killswitch.rs
    |   |   |-- mod.rs
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
    |       |-- domain_fronting.rs
    |       |-- escalation.rs
    |       |-- flow_shaping.rs
    |       |-- http3_masquerade.rs
    |       |-- manager.rs
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
- `Ipv6Pool` (`src/implementations/server/ip_pool.rs`): Allocate/release IPv6 addresses from ULA range (default fd00::2-fd00::fe) through a forward cursor and release FIFO; capacity counters use `u128`, with the full `2^128` range explicitly saturated at `u128::MAX`.
- `Session::new_dual_stack()` (`src/implementations/server/session.rs`): Creates session with both IPv4 and IPv6 client addresses.
- `RoutingManager::new_dual_stack()` (`src/implementations/server/routing.rs`): Configures dual-stack Linux NAT and forwarding (ip6tables or nftables) for the shipped server runtime. Linux writes a 0600 atomic ownership record under `/run/quicfuscate/routing/` before host mutation, binds it to the TUN ifindex and process boot/PID/start-time identity, and recovers only exact recorded state when no active owner exists. macOS pf and Windows NetNat remain pure, non-advertised generators; mutating server setup, stale cleanup, and teardown return `UnsupportedPlatform` until native ownership and proof exist.
- `TunConfig.ip6` / `TunConfig.prefix6` (`src/interface.rs`): IPv6 TUN interface address fields, wired to standalone CLI flags `--tun-ip6` / `--tun-prefix6` and consumed by the native Linux/macOS/Wintun backends. `InterfaceConfig::client_tunnel_addresses()` now provides the canonical IPv4-only, IPv6-only, or dual-stack model for generic `ClientRuntime` projection, while the public compatibility `ClientBackend` remains single-family and rejects canonical IPv6 fields. TODO-866 owns the still-missing server-assignment control plane.

### Wiring
- `SharedServerDomain` (`src/implementations/server/mod.rs`):
  - Holds `ipv6_pool: Option<Arc<Mutex<Ipv6Pool>>>` created from `ServerConfig.ipv6_pool_start/end`.
  - `accept()` → `accept_session_in_domain()` allocates from both IPv4 and IPv6 pools, creates dual-stack session.
  - `remove()` / `reap_expired()` → release IPv6 address back to pool.
- `ServerHostResources::start()` (`src/implementations/server/mod.rs`, Linux runtime path):
  - Calls `RoutingManager::new_dual_stack()` when `server_config.ipv6_server_ip.is_some()`.
  - `RoutingManager::setup()` records the current Linux address, link, and forwarding state before mutation, then assigns and verifies exact TUN interface addresses/prefixes and link-up state before the selected firewall backend is admitted.
  - Both embedded and standalone Linux startup call `RoutingManager::cleanup_stale()` before opening a new TUN; unnamed standalone startup enumerates persisted state records first, so stale recovery cannot be confused with a newly allocated interface. The manager refuses an active or boot-mismatched durable owner, then validates and recovers the record before removing stale firewall identities; a failed recovery keeps the record for retry and never guesses at unrelated host state.
  - Non-Linux server TUN startup is rejected by `open_server_tun()` before creating host state; `RoutingManager` also rejects non-Linux mutating methods, while internal macOS/Windows rule generators are not shipped server capabilities.
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
- Client DNS runtime (`src/implementations/client/dns_runtime.rs`): `ClientDnsRuntime` binds the client DoH proxy on localhost UDP/53, configures the active platform resolver with the live TUN interface name, owns IPv4 plus best-effort IPv6 listeners, and restores resolver state before connection/TUN teardown. A restore failure retains the runtime for retry and prevents the Engine from reporting `Stopped` or disabling its kill-switch policy.
- macOS: PF policy is available only when the main ruleset exposes the QuicFuscate anchor. Client activation parses an actual `anchor` statement, returns an actionable error when the reference is absent, and rolls back a just-loaded anchor before reporting activation failure; `enable()` clears state after a successful bounded rollback and retains fail-closed ownership only when rollback itself fails. Client cleanup touches only `com.quicfuscate.killswitch` and never disables shared PF. Server routing rejects macOS before host mutation and retains only pure rule generation. `scripts/tests/macos-pf-anchor-proof.sh` owns the read-only privileged main-ruleset/anchor/block-rule check. TODO-548 owns managed installation and privileged proof.
- Windows: `src/implementations/client/killswitch/windows.rs` owns one fixed persistent WFP provider/sublayer plus eight fixed filter slots. Each state replacement transaction deletes and recreates only those identities, then installs higher-weight loopback, exact endpoint, and optional live Wintun-LUID permits before a lower-weight catch-all block at IPv4/IPv6 outbound transport layers. Those layers also classify third-party transports and raw packets without widening the endpoint beyond its UDP address/port tuple. Engine/session/transaction guards check native statuses and preserve the previous committed policy on replacement failure, but TODO-683 found that failed inner engine close and transaction abort ownership is not retryable; TODO-847 owns that gap. Explicit disable and stale cleanup delete the complete identity set plus the two exact legacy `netsh` rules. The legacy `WindowsPlatform` adapter path still fails before host mutation. `src/interface/wintun.rs` remains the only valid native data-plane owner and its WFP test observes the adapter ring instead of treating socket acceptance as packet delivery. Run `30508948149`, job `90764941801` is historical native evidence for Wintun lifecycle, all WFP packet-policy states, process-exit retention, stale cleanup, and zero residue; release run `30533862566` is historical evidence for the signed packaged boundary; Windows-Omega runs `30535603045` and `30536002374` are historical evidence for the authenticated connected-policy data plane and exact cleanup. They do not cover the new injected-failure cases.

### Automatic Loss Ownership
- `Connection::last_activity_elapsed()` (`src/transport/connection/`): Exposes time since the last inbound datagram.
- `ClientRuntime::start_loss_watchdog()` (`src/implementations/client/mod.rs`): Owns one 50 ms remote-close/inactivity loop, records the first `DisconnectReason`, stops the I/O driver, and invokes the loss transition callback once.
- `QuicFuscateEngine::connect()` (`src/engine/engine.rs`): Applies endpoint-only policy before handshake, connected policy after handshake, and installs the runtime watchdog. Callback and event snapshots avoid holding callback locks during user code.
- TUN runtime ownership: `TunInterface::reader_loop_with_shutdown()` owns the cooperative atomic stop and Unix `poll(2)` wait; client and standalone server readers publish cooperative shutdown before dropping their bounded receiver, wake the native Wintun event where required, join their owned `JoinHandle`, and release the TUN descriptor after the thread exits. Unexpected reader termination, channel disconnect, TUN write, and transport send/receive failures publish typed data-plane faults; `Notify` wakes both select loops for queued frames or faults, while adaptive housekeeping uses a 5 ms active floor and 250 ms idle ceiling.
- Generic TUN result ownership remains an open boundary: external/native read counts are not yet uniformly checked against pooled block lengths, and short writes are not yet uniformly rejected or completed at every client/server caller. TODO-844 owns the shared contract; TODO-845 owns Linux/macOS raw progress and length validation.
- `run_client()` (`src/main.rs`): Owns the standalone select-loop equivalent and distinguishes clean signal shutdown from remote close, socket failure, and heartbeat timeout. Its adaptive housekeeping owner queues an ack-eliciting QUIC keepalive every third of a nonzero heartbeat window so a responsive idle peer advances inbound activity before the fail-closed deadline.
- `QuicFuscateEngine::check_heartbeat()`: Compatibility query only; it never drives a duplicate watchdog.
- `scripts/tests/tun-e2e-killswitch-netns.sh`: Privileged Linux process proof for explicit/automatic selection, unavailable-backend failure, rollback-safe nftables and iptables replacement, real TUN traffic, selected VPN DNS, direct DNS and IPv6 leakage, timeout latency, retained fail-closed state, stale recovery, and client/server SIGTERM cleanup.

## Implementation Reconciliation (2026-08-03, TUN data-plane fault propagation)

- **Fault ownership:** `engine::DataPlaneFault` is the shared typed taxonomy for reader termination, channel disconnect, TUN writes, transport sends, and transport receives. `ClientRuntime` records the first fault, stops its I/O driver, reports `DisconnectReason::DataPlane`, and exposes the fault through `EngineStats` and `IoDriverStats`; standalone client and server loops preserve the first fault through cleanup.
- **Readiness and health:** `EngineStats.data_plane_ready` is distinct from connected/QUIC state. Server `Metrics` exports `quicfuscate_tun_data_plane_ready`, `quicfuscate_tun_data_plane_faults_total`, and JSON `tun_data_plane_ready`; an unexpected TUN fault makes server health `not_ready`, while cooperative shutdown remains non-error and uncounted.
- **Backpressure and terminal sends:** Linux `IoDriver` flushes pending transport output before retrying `DgramQueueFull`; `Done` and zero output remain normal polling outcomes, while all other receive, send, and TUN-write failures propagate as typed faults. Server downlink and standalone client paths use the same terminal ownership contract.
- **Verification:** `cargo fmt -- --check`, `git diff --check`, `cargo check --all-targets`, full library `rust-tests` (`2120 passed`), focused runtime/server/driver tests, and targeted Clippy with warnings denied passed locally on macOS. `x86_64-unknown-linux-gnu` cross-checking was attempted but the host lacks `x86_64-linux-gnu-gcc` and a Linux sysroot (`assert.h`); no Linux compile pass is claimed from this host.

## ICMP Server Architecture (Review Fix Session)
- `build_echo_reply()` (`src/implementations/server/icmp.rs`): Sets fresh TTL=64 for locally-originated echo replies (RFC 1812 §5.3.1), not decremented from original request.
- Live local echo handling selects the connection's frozen network profile before the reply enters the bounded MASQUE response queue. Optional unreachable suppression never removes IPv4 Fragmentation Needed or ICMPv6 Packet Too Big.

## Deep Audit Update (2026-08-01)

A full source-audit sweep produced TODO-626 through TODO-689 and augmented TODO-570, TODO-584, TODO-587, TODO-592, TODO-615, TODO-576, and TODO-649. The new findings affect the following wiring surfaces and should be reconciled before treating those areas as production-proven:

- **Crypto data plane**: constant-time tag comparison (TODO-626), key/IV length validation (closed by TODO-627), AEGIS mutex/`unwrap` path (TODO-628, resolved by TODO-582), AEAD header-protection sample validation (TODO-629), GHASH dispatch configuration (TODO-630), target-specific `AesGcm128` schedule zeroization (TODO-631), nonce/IV uniqueness (TODO-632), QUIC KDF input validation (TODO-633, local exact-length implementation active), and the completed TODO-681 unsafe-crypto audit. TODO-681 leaves separate `Aes128Ctx` and temporary-schedule erasure, checked seal-length arithmetic, owner-only packet-number enforcement, AEGIS copied-state erasure, AES table side-channel scope, GHASH release-control proof, and native ISA proof open.
- **FEC recovery**: unbounded fountain-decoder storage (TODO-634), adaptive emitted-ID cap (TODO-635), decoder peeling complexity (TODO-636), and Wiedemann buffer reuse (TODO-637).
- **Transport/Stealth**: terminal close priority (TODO-697; first-close-wins idempotency resolved by TODO-606; local close error-kind semantics resolved by TODO-772), ConnectionId clone hot path (TODO-638), StealthShaper RNG fallback logging (TODO-639), H3 masquerade time source (TODO-640), domain fronting jitter (TODO-641), TLS cover zero-key fallback (TODO-642), qftls `munlock` (TODO-643), bounded probe detector history (TODO-644), EscalationState timestamp bound (TODO-808), and brain escalation/histogram/config correctness (TODO-584). Reality session map timer-driven cleanup is resolved by TODO-570.
- **TLS fingerprint metadata**: TODO-595 corrects the Chrome-based `qftls` extension order to use one `server_name`, registered `renegotiation_info` (`0xff01`), one `compress_certificate` (`0x001b`), and no invalid `0x0019`; a regression test enforces uniqueness and the scoped registered-ID set.
- **TLS Cover and persona boundary**: TODO-596 removes the unread `TlsCoverProvider` ClientHello-template and extension-builder machinery, removes the no-op `CombinedProvider` override seed, and keeps rustls as the real ClientHello owner. `CombinedProvider::supports_ch_override()` is false for the cover overlay. TODO-598 removes the dead advanced builder and enforces the no-ChaCha real-TLS policy through one filtered rustls provider shared by client and server connections. Safari uses a dedicated HTTP/3 header template without `sec-fetch-*`, `upgrade-insecure-requests`, or `cache-control`. `TlsClientHelloSpoofer` retains deterministic templates only as compatibility/audit metadata; the write-only transport storage is tracked by TODO-766.
- **MASQUE/DoH ownership**: TODO-597 makes Core H3/MASQUE the sole active CONNECT-UDP/capsule carrier, buffers split capsule DATA, rejects malformed or truncated FIN tails before event delivery, and covers all 1/2/4/8-byte varints including 16,384-byte payloads. The empty `stealth::MasqueManager`, its false-success send path, the stale stealth-local DoH resolver, and their integration test are retired and preserved under `archive/`; shared DoH primitives remain in `src/dns/mod.rs`, while `ClientDnsRuntime` owns the active client resolver path. The server's final DNS hop remains plain UDP by design. TODO-771 completed the runtime wiring.
- **Optimize/Engine/Admin**: engine config reload (TODO-645), io_uring executor ownership (TODO-646), io_uring partial-send disposition (TODO-798), admin HTTP capacity and operation ownership (TODO-647, TODO-661), config write validation (TODO-648), MemoryPool lock release ownership (TODO-516), unsafe raw-pool ownership (TODO-826), safe-pool origin/capacity/TLS/ephemeral accounting (TODO-827), zstd FFI/context synchronization (TODO-828), allocation layouts and recoverability (TODO-829), zero-copy syscall conversion (TODO-830), generic pooled-buffer failure cleanup (TODO-831), FEC pooled-buffer cleanup and symbol lengths (TODO-832), zero-copy DATAGRAM queue return (TODO-833), metrics export allocations (TODO-587, TODO-615), and TUN interface unaligned/fcntl safety (TODO-654, TODO-655). Admin-web capacity is CLI-owned with default `16` and maximum `1024`; admission is acquired after `accept()` but before task creation, excess sockets are dropped without a user-space pending queue, and accepted tasks are joined on shutdown. Each accepted request uses a validated `50..=120000` ms operation deadline, a bounded command/result channel, an owned blocking worker `JoinSet`, explicit timeout/cancellation/panic/late-completion counters, and a one-second shutdown drain. Effective operation state is included in runtime admin status and health. TODO-687 closed the io_uring unsafe/lifetime and receive-slot audit boundary; TODO-801 closed the additional Linux kernel evidence boundary.
- **Privilege and secrets**: TODO-651 now stores SecretString in a private String owner, validates the checked SecretBytes-to-SecretString boundary, and retains zeroization on drop; native runtime proof remains environment-specific. TODO-652 validates libc result-pointer identity before `assume_init`, and TODO-653 bounds account-name pointers to the returned lookup buffer and a verified NUL before `CStr::from_bytes_with_nul`; both boundaries have local tests. The completed TODO-684 audit also found forged identity and Windows `CurrentIds` portability boundaries (TODO-849), incomplete post-drop state proof (TODO-850), process-lock policy and embedded propagation gaps (TODO-851, TODO-852), and TLS identity/key-output lifecycle gaps (TODO-643, TODO-853); fsutil TOCTOU is resolved by TODO-591 (duplicate TODO-667).
- **SIMD/time-source**: AMX `static mut` tile config reached from a concurrent Rayon solver, with compiled/runtime eligibility, tile ownership, kernel semantics, detector process bounds, proof-lane, and profile/documentation gaps (TODO-676, TODO-816-TODO-819). The complete clock inventory covers direct and implicit Rust/Tokio/browser monotonic and wall-clock reads across transport, H3, core, engine, stealth, qftls, server, client, runtime, telemetry, audit, PKI, Tauri, Svelte, tests, probes, and scripts (TODO-677); TODO-656 closes the PKI validity-time boundary. TODO-820 owns transport/stealth/core, TODO-821 server/client state, TODO-822 Tokio/OS/runtime domains, TODO-823 wall-clock provenance, TODO-824 Rust injection/test isolation, and TODO-825 frontend/browser clocks; TODO-640, TODO-658, TODO-662, TODO-671, TODO-675, TODO-768, TODO-584, and TODO-588 remain narrower owners.
- **SIMD safety hardening**: TODO-593 covers debug-only dimension checks for x86 GF(256) matrix kernels, capacity checks for BMI2 varint encoding, scalar delegation for the AVX2 header validator, zero-padded partial-shard encoding across scalar/NEON/GFNI backends, and fail-loud Windows SHA-256 fallback stubs. TODO-835 completed the boundary audit and confirmed that the matrix/BMI2 checks remain debug-only, the SSE4.2 short-needle path loads sixteen bytes for a shorter slice, and Berlekamp-Massey accepts an unchecked length; release-safe remediation and malformed-input proof remain open.
- **SIMD audit follow-up**: TODO-679 completed the read-only audit of all 31 SIMD source/test files, 138 unsafe function declarations, 102 actual target-feature attributes, direct callers, tests, audit scripts, documentation claims, and relevant history. TODO-834 then completed the exact dispatch-owner audit and confirmed SVE2 decode, ACK AVX512VL, SHA-VNNI, AES/VAES, GF16, AVX-512 compression/pattern/histogram, neural FMA, optimization string, stale BMI2 profile, and scalar-claim boundaries. TODO-835 completed the release-safe boundary audit and confirmed the short-needle, debug-only matrix/BMI2, unchecked Berlekamp-Massey, and caller-only private-helper contracts; remaining vector tails were cross-checked. TODO-836 completed the proof-owner audit and confirmed the blanket safety-doc suppression, only four function-level `# Safety` sections, silent ISA-test returns, stale unsafe-surface matching, and missing native-ISA proof lane. TODO-835 and TODO-836 retain their respective release-safe and proof remediations.
- **SIMD Reed-Solomon compatibility path**: TODO-594 corrects the standalone x86 AVX2/GFNI Reed-Solomon encode/decode implementations, including cross-shard accumulation, canonical GF(256) coefficients, full matrix inversion, dynamic LUT multiplication, safe vector tails, and runtime shard metadata checks. Rosetta-executed x86 tests pass; production recovery remains wired through `src/fec/`, while the completed FEC/GF16 audit is TODO-686 and GF16 polynomial correctness remains TODO-715. TODO-679's audit confirmed that the old AVX2-to-GFNI delegation claim is stale and split the remaining SIMD work into TODO-834, TODO-835, and TODO-836; FEC-specific SIMD remediation is TODO-855.
- **Unsafe memory and pooled-buffer boundaries**: `UnsafeMemoryPool` cache/raw-pointer ownership (TODO-826), safe `MemoryPool` origin/capacity/TLS/ephemeral accounting (TODO-827), `UnsafeCompressor` FFI and synchronization (TODO-828), allocation layouts and recoverability (TODO-829), `ZeroCopyBuffer` platform conversions (TODO-830), generic pooled-buffer failure cleanup (TODO-831), FEC pooled-buffer cleanup and symbol lengths (TODO-832), and zero-copy DATAGRAM queue return (TODO-833). TODO-678 remains the umbrella audit index. TODO-679 is the completed SIMD audit owner; feature intersections, release-safe unsafe boundaries, and safety proof guardrails remain TODO-834 through TODO-836. TODO-680's Optimize audit is also complete and recorded the P1f-to-AVX2 reduction route, P4a-to-AVX512 moving-average route, test-only BMI2 bitmap boundary, short-pattern overwrite, overflow-prone pattern positions, SVE2 base64 output coverage, packet-number/VNNI contracts, Linux batch FFI proof gaps, and percentile/profile test gaps. Remediation remains open.
- **Unsafe crypto/transport/interface/privilege**: crypto primitives (TODO-681 audit complete with lifecycle, checked-length, nonce-owner, AES table, GHASH-control, and native-proof findings), transport batching/UDP FFI/AF_XDP/frame-packet/PMTU surfaces (TODO-682 audit complete; remediation split into TODO-837-TODO-842), interface/Wintun/platform/WFP (TODO-683 audit complete; remediation split into TODO-843-TODO-848), and privilege/mlock/qftls/secret handling (TODO-684 audit complete; TODO-516, TODO-643, TODO-652, and TODO-653 have local remediation while TODO-849-TODO-854 retain the remaining boundaries; TODO-651's local String-backed UTF-8 remediation is implemented, with native proof still open). No production implementation or verification command was performed for the remaining audit-only passes.
- **Unsafe FEC/io_uring/auxiliary**: TODO-686 completed the FEC GF-table/decoder and public-boundary audit; remediation is split across TODO-634, TODO-636, TODO-637, TODO-690, TODO-715, TODO-832, and TODO-855-TODO-860. io_uring/io_driver lifetime ownership is TODO-687, unordered partial-send disposition is TODO-798, audit-file FFI and Windows API boundaries are audited under TODO-688 with remediation TODO-861, and TODO-689 completed the remaining cpu_dispatch/telemetry/cache/lib.rs/tests audit. Auxiliary remediation is TODO-862 through TODO-865; SIMD dispatch remains TODO-834, slice/proof boundaries remain TODO-835/TODO-836, and environment ownership remains TODO-670/TODO-811.
- **Unsafe QKey/admin**: QKey registry and admin session blocks (TODO-685).

`cargo check --all-targets --all-features` and `cargo clippy --all-targets --all-features -- -D warnings` pass after a `cargo clean` recovered a corrupted `target/` cache.

## Deep Audit Update (2026-08-02)

The follow-up source reconciliation confirmed and expanded the server/runtime backlog without changing implementation code:

- **Server data plane:** the shared client fan-out queue is uncapped and its drain materializes the complete backlog into a second container (TODO-612); TODO-613 closes the explicit PTB-for-all repair for oversized IPv4 uplink packets before either TUN write. The focused DF=0/DF=1 PTB regression and the native Linux PTB gate pass; TODO-806 closes the separate TTL-expiry failure observed later in the same broad harness, while the later queue/quiescence failure remains independent.
- **Limits and sessions:** TODO-614 defines the byte-rate burst as `ceil(max_bps * effective_burst / max_pps)` with `refill_interval` reserved for refill cadence; TODO-615 closes the HealthServer, production MetricsServer, and test-only GlobalMetricsServer read gap with bounded incremental framing and per-connection workers, while the separate telemetry endpoint retains its own protections; SessionManager insertion validates session-ID, client IPv4/IPv6, and remote-address ownership before mutation, while path rebind rejects a foreign remote owner and lets the migration caller restore its transport key. TODO-616 is closed with focused conflict/migration tests and full local gates.
- **Admin control plane:** TODO-617 is closed on the Unix admin socket boundary: mode `0600`, an 8 KiB command-frame cap with a five-second absolute read deadline, bounded liveness probing, and type-, owner-, and device/inode-identity-aware stale and shutdown cleanup are enforced. Focused admin tests pass 13/13 and the full library and strict all-feature Clippy gates pass.
- **Scope corrections:** the separate telemetry server already has a five-second read timeout, a 32-connection semaphore, and an environment-configurable bind; the test-only GlobalMetricsServer is not an active production surface. These boundaries remain recorded in TODO-615.

## Deep Audit Update (2026-08-02, client and platform reconciliation)

- **Retry admission:** TODO-618 is closed. `RetryToken` admits the exact 169-byte bounded IPv6/20-byte-CID/64-byte-credential encoding under `MAX_RETRY_TOKEN_LEN=192`, and the real issue/validate round-trip is covered. No duplicate length constant was found in the DDOS policy probe. TODO-659 was reconciled as stale: field limits reject oversized inputs before allocation/HMAC, and every accepted combination fits under the active aggregate limit.
- **Client runtime lifecycle:** TODO-619 is closed. `ClientRuntime::connect()` routes every post-assignment failure through explicit connection close and transport-state rollback, including missing runtime, UDP/socket, TUN, driver, and task-setup failures. Focused client tests pass 5/5, the full library passes 2,179/2,179, and locked all-target checking plus strict all-feature Clippy pass.
- **Client backend configuration:** TODO-620 is closed. The legacy `ClientBackend` setup path now resolves `tun_ip`, `tun_netmask`/`tun_subnet_prefix`, and `tun_gateway`, validates their address-family and contiguous-mask contracts, and installs family-matched split default routes while retaining the `10.8.0.2/24` compatibility default. Focused backend tests pass 11/11, the full library passes 2,183/2,183, and locked all-target checking plus strict all-feature Clippy pass. TODO-604 remains closed as its duplicate.
- **Client TUN projection:** TODO-663 closes the static portion of the split ownership boundary. The generic EngineConfig schema now has canonical `tun_ip6`/`tun_prefix6` fields, `InterfaceConfig::client_tunnel_addresses()` validates and normalizes legacy and canonical sources, and `ClientRuntime` projects the result into typed `TunConfig` IPv4 and IPv6 fields. The compatibility `ClientBackend` remains explicitly single-family and fails before platform mutation when canonical IPv6 fields are supplied. The former generic string-reparse finding was corrected as unconfirmed; TODO-731 owns CLI parse handling. Server `AssignedClientIps` is still used only for server-side policy/routing, with no client-facing address propagation found; TODO-866 owns that control-plane contract. Config projection tests pass 3/3, generic client projection tests pass 5/5, compatibility backend tests pass 6/6, format/check/strict library Clippy/all-target check pass, and the complete library passes 2,295/2,295. The all-target test matrix passes 2,295/2,295 library tests and 41/43 binary tests; the two failures are the known runtime-reload assertions at `src/main_parts/late_tests_and_mlock.rs:566,638`, and all-target Clippy retains eight pre-existing diagnostics.
- **Linux resolver ownership:** TODO-623 remains the owner of absent-original, stale-ownership, and crash recovery. TODO-649 now supplies the typed `LinuxResolverPaths` owner with standard `/etc/resolv.conf` defaults, backup-derived state/lock paths, schema-3 source/target/backup identities, create-only and atomic state publication, and fail-closed broken-link, replaced-target, foreign-backup, and read-only-parent handling. Valid symlinks remain symlinks through verified restore. The focused resolver suite passes 14/14 and host workspace checking plus library strict Clippy pass. The full local matrix reaches 2,259/2,261 library tests and 41/43 binary tests, with unchanged external-DNS/qftls and runtime-reload/PMTU baselines. Native Linux verification remains blocked by the macOS C compiler/sysroot boundary; the configured Omega SSH path is unavailable.
- **macOS pf:** TODO-624 closes the client activation rollback gap. `MacOSKillSwitch::ensure_pf_enabled()` now requires a successful `pfctl -sr` query with an exact QuicFuscate `anchor` statement or the approved wildcard, emits an actionable diagnostic when absent, and flushes/removes a just-loaded anchor when the later activation check fails. `KillSwitch::enable()` rolls back failed backend activation and exposes a fail-closed retained state only when rollback cannot be proven. The supported server TUN runtime remains Linux-only because `RoutingManager` rejects macOS before host mutation. Focused local tests pass 9/9; the privileged live PF proof is exposed by `scripts/tests/macos-pf-anchor-proof.sh` but was not run because this session lacks root and must not mutate shared PF state.
- **Client FEC surface:** TODO-625 removes the uncompiled `src/implementations/client/pipeline.rs` adapter, its packet-id-zero `FecCodec` wrapper, and the unused `ClientSubsystems.fec` construction. Client tests pass 74/74; locked all-target checking, strict all-feature Clippy, format, diff, and source-reference gates pass. The full local library reached 2,193/2,195; TODO-768 and TODO-807 own the two unrelated failures. The active FEC wire/framing owner remains `QuicFuscateConnection`/`src/core.rs`; TODO-602 is its closed duplicate.
- **Tracker reconciliation:** TODO-621 is closed as the exact duplicate of TODO-662, and TODO-622 is closed as the exact duplicate of TODO-658. No product code changed in this reconciliation.

## Deep Audit Reconciliation (2026-08-02, runtime and control surfaces)

- **Engine reload:** The generic `QuicFuscateEngine` exposes validated in-memory `update_config` and file-backed `reload_config_from_file`. Created/stopped engines replace the complete config; running clients synchronize the next-connection projection and preserve active non-FEC sessions, while startup-owned engine/interface/telemetry/logging/audit/crypto/optimization/security sections require a stopped engine. Running generic servers reject these mutations. The standalone server has a separate validated file reload path with explicit `NextConnectionOnly` scope, startup-owned fields, and a shared-policy-before-best-effort-transport publication boundary. That path reads `EngineConfig` only, so construction-time `ServerConfig` including blacklist/GeoIP/DDoS/auth policy is not replaced. TODO-645 owns the generic contract; TODO-660 owns blacklist worker lifecycle; TODO-724 owns standalone transactional publication.
- **io_uring:** `UringBatchSender` has no cross-call pending queue: scratch vectors are reused and submissions are chunked to SQ capacity. Public sender and worker methods reject batches above 256 packets or 524,288 aggregate payload bytes before their owned copies. Client and standalone server packet paths use one bounded `UringBatchWorker` per runtime, with a joined blocking thread, controlled completion deadline, quarantine on cancellation/timeout, and typed failure without ambiguous replay. Generic client TUN reads now use a trait-level `TunReadContract`; native backends declare nonblocking and custom backends default to a separately owned blocking-reader contract. TODO-687 covers pointer/lifetime safety and TODO-798 covers exact partial-send disposition; Linux-target compilation and live io_uring proof remain TODO-646 gates.
- **Config writes:** The active `write_runtime_config` handler parses `AppConfig`, validates it, validates transport overrides, and only then calls `atomic_write_file`. TODO-648 is closed as stale; the earlier `config.rs` location was not the TOML write path.
- **Linux DNS backup:** Restore copies the backup before removing it, verifies source/target identity and restored bytes, and deletes the backup only after successful read-back. TODO-649 now owns the standard and typed alternate source/backup contract, derives state/lock paths from the backup, and rejects broken or replaced symlinks plus foreign backup/state entries without overwriting or removing them. TODO-623 owns absent-original and crash recovery; native Linux proof remains environment-blocked.
- **TUN fcntl:** Linux and macOS check `F_GETFL` and `F_SETFL`, close only on the error path, and return before device publication. TODO-655 is closed as stale. TODO-654 now owns the alignment-safe BMI2 load and unaligned-subslice regression proof; the broader interface/platform remediation is TODO-843 through TODO-848.
- **Probe parsing:** `qf-privilege-probe`, `--initial-count`, and `--initial-interval-us` already return parse errors. TODO-657 now makes `--timeout-ms` and `--hold-ms` in `qf-e2e-client` and `qf-e2e-desktop` explicit and testable: malformed or missing values fail, omitted values retain defaults, zero is valid, and duplicates remain last-value-wins.
- **Retry token:** Per-field bounds already exist. TODO-618 owns the corrected 192-byte aggregate capacity and 169-byte worst-case round-trip. TODO-659 was reconciled as stale because accepted inputs cannot exceed the active aggregate limit and oversized fields fail before body allocation and HMAC.
- **Blacklist sync:** The only current production caller is `ServerRuntime::run_loop()` housekeeping -> `LiveServerState::maybe_sync_blacklist()`. `BlacklistSyncOwner` now stores the owned task and cancellation flag, performs one atomic due/in-flight claim, observes success/failure/cancellation, and closes on drain. The synchronizer retains strict HTTPS, redirect, request-timeout, body, UTF-8, entry, custom-CA, cache-format, expiry, and atomic last-known-good checks; parsing, durable cache publication, and active-state replacement run in `spawn_blocking` after a pre-publication cancellation check. Retry delays are bounded at `5` through `300` seconds; absolute caps are `300` seconds request timeout, `16777216` bytes body/cache, `250000` entries, and `604800` seconds TTL/interval. Lifecycle events, freshness ages, stale state, active entries, and in-flight state are exported through Prometheus, health, and admin status. TODO-660 local gates pass; controlled external HTTPS-feed, native Linux, full-matrix, and publication proof remain open gates.
- **Replay protection:** The admin session store uses bounded `VecDeque` plus `HashSet` and evicts one fingerprint at a time. TODO-665 Finding 1 is stale. The remaining issue is the undocumented replay-window tradeoff when FIFO eviction precedes sliding session expiry; TODO-809 separately tracks the uncapped outer live-session map.
- **Environment parsing:** No supported external-process or safe concurrent mutation path establishes a torn-read defect. TODO-670 owns the shared helper's invalid/default/alias/whitespace/snapshot contract and caller coverage; TODO-811 owns active direct `std::env::var` parser authorities, subsystem-specific fallbacks, and lazy initialization boundaries.
- **File modes:** `fsutil`, audit persistence, QKey registry, resolver ownership state, routing ownership state, PKI private-key writers, and client profile persistence set restrictive creation modes before opening files. TODO-671 retains the Linux resolver source/lock/backup contract, rotating-log initial/reopen creation, credential-bearing standalone profile persistence mode inventory, and direct public audit reopen mode; TODO-662 owns profile atomic publication, deterministic serialization, temporary cleanup, and Unix parent-directory durability.
- **Log rotation:** Unix SIGHUP is already routed to next-connection-only configuration reload, not rotation. `LoggerControl` has no writer-owned rotate command, the admin logging routes only change mode or clear the in-memory buffer, and external rename/copytruncate behavior is unproven while the appender retains one file handle. TODO-672 owns the trigger, acknowledgement, and reopen contract.
- **CLI control protocol:** `quicfuscate-ctl` still interpolates `kick`/`block`/`unblock` values into JSON without escaping, preflight bounds, or exact arity. The Unix reader is already bounded to 8 KiB with a five-second deadline (TODO-617), and the CLI response side enforces one bounded newline-terminated UTF-8 frame and typed command-specific schemas (TODO-795); Unix command-value validation still differs from the HTTP normalization path. TODO-673 owns the remaining request boundary.
- **Audit persistence:** `AuditLog::flush` bounds the producer acknowledgement wait, but the writer's `flush` and `sync_data` remain synchronous and uninterruptible. Flush/checkpoint errors do not enter the same terminal state as event-write errors; drop/shutdown results are not sticky, and concurrent event admission is not closed before the shutdown command. TODO-675 retains durability/cancellation and failure-state truth; TODO-726, TODO-815, TODO-813, and TODO-814 retain terminal admission, shutdown ordering, configuration maxima, and payload-size boundaries.

## Deep Audit Reconciliation (2026-08-02, unsafe and protocol lifecycle)

This pass reconciled the remaining unsafe inventory and the next transport/FEC lifecycle surfaces against the current source. No product implementation was changed.

- **Crypto corrections:** TODO-631's blanket round-key zeroization claim is stale because the AES-NI schedule exists only on x86_64 and is zeroized in its target-specific `Drop`; key and IV zeroization remains cross-target. TODO-642's zero-key fallback claim is stale because TLS cover entropy failure returns a typed crypto error before derivation. TODO-627 closes the constructor key/IV boundary; TODO-629 and TODO-632 retain the independent header-protection and nonce-lifecycle contracts, while TODO-633 now owns the local exact 32-byte KDF boundary and its remaining full-matrix/native proof.
- **AMX:** `src/optimize/parts/cpu_dispatch.rs` derives AMX planner flags from external `cpuid` output even when the binary is not compiled with `target_feature="amx-tile"`. `src/fec/parts/decoders.rs` can therefore select the AMX plan while the cfg-gated AMX call is absent and the next vector remains zero-initialized. The active GF(256) path performs scalar coefficient multiplication after tile load/store, while the separate integer kernel is uncalled and dimension-blind. The tile config is global while the solver runs through Rayon, and AMX cleanup is only proven on the normal return path. TODO-676 owns the race/dispatch/dimension boundary; TODO-816 owns kernel semantics, TODO-817 owns detector process bounds, TODO-818 owns proof coverage, and TODO-819 owns profile/documentation truth.
- **Unsafe memory and pooled-buffer boundaries:** `src/optimize/unsafe.rs` calls a field named `tls_cache` through shared `UnsafeCell` state without actual thread-local storage, permits fallback allocations to desynchronize capacity/available counters, and performs block-size-independent prefetch pointer arithmetic. `UnsafeCompressor` exposes a shared mutable zstd context through `Sync`. The active safe `MemoryPool` has separate ephemeral, foreign-origin, TLS-shrink, and counter contracts, while direct `AlignedBox` drops bypass accounting on compression, TUN, frame, FEC, and zero-copy DATAGRAM failure or teardown paths. The historical `copy_to_block` inventory is absent from the current source. TODO-678 is the umbrella index; TODO-826 through TODO-833 own the split boundaries.
- **SIMD:** TODO-679's current-source pass confirmed that the old AVX-512/GFNI Reed-Solomon delegation claim is stale for the active decoder. TODO-834 owns the dispatch and compiled-surface truth and confirmed several exact feature intersections that remain open. TODO-835 completed the boundary pass and confirmed the critical `find_pattern_sse42_short` short-needle load, debug-only matrix/BMI2 dimension/output checks, unchecked Berlekamp-Massey length, and caller-only private-helper proofs; remaining vector tails were cross-checked. TODO-836 completed the proof pass and confirmed the blanket safety-doc suppression, only four function-level `# Safety` sections, silent ISA-test returns, stale unsafe-surface matching, and missing native-ISA proof lane. TODO-835 and TODO-836 retain their respective release-safe and proof remediations.
- **Optimize and UDP:** TODO-680's complete source audit found three public reduction entrypoints that route P1f (AVX only) to AVX2, P4a moving-average dispatch to an AVX512F kernel without an AVX512F proof, test-only P3/P4 BMI2 bitmap dispatch with reversed/clipped range arithmetic, SSE2 short-pattern overwrite, overflow-prone pattern positions, SVE2 base64 output-lane undercoverage, unchecked QUIC packet-number lengths, VNNI truncation beyond 64 samples, percentile index gaps, and Linux batch receive-length/sockaddr/count contracts. TODO-682 then completed the direct transport source, caller, feature, test, guardrail, documentation, and history pass and split its open remediation into TODO-837-TODO-842. Valid vector tails and direct production bounds were cross-checked; no production implementation was made. TODO-680, TODO-834, TODO-837-TODO-842, TODO-689, and TODO-836 retain adjacent ownership.
- **Interface and platform:** TODO-683 completed the full read-only source,
  caller, platform-gate, cleanup, test, script, documentation, and history
  pass. P3a-P3e and P4a/P4b can reach the BMI2 parser without an equivalent
  BMI2 predicate; the generic TUN trait does not bound read counts or require
  complete writes; Linux/macOS retain zero-progress, vectored-result,
  kernel-name, and Drop-close gaps; Wintun can lose ownership after event,
  library, or early Drop failure; and WFP engine/transaction failures are not
  retryable. TODO-654 replaces the unaligned BMI2 load with
  `std::ptr::read_unaligned` and owns its regression proof; TODO-843 through
  TODO-848 own the remaining remediation and negative proof boundaries. No
  product implementation or verification command was performed for TODO-683.
- **Privilege and FFI:** TODO-683 completed the full read-only source, caller, platform-gate, cleanup, test, script, documentation, and history pass for interface and platform boundaries. TODO-684 completed the corresponding privilege, memory-lock, qftls, secret, caller, platform, cleanup, test, script, documentation, related-TODO, and history pass. TODO-652 closes returned-pointer identity and TODO-653 closes bounded account-name conversion in `src/privilege/drop.rs`, both with local deterministic tests; final-boundary identity validation, complete filesystem-ID verification, and a portable `CurrentIds` type remain under TODO-849-TODO-850. Process-lock failure remains warning-only, the embedded engine does not propagate the CLI lock settings, and pool/key unlock ownership remains TODO-516/TODO-643; TODO-851-TODO-853 own the distinct policy and identity gaps. TODO-854 owns the missing negative proof and guardrails. Native privilege proof remains environment-specific.
- **FEC unsafe inventory:** TODO-686 completed the full FEC audit. Active GF(256)/GF(16) wrappers clamp slice lengths before private vector calls; the old public raw-slice and SSSE3 claims are stale. The P4 GF16 threshold map can still select a VBMI2 threshold while the actual policy falls back to scalar when VBMI2 is unavailable; FEC-specific dispatch remediation is TODO-855 and broader SIMD ownership remains TODO-679/TODO-834-TODO-836. Direct public decoder/matrix/wire/Fountain inputs, FEC configuration/feedback, sequence arithmetic, negative proof, and documentation truth remain TODO-856-TODO-860. AMX remains open under TODO-676 and TODO-816-TODO-819.
- **io_uring:** The current sender copies payloads into owned slots before publishing pointers and quarantines after submit/protocol errors; SendMsgZc tracks `CQE_F_MORE` and waits for every announced notification, including errored primaries. Receive completion metadata is range-checked, zero-length and error receives are re-armed, and ring destruction precedes pool-block return. Client eventfd reads require exactly eight bytes. TODO-687 closed the unsafe/lifetime boundary and TODO-801 closed the additional Linux kernel evidence boundary. TODO-646 now owns the bounded sender admission, runtime worker, shutdown, and generic client TUN contract; its Linux compile/live-proof gate is blocked by the local macOS toolchain. TODO-798 owns unordered partial-send retry disposition.
- **Auxiliary unsafe surface:** TODO-689 completed the read-only audit of the remaining `cpu_dispatch`, prefetch, Windows NUMA, global-pool/auto-tuner, test-environment, telemetry, crate-root, transport/config, and test-only constant-buffer surfaces. The non-iOS AArch64 fallback uses `read_volatile`, Windows `GetCurrentProcessorNumberEx` status is ignored, lazy and explicit pool initialization differ, test-environment locks are fragmented, and `ConstPacketPool<N>` exposes `N - 1` slots while documenting `N`. Remediation is TODO-862 through TODO-865; TODO-670/TODO-811, TODO-834/TODO-835/TODO-836, TODO-841, TODO-843, and TODO-752 retain adjacent ownership. Telemetry, crate-root, and transport/config matches are source-text false positives.
- **FEC solver:** `solve_wiedemann_system` still returns a copy of `rhs` after constructing the Krylov sequence and minimal polynomial; the existing equation check and Gaussian fallback are containment, not a functional solver. The all-feature fixture also uses an inconsistent repair packet identity. TODO-690 owns both mathematical correctness and fixture separation.
- **HTTP/3 control and parser:** The local H3 constructor records a control stream and settings in memory without emitting the stream type or SETTINGS bytes, and the server skips initialization. The frame parser reads a one-byte type, ignores SETTINGS/unknown state, and does not enforce stream-specific legality or push ownership. TODO-691 and TODO-692 own wire initialization and varint/state validation.
- **Transport receive accounting:** STREAM flow control increments connection bytes before overlap/deduplication, so retransmitted bytes consume credit. `take_ack` clears pending ACK state before capacity/write success. Loss detection materializes and sorts a packet-number prefix, while terminal timeout clears connection counters without retiring per-space recovery state. TODO-693 through TODO-696 own these accounting and terminal-owner contracts.
- **Terminal close and queued sends:** Congestion-bypass control flushing can block a later CONNECTION_CLOSE behind an earlier ack-eliciting frame; TODO-606 now suppresses duplicate local close frames and TODO-772 preserves the selected local close kind in typed error state. FEC and DATAGRAM queues pop items before every serialization/seal stage has committed, so a later failure can lose local payload ownership. Server stop can report `Stopped` while a startup-timeout runtime thread remains live. TODO-697, TODO-698, and TODO-699 own priority, transactional send ownership, and server thread lifecycle.

The audit remains open. These reconciliations document current evidence and ownership; they do not constitute implementation or runtime closure of the listed TODOs.

## Deep Audit Reconciliation (2026-08-02, target and scope contracts)

- **Cargo tests:** 71 integration-test targets are declared and all 71 source paths exist. The desktop/web-admin Rust validation suite now invokes five current declared targets; the archived `it-masque-runtime-integration` source is evidence only and is not part of the active Cargo target surface. TODO-774 closed the stale runner edge, while TODO-734 owns the remaining feature and non-vacuity contract.
- **Feature propagation:** All 64 declared test targets with crate-level feature cfgs now declare matching Cargo `required-features`. Orchestrator requires `rust-tests,orchestrator`; SIMD self-check requires `rust-tests,simd-selfcheck`; Linux io_uring targets require `rust-tests,io_uring`; and XDP requires `rust-tests,internal_af_xdp_experimental`. `run_cargo` still injects the baseline `rust-tests` feature for generic test commands, while the targeted desktop, transport, full-suite, and CI lanes now pass their target-specific feature sets explicitly.
- **Non-vacuity:** `qf_cargo_test_run_expect` requires a positive executed-test count plus a named `test ... ... ok` marker. The transport bundle verifies one intended test per target and records Linux-only paths as explicit `SKIP` items. The dynamic-discovery contract includes negative Cargo invocations for missing `rust-tests` and `orchestrator`, which must fail before a zero-test result can be emitted. The CI SIMD lane requires the `varint_roundtrip_and_consistency` success marker; the default feature-matrix lane enables `rust-tests`.
- **Architecture skips:** The x86_64-only parity targets and the aarch64-only random helper target retain exact Cargo feature requirements but now provide explicit ignored `SKIP` fixtures on unsupported architectures, so direct target invocations cannot report an empty passing crate.
- **Examples:** `examples/tun_factory_example.rs` is Cargo- and crate-gated only to `tun-tests`; its `main()` demonstrates external factory registration and no longer advertises unreachable `tun-windows`/`tun-ios` branches. The example proves factory wiring, not platform backend behavior. TODO-775 closed the target contract; the production platform owners remain TODO-443 and the related Windows/TUN tasks.
- **Scope gate:** The current register has 703 tracker headings, 364 current detail files, and 374 archived detail files. The last recorded validator pass enumerated 902 tracked, 58,787 ignored, and 0 non-ignored untracked paths, for 59,689 accounted paths, including exactly three `historical-archive` paths. The current validator stops before those counts because it rejects the canonical `Blocked` tracker section; TODO-799 owns that schema mismatch. TODO-773 classifies tracked archive paths as `historical-archive` evidence; TODO-795 owns the Unix admin CLI response-contract gap, TODO-796 is closed for the E2E migration finalization evidence gap, TODO-797 is closed for the persisted logging-mode state gap, and TODO-798 owns the io_uring partial-send disposition gap.
- **Migration proof finalization:** `src/bin/qf-e2e-client.rs` classifies HTTP/3 body/FIN completion as `accepted` or the transport's explicit terminal `already-done` state before emitting `migration-proof`; all other outcomes fail the probe without a success marker. Focused regression coverage owns accepted, rejected, and unavailable-HTTP/3 outcomes. TODO-796 is closed after the complete evidence gate.
- **Logging-mode persistence:** `src/implementations/server/parts/config.rs` uses a typed four-mode sidecar contract at `<config>.logging.json`; an absent sidecar applies `normal`, while malformed, unreadable, missing-mode, unknown-field, and unsupported state aborts bootstrap. `write_logging_mode()` persists configured updates before live publication, retains the old live mode on write failure, and labels no-config changes live-only. TODO-797 is closed after the 2,139-test library gate, all-target check, targeted Clippy, formatting, and diff hygiene.

## Implementation Reconciliation (2026-08-02, frontend polling lifecycle)

- **Admin ownership:** `apps/svelte-admin/src/lib/request-coordinator.ts` serializes one current operation plus one coalesced pending operation per resource. Dashboard status, clients, metrics, and blocked-IP resources; configuration/status; logging mode/status/logs; and the nested admin-auth and QKey panels use generation checks, current-only loading/error/optimistic/history/cursor commits, and effect teardown invalidation. Manual refresh and mutation reconciliation enter the same coordinators.
- **Desktop ownership:** `startEnginePollers()` serializes status, stats, and log calls independently, rejects responses from stopped or superseded poller owners, binds stats to the status generation and active tunnel captured at request start, and rejects log cursor regression or log-clear epoch responses. The poller invokes the statically imported Tauri API for deterministic runtime/test resolution; unrelated bridge operations retain their existing browser-safe dynamic imports.
- **Verification:** The affected Admin view tests pass 43/43 across Dashboard, Configuration, and Logs; the Desktop polling lifecycle tests pass 2/2; both `bun run check` commands report 0 errors and 0 warnings. The repository-wide frontend `bun run test:unit` command did not return a report within the bounded local run and was stopped; it is not represented as a passing gate.

## Implementation Reconciliation (2026-08-02, admin confirmation lifecycle)

- **Ownership:** `apps/svelte-admin/src/lib/stores/app.svelte.ts` owns one active confirmation with a monotonic request ID and one resolver. A newer request explicitly cancels the prior caller with `false`; stale IDs cannot settle the active request.
- **Rendering and teardown:** `apps/svelte-admin/src/routes/+layout.svelte` renders and resolves the dialog using the captured request ID and cancels the active request on layout teardown. Sidebar navigation/logout, Configuration refresh, Logs refresh, and keyboard reload/close therefore share one deterministic latest-wins policy without independent resolver overwrite.
- **Verification:** `scripts/tests/frontend/web-admin/unit/src/confirm-dialog-store.test.ts` covers supersession, stale callbacks, exactly-once settlement, and teardown cancellation. The UI presentation and shared dialog component remain unchanged.

## Implementation Reconciliation (2026-08-02, fast FEC gate)

- **Focused unit-test contract:** `scripts/tests/fast/test-fast-fec.sh` runs `fec::tests::`, `gf16`, `wiedemann`, and `streaming` as separate libtest invocations with the explicit `benches,rust-tests` feature set. Each result records the requested filter, command status, executed-test count, status, and bounded log name; zero-test or missing-`ok` output is a failure.
- **Bench boundary:** The `cargo bench --no-run --features benches` smoke compile is recorded as its own result and never substitutes for focused unit-test execution. `util-run-full-suite.sh` and `test-fec-all.sh` invoke the helper as a child, so a focused or bench failure propagates through their existing `run`/`exec` boundary.
- **Negative proof:** `scripts/tests/fast/test-fast-fec-fail-closed.sh` injects a real invalid Rust flag, requires a nonzero helper status and a bounded focused `FAIL`/`UNAVAILABLE` record, rejects the green completion marker, and proves that no bench result is emitted after the focused failure. The positive local run passed 4/4 filters with 112 executed tests and a separate bench `PASS`.

## Implementation Reconciliation (2026-08-02, dynamic test discovery)

- **Shared contract:** `scripts/tests/lib/lib-common.sh` owns target-scoped Cargo test discovery and execution classification. It preserves raw output and command status, requires a positive listed or executed test count, and emits `PASS`, `FAIL`, or `UNAVAILABLE` metadata with target, feature set, filter, and reason.
- **Suite wiring:** `test-optimization.sh`, `test-performance-regression.sh`, and `test-security-fuzzing.sh` discover and execute the same release `--lib` test universe, including the effective `rust-tests` feature set. Optimization keeps a separate zero-copy feature scope; platform and toolchain skips retain explicit prerequisites and machine-readable reasons.
- **Negative proof:** `scripts/tests/fast/test-dynamic-discovery-fail-closed.sh` uses real Cargo calls to prove discovery command failure, integration-to-library target mismatch, stale-pattern discovery, and zero-test execution are non-pass results. Raw outputs and exit statuses remain in the bounded result artifact.

## Implementation Reconciliation (2026-08-02, harness argument safety)

- **Array boundary:** `scripts/tests/lib/lib-common.sh` now validates control-free values, bounded decimal integers, feature lists, output paths, and environment assignments. `run_cargo_with_env` exports validated assignments without `eval`, `bash -lc`, word splitting, or loss of argument boundaries.
- **Suite wiring:** FEC, FEC simulation, StealthBrain, optimization, security/fuzzing, and crypto benchmark suites pass environment and Cargo arguments as arrays. Their result rows retain `PASS`, `FAIL`, or `SKIP` state, command status, and bounded command/environment identity.
- **Orchestration and input gates:** `bench-orchestrator.sh` uses fixed executable-plus-argv resolution and structured manifests; QPACK, UDP, crypto microbench, fuzz, and Admin E2E boundaries reject malformed numeric, size, feature, endpoint, credential, timeout, TTL, flag, and path inputs before execution or numeric JSON serialization. Admin E2E dry-run is plan-only and redacts the password.
- **Negative proof:** `scripts/tests/fast/test-harness-argument-safety.sh` exercises the real orchestrator, Admin E2E, QPACK, UDP, and crypto harnesses with shell metacharacters, malformed sizes, invalid numerics, and paths containing spaces. It requires bounded JSON failure/skip records and proves that no side-effect marker is created.
- **Ownership boundary:** TODO-735 remains open for the broader benchmark build/export/selection matrix, and TODO-738 remains open for typed parsing and checked workload arithmetic inside the Rust benchmark/probe examples.

## Implementation Reconciliation (2026-08-02, profiling evidence contract)

- **Runner ownership:** `scripts/benchmarks/profiling-common.sh` owns schema version `1`, JSON/CSV serialization, source and executable provenance, tool versions, bounded readiness waits, process status, metric validation, flamegraph execution, and cleanup status. `profiling-baseline.sh`, `profiling-tun-mode.sh`, and `profiling-zc.sh` each write a unique run directory and a manifest without overwriting a previous run.
- **Baseline matrix:** Scenarios `a`-`c` are the real UDP harness boundary. Scenarios `d`-`f` are real loopback client/server runs with explicit FEC and cover-feature flags. The runner no longer claims a CLI stealth mode that the standalone parser does not expose.
- **TUN boundary:** Scenarios `g`-`k` require native Linux/root, `tc`, `iperf3`, certificates, `perf`, and FlameGraph. A qdisc is owned only after successful setup and is removed through the same scenario owner. Setup, readiness, traffic, metrics, perf, flamegraph, and cleanup are independent evidence fields.
- **Zero-copy boundary:** `profiling-zc.sh` is the only canonical SendMsgZc runner. It launches the actual product binary with `QUICFUSCATE_IO_URING_ZC=1` and `--telemetry`, and requires positive send and notification counters from both telemetry endpoints before emitting a pass.
- **Evidence status:** `PASS`, `FAIL`, `SKIP`, and `UNAVAILABLE` are the only scenario states. Missing setup, process, traffic, measurement, or tooling evidence cannot be encoded as `N/A`. Generated `docs/profiling/` output remains ignored; historical ignored profiling files are evidence-boundary inputs, not current tracked proof.
- **Negative coverage:** `scripts/tests/fast/test-profiling-evidence-contract.sh` exercises portable dry-runs, unavailable-tool manifests, invalid iperf/SendMsgZc metric payloads, side-effect-safe paths, and source-backed failure markers. Native failed-process and netem fixtures run only when real Linux/root prerequisites are present.

## Implementation Reconciliation (2026-08-02, benchmark and analysis fast/full modes)

- **Suite matrices:** `bench-crypto.sh`, `bench-fec.sh`, `bench-optimization.sh`, `bench-stealth.sh`, and `bench-transport.sh` now consume `--fast` and `--full`. Fast selects bounded native, pipeline, single-size, or single-group cells; full selects the complete architecture or benchmark-group matrix. Each runner writes a machine-readable `meta` item with the effective mode and selected cells.
- **Orchestration:** `bench-orchestrator.sh` records the selected suite list and passes `--fast` or `--full` to every mode-aware child. Its dry-run manifest therefore exposes both the parent mode and the exact child argv contract.
- **Coverage analysis:** `analysis-coverage-summary.sh --fast` performs only the static function/test inventory and records that scope; `--full` retains the cargo-llvm-cov path or its Cargo-test proxy. A dry run records the backend without launching Cargo.
- **Regression proof:** `scripts/tests/fast/test-benchmark-fast-mode-contract.sh` validates both modes for all affected helpers, exact selected cells, orchestrator propagation, valid JSON, and output paths containing spaces without executing a benchmark.

## Implementation Reconciliation (2026-08-02, shared artifact writer contract)

- **Structured serialization:** `scripts/tests/lib/lib-common.sh` records command `argv` and relevant environment as JSON values, validates every appended object and completed suite document, and provides a parser-backed standalone writer for metadata and domain summary objects.
- **Ownership:** `json_begin`, standalone object writers, and profiling scenario/manifest writers reject an existing target by default. `QUICFUSCATE_ARTIFACT_POLICY=replace-with-backup` preserves the previous target under a unique `.previous-<run-id>` name before installing the replacement; the active artifact records the policy and source revision.
- **Coverage:** The contract now includes profile runners, benchmark and microbench metadata/dry-run rows, FEC matrices, analysis reports, probe detection, audit/test/utility result rows, Linux E2E summaries, Python probe/sampler outputs, and Linux send-path decision output. Domain-specific payloads use exclusive creation and parser-safe JSON serialization while remaining separate schemas. Externally produced Cargo, curl, iperf3, and third-party probe JSON remains an external-input boundary rather than shell-assembled evidence.
- **Regression proof:** `scripts/tests/fast/test-shared-artifact-writer-contract.sh` exercises quotes, backslashes, control characters, Unicode, spaces, structured argv/environment identity, malformed JSON rejection, default rerun immutability, backup replacement, standalone metadata, and profiling scenario/manifest create-new behavior.

## Implementation Reconciliation (2026-08-02, PGO release evidence)

- **Run ownership:** `scripts/build/build-pgo-release.sh` creates a unique `scripts/out/build/pgo-<UTC>-<random>/` directory, keeps profile data and Cargo target state inside that run, rejects caller target overrides, and never removes a global `/tmp` profile directory. The EXIT trap writes a retained manifest for normal, failed, and interrupted runs.
- **Evidence contract:** `manifest.json` uses `quicfuscate.pgo-release.v1` and records source revision/dirty state, feature list, toolchain versions, structured build argv and environment, required help plus optional benchmark workload statuses, profile file counts and sizes, merge/show validation, final artifact path/size/SHA-256, and bounded phase logs. `PASS`, `FAIL`, and `UNAVAILABLE` are explicit; empty profile output, empty profile files, malformed merge input, and missing tools cannot pass.
- **Regression proof:** `scripts/tests/fast/test-pgo-build-artifact-contract.sh` uses isolated fake tools to exercise missing `llvm-profdata`, no profile output, merge failure, and two concurrent successful runs. It verifies parser-valid manifests, nonzero negative exits, distinct run IDs/profile directories, and final binary hashes without a real Rust build.

## Implementation Reconciliation (2026-08-02, tray autostart state contract)

- **State outcomes:** `apps/tauri/src-tauri/src/state_store.rs` keeps a missing file as explicit first-run absence, while corrupt JSON, unreadable paths, and failed state normalization return errors. Corrupt input remains at its original path so a restart cannot reinterpret it as a clean first run.
- **Startup/rendering:** `main.rs` represents `FirstRun`, `Loaded`, and `Unavailable` tray state separately. Startup may synchronize OS autostart only for the first-run or loaded outcomes; unavailable state records an error, skips the OS mutation, and renders both persisted-preference menu items disabled with an explicit `(unavailable)` label.
- **Mutation transaction:** `StartAtLoginBackend` reads the current OS registration before mutation. State writes run after the OS change; save failure compensates the OS, failed enable/disable attempts compensate to the prior state, and failed compensation returns a retryable partial result. The tray reload after a successful save is mandatory before emitting the settings event.
- **Regression proof:** Native desktop unit tests cover missing, corrupt, unreadable, persisted restart state, read failure, failed enable, failed disable, failed save, failed compensation, retry, and first-run-versus-unavailable outcome separation. The bin test target passed 37/37 tests; Clippy passed with `-D warnings` for the desktop target, while the existing `quicfuscate::TlsCover::client_hello_custom` dead-code warning remains outside this change.

## Implementation Reconciliation (2026-08-02, desktop engine cleanup propagation)

- **Native ownership contract:** `apps/tauri/src-tauri/src/main.rs` now routes disconnect, replacement-connect, and tray shutdown through one bounded cleanup transaction. Connected engines are disconnected before stop; both failures are retained in order with their original context.
- **Failure state:** If cleanup cannot reach `Stopped`, the Tauri owner and active tunnel remain retained for retry and `last_error` is populated. If a later stop reaches `Stopped` after an earlier failure, the owner is released while the original failure remains visible instead of being converted into success.
- **Replacement and quit:** Replacement-connect returns before constructing the new engine when old cleanup fails. Tray quit emits an explicit owner-retained outcome, exits with status `1` on cleanup failure, and uses the existing mandatory startup stale kill-switch cleanup as the bounded process-residue recovery boundary.
- **Regression proof:** Native adapter tests cover user disconnect, replacement gating, terminal recovery, and tray shutdown outcomes while injecting TUN, routing, firewall, service-task, and kill-switch error contexts. The desktop bin test target passed 41/41 tests; Clippy passed with `-D warnings`, with only the existing `quicfuscate::TlsCover::client_hello_custom` warning outside this change.

## Implementation Reconciliation (2026-08-02, admin credential persistence contract)

- **Initialization ownership:** `resolve_admin_web_auth()` now propagates the typed `AdminAuthError` boundary through `std::io::Result`; `AdminAuth::new()` rejects hash failures, empty usernames, and invalid PHC verifiers. `AdminHttpServer::new()` treats an unreadable, malformed, or invalid persisted auth file as a startup error and persists a missing file before `run()` can bind the listener.
- **Durable update ownership:** `/api/admin/auth` builds a candidate credential under the auth write lock, validates and atomically persists it when an auth path is configured, then publishes the candidate. Hash or filesystem failure returns HTTP 500 with explicit error logging; the prior in-memory credential, durable credential, rate-limit success state, and sessions remain unchanged on failure. The shared `fsutil::atomic_write_file()` guard removes an uncommitted temporary file after any write, sync, or rename failure.
- **Session and restart contract:** Successful username-only updates preserve the password-change flag, successful password updates replace the verifier, and all sessions are invalidated only after the durable commit. A failed atomic destination write leaves restart behavior anchored to the last valid persisted credential.
- **Regression proof:** Admin HTTP tests cover typed hash/verifier failure, startup persistence failure before listener publication, directory/atomic update failure with owner/session retention, successful durable username update and post-commit session invalidation, and restart after a failed password update. `fsutil` additionally proves temporary-file cleanup after a failed atomic replacement. The focused admin-auth suite passed 18/18; the startup-failure test passed 1/1. Repository Clippy remains blocked by pre-existing `TlsCover::client_hello_custom` dead code and two unrelated `dns_runtime.rs` needless-borrow lints under `-D warnings`.

## Implementation Reconciliation (2026-08-02, standalone FEC file configuration)

- **Loader ownership:** `src/main_parts/runtime.rs::load_runtime_profiles()` now returns `std::io::Result` and propagates unified-config and standalone `--fec-config` errors to both client and server startup callers. An explicit FEC file is parsed and validated before the runtime profile tuple is returned; missing, malformed, or semantically invalid input cannot fall back to `FecConfig::product_default()`.
- **Parser and bounds:** `src/fec/parts/gf16_and_config.rs` rejects unknown `adaptive_fec.modes[].name` and `initial_mode` values, preserves an explicit `stream_every = 0` long enough for validation to reject it, supports the complete public mode set, and validates zero/nonzero windows against the wire source bound plus the product Fountain bound.
- **Source provenance:** The accepted source is emitted as `Accepted FEC policy source=product-default`, `standalone-file:<path>`, or `unified-config:<path>`. Supplying both `--config` and `--fec-config` fails before either source is silently ignored.
- **Regression proof:** The focused standalone parser suite passed 3/3, all 281 FEC-filtered library tests passed, and the standalone loader suite passed 5/5. `cargo clippy --bin quicfuscate --tests -- -D warnings -A dead_code -A clippy::needless_borrow`, `cargo fmt -- --check`, and `git diff --check` passed; the unchanged TLS Cover dead-code warning remains outside this task.

## Implementation Reconciliation (2026-08-03, client CA ownership and fail-closed loading)

- **Standalone startup boundary:** `src/main_parts/runtime.rs::load_client_ca_file()` propagates missing, unreadable, non-UTF-8, empty, malformed, and invalid-DER CA failures before the client kill switch is published. The accepted path remains on the owning `transport::Config`; no process-global client CA override is installed.
- **Provider ownership:** `src/transport/connection/parts/impl_lifecycle.rs::Connection::enable_tls()` passes the transport-owned CA path to `qftls::CombinedProvider` and its rustls provider. Initial construction and version-negotiation/profile/SNI rebuilds reload the same connection-scoped path. `TLS_CA_PATH_OVERRIDE` and `set_tls_ca_path()` were removed; server certificate/key globals remain a separate server identity boundary.
- **Caller reconciliation:** Standalone runtime, generic engine, `qf-e2e-client`, and the QKey HTTP/3 integration fixture all load CA files through their own transport configuration and fail closed on loader errors.
- **Regression proof:** The qftls suite passed 21/21, the transport configuration suite passed 50/50, the standalone CA-loader test passed 1/1, the generic engine missing-CA test passed 1/1, and the real QKey HTTP/3/TLS integration passed 1/1. `cargo fmt -- --check`, targeted Clippy with warnings denied plus the documented baseline suppressions, and `git diff --check` passed; the unchanged TLS Cover dead-code warning remains outside this task.

## Implementation Reconciliation (2026-08-03, client URL target validation)

- **Target ownership:** `src/main_parts/runtime.rs::resolve_client_target()` is the single validation boundary for the standalone client URL. It records machine-readable `default` versus `explicit` provenance, requires an HTTPS scheme and a syntactically present authority, rejects credentials and fragments, validates host and port, normalizes an empty path to `/`, and preserves queries in the HTTP/3 request path.
- **Identity projection:** The validated target supplies the SNI host, HTTP/3 authority/path, and resolved QUIC transport destination together. IPv6 SNI uses the unbracketed address while HTTP/3 `:authority` retains brackets and any explicit port. The required `--remote` value remains an explicit underlay input, but its resolved destination and alternate address-family candidate are retained on the same target object after URL validation.
- **Connection boundary:** `src/core_parts/connection.rs::QuicFuscateConnection::new_client_with_runtime()` accepts an optional HTTP/3 authority override so standalone URL authority cannot diverge from the validated target. Generic engine callers pass `None` and retain their existing host-header behavior.
- **Regression proof:** The standalone binary tests cover omitted/default provenance, HTTPS host and empty path, IPv4 with query and explicit port, IPv6 authority/SNI projection, invalid syntax, hostless forms, unsupported schemes, malformed authority, credentials, fragments, and validation ordering before remote resolution. `cargo check --lib --bins`, targeted URL tests (6/6), `cargo fmt -- --check`, and `git diff --check` passed; the unchanged TLS Cover dead-code warning remains outside this task.

## Implementation Reconciliation (2026-08-03, standalone client TUN activation)

- **Activation ownership:** `src/main_parts/runtime.rs::run_client()` treats an explicit `--tun` request as mandatory. `TunInterface::open()` configuration/backend errors and client reader-thread spawn errors now return through startup cleanup instead of converting the requested data plane to an absent optional bridge.
- **Readiness invariant:** Standalone connected policy requires the complete TUN resource set (receiver, writer, shutdown signal, and owned reader handle), a healthy reader-failure flag, an established QUIC connection, and an established MASQUE tunnel. A reader-loop error or callback send failure wakes the client loop and exits with a socket/data-plane error, so a dead reader cannot remain published as ready.
- **Failure cleanup:** Startup cleanup closes the QUIC connection, reapplies the kill switch's fail-closed disconnected policy, and uses the bounded stealth-runtime shutdown. Cleanup errors are appended without replacing the original TUN setup error. Reader ownership is retained until the normal bounded shutdown/join path completes.
- **Boundary reconciliation:** Generic `ClientRuntime::start()` already reports TUN requirement/open errors as an error state, and standalone server TUN setup already returns open/reader-spawn failures after routing rollback. The standalone client now follows the same explicit failure boundary; platform-unavailable behavior remains an explicit backend/configuration error.
- **Regression proof:** Binary tests cover primary-error preservation, reader-spawn failure propagation, owned reader join, complete-resource readiness, and invalid activation configuration. The TUN library suite passed 30/30 on macOS, including the existing non-Windows Wintun unsupported test. `cargo check --lib --bins`, the focused client-TUN suite (4/4), the complete runtime reload suite (29/29), targeted Clippy with warnings denied and documented baseline suppressions, `cargo fmt -- --check`, and `git diff --check` passed. The unchanged TLS Cover dead-code warning remains outside this task.

## Implementation Reconciliation (2026-08-03, standalone initial handshake send)

- **Startup gate:** `src/main_parts/runtime.rs::run_client()` now treats the first `conn.send()` result as mandatory. Construction errors, a zero-length result, and connected UDP send errors return before later HTTP/3 request, TUN, or readiness work. The existing stealth owner and kill-switch state are cleaned up through the bounded startup failure path.
- **Evidence separation:** `initial_client_packet_constructed()` validates and records the non-empty construction boundary. `initial_client_packet_sent()` retains the socket-send boundary and returns separate constructed/sent byte counts. `BYTES_SENT` increments only after the socket accepts the complete datagram, so a failed socket send is not reported as wire traffic.
- **Error retention:** Construction failures keep the transport error context in the returned `std::io::Error`; socket failures preserve their original `ErrorKind` and append the initial-handshake context. QUIC close, kill-switch fail-closed transition, and bounded stealth shutdown errors are appended without replacing the primary failure.
- **Regression proof:** Runtime tests cover construction failure, zero-length construction, socket-send failure, and successful evidence separation. The complete `runtime_reload_tests` suite passed 33/33; `cargo check --lib --bins`, targeted Clippy with warnings denied and documented baseline suppressions, `cargo fmt -- --check`, and `git diff --check` passed. The unchanged TLS Cover dead-code warning remains outside this task.

## Implementation Reconciliation (2026-08-03, DNS upstream failure result contract)

- **Shared result semantics:** `src/dns/mod.rs::resolve_via_dns_upstreams()` and the DoH endpoint loop now return successful upstream packets unchanged, including genuine NXDOMAIN, while resolver, configuration, and endpoint failures remain typed errors.
- **SERVFAIL construction:** `process_dns_query()` returns SERVFAIL for parseable upstream failures and for malformed packets that still contain a transaction ID. Synthesized answers preserve transaction ID, opcode, RD/CD semantics, QCLASS, and the original raw QTYPE; response packets are rejected at the query parser boundary.
- **Server parity:** `src/implementations/server/parts/dns_signals.rs` uses the shared plain-DNS result contract and returns SERVFAIL instead of synthesizing NXDOMAIN or dropping a parseable failure response. TODO-611 now owns the bounded server-TUN admission; its active policy is aggregate and source-IP keyed, not session keyed or per-upstream. TODO-668 retains active client-listener/generic-helper admission plus the source/session and budget boundary, TODO-669 retains timeout, response bounds, and measured allocation evidence, TODO-810 retains DoH response semantics beyond transaction ID, and TODO-770 retains complete wire-question preservation and admission hardening.
- **Targeted proof:** `CARGO_BUILD_JOBS=2 cargo test --locked --lib dns::tests -- --nocapture` passed 22/22. The complete server module passed 131/131, including upstream failure and genuine NXDOMAIN passthrough. `cargo fmt --all -- --check` and `git diff --check` passed. Clippy Matrix run `30811429734` passed all eight feature lanes on revision `5b3b8c2`; the broad CI workflow retains separate non-DNS baseline failures.

## Implementation Reconciliation (2026-08-03, bounded client fan-out queue)

- **Queue owner:** `live_auth.rs` gives the MASQUE datagram and framed HTTP/3 uplink callbacks one shared `Arc<Mutex<ClientFanoutQueueState>>`; route filtering happens before any payload clone.
- **Admission and drain bounds:** The queue accepts at most 256 entries/384 KiB globally and 32 entries/64 KiB per source socket. `live_state.rs` pops at most 64 FIFO packets per drain and updates total/per-source byte accounting, with no backlog-to-`Vec` materialization; housekeeping drains even without a new UDP datagram.
- **Telemetry and proof:** Rejected fan-out packets increment `quicfuscate_client_fanout_dropped_total`. Four focused tests, 133 server tests, and 2,156 library tests passed locally; all-target checking, formatting, and diff hygiene passed. Strict local Clippy retains only the pre-existing TLS Cover dead-code lint. Remote Clippy Matrix run `30815583508` passed all eight feature lanes on source revision `c216cc5`.

## Implementation Reconciliation (2026-08-03, server TUN DNS intercept admission)

- **Admission owner:** Each standalone server loop creates one `DnsInterceptAdmission` shared by all client MASQUE/TUN uplink callbacks. Before `spawn_blocking`, it requires one of 128 global semaphore permits, one token from the 2,000 PPS global bucket with a 4,000-query burst, and one token from the 100 PPS per-source-IP bucket with a 200-query burst.
- **Drop and lifecycle behavior:** Admission failure returns `true` to consume the DNS packet without generic fan-out or TUN forwarding, records `quicfuscate_dns_intercept_dropped_total`, and emits only a debug log. The semaphore permit is moved into the blocking task and released after upstream resolution and response queue admission. Idle source buckets are pruned after 60 seconds with a five-second prune cadence.
- **Scope boundary:** The optional response cache was evaluated but not introduced because a correct cache requires explicit TTL handling plus transaction-ID and original-question projection. TODO-771 now makes `ClientDnsRuntime` an active `process_dns_query()` caller, but its listener still has no explicit query admission contract; TODO-668 owns that client boundary and the server source/session/per-upstream budget semantics. Accepted worker outcome ownership, panic/cancellation telemetry, and shutdown drain remain TODO-650; timeout/allocation/response bounds remain TODO-669, DoH semantic response validation remains TODO-810, and complete wire semantics remain TODO-770.
- **Worker ownership audit:** The current semaphore bounds accepted work but does not own the returned `JoinHandle`. `finish_drain()` and `ServerRuntime::stop()` do not await DNS workers, so a started synchronous resolver can outlive the final queue flush and a queued worker can be cancelled by runtime teardown without a DNS-specific outcome. TODO-650 owns this boundary; TODO-699 owns the separate engine thread timeout state.
- **Targeted proof:** Admission tests passed 2/2, the drop metric test passed 1/1, DNS module tests passed 22/22, and the complete server module passed 131/131. `cargo fmt --all -- --check` and `git diff --check` passed. Clippy Matrix run `30812779253` passed all eight feature lanes on source revision `69e3511`.

## Deep Audit Reconciliation (2026-08-03, io_uring ownership and completion contracts)

- **Sender ownership:** `src/optimize/uring_batch.rs` copies connected and unconnected send payloads into sender-owned slots before publishing `iovec` pointers. Standard SendMsg and SendMsgZc metadata cannot borrow the caller's batch after the call boundary.
- **Failed submissions:** Submit or completion-protocol errors quarantine the sender, attempt synchronous cancellation of accepted requests, drain available CQEs, and prevent scratch reuse. If cancellation cannot prove quiescence at drop, pointer-bearing storage is leaked deliberately rather than released while a kernel request may still reference it.
- **Zero-copy lifetime:** SendMsgZc uses `CQE_F_MORE` on the primary CQE to decide whether a `CQE_F_NOTIF` release CQE is required, waits for every announced notification including errored primaries, and rejects stale, duplicate, or unannounced notification state.
- **Receive slots:** `UringRecvBatch` validates completion user data, tracks armed/pending state one-to-one, re-arms positive, negative, and zero-length receives, resets source-address storage on every consumed slot, and destroys the ring before returning pool blocks. A bounded Linux regression consumes a full receive depth of zero-length datagrams before proving a later marker datagram is delivered.
- **Client FFI:** `io_driver.rs` documents eventfd `read`, `dup`, and `OwnedFd::from_raw_fd` ownership; only an exact eight-byte eventfd read reaches completion draining.
- **Separate owners:** Runtime async paths isolate synchronous submit/wait/CQE draining behind the bounded `UringBatchWorker`; direct sender calls remain explicit synchronous compatibility primitives. The contiguous-prefix API can retry a later packet after an unordered earlier error; TODO-798 owns exact per-slot disposition and duplicate prevention.
- **Evidence boundary:** macOS client io_driver focused tests passed 12/12; the complete host library gate passed 2,144/2,144; `cargo check --all-targets --features rust-tests`, targeted Clippy with warnings denied and documented baseline suppressions, `cargo fmt --all -- --check`, and `git diff --check` passed. Remote Clippy Matrix run `30791153445`, job `91614771683`, passed the `io_uring` feature lane. Follow-up CI run `30807353972`, Linux fastpath job `91665699625`, passed on source revision `c4209ebba7f5b32dbb0400cbd94400271286b242`: the rearm proof recorded four kernel-consumed zero-length CQEs and a delivered marker, and the opt-in SendMsgZc proof recorded three primary sends, four notifications, three delivered payloads, and a classified CQE error. The regular lane passed 529 library tests, `rt-transport-uring` 14/14, and `rt-io-hotpath-kernel-integration` 1/1. The local macOS host still cannot compile the Linux target because its GNU/Linux C sysroot is absent (`ring` cannot find `assert.h`).
- **Tracker gate:** `bash scripts/tests/audits/verify-audit-completeness.sh` currently fails before corpus validation with `unexpected tracker section 'Blocked'`; an independent filename/register reconciliation finds 709 tracker headings, 370 current detail files, and 340 archived filename-ID detail files with no filename-ID orphan or duplicate. The preceding section/status snapshot found Active `1`/`IN_PROGRESS`, Blocked `1`/`BLOCKED`, Queue `158` (`144` `OPEN`, `14` `QUEUED`), and Completed `549`; TODO-801 is now closed by the Linux evidence recorded above. TODO-799 owns alignment of the validator with the canonical task lifecycle, and TODO-800 owns the stale macOS runtime-reload fixtures exposed by the same CI run. The legacy archive-schema observations remain unchanged.
- **Other CI failures:** The same completed CI run also fails the Windows core check at `src/privilege/drop.rs:676` because `CurrentIds` is unavailable (existing TODO-593/TODO-684 boundary), and strict macOS Clippy at `src/stealth/tls_cover.rs:393` plus `src/implementations/client/dns_runtime.rs:279,289` (existing TODO-709/TODO-752/TODO-787 lint boundary). These failures are recorded as existing owners and were not changed in this audit.
- **TODO-607 root cause:** `RoutingManager::teardown()` calls `recover_persisted_ownership()`, whose startup-only `reject_active_owner()` check rejects the current process PID before its graceful release. This exactly explains the native residue `/run/quicfuscate/routing/7174756e30.json`; current-owner release and stale-owner recovery must be separated before the lifecycle gate can close.
- **TODO-607 follow-up:** `RoutingManager::teardown()` removes the fixed firewall resource before the active-owner guard can succeed. On the current failure path this creates partial cleanup, and setup rollback reuses the same ordering. TODO-802 additionally tracks that fixed iptables/nftables identities are not bound to the per-TUN durable owner, so independent managers can replace or remove one another's firewall state.
- **TODO-607 evidence gap:** `scripts/tests/tun-e2e-netns.sh` checks only durable-record removal after graceful shutdown and then deletes the test namespaces; it does not directly prove pre-deletion cleanup of the managed TUN, address/link, forwarding, or selected firewall resources. The native zero-residue acceptance therefore remains open even after the current-owner teardown fix.
- **Audit-runner evidence:** `bash scripts/tests/audits/audit-runtime-guardrails.sh --output-dir /tmp/quicfuscate-audit-guardrails` completed with one Critical and one Warning. The Critical is a checker false negative: its exact-column regex misses the correctly indented `SERVER_PID=$!` assignment inside `start_server()`; the Warning is the known module-wide `dead_code` allowance in `src/simd/x86_ack.rs:3`, owned by TODO-752. TODO-730 owns the guardrail result-integrity repair.
- **Comprehensive audit evidence:** The strict `audit-all-comprehensive.sh` run on revision `1b91a55` completed its full report with exit `1`, `4` Critical classifications, and `7` Warnings. Its current `strict-runtime-clippy.log` contains `22` diagnostics (`1` `unwrap`, `20` `expect`, `1` `panic`); the previous `68` count is historical scope evidence. TODO-730 owns command/result integrity and raw-text heuristic classification, TODO-676 owns the AMX `static mut` and dispatch/runtime boundary, TODO-816 owns kernel semantics, TODO-817 owns detector process bounds, TODO-818 owns the AMX proof lane, TODO-819 owns profile/documentation truth, TODO-757 owns the strict panic/invariant cluster, and TODO-803 owns the two redundant-clone findings. The run is not a clean project gate.
- **Readiness and analysis evidence:** On 2026-08-03 at revision `6b18d373da46242c47283ee5093d359e6a0792a0`, `audit-readiness-gates.sh` passed Clippy Strict, Cargo Audit, Cargo Deny, and deny-only Cargo Geiger, while the explicit `--strict-geiger` rerun returned `1` for 31 dependency unsafe surfaces. The static coverage helper reported 7,029 functions and 2,575 test functions without executing coverage; the script-quality helper reported 122 scripts with 10 missing strict-mode cases, 21 missing descriptions, 14 missing help handlers, 24 naming violations, 10 missing usage lines, and 2 unknown-argument cases; the suite matrix found 28 suites, 21 invoked by the full-suite utility, and 7 omitted. The dead-code helper remains incomplete on Darwin because its BSD `sed` dependency scan fails and leaves unterminated JSON. TODO-730 owns these result and scope boundaries; TODO-799 owns the completeness validator's `Blocked` section failure. The project audit is not complete.
- **Suite exclusion evidence:** `test-graceful-shutdown.sh --help` exits on the missing default binary instead of returning usage. `test-fec-all.sh` is a dispatcher with constituent modes already called directly; `test-linux-installer.sh` owns the executable native CI lane and calls its systemd-nspawn guest helper. No executable `.github/workflows` or full-suite invocation is present for `test-ddos-admission.sh`, `test-graceful-shutdown.sh`, `test-qkey-auth-policy.sh`, or `test-qkey-registry-encryption.sh`. TODO-730 owns the open inclusion/exclusion contract and missing live-lane ownership.
- **Omega proof boundary:** Read-only inspection found two remote `main` checkouts: `SOFTWARE/QuicFuscate` at `9b57474` with 97 untracked status paths, 43,722 untracked files, and a running server; `CODE/QuicFuscate` at `d36652d` with 20 tracked modifications and a missing Git object during diff inspection. TODO-804 owns singular checkout selection, Git readability, exact attribution, and bounded remote cleanup. No remote state was modified.
- **Fast full-suite evidence:** `util-run-full-suite.sh --fast` at revision `aab0c51018ad146607f7f4aef885f85ae5cc2521` passed the build check, 2,144/2,144 root library tests, Core Integration, Desktop/Admin validation, Stealth Fast, and Crypto Fast, then exited `1` in `test-optimization.sh` because `environment=json:${COMMAND_ENVIRONMENT_JSON:-{}}` supplied an extra closing brace to the shared JSON writer. TODO-782 owns the three consumer call sites (`test-optimization.sh`, `test-performance-regression.sh`, and `test-security-fuzzing.sh`); TODO-730 owns aggregate result classification. The project audit is not complete.
- **Frontend dependency evidence:** `bun audit --json` exits `1` with `29` advisories across nine locked package keys: `@sveltejs/kit@2.55.0`, `cookie@0.6.0`, `devalue@5.6.4`, `esbuild@0.27.4`, `picomatch@4.0.3`, `postcss@8.5.8`, `svelte@5.53.12`, `undici@7.24.3`, and `vite@7.3.1`. `bun pm scan` is unavailable because no scanner is configured. Applicability across static output, Tauri packaging, development servers, and test-only dependencies remains open under TODO-805; no dependency or frontend implementation was changed during this audit.
- **Frontend dependency gate:** CI currently installs and builds the Bun workspaces but invokes only Cargo dependency auditing; no workflow invokes `bun audit` or a configured `bun pm scan`. The frontend advisory result therefore has no required CI failure lane and remains open under TODO-805.

## Implementation Reconciliation (2026-08-03, crypto key and IV constructor boundaries)

- **Typed boundary:** `src/crypto/aead.rs` owns `KeyMaterialError` plus exact-length helpers. `ChaCha20Poly1305` requires a 32-byte key and 12-byte IV; `AesGcm128`, AEGIS L/X4/X8 wrappers, and `MorusAead` require a 16-byte key and 12-byte IV. Public data-AEAD selection and the benchmark builder enforce the same 16/12 contract before copying into fixed arrays.
- **Header protection:** `AesHp::new` rejects secrets shorter than 16 bytes without a panic. Its documented raw-secret API still consumes the first 16 bytes of a longer secret; all packet setup paths derive the exact 16-byte header-protection key first and use the typed array constructor, so a 32-byte traffic secret is never silently installed as an HP key.
- **Propagation:** QKey registry encryption/decryption, TLS cover ciphers, packet initial/handshake/0-RTT/1-RTT setup, examples, runtime fixtures, property/security fixtures, and the retained backend benchmark all propagate or prove the fallible constructor boundary. No key/IV `unwrap_or(0)` construction fallback remains; QUIC KDF traffic-secret derivation now enforces 32-byte inputs under TODO-633, and header-protection sample handling remains separately owned by TODO-629.
- **Verification:** Locked all-target/all-feature check and strict Clippy passed. Serial crypto tests passed 143/143, QKey registry storage 11/11, packet tests 25/25, baseline/property/security integration targets 6/6, 12/12, and 24/24, and all four retained backend benchmark smokes executed successfully. The Criterion benchmark target compiled with `--no-run`. The full local library passed 2,194/2,196; DNS resolution remains TODO-807 and rustls ClientHello readiness remains TODO-768. The fuzz manifest remains unbuildable at its pre-existing path boundary owned by TODO-758.

## Implementation Reconciliation (2026-08-03, header-protection sample and packet-number bounds)

- **Typed sample boundary:** The crypto and transport `HeaderProtector` traits now return errors. `AesHp` requires an exact 16-byte sample and exact 5-byte mask, while the Rustls-backed provider rejects every non-exact sample length and propagates mask-derivation failures as `ConnectionError::CryptoError`; no zero mask or zero-padded sample is synthesized.
- **Receive boundary:** `unprotect_and_decrypt_with_key()` requires the complete 16-byte sample window before reading or mutating the protected header, validates the decoded 1-4 byte packet-number range before mutation, and propagates failures through the 1-RTT fast path, fallback key path, and previous-key candidates. `remove_hp()` has the same sample and packet-number bounds.
- **Send boundary:** `protect_header()` validates packet-number length, offset, and buffer bounds before mutation. `apply_hp()` now propagates sample and packet-number-buffer errors. The short-header sealing path pads to the minimum sample-bearing ciphertext length before AEAD sealing and no longer silently emits an unprotected packet when the payload is short.
- **Regression proof:** The locked all-target/all-feature check and strict Clippy passed; 144/144 Crypto tests, 29/29 packet tests, and baseline/property/security integration targets 6/6, 12/12, and 24/24 passed. Format and diff checks passed. The full local library passed 2,199/2,201; the two unrelated failures remain TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness.
- **Scope boundary:** No UI or Omega state was changed. TODO-633's local KDF implementation still awaits its full matrix and native/external proof gates; fuzz-manifest dependency resolution remains TODO-758, and the broader project audit remains open under its existing task owners.

## Implementation Reconciliation (2026-08-03, GHASH dispatch configuration)

- **Test boundary:** `GHASH_TEST_OVERRIDE` and `__test_set_ghash_override` remain behind `cfg(test)` on x86_64; the prior claim that the test hook was compiled into production builds is not confirmed.
- **x86 dispatch:** `GHASH_OVERRIDE` stores a parsed `GhashOverride` in `OnceLock`. `QUICFUSCATE_GHASH` is read and interpreted once, while normal GHASH calls use the immutable enum without environment access, string allocation, or case normalization.
- **ARM dispatch:** `GHASH_PMULL_ENABLED` caches the startup value of `QUICFUSCATE_GHASH_PMULL`, removing the per-call environment read from the AArch64 GHASH path. CPU feature selection remains owned by the existing process-cached `FeatureDetector`.
- **Benchmark:** `examples/microbench.rs ghash-short` measures repeated 32-byte AAD plus 128-byte ciphertext GHASH calls; `scripts/benchmarks/micro/micro-ghash.sh` runs it before the configurable size matrix and retains the CSV/JSON/log evidence.
- **Regression proof:** Native all-target check and strict Clippy passed. The complete Crypto group passed 144/144, GCM passed 11/11 with `QUICFUSCATE_GHASH_PMULL=0` and `=1`, the release short-packet benchmark completed 1,000 packets, and the runner smoke completed with isolated artifacts. The x86_64-Apple cross-check remains blocked by pre-existing `avx10.1-*` feature-macro errors and the existing non-constant `_mm_prefetch` argument at `src/optimize/parts/cache_and_const.rs:54`; no x86 runtime proof is claimed on this ARM host.
- **Scope boundary:** No UI, Omega, or unrelated crypto backend behavior changed. The broader project audit remains open under its existing task owners.

## Implementation Reconciliation (2026-08-03, QUIC nonce and packet-number lifecycle)

- **Wiring:** `transport::connection::Connection` owns the three outbound packet-number counters and routes Initial/Handshake, normal 1-RTT, and targeted path-control sends through shared `next_send_packet_number()` and `advance_send_packet_number()` guards in `parts/types.rs`.
- **Crypto relation:** `crypto::make_nonce16` consumes the packet number as a stateless primitive. The connection owner preserves packet-number monotonicity across 1-RTT `CryptoContext::key_update_1rtt_write()` and only resets counters when the corresponding key/connection epoch is replaced.
- **Fail-closed edge:** `pnspace::PktNumSpace::MAX_PACKET_NUMBER` is shared by receive validation and outbound validation. Values above `2^62 - 1`, checked counter overflow, and invalid send state return `ConnectionError::AeadLimitReached`; no wrapping packet number can reach AEAD sealing.
- **Proof surface:** `src/transport/connection/parts/tests.rs` covers key-update preservation, the last valid packet number, overflow non-wrapping, and pre-mutation rejection. Locked all-target/all-feature check, strict Clippy, format, and diff checks passed; Connection 119/119, Crypto 144/144, Packet 28/28, and baseline/property/security integration targets 6/6, 12/12, and 24/24 passed. The full local library reached 2,203/2,205; TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness remain unrelated blockers.

## Audit Reconciliation (2026-08-03, FEC complete audit)

- TODO-686 is complete as a read-only audit across every current FEC source and test module, all FEC `unsafe` sites and direct callers, public decoder/matrix/wire/Fountain boundaries, feature gates, malformed-input tests, fuzz and shell/benchmark/netns proof, documentation, related owners, and history.
- The audit separates current product-wire validation from direct public API reachability and does not claim that unsafe contracts, decoder mathematics, resource ownership, native ISA paths, negative proof, or documentation are fixed. Open remediation is tracked by TODO-634, TODO-636, TODO-637, TODO-690, TODO-715, TODO-832, and TODO-855 through TODO-860, with shared SIMD, AMX, transport, and environment owners retained.
- No production implementation, build, test, native probe, privileged network run, commit, or push was performed for TODO-686. The complete findings and evidence boundary are in `docs/todo/todo-686-fec-unsafe-audit.md`.

## Audit Reconciliation (2026-08-03, audit-file FFI complete audit)

- TODO-688 is complete as a read-only audit across the complete current audit implementation and tests, the audit probe, direct startup/runtime callers, the limits false-positive source, audit suites and guardrails, documentation, related owners, and relevant history.
- The confirmed inventory is three production FFI sites in `src/audit/mod.rs` (`geteuid`, `chown`, and Windows `MoveFileExW`) plus one Unix-only test guard. No production `unsafe` operation was found in `src/implementations/server/limits.rs`.
- Open remediation is split by boundary: TODO-861 owns local FFI safety contracts, Windows interior-NUL rejection, warning-only permission/ownership failure semantics, and platform-negative proof; TODO-671 owns direct existing-file mode; TODO-675 and TODO-726 own writer lifecycle and terminal admission; TODO-728 owns pathname-to-inode binding; TODO-813, TODO-814, and TODO-815 own configuration, payload, and shutdown-order bounds.
- No production implementation, build, test, native Windows/root probe, privileged network run, commit, or push was performed for TODO-688. The complete evidence boundary is in `docs/todo/todo-688-audit-server-unsafe.md`.

## Audit Reconciliation (2026-08-03, auxiliary unsafe audit complete)

- TODO-689 is complete as a read-only audit across the remaining auxiliary
  source and test modules, all real unsafe operations and false-positive
  matches, direct prefetch callers, SIMD feature/profile intersections, Windows
  NUMA FFI, global-pool and auto-tuner initialization, test-environment
  mutation, the test-only constant-buffer helper, feature/platform gates, audit
  scripts, CI workflows, documentation, related TODO owners, and history.
- The confirmed open boundaries are split without overlap: TODO-862 owns the
  shared portable prefetch facade and non-PMTU callers; TODO-863 owns Windows
  NUMA result and safety proof; TODO-864 owns global-pool/auto-tuner lifecycle
  and telemetry side effects; TODO-865 owns the test-only `ConstPacketPool`
  capacity and zero-size contract. TODO-670/TODO-811, TODO-826/TODO-827,
  TODO-834/TODO-835/TODO-836, TODO-841, TODO-843, and TODO-752 retain their
  existing boundaries.
- The whole-project source audit is read-complete through this owner, but the
  coverage/register owner TODO-754 remains active because the current
  `verify-audit-completeness.sh` invocation stops on the canonical `Blocked`
  section before validating the corpus. TODO-730 and TODO-799 retain that
  machine-checkable gate boundary.
- No production implementation, build, test, native architecture probe,
  privileged run, commit, or push was performed for TODO-689. Completion means
  audit coverage and ownership are recorded, not that any remediation or
  runtime proof is closed.

## Audit Register Reconciliation (2026-08-04, TODO-799 complete)

- TODO-799 repaired the completeness validator's canonical tracker contract. It now accepts and validates `Active`/`ACTIVE|IN_PROGRESS`, `Blocked`/`BLOCKED`, `Queue`/`OPEN|QUEUED|AUDIT_COMPLETE`, and `Completed`/`DONE|SCRAP|COMPLETE|COMPLETED|CLOSED|AUDIT_COMPLETE`, enforces section order and presence, and derives the global status allowlist from the same contract.
- The live validator passes: tracker `769` headings across Active `1`, Blocked `3`, Queue `190`, and Completed `575`; current details `411/411`; archived Markdown files `393` with `36` explicit exceptions; tracked paths `927`; ignored paths `37,803`; untracked paths `0`. The fixture suite covers a valid blocked/audit-status register plus malformed section, duplicate ID, missing detail, and status mismatch failures.
- TODO-754 is active again. This closes the register/schema/Git-scope gate only; TODO-730, TODO-734, TODO-749, TODO-758, TODO-759, TODO-760, TODO-761, TODO-762, TODO-763, TODO-764, TODO-782, TODO-798, TODO-804, TODO-805, and the other named native/runtime/external owners remain open.

## Audit Infrastructure Wiring (2026-08-04, TODO-730)

- `scripts/tests/audits/audit-all-comprehensive.sh` is the strict aggregate entrypoint. It calls `audit-rust-scope.py`, `audit-secret-scope.py`, `analysis-dialect-validation.py`, `audit-runtime-guardrails.sh`, `audit-result-contract.py`, and the dependency/tooling probes, then writes one fail-closed JSON result.
- `scripts/tests/analysis/` owns portable analysis contracts: `analysis-dead-code-report.sh` emits a completed report, `analysis-scripts-quality.sh` emits strict/advisory findings, and `analysis-suite-matrix.sh` accounts for all 28 suite scripts and their seven explicit exclusions.
- `scripts/tests/utils/util-run-full-suite.sh` invokes the comprehensive audit in strict mode and propagates stealth benchmark preflight failure. Optimization, performance-regression, and security-fuzzing suites serialize `COMMAND_ENVIRONMENT_JSON` through the shared JSON writer without malformed default expansion.
- `scripts/tests/audits/audit-readiness-gates.sh` exposes deny-only versus strict Geiger policy, retains dependency-unsafe package names, and classifies unavailable advisory databases as `UNAVAILABLE`. Local PowerShell parser absence is retained by the dialect result rather than treated as a pass.
- Contract fixtures under `scripts/tests/audits/fixtures/`, `scripts/tests/analysis/fixtures/`, and `scripts/tests/fast/fixtures/` prove failable command status, Rust and secret scope, parser dialects, scoped PID ownership, benchmark propagation, environment JSON, and strict/advisory result semantics.
- Current local proof is deliberately non-green: the complete strict runner returns `FAIL`; readiness returns `UNAVAILABLE` in deny-only mode and `FAIL` in strict-Geiger mode. Product remediation, native/external runtime evidence, Graphify/feature boundaries, and Omega checkout attribution remain with their existing TODO owners.
- Post-staging validator refresh: `verify-audit-completeness.sh` passes with tracker `769`, Active `1`, Blocked `4`, Queue `189`, Completed `575`, current details `411/411`, tracked paths `956`, ignored paths `28,123`, and zero non-ignored untracked paths. The earlier `927`/`37,803` counts in the preceding register snapshot are historical pre-infrastructure-change values.

## Implementation Reconciliation (2026-08-04, QUIC KDF secret-length validation)

- **Wiring:** `src/crypto/quic_kdf.rs` exact-validates all traffic-secret derivations; `src/transport/packet.rs` maps KDF errors into `ConnectionError`, and the Initial/Retry/lifecycle, packet-installation, key-update, and `KeyScheduleHooks` edges return the failure instead of coercing input.
- **Ownership:** Invalid material is rejected before mutation of the corresponding packet-protection slot. The established previous-read-key AEAD window remains unchanged because its retained candidates do not include previous HP keys.
- **Verification:** Local library check, strict library Clippy, 26 KDF tests, 29 packet tests, and 4 connection key-update tests pass. Full workspace/all-target tests completed with 2,204/2,206 passing; the two failures are the existing TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness boundaries. Full workspace/all-target strict Clippy reports only the existing backend type-complexity and DNS-runtime needless-borrow findings; no TODO-633 diagnostic was emitted. Native/external proof remains open under TODO-633 and the existing environment blockers.

## Implementation Reconciliation (2026-08-04, bounded Fountain decoder state)

- **Admission wiring:** `WirePacketMeta::validate()` keeps Fountain's global deterministic symbol ID in `sequence` and validates the bounded repair ordinal. `ReceiveWindow` binds each ordinal to one global ID before allocating a repair packet; duplicate IDs and ordinal reuse are rejected without entering `InterleavedDecoder`.
- **Decoder wiring:** `InterleavedDecoder -> LazyDecoder -> DecoderVariant::Fountain -> LTDecoder` now receives the profile repair capacity. `LTDecoder` owns bounded symbol maps, FIFO order, queue membership, retained bytes, and propagation-work accounting. Eviction, rejection, and propagation work are exported through dedicated FEC telemetry counters.
- **Proof:** Fountain 25/25, wire 22/22, complete FEC 241/241, strict library Clippy, and all-target workspace check pass. The full all-target workspace test run is 2,207/2,209 because the unchanged TODO-807 DNS and TODO-768 Rustls baseline tests fail; full all-target strict Clippy has only the existing backend/DNS-runtime findings. No UI, Omega, or remote state was changed.

## Implementation Reconciliation (2026-08-04, linear FEC equation peeling)

- **Decoder wiring:** The GF8, GF4, and GF16 `try_peel_all` loops use bounded `VecDeque` passes. A pass preserves unresolved-equation order while avoiding `remove`/`insert` shifts; all solver and interleaved/lazy callers continue to consume the same equation sequence.
- **Measured path:** The dedicated `fec_peeling/gf8_k256_linear_equation_traversal` Criterion case measures 128 repair equations plus 128 systematic sources. Old Vec: 17.598 ms; new VecDeque: 16.080 ms; approximately 8.6% faster under identical 30-sample settings. The benchmark is registered in `fec_pipeline` and initializes FEC tables through the production constructor.
- **Verification boundary:** FEC 241/241, workspace check, strict library Clippy, format, and diff checks pass. Full workspace/all-target tests are 2,207/2,209 due only to the existing TODO-807 DNS and TODO-768 Rustls failures. Omega/native proof is not claimed, and no UI or remote state changed.

## Implementation Reconciliation (2026-08-04, Wiedemann scratch ownership)

- **Decoder wiring:** `try_eliminate_wiedemann -> Rayon worker-sized chunks -> map_init -> WiedemannScratch -> solve_wiedemann_system` keeps mutable column/SpMV scratch producer-local. The immutable equation lookup remains shared, while each payload-byte solve receives the producer's scratch by mutable reference.
- **Allocation telemetry:** `src/optimize/telemetry.rs` exports separate Wiedemann counters for column buffers, the scalar accumulator, matrix/RHS, Krylov vectors, per-iteration vectors, candidate temporaries, and AMX scratch. This maps the allocation profile to the actual solver stages.
- **Benchmark wiring:** `benches/fec_pipeline.rs` registers `fec_wiedemann_allocations/high_loss/{128,256}` beside the existing peeling benchmark. The benchmark forces the Wiedemann policy only on its feature-gated decoder wrapper and reports one-shot counter deltas before Criterion timing.
- **Measured boundary:** The same-host profile reports 75% fewer logical column-buffer and SpMV-accumulator events after worker-sized chunking. Latency stayed within approximately +2.2% at `k=128` and +0.6% at `k=256` in the direct pre/post run; no throughput improvement is claimed. The first harness run exposed and fixed missing GF-table initialization before recording the successful measurement.
- **Proof:** Wiedemann-focused tests 2/2, FEC 242/242, telemetry export 1/1, all-target check, strict library Clippy, benchmark compile/run, format, and diff checks pass. Full workspace tests are 2,208/2,210 because TODO-807 DNS and TODO-768 Rustls remain unchanged; all-target Clippy retains three existing client diagnostics and benchmark Clippy two existing dead-code diagnostics.
- **Boundary:** No FEC equation mathematics, validation/fallback semantics, UI, Omega state, or remote state is changed by this wiring. Omega/native proof is unavailable because SSH fails with `No user exists for uid 501`; TODO-637 remains blocked at that external boundary.

## Implementation Reconciliation (2026-08-04, receive-side Retry and destination-CID ownership)

- **Receive wiring:** The client Retry branch in `src/transport/connection/parts/impl_recv.rs` consumes the owned pre-parsed header after tag verification, moving its token into configuration and retaining the existing SCID-to-DCID, Initial-key, and packet-number reset sequence.
- **CID representation:** `src/transport/pn.rs::cid::ConnectionIdSet` now uses `HashSet<ConnectionId>` rather than `HashSet<Vec<u8>>`. `ConnectionId` remains the inline 20-byte maximum `Copy + Hash` protocol value, so destination-CID tracking no longer allocates a vector at each `set_destination_cid()` call.
- **Lifecycle edges:** Initial setup, Retry adoption, first long-header CID learning, and version-negotiation reset still converge on the same `set_destination_cid()` and `ConnectionIdSet` lifecycle; no caller was removed or broadened.
- **Proof edges:** The transport unit test exercises a valid authenticated Retry and verifies token, CID, set membership, and Initial packet-number reset. The `ci_regression` target now measures the full authenticated Retry receive at `[10.840, 10.887, 10.912] us` per call plus the 16-CID insert/lookup surface at `[1.2300, 1.2365, 1.2461] us` and `[251.56, 262.58, 277.34] ns` under the bounded 10-sample run. The CID module test covers value identity and duplicates.
- **Verification boundary:** The authenticated Retry/CID tests pass, the transport filter passes 538/538, workspace all-target checking and library strict Clippy pass, and the CID benchmark runs successfully. The full workspace/all-target run is 2,210/2,212 because unchanged TODO-807 DNS and TODO-768 Rustls tests fail; all-target and benchmark Clippy retain only their previously recorded unrelated diagnostics. Omega/native proof remains unavailable.
- **Scope boundary:** This reconciliation does not change header parsing, Initial-send token cloning, `ConnectionId::from_ref`, UI, Omega, remote state, or unrelated allocation findings.

## Implementation Reconciliation (2026-08-04, StealthShaper RNG seed lifecycle)

- **Construction wiring:** `Recovery::set_stealth_mode()` creates fallible BBR2, BBR3, and CUBIC shapers through `StealthShaper::new()`. A failed seed returns the original controller and restores it into `Recovery`; the temporary Reno placeholder is never retained.
- **Error wiring:** `StealthShaperError` crosses `Recovery`, `Connection::set_cc_stealth_profile()`, and `Connection::apply_brain_stealth_runtime_delta()`. The Brain observer handles the error after the transport owner emits the operator-visible warning, while the rest of the runtime delta remains governed by the existing connection owner.
- **Reno wiring:** `CcImpl::StealthReno` uses `StealthShaper::new_without_rng()`. Reno remains a state-continuity wrapper only; `Recovery::on_ack()` does not invoke paced stealth post-processing for it.
- **Proof wiring:** Unit and integration tests force the canonical test entropy failure and verify direct error reporting, base-controller retention for all paced algorithms, entropy-independent Reno activation, and Brain-driven rejection. The stealth library group passes 266/266, CC/Recovery integration passes 20/20 and 2/2, workspace all-target checking passes, and strict library Clippy passes. The full library run passes 2,214/2,216; TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello remain the two unchanged baseline failures. The no-fail-fast workspace run executes every target and records `quicfuscate` binary 41/43, with the two existing TODO-800 runtime-reload PMTU fixture failures.
- **Global gate boundary:** Workspace all-target strict Clippy retains only the three existing client backend/DNS-runtime diagnostics. Authorized Omega/native proof remains unavailable because the local SSH client fails with `No user exists for uid 501`; GitHub push remains unavailable because `github.com` DNS resolution fails.
- **Boundary:** No engine or standalone configuration field is added because the selected policy is fixed and non-cryptographic. Security-critical entropy remains governed by `src/rng.rs` and its fail-closed callers; transport padding/timing RNG remains TODO-479-owned.

## Implementation Reconciliation (2026-08-04, H3 masquerade cookie time source)

- **Wiring:** The normal `StealthManager::get_http3_header_list()` path reaches `Http3Masquerade::generate_headers()`, whose optional cookie now consumes the canonical `crate::time_source::now_system()` value.
- **Failure boundary:** `duration_since(UNIX_EPOCH)` failure omits the optional cookie and preserves the rest of the request header list. The pure `generate_realistic_cookies_at()` formatter remains unchanged.
- **Proof wiring:** A fixed test `TimeSource` drives a normal epoch through the public header list and verifies that a pre-Epoch source produces no cookie while retaining the user-agent header. The H3 filter passes 9/9, the external persona-header target passes 13/13, and the complete stealth filter passes 268/268. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: library 2,216/2,218 with TODO-807 and TODO-768 failures, and binary 41/43 with TODO-800 failures. Cover scheduler clock ownership is not changed.
- **Test isolation:** The forced secure-entropy hook is thread-local under `cfg(test)`, keeping parallel normal-randomness tests independent.
- **Scope boundary:** This reconciliation is limited to HTTP/3 masquerade cookie timestamps; TODO-677 retains the broader direct-clock inventory.
- **Global gate boundary:** Workspace all-target strict Clippy retains only the three existing client backend/DNS-runtime diagnostics. Omega/native proof is unavailable because SSH fails with `No user exists for uid 501`; GitHub push remains unavailable because `github.com` DNS resolution fails.

## Implementation Reconciliation (2026-08-04, domain-fronting selection semantics)

- **Selection wiring:** `get_fronted_domain()` uses one `AtomicUsize::fetch_add(1)` per non-empty call, so serial consumers receive exact round-robin order without random jitter.
- **Concurrency wiring:** Concurrent callers reserve unique sequence slots; tests assert balanced domain coverage, while no completion-order guarantee is claimed.
- **Boundary wiring:** `random_domain()` remains an explicit random opt-in. Cover scheduler, SNI/Host, and WebTransport consume round-robin; MASQUE keeps its fixed first configured authority by design.
- **Empty/API wiring:** Empty managers return `cdn.cloudflare.com`; the actual owned-`String` methods are documented and stale allocation-free `_ref` claims are removed.
- **Verification status:** Exact serial/concurrent tests are added; the focused domain-fronting filter passes 9/9, the complete stealth filter 269/269, the stealth-config target 9/9, and the stealth-mode integration target 7/7. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: the library passes 2,217/2,219 with unchanged TODO-807 DNS and TODO-768 Rustls failures, and the `quicfuscate` binary passes 41/43 with the two unchanged TODO-800 runtime-reload PMTU fixture failures. Workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics.
- **External boundary:** Authorized Omega SSH proof remains unavailable because the local client reports `No user exists for uid 501`; GitHub publication remains unavailable because DNS cannot resolve `github.com`.

## Implementation Reconciliation (2026-08-04, preloaded TLS key lock ownership)

- **Ownership wiring:** `src/qftls.rs::PreloadedServerIdentity` owns a zeroizing `LockedKeyMaterial` guard. The guard distinguishes disabled policy, process-wide `MCL_FUTURE` coverage, successful individual `mlock`, and unavailable locking.
- **Cleanup wiring:** Only individually locked rejected values call `munlock`, after zeroizing the exact buffer range. The accepted `OnceLock` identity remains process-lifetime-owned and is not treated as a normal shutdown-drop resource.
- **Publication wiring:** Exact same certificate/key bytes return idempotent `AlreadyLoaded`; conflicting bytes return a typed TLS error. A shared publication helper makes the `OnceLock::set` rejection path drop every rejected guard.
- **Configuration wiring:** Standalone and embedded server callers propagate `SecurityConfig.lock_memory`; standalone reports only successful `MCL_FUTURE` coverage, so finite `MCL_CURRENT` locking does not suppress per-key locking for later allocations.
- **Proof status:** Real fixture generation plus an isolated child process covers first, duplicate, and conflict behavior; the local publication test covers accepted and rejected ownership. Focused qftls lifecycle coverage passes 2/2; the broader qftls filter passes 22/23 with only the unchanged TODO-768 Rustls ClientHello failure. Workspace all-target checking and strict library Clippy pass. The no-fail-fast workspace matrix executes every target: the library passes 2,219/2,221 with TODO-807 DNS and TODO-768 Rustls failures, the `quicfuscate` binary passes 41/43 with the two TODO-800 runtime-reload PMTU fixture failures, and all other targets pass. Workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics. Native Linux and remote publication gates remain unavailable.

## Implementation Reconciliation (2026-08-04, TUN unaligned BMI2 header load)

- **Alignment wiring:** `src/interface.rs::parse_ip_header_bmi2()` uses `std::ptr::read_unaligned` for the four-byte IPv4 header word. The complete `src/interface.rs` and `src/interface/` search found no remaining raw `*const u32` packet read.
- **Regression wiring:** `write_packet_accepts_intentionally_unaligned_ipv4_slice` constructs a non-four-byte-aligned subslice and verifies device output plus IPv4 telemetry. On x86-64 with BMI2 support, `bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported` directly exercises the target-feature parser; the portable write test remains valid for scalar dispatch and non-x86 targets.
- **Boundary wiring:** TODO-654 is limited to alignment-safe header loading and its regression proof. CPU-profile/BMI2 dispatch, generic TUN read/write result contracts, Unix syscall progress and close ownership, Wintun, WFP, and negative platform proof remain TODO-843 through TODO-848-owned boundaries.
- **Verification status:** `interface::tests::` passes 11/11 on this ARM64 macOS host and `rt-interface` passes 4/4. Workspace all-target checking passes, strict library Clippy passes, and workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics. The no-fail-fast workspace matrix executes every target: the library passes 2,220/2,222 with unchanged TODO-807 DNS and TODO-768 Rustls failures, the `quicfuscate` binary passes 41/43 with the two unchanged TODO-800 runtime-reload PMTU fixture failures, and all other targets pass. Formatting and diff hygiene pass. The x86-64 BMI2-specific test is target-gated and was not runnable on this ARM64 host; native x86/Linux and remote publication remain separate closure gates.

## Implementation Reconciliation (2026-08-04, reproducible dependency resolution)

- **Ownership path:** `config/tool-versions.env` owns the exact CI/release versions; `rust-toolchain.toml` pins Rust `1.97.1`. Bun, Cargo, Tauri CLI, audit, fuzz, and benchmark inputs are now reviewed against that source-owned contract.
- **Workflow path:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/clippy-matrix.yml`, and `.github/workflows/windows-omega-e2e.yml` use frozen Bun installs, locked Cargo operations, exact Rust action toolchains, and exact locked installs for release tools. The release Tauri jobs run locked metadata/check/Clippy before forwarding `--locked` to packaging.
- **Verification path:** `scripts/audits/verify-reproducible-dependencies.sh` performs static workflow checks plus two-run Cargo and Bun resolution probes. The local gate passes with the stable Bun lock hash `10111F769AB0DF7E-c8bf34ac712c2681-9B1E6056451B6CA1-bfc42866eebd8464`.
- **Native boundary:** The Tauri host locked check, all-target strict Clippy, and 41-test host suite pass on ARM64 macOS. Linux/Windows packaging, updater signing, hosted CI, and remote release publication remain external evidence gates; no UI or remote state was changed.
