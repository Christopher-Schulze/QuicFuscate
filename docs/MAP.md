# QuicFuscate Map

This document is the single combined **file map** and **architecture index** for the repository.
It is maintained as the current architecture and repository index, with a curated tracked-source tree snapshot included below for navigation.

Current task status and evidence ownership are canonical only in `docs/todo.md` and the frontmatter of its linked detail files. Dated, session, and evidence sections below are historical snapshots for the commit/date named in their heading; their then-current status wording is evidence, not a current task-state claim.

## High-Level Architecture and Wiring

- Native IPv4 TTL-expiry proof: `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh::prove_icmp_boundaries()` captures the client-TUN request and server `TIME_EXCEEDED` response into a pcap, then `scripts/tests/utils/verify-icmp-time-exceeded-pcap.py` checks endpoints, TTLs, ICMP type/code, IPv4 and ICMP checksums, and the exact 28-byte quoted request; before/after metrics require a positive `time_exceeded` delta. Run `30827540460`, job `91733001327`, artifact `8861606310`, proves one request, one server response, the exact 28-byte quote, valid checksums, and `time_exceeded=0 -> 1`. The native job later failed at the independent backpressure-quiescence gate; TODO-806 is closed and TODO-559 owns that queue evidence.
- Runtime core: Rust crate under `src/` with entrypoints in `src/main.rs` and `src/lib.rs`.
- Unified configuration boundary: `config/quicfuscate.toml` -> strict `EngineConfig` parse -> complete section validation -> dedicated transport/client/server projections. `AppConfig` retains only validated FEC, stealth, optimization, and anti-replay runtime state; transport policies and startup-owned sections remain on their canonical owners, and invalid or unknown submitted values fail before admin persistence or runtime construction.
- Fingerprint rotation wiring: `[fingerprint_rotation]` and `--profile-seq` use one `browser@os` grammar -> validated concrete `FingerprintProfile` slots -> `StealthConfig` typed pool -> `StealthManager` next-session cursor and shared `StealthRuntimeOwner` template worker. Fixed has no pool, Slots uses the submitted sequence, and All uses the supported catalog. Established TLS/H3 personas remain frozen; invalid separators, unsupported pairs, empty explicit sequences, and silently dropped slots are rejected. Frontend field exposure remains intentionally deferred.
- Data path wiring: app or TUN ingress -> core/transport -> stealth shaping -> crypto -> FEC -> network I/O.
- QUIC version wiring: Engine and standalone CLI config default to ordered v2/v1 support; `transport::version` owns selection, greasing, type mapping, and authenticated Version Information; `transport::packet` owns v1/v2 Initial and Retry material plus stateless VN; standalone server ingress bypasses VN for the FEC magic before existing-session dispatch; `transport::Connection` owns strict CID validation and one bounded fresh-state restart.
- Production VPN carrier: authenticated Core H3/MASQUE CONNECT-UDP carries TUN IP packets for standalone, embedded generic, and live server paths. One registered Flow-ID (`0`) is checked against the active CONNECT-UDP stream before decoded MASQUE DATAGRAM payloads reach TUN; oversized/unavailable datagrams use the bounded `QFT1` length-framed H3 fallback. `crates/qf-control-plane/src/lib.rs` owns the bounded versioned assignment capsule; the client sets a reconnect generation in the CONNECT request, waits for the authenticated assignment before opening TUN, and uses one bounded H3/MASQUE ingress owner for downlink. The public QKey ID in the QUIC Initial selects the server record; the bearer is presented only through the encrypted H3 `x-qf-auth` header. The server gates MASQUE DATAGRAM-to-TUN delivery on the current authenticated state and emits the assignment from the authenticated session allocation. TODO-866 owns assignment lifecycle; TODO-867 owns the remaining carrier integration and native/authenticated evidence gates. The retired stealth manager and stealth-local DoH resolver are archived, not compiled.
- Frontend request lifecycle wiring: the Svelte admin dashboard, configuration, logging, credential, and QKey resources share per-resource serialized request coordinators with generation checks and teardown invalidation, so interval, initial, manual-refresh, and mutation reconciliation responses cannot commit stale state. Desktop Tauri status, stats, and log pollers own one in-flight request per resource; a poller owner generation, status-state version, and log cursor epoch reject delayed teardown, tunnel-state, cursor-regression, and log-clear responses.
- TUN provisioning proof: `src/interface.rs`, `src/interface/wintun.rs`, and `src/implementations/client/platform/{linux,macos}.rs` enforce the shared address/prefix/MTU contract; Linux server routing in `src/implementations/server/routing.rs` recovers persisted ownership before a new TUN is opened, rejects addresses owned by another interface, records exact ifindex/config ownership before mutation, verifies exact postconditions, and performs bounded owned rollback and stale recovery; `scripts/tests/tun-provisioning-negative-netns.sh` owns the privileged negative/retry/residue proof and `scripts/tests/tun-e2e-netns.sh` owns the process-loss and graceful-removal lifecycle proof.
- QKey auth abuse-policy wiring: `ServerConfig.auth_policy` resolves and validates bounded environment controls -> `LiveServerState` owns one monotonic `AuthRateLimiter` -> new Initial admission allocates one attempt ID before registry lookup -> the same ID survives pending H3 authentication -> QUIC/TLS establishment starts the bounded encrypted-bearer deadline exactly once -> success, failure, timeout, pre-auth close, and internal abandonment complete the attempt at most once. Constant-size per-IP state applies capped exponential backoff, explicit block expiry, pending/state capacity bounds, and periodic idle pruning; admission outcomes remain wire-indistinguishable while Prometheus and typed audit events remain distinct.
- QKey revocation wiring: explicit admin revoke persists the registry mutation -> `LiveServerState` records the single revocation state and atomically drains the SessionId-to-QKey tracker -> affected transports queue authenticated QUIC CONNECTION_CLOSE frames -> the next live flush delivers the close before closed-client reconciliation releases the session/domain state. Pending authentication checks the same revocation owner before and during commit. Revoked records use the validated 90-day default retention, are pruned at most every five minutes from housekeeping, and expose `quicfuscate_revocation_pruned_total`; no automatic QKey-rotation scheduler or external revocation callback remains in the housekeeping path.
- Brain observer wiring: transport receive callbacks update packet count, reorder state, and size bins through lock-free atomic accumulators and sample inter-arrival bins every eighth packet -> `StealthBrain::apply_policy` drains those accumulators under its consolidated mutation lock. Transport control producers route through one bounded queue admission helper that coalesces the latest `MAX_DATA` and per-stream `MAX_STREAM_DATA` update and preserves terminal close frames under saturation. `Connection::close()` is first-close-wins under TODO-606 and records structured local application/transport errors under TODO-772; terminal close priority is closed by TODO-697.
- Sustained DDoS admission wiring: validated environment policy -> interval-delta accepted PPS -> monotonic EWMA activation/clear windows -> ordered global, GeoIP, blacklist, and per-IP admission -> normal-cost cryptographically established traffic or enhanced-cost half-open/new traffic -> source/IP/CID/credential/time-bound stateless QUIC Retry for supported Initial packets -> validated public QKey credential restoration plus RFC 9001 Initial keys from the Retry SCID. GeoIP activation validates the country policy, fully verifies a regular MaxMind country database before readiness, rejects valid non-country databases, propagates configured activation failure through every server constructor, exposes actual disabled/active state through health/admin/metrics, and drops lookup/decode failures fail-closed with explicit counters. Stateless Version Negotiation remains behind the admission caps. Strict HTTPS blacklist refresh is owned by `BlacklistSyncOwner`, which claims one due task, retains completion/cancellation state, applies bounded retry, isolates feed parsing, atomic cache publication, and active-list replacement in `spawn_blocking` after a pre-publication cancellation check. Absolute timeout/body/entry/TTL/interval caps and lifecycle/freshness metrics are exposed through Prometheus, health, and admin status.
- Idle-session lifecycle wiring: `transport::Connection` derives idle expiry from configured `max_idle_timeout`, treats zero as disabled, and marks an expired connection terminal without emitting CONNECTION_CLOSE -> standalone housekeeping reconciles the closed transport owner -> `LiveServerDomain` releases the session, IPv4/IPv6 pool addresses, connection-limit ownership, QKey association, bandwidth state, and pending policy state. The independent `client_timeout_secs` expiry remains a longer shared-domain safety boundary. Error ownership preserves the first local root cause separately from the first peer close, including peer close code, frame type, and reason bytes. TLS provider failures queue a CRYPTO_ERROR close with the 0x0100 alert base before termination; received peer closes remain receive-only terminal events.
- Per-session bandwidth wiring: validated `QUICFUSCATE_CLIENT_*` defaults -> `SharedServerDomain` constructs one `PerClientBandwidthManager` -> session admission creates independent uplink/downlink token buckets plus shared UTC daily/monthly quotas -> encrypted QKey authentication optionally replaces the effective policy -> authenticated admin read/update/reset has final live precedence. MASQUE and framed-H3 uplink boundaries admit bytes directly. Unshaped TUN/fan-out downlinks with no session backlog use direct admission; shared shaping, rate backpressure, or transport backpressure enters the existing bounded pending owner, whose optional validated shared token bucket defines aggregate service capacity before weighted byte-deficit round robin applies FIFO-preserving per-session shares. Session close, expiry, revoke, and kick remove the same state; metrics and deduplicated audit expose typed rate/daily/monthly outcomes.
- Tunnel MTU ownership: `transport::PmtuState` discovers a validated 1280-1500 outer packetization budget; `core::QuicFuscateConnection` derives the FEC/QUIC/MASQUE datagram payload and a separate IPv6-safe inner tunnel MTU. The client applies live TUN MTU changes and returns local IPv4/IPv6 PTB above that boundary. The server's `allow_client_uplink()` returns IPv4 Fragmentation Needed for both DF states before either MASQUE or framed-H3 TUN write, intentionally avoiding platform-dependent oversized writes and userspace fragmentation. The Linux CI native job first runs a separate 1280-byte carrier phase for bidirectional framed-H3 fallback, then gives its PTB phase a 1472-byte carrier on both ends, a 1500-byte client TUN ceiling, and a 1280-byte server TUN ceiling so the 1,328-byte probe crosses only the server TUN boundary; `prove_server_ptb_from_client()` captures the server-sourced PTB for both IPv4 DF states and IPv6 and retains the exact wire and metric evidence. The two IPv4 probe destinations are isolated to prevent the client's learned PMTU from fragmenting the later DF=0 probe. Run `30823185685` proved that keeping the server carrier at 1280 truncated the probe before routing and produced `MalformedPacket`; run `30823826169` exposed same-destination PMTU-cache contamination; run `30824438300`, job `91722362887`, passed the complete PTB gate with unfragmented 1,328-byte DF=1 and DF=0 probes, server-generated IPv4 PTB for both, IPv6 Packet Too Big, and metric deltas `packet_too_big=3` plus `icmpv6=1`. Tunnel-ingress fingerprint normalization now preserves valid IPv4 TTL 0/1 packets until routing can emit `TIME_EXCEEDED`; the native proof of that correction is closed under TODO-806, while the independent queue failure remains separate.
- Windows Wintun and kill-switch ownership: `src/interface.rs` selects the built-in backend only with `tun-windows` -> `src/interface/wintun.rs` securely loads the upstream DLL, creates one adapter/session, captures its LUID and session-owned read event, configures addresses and active MTU, and serializes packet operations against one shutdown event and one retryable teardown ledger -> `src/implementations/client/killswitch/windows.rs` resolves the live alias to its LUID and transactionally replaces fixed persistent WFP provider/sublayer/filter identities across IPv4/IPv6 outbound transport layers, which also classify third-party transports and raw packets while preserving the exact UDP tuple -> ignored native tests prove data-plane lifecycle, observe exact IPv4/IPv6 WFP packet absence or presence at the Wintun ring, retain block policy across child-process exit, and prove exact stale cleanup -> `scripts/utils/provision-wintun.ps1` pins archive/DLL hashes plus Authenticode -> CI and Tauri MSI paths provision the untracked DLL beside their executable. Run `30508948149`, job `90764941801` proves the native adapter/WFP lifecycle and zero residue; release run `30533862566`, Windows job `90842338800`, proves the signed MSI plus byte-exact packaged DLL; Windows-Omega runs `30535603045` and `30536002374` prove encrypted QKey/MASQUE connected policy with five IPv4 and five IPv6 tunnel pings twice against unchanged server PID `1158967`, followed by zero WFP/adapter residue.
- Oversized tunnel carrier: raw IP packets within the effective tunnel MTU but above the MASQUE datagram payload use bounded `QFT1` length framing on the `/tun` HTTP/3 stream. `core.rs` reassembles arbitrary DATA-read segmentation per stream and rejects invalid magic, empty frames, non-IP payloads, and unbounded pending data.
- Reliable STREAM ownership: `transport::Connection` keeps a 16 MiB immutable range ledger, binds compact transmission IDs to packet numbers, retires exact ACKed ownership, and requeues packet-threshold/PTO loss before new data. Readable/writable membership uses O(1)-average HashSet admission beside ordered VecDeque scheduling; front removals are O(1), while priority changes retain their explicit reorder scan. A PMTU decrease byte-exactly splits queued transmissions to the new packet budget while late ACKs retire all derived segments once. Bounded flow-control notifications coalesce to one current `DataBlocked` frame per connection window and one `StreamDataBlocked` frame per stream window. Low-level 1-RTT write key updates are provider-owned when TLS is configured and fail closed without a raw transport fallback.
- Outbound pacing: `core::OutboundPacer` centrally gates congestion-controlled transport and FEC emissions from every socket path; ACK-only output is explicitly exempt. Partial burst accounting decays at the configured pacing rate over elapsed time before new bytes are admitted, preventing stale idle bytes from creating false pacing blocks. BBR2 and BBR3 own a congestion-window/initial-RTT Startup pacing floor that cannot collapse on a transient slow delivery sample; measured pacing becomes authoritative after Startup. Reno, BBR2, and BBR3 use saturating in-flight accounting, BBR2 keeps send-side rounds separate from its ACK delivery clock, and both BBR filters expire stale minimum-RTT samples through the shared `QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS` window.
- Traffic-analysis defense wiring: canonical `[transport.traffic_analysis]` plus independent QKey and Intelligent ceilings -> `transport::Config` validated policies -> `transport::Connection` one `TrafficAnalysisScheduler` deadline and one pending slot -> `QuicFuscateConnection::next_send_deadline()` merged with pacing, stealth release, and recovery -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted PING plus PADDING chaff at path-bounded size. Due cover packets consume a slot, but only application STREAM or DATAGRAM traffic extends the idle lifecycle. Idle timeout, ramp-down, reactivation, and shutdown cancellation remain connection-owned. QKey and Intelligent upgrades stay inert until encrypted bearer authentication and cannot exceed their operator ceilings.
- CUBIC wiring: engine config, CLI, client/server conversion, and TOML select `Algorithm::Cubic`; `Recovery` owns RTT-before-ACK delivery, recovery-episode loss collapse, and enum-dispatched `Cubic`/`StealthCubic` pacing without vtable indirection.
- Validated migration wiring: `[connection]` reduction/cooldown/probe-target policy -> `transport::Config::migration_policy` -> exact PATH_CHALLENGE/PATH_RESPONSE candidate validation -> `Recovery::on_path_change()` path epoch and typed `PathChangeEvent` -> Reno/CUBIC/BBR2/BBR3/StealthShaper state transition. `SendInfo::path_control` routes validation datagrams ahead of buffered FEC output without FEC, outer-pacer, or stealth delay; standalone server DCID routing commits a candidate peer tuple only after validation, while simultaneous peer PATH_RESPONSE ownership remains queued independently.
- Standalone Linux TUN routing: explicit `--tun-ip` / `--tun-netmask` on the server updates `ServerConfig.server_ip`, `server_netmask`, and the client IPv4 pool, keeping Linux namespace deployments and runtime session routing in the same subnet. Server TUN mode rejects macOS, Windows, and other platforms before host mutation until a native routing owner and proof exist.
- DNS-through-tunnel: `src/implementations/client/dns_runtime.rs` owns the supported client TUN resolver lifecycle, binds localhost UDP/53, pre-pins RFC 8484 DoH endpoint addresses before resolver/firewall mutation, applies one shared `DnsAdmission` across IPv4/IPv6 listeners using localhost source-IP identity, exposes admission counters, and restores the prior platform resolver before teardown; the public `process_dns_query_with_admission()` wrapper makes caller identity explicit while the low-level forwarding helper remains admission-free for already-admitted callers. The server MASQUE/TUN uplink separately intercepts IPv4/IPv6 UDP/53 packets before generic TUN egress, propagates authenticated session identity into the same admission contract, removes session/source buckets on lifecycle transitions, bounds idle state to 1,024 identities, resolves through configured plain-UDP server DNS upstreams, and queues rebuilt DNS responses over MASQUE downlink. One aggregate budget covers sequential upstream fallback rather than multiplying per resolver. `DnsInterceptWorkerOwner` retains every accepted blocking worker, closes admission before standalone drain closes the live data-plane boundary, serializes response publication against that close, reaps finished handles during housekeeping, and classifies queued cancellation, panic, terminal response/queue outcomes, late publication, and started-operation shutdown expiry through `quicfuscate_dns_intercept_worker_events_total`; `quicfuscate_dns_intercept_admission_events_total` reports accepted/rejected admission causes and `quicfuscate_dns_intercept_dropped_total` remains the aggregate server drop counter. Forwarding now enforces a shared 4,096-byte DNS message limit, a monotonic 5-second aggregate DoH/UDP fallback deadline, bounded streamed DoH bodies, typed public input rejection, UDP oversize sentinel rejection, and a non-blocking async plain-DNS boundary; DoH responses also require QR, standard opcode, one bounded matching question, and transaction ID while preserving opaque answer/EDNS compression. The shared DNS query gate additionally enforces the supported query flags, exactly one question, bounded reserved and compression-pointer semantics, exact question-wire preservation, and raw QTYPE/QCLASS retention. Server IPv4/IPv6 UDP/53 admission enforces exact lengths, rejects IPv4 fragments, validates the IPv4 header and applicable UDP checksums, and requires the IPv6 UDP checksum. UDP response matching remains TODO-721; native Linux/TUN, Omega, and live publication proof remain separate.
- NAT traversal: optional `NatPathDiscovery` is default-off and reason-gated (`connectivity-fallback`, `roaming`, `mesh`, `always`). It feeds transport path discovery when explicitly enabled; it is not part of the baseline stealth path.
- TUN downlink hotpath: after one MASQUE downlink packet is queued, the server flushes only the owning client connection rather than sweeping all connected clients.
- TUN data-plane fault wiring: typed `DataPlaneFault` outcomes cover reader termination, channel disconnect, TUN write, transport send, and transport receive failures -> client `ClientRuntime` and standalone client first-wins fault slots -> watchdog/exit reason, driver shutdown, and bounded cleanup -> `EngineStats.data_plane_ready`/`data_plane_faults` plus server `Metrics` readiness and fault counters. Cooperative shutdown is published before receiver drop, owned reader joins are awaited, and deliberate shutdown remains outside fault health.
- MASQUE observability: CONNECT-UDP lifecycle and peer-flow registration stay at `info`; per-packet MASQUE TX/downlink TX lines are `debug` to avoid production log amplification.
- Packet crypto wiring: Initial/Handshake use boxed AES-GCM compatibility keys; normal 0-RTT/1-RTT data-plane AEAD uses concrete `DataAead` enum dispatch with local per-packet or per-batch AEGIS state and no wrapper mutex; Rustls packet-key integrations use the explicit dynamic packet wrapper arm.
- PKI identity wiring (TODO-577, TODO-656): `ensure_pki()` captures one checked `PkiTime` from the canonical or injected clock and passes it unchanged to existing leaf/intermediate/root validation, quarantine naming, and fresh root/intermediate/leaf generation. Rustls/WebPKI verifies hostname, validity, trusted chain, and leaf/private-key match before reuse; invalid or incomplete material moves to a unique quarantine directory before a fresh hierarchy is written. Pre-epoch, unrepresentable, overflowed, and non-positive validity timestamps fail through typed PKI errors.
- FEC recovery wiring: Initial, Handshake, product Auto startup, and stable Zero datagrams remain raw; active 1-RTT framing is also deferred while any Initial/Handshake PTO probe is pending. Active 1-RTT output reserves the exact 36-byte maximum FEC overhead before QUIC serialization. The encoder stores `[outer FEC source length | inner QUIC length | QUIC]`; systematic wire frames omit only the outer length, while repairs retain both layers. The validated product receiver checks transmitted epoch, window, codec, source/total counts, interleave lane, sequence, and repair ordinal before its bounded wire-path decoder allocation; TODO-856 now closes the direct decoder, matrix, and wire-helper input boundaries, while TODO-857 closes the direct Fountain constructor, source-index, and symbol-size admission boundaries, and TODO-858 closes the FEC configuration, runtime policy, transport feedback, Kalman, and mode-manager validation contracts. It reconstructs GF4/GF8/GF16 rows or keyed Fountain source sets deterministically instead of receiving coefficient vectors. Fountain seeds derive from the matching QUIC 1-RTT traffic secret through HMAC-SHA-256 and are applied before the first protected window. Both accepted systematic sources and recovered sources validate then remove the exact inner QUIC length before entering QUIC header protection and AEAD processing. `InterleavedEncoder` assigns source/repair symbols to lanes and complete-block transitions advance the wire epoch. The validated product Fountain rescue policy is bounded to 128 sources and at most 512 repairs at the current 5x total code rate. Every retained receive window caps duplicate-repair state at its profile repair capacity and evicts oldest keys through a bounded FIFO. Decoder equation, solver, timing, success, and eviction counters flow to `crates/qf-telemetry/src/lib.rs`. Other transitions remain block-boundary safe; only a return to raw Zero after 32 transport-classified clean ACKs may retire an incomplete repair-only encoder window immediately. GF8 remains the wire-canonical GF(256)/0x11D field; GF4 uses fused scalar/AVX2/NEON multiply-XOR, and GF16 uses carryless polynomial multiplication and exact odd-length recovery. Direct Fountain constructor bounds clamp zero and oversized `k` and `symbol_size`, source-index admission rejects empty, out-of-range, and duplicate sets, and symbol/data lengths are bounded against the configured `symbol_size` before buffer mutation. Product startup validates FEC configuration before runtime construction, while direct `AdaptiveFec`, `LossEstimator`, `KalmanFilter`, and ModeManager paths retain separate policy and feedback audit boundaries under TODO-858. TODO-855 now closes the local FEC SIMD intersection, threshold, telemetry, release-safe length, and unsafe-contract implementation boundary; native and complete differential proof remain under TODO-859 and GF16 polynomial proof under TODO-715. TODO-860 additionally retains direct zero/Fountain counter wrap, non-divisible interleave flooring, 32-bit sequence narrowing, repair-ID shift aliasing, Fountain wire source-ID subtraction, and unchecked decoder/Wiedemann/Fountain arithmetic.
- Active FEC policy wiring: `QuicFuscateEngine::set_fec_mode()` returns a typed requested/configured/effective acknowledgement with active-versus-next-connection scope. `ClientRuntime` retains the canonical Engine projection for reconnect. The existing connection mutex serializes active commands with all I/O and controller inputs; `QuicFuscateConnection` preserves queued sources, retires queued repairs, resets wire state, and replaces all adaptive/codec/recovery state at Zero. Hard-Off framed receive uses source-only parsing with no recovery window. Other generic Engine setters and `reload_config_from_file()` are next-connection/reconnect controls for clients, with startup-owned sections requiring a stopped engine; standalone reload reports `NextConnectionOnly`, is serialized with connection construction by the single live loop, records the unchanged active-session count, advances a shared `RuntimePolicyGeneration`, and tags each new-connection `RuntimePolicySnapshot` with the generation used across transport, FEC, optimization, and stealth.
- Compression wiring: `src/compress.rs` writes safe-path zstd compression and decompression directly into `PooledBlock` owners backed by `MemoryPool` via bulk buffer APIs; the explicit `body_pool()` constructor and `BODY_POOL_BLOCK_SIZE` telemetry publish the same effective block size after the 2 KiB minimum clamp. `PooledBlock::Drop` returns basic and dictionary compression/decompression allocations through `MemoryPool::free()` on success, caller error, malformed input, and unwind paths. H3 centralizes MIME allow/deny evaluation with deny precedence, and `0x5A` / `0x5D` frame headers remain unchanged. Exact decompression length remains TODO-603.
- Client packet I/O is owned by `src/implementations/client/io_driver.rs` plus `src/core.rs`; no parallel client pipeline adapter or client-local `FecCodec` is retained.
- Client IO ownership: inbound flushes reuse caller-owned 65,535-byte buffers, Linux outbound dispatch reuses one batch-reference vector per loop, and the client TUN reader transfers pool-backed `interface::TunPacket` blocks through its bounded channel so backpressure preserves ownership without a per-packet `Vec` allocation. `TunDevice::read_contract()` distinguishes native nonblocking descriptors from custom blocking backends before the generic async outbound loop starts. Admin HTTP auth/session state uses `parking_lot`; its login limiter is a 10,000-key LRU with all-attempt accounting, session replay uses a timestamped `HashSet` plus bounded FIFO eviction, and the outer live-session map admits at most 256 records with explicit capacity rejection, expiry pruning, counters, and shutdown clearing.
- Linux outbound dispatch wiring (TODO-578, TODO-646): `OutboundDispatch::IoUringBatch` is admitted only when a runtime-owned `UringBatchWorker` initialised successfully. The worker owns one synchronous sender on one joined blocking thread, has one queued request, admits at most 256 packets and 524,288 aggregate payload bytes before copying, disables SendMsgZc, and turns timeout or hard completion failures into typed data-plane faults. A busy worker falls back to `sendmmsg`/socket sends; the shared `try_sendmmsg_batch()` match rejects accidental io_uring fall-through explicitly instead of silently returning zero sends, while `SendmmsgBatch` remains bounded by the payload count. Direct `UringBatchSender` calls remain synchronous compatibility primitives. TODO-798 continues to own partial-send semantics.
- Audit logging wiring (TODO-515, TODO-525): `src/main_parts/late_tests_and_mlock.rs` resolves `[audit]` bounds and initializes the global `OnceLock<Arc<AuditLog>>` owner before privilege reduction -> typed lifecycle, privilege, authentication, QKey, admin, connection, configuration, and routing emitters validate JSON-encoded UTF-8 payload bounds before cloning dynamic fields and call non-blocking producer APIs -> one bounded `qf-audit-writer` assigns order and owns schema-v2 serialization, SHA-256 chaining, file I/O, deterministic rotation, retention, and atomic checkpoint durability -> Prometheus exposes queue-drop, payload-rejection, and persistence-error counters -> the atomic `Open`/`Closing`/`Closed` admission gate linearizes shutdown, drains in-flight producers, then sends the acknowledged final flush and joins the worker -> `verify-audit-log <path>` validates the checkpoint-declared ordered segment set with schema-v1 compatibility. Source IP, client ID, reason, message, and combined dynamic payload limits are 128, 512, 512, 8,192, and 8,192 JSON-encoded UTF-8 bytes. All audit artifacts are mode-`0o600` regular files owned by the runtime identity; special files and symlinks are rejected.
- Memory locking wiring (TODO-516, TODO-851, TODO-852, TODO-854): `src/memory_lock.rs::MemoryLockPolicy` is the shared mapping for `SecurityConfig.lock_memory`, `lock_blocks`, and `memory_lock_failure_policy`. The default `best-effort` policy publishes typed degraded state after an `RLIMIT_MEMLOCK`, `mlockall`, or unsupported-platform failure; the Linux server template selects explicit `fail-closed`, which aborts before TLS/service exposure. Standalone `src/main.rs::run_server()` and embedded `QuicFuscateEngine::start()` apply the policy before server TLS identity construction; embedded startup applies it before `global_pool()` and runtime transport creation. Linux standalone startup with a configured UID/GID transition individually locks the TLS key before the transition and defers process-wide `mlockall` until verified setxid completion; the deferred result is propagated before runtime services and systemd `READY=1`. Unlimited budgets use current-and-future locking, finite budgets use current-only locking, and an unreadable budget is an explicit best-effort degradation or fail-closed error rather than an opaque `.ok()` fallback. `MemoryLockStartupStatus` is published to server Metrics, admin health/status, and systemd `/health`, `/ready`, and `/live`; degraded best-effort health remains service-ready, while deferred or failed state is not ready. The policy resets qftls process-coverage state, and the accepted TLS identity remains process-lifetime-owned; rejected values use an exact-range zeroize-before-`munlock` guard. Successful pool locks are tracked by `BlockLockLedger`; `MemoryPool::free()`, queue shrink, full-queue disposal, pool `Drop`, and TLS-cache `Drop` zeroize and `munlock()` before allocation release, while direct `AlignedBox` drops remain outside this owner boundary under TODO-516/TODO-678. Standalone reload rejects changes to all three startup-owned settings before runtime mutation. TODO-854 closes local deterministic negative-proof wiring; native Linux root-regain and Windows native fault lanes remain explicit unavailable boundaries. TODO-853 closes certificate/key correspondence and zeroizing identity-output ownership.
- Retained-secret erasure wiring (TODO-526): `src/secret.rs` zeroizing byte/string owners -> `src/engine/qkey.rs` typed `QKeyToken` plus zeroizing JSON/base64 parse/generate temporaries -> server issuance and registry decode/hash -> client profile/config/live connection ownership. `src/qftls.rs` and `src/transport/config.rs` zeroize session-cache ticket owners, ticket copies, test-bound ticket/session owners, and private-key PEM read buffers; `src/transport/packet.rs` wraps QuicFuscate's copied 1-RTT secrets, `src/crypto/aead.rs` wipes AES header-protection keys, and `src/crypto/aegis.rs` wipes L/X4/X8 wrapper key/IV plus non-`Copy` local AEGIS state values on drop while concurrent packet operations remain mutex-free. Compiler-level register erasure remains a separate TODO-681 proof boundary.
- QKey registry persistence wiring (TODO-539): standalone startup -> `qkey_registry.rs::QKeyRegistry::open()` -> `qkey_registry_storage.rs` protected current/previous keyring -> authenticated `QFQREG` version-1 ChaCha20-Poly1305 envelope. Startup propagates typed missing-key, wrong-key, corruption, version, permission, and I/O failures. Admin issue/revoke mutations serialize into zeroizing buffers and publish durable state before updating memory. Plaintext migration writes encrypted recovery before encrypted primary; an existing encrypted backup anchors plaintext-downgrade rejection; legacy/current-key rotation retains encrypted recovery and never interprets failed ciphertext as plaintext.
- QKey replay-window maintenance wiring (TODO-578): standalone housekeeping -> `QKeyRegistry::prune_replay_window()` -> current Unix-epoch timestamp -> `ReplayWindow::prune(now)` -> stale-slot removal and logical-base advancement, including an empty quiet window.
- Linux privilege-boundary wiring (TODO-527): CLI `--drop-user`/`--drop-group` -> `src/privilege/drop.rs::resolve_identity()` reentrant NSS or numeric-ID resolution -> pre-setup `try_check_capabilities()` and operation-specific capability gate -> TLS identity preload plus privileged UDP/TUN/routing initialization -> blocking-thread `drop_privileges_resolved()` clears supplementary groups, transitions all real/effective/saved IDs, and clears ambient/effective/permitted/inheritable capability sets -> `verify_process_privilege_state()` validates every Linux thread has the target real/effective/saved/filesystem IDs, empty groups, zero capability sets, and `PR_SET_NO_NEW_PRIVS` -> process-wide memory locking is applied after setxid while the TLS key and MemoryPool allocations are individually locked before it. TODO-849 makes `ResolvedIdentity` opaque, revalidates its non-root selector/account mapping at the final boundary, bounds `getgroups()` result counts, and defines `CurrentIds` on every target; TODO-850 adds typed partial-transition failure and complete local standard/Tokio probe assertions. The isolated `qf-privilege-probe` alone performs the destructive UID/GID root-regain attempt. `quicfuscate capabilities --json` exposes the same identity, capability, target, and readiness state; saved UID/GID fields are optional and remain null on Unix targets without a reliable query instead of copying effective IDs; systemd root-starts with only bounded setup capabilities and owns confinement plus post-drop host cleanup.
- Memory-pool growth and ownership wiring: `src/engine/config.rs` bounds automatic engine pools to 16-64 MiB and passes an explicit block-size contract; the adaptive `global_pool()` packet path and default `OptimizationManager::new()` retain the MTU-selected constructor. `MemoryPool` derives a per-instance hard ceiling of at least its explicit initial capacity and otherwise 64 MiB by effective block size. The global auto-tuner defaults to 1,024 blocks and cannot bypass that instance ceiling. Its stop flag, wakeup, and join handle are owned by `MemoryPool::shutdown_auto_tuner()`. TODO-827's `PoolOwnershipLedger` now binds exact block addresses to accounted or ephemeral origin and queue, TLS, or checked-out state, serializes transitions, rejects foreign and duplicate returns, bounds shrink when remote TLS owns blocks, stops stale-address growth without progress, and keeps the ledger alive through TLS cleanup after pool drop. TODO-767 remains the requested-versus-effective block-size owner. TODO-831 adds `PooledBlock` for generic compression, TUN, frame, and pre-FEC caller failures; TODO-832 closes the FEC return boundary; TODO-833 closes the DATAGRAM return boundary through the same guard. The feature-gated `UnsafeMemoryPool` uses a separate synchronized ownership registry with exact-base live-state checks under TODO-826. Final FEC evidence passes `252/252`, the full library passes `2,436/2,436` in both debug and release, and the final target remains within the task disk ceiling. All-target Clippy outside the strict `unsafe_rust` lane retains unrelated baseline diagnostics.
- Graceful shutdown wiring (TODO-448): `ServerRuntime` owns the shared `GracefulShutdown` lifecycle consumed by the UDP loop and admin handlers. SIGINT/SIGTERM/admin drain stop `AcceptLoop` admission, wait for established clients or `[engine] shutdown_timeout_ms`, flush final QUIC close packets, then stop control-plane services and host resources. SIGHUP uses the canonical runtime reload path. `implementations/server/systemd.rs` emits READY, RELOADING, STOPPING, STATUS, and watchdog notifications.
- Control plane wiring: CLI + engine + admin surfaces + metrics/telemetry endpoints. Embedded Engine server startup constructs `ServerRuntime` and its Tokio-bound socket inside the dedicated runtime thread, then transfers shutdown and metrics handles through a bounded readiness acknowledgement before reporting `Running`; every failure after entering `Starting`, including firewall preflight and kill-switch setup, transitions to `Error` so no failed start remains in `Starting`.
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
- `scripts/tests/tun-e2e-netns.sh`: real server/client netns TUN over authenticated H3/MASQUE, pre-open durable routing recovery, durable routing-record publication, SIGKILL/restart stale recovery, 5/5 ping, 0% tunnel loss, graceful record removal, pre-deletion forwarding/TUN/firewall residue assertions, exit-scoped owned-PID cleanup, and fail-closed pre-existing-runtime isolation.
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
- `anti_dpi()`: fingerprint rotation remains next-session policy owned by the shared runtime worker, not active-session mutation
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
- `crates/qf-transport-udp/src/lib.rs` + `fastpath.rs` (11): GSO/GRO config, bounded syscall metadata, sockaddr conversion, send_batch single/multi/IPv6, and UdpFastPath runtime coverage
- `crates/qf-simd/src/lib.rs` + architecture modules (61): SIMD dispatch, QPACK Huffman, QUIC varints, GF arithmetic, FEC solvers, crypto hashing, and scalar parity coverage

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
6. Packet-number and packet-boundary path: `src/transport/packet.rs` checked header-protection removal, big-endian packet-number encoding, CID/token/VN/Retry validation, and AEAD/CRYPTO range ownership -> `crates/qf-cpu/src/transport.rs` `decode_packet_number()` -> BMI2/SVE2/NEON/scalar dispatch; portable malformed and unaligned coverage lives in `scripts/tests/rust/rt-transport-packet-headers.rs`, while native x86_64 AVX2 execution remains an external gate.
7. Compression and H3 receive-buffer path: `src/transport/h3.rs` payload policy -> `src/compress.rs` direct zstd `compress_to_buffer` into `MemoryPool` / explicitly sized body-pool blocks -> H3 compressed body bytes; dictionary decompression requires the supplied pool block to cover the declared original length and rejects mismatches; one caller-owned 64 KiB STREAM receive buffer is reused across polls, while the one-per-connection MASQUE receive buffer follows `Connection::max_recv_udp_payload_size()`
8. Probe mitigation path: `src/stealth/` detector -> `src/reality.rs` fallback proxy -> upstream targets
9. Engine embedding path: `src/engine/engine.rs` -> complete `EngineConfig::validate()` -> `src/implementations/{client,server}/` runtimes; client/server pools, FEC, stealth, and transport policies use the same validated projections.
10. Admin control plane path: `src/implementations/server/admin_http.rs` -> `qkey_registry.rs` -> `qkey_registry_storage.rs` durable fail-closed commit -> live server policy enforcement
11. Desktop frontend path: `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts` -> Tauri invoke -> engine/control runtime
12. 0-RTT anti-replay path: `src/transport/anti_replay.rs` (`StrikeRegister` with SHA-256 fingerprints, Bloom fast-negative, FIFO ring eviction) -> `src/transport/config.rs` (attached at server startup) -> `src/transport/connection/` `recv()` gate -> silent discard on replay
13. Desktop native host path: `apps/tauri/src-tauri/src/main.rs` -> Tauri commands -> engine/control runtime
14. Web-admin path: `apps/svelte-admin/src/lib/api.ts` -> Vite dev proxy (`/api` -> `127.0.0.1:9000`) -> admin HTTP endpoints -> server runtime state
15. Generated build publish path: `apps/svelte-admin/build/` -> `scripts/build/build-web-admin.sh` -> ignored `assets/web-admin/` -> `--admin-web-root`
16. Shared packages path: `packages/ui` (Svelte 5 components) + `packages/theme` (CSS tokens/glass/layout) -> consumed by both Svelte apps
17. GitHub CI app backend gate: `.github/workflows/ci.yml` `app-backend-checks` -> `apps/svelte-desktop` build output -> `apps/tauri/src-tauri` `cargo check` / `cargo test`
18. NAT traversal path discovery: `src/engine/config.rs` `[nat_traversal]` -> `qf-transport-nat::NatTraversalSection` serialized validation/conversion -> `src/transport/config.rs` `NatTraversalConfig` -> `src/transport/nat.rs` `NatPathDiscovery` -> path-management consumers when policy permits discovery.
19. Audit logging path: `src/main_parts/late_tests_and_mlock.rs` pre-resolves the privilege target plus `[audit]` queue/segment/flush bounds -> `AuditConfig::to_audit_options()` -> shared `AuditOptions::validate()` -> `--audit-log <path>` -> `src/audit/mod.rs::init_audit_log_with_options()` creates the global owner and mode-`0o600` active file -> typed producer calls validate JSON-encoded UTF-8 payload limits before cloning or queue admission -> bounded `qf-audit-writer` assigns sequence/timestamp, writes schema-v2 NDJSON, rotates immutable sequence-ranged segments, atomically advances the retained checkpoint, and exposes dropped/payload-rejection/persistence/terminal-discard/slow-flush/shutdown-failure counters -> a writer-side durability watchdog publishes terminal failure when synchronous filesystem durability exceeds the configured deadline -> the atomic shutdown gate closes admission, drains already-admitted producers, then sends the final barrier and joins within the bounded lifecycle contract -> `src/main.rs` `verify-audit-log <path>` validates ordered retained continuity, restart state, and checkpoint tail -> `src/bin/qf-audit-probe.rs` proves concurrent durable throughput and restart verification with explicit event, producer, persistence, timeout, and payload ceilings. Direct `AuditLog` reopens reassert mode `0o600` through the active handle before append. TODO-727 and TODO-728 retain existing-file read bounds and pathname binding; TODO-814 closes the payload-size boundary.
20. Memory locking path: `src/engine/config.rs` `[security] lock_memory/lock_blocks/memory_lock_failure_policy` -> shared `src/memory_lock.rs::MemoryLockPolicy` -> standalone `src/main.rs::run_server()` or embedded `QuicFuscateEngine::start()` -> typed process-lock status/error -> `MemoryPool::set_lock_blocks()` -> server TLS identity construction -> successful `mlock_block()` registration in `BlockLockLedger` -> `MemoryPool::free()`, queue shrink, pool `Drop`, and TLS-cache `Drop` zeroization plus `munlock()` before allocation release. Best-effort failures publish degraded health; fail-closed failures abort before TLS/service readiness. Unlimited budgets request current-and-future locking, finite or unknown budgets request current-only locking, and the deferred Linux UID/GID boundary is applied before runtime service readiness. Standalone reload rejects changed startup-owned memory settings before runtime mutation. Metrics, admin health/status, and systemd health endpoints expose the policy/state/limit/failure fields. TODO-854 closes local deterministic negative-proof wiring; native Linux root-regain and Windows native fault lanes remain explicit unavailable boundaries. qftls certificate/key correspondence and exporter ownership are closed by TODO-853, while lower-level key lock/publication ownership remains TODO-643.
21. Windows core CI gate: `.github/workflows/ci.yml` `windows-core-checks` -> two-job native `windows-latest` `tun-windows,rust-tests` check/test compile -> `scripts/utils/provision-wintun.ps1` verified DLL beside the test executable -> ordinary unit tests plus the deterministic WFP ownership filter -> serial ignored privileged dual-stack adapter, bidirectional UDP, blocked-read close, repeated-lifecycle, WFP packet-outcome, process-exit retention, and stale-cleanup tests -> exact WFP-object/adapter/firewall residue inspection -> `quicfuscate.interface_platform_negative_proof.v1` boundary manifest with unavailable native fault prerequisites explicit -> evidence upload -> strict library Clippy. Run `30508948149`, job `90764941801` predates the manifest and proves the complete native lifecycle; manual workflow runs `30535603045` and `30536002374` prove authenticated dual-stack Wintun/WFP traffic twice against one unchanged Omega server process.
22. Signed release path: `scripts/audits/verify-release-version.sh` -> `.github/workflows/release.yml` `release-version-contract` -> required macOS/Linux/Windows Tauri jobs with `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE=true` -> signed bundle verification -> verified Wintun provisioner and Windows MSI extraction/hash gate -> required `publish-release` dependency -> `scripts/audits/verify-release-updater.sh` -> complete `latest.json` platform map. Release run `30612996058`, job `91099832490`, publishes `QuicFuscate_0.4.4_x64_en-US.msi` with SHA-256 `eba3a9b59b05474e887ed0491f66998523573cae675a44c4469394ee4a9c025f` plus its signature and Wintun provenance.
23. Reliable tunnel fallback path: `src/core.rs` `QFT1` packet framing -> `src/transport/connection/` immutable STREAM ledger -> confirmed-PMTU packetization -> centralized `OutboundPacer` -> ACK/loss/PTO retirement and requeue -> byte-exact PMTU fallback splitting -> peer `core.rs` bounded packet reassembly.
24. QUIC version negotiation path: `src/engine/config.rs` or `src/main.rs` ordered v2/v1 policy -> `src/transport/version.rs` selectable versions and grease -> `src/transport/packet.rs` stateless server VN -> `src/transport/connection/` strict CID/original-version gate and single restart -> `src/qftls.rs` version-matched rustls handshake plus authenticated Version Information downgrade validation.
25. Base Linux TUN proof lifecycle: `scripts/tests/tun-e2e-netns.sh` shared `flock` -> fail-closed pre-existing process/namespace check -> pre-open stale routing recovery -> exact server PID and durable routing-record capture -> SIGKILL/restart stale recovery -> TLS/H3/MASQUE TUN assertions -> graceful shutdown record removal -> exact child reap and owned namespace teardown; `scripts/tests/audits/audit-runtime-guardrails.sh` rejects global product-name process reapers on this path.
26. FEC operator-policy and observability path: `src/main.rs` / `src/implementations/server/mod.rs` engine `FecMode` -> `src/fec/` `FecConfig::apply_engine_mode()` -> independent `FecControlPolicy::{Off, Auto}` with Zero bootstrap -> `src/transport/connection/` independent recovery send/loss callback counts, transport-classified ACK counts, and congestion-controller smoothed loss -> `src/core.rs` typed `FecCallbackFeedback` transfer that admits only ACK/loss-bearing feedback to `AdaptiveFec::report_transport_loss()` -> recent-window-confirmed adaptive target or 32-clean-ACK Zero proof -> committed codec state -> actual wire send and `src/fec/wire.rs` accepted receive/recovery reports -> connection-local `FecTelemetrySnapshot` plus explicit process aggregates in `crates/qf-telemetry/src/lib.rs` -> read-only server metric projections in `src/implementations/server/metrics.rs`. Active Engine commands follow `EngineCommand::SetFecMode` -> typed `FecPolicyCommandResult` -> existing `ClientConnection` mutex -> `QuicFuscateConnection::set_fec_control_policy()` -> queued-source preservation/repair retirement -> fresh Zero controller and wire receive state; accepted policy persists into `ClientRuntime` reconnect configuration.
27. Client TUN uplink pressure and fault path: `src/main.rs` TUN reader channel -> event-loop drain with `tun_backpressure_frame` retry ownership -> `src/core.rs::send_tunnel_packet()` -> `src/transport/h3.rs::send_masque_datagram()` -> QUIC DATAGRAM queue (`ConnectionError::DgramQueueFull` backpressure) or oversized-packet framed H3 carrier -> socket flush and peer TUN delivery. Packets are not consumed from the TUN reader channel until the carrier accepts them; channel disconnect, reader termination, and non-retryable transport errors become typed data-plane faults and wake the owner.
28. Server TUN downlink pressure, fairness, and fault path: `src/implementations/server/mod.rs` TUN reader or authenticated client fan-out -> shared `ClientFanoutQueueState` admission (256 entries, 384 KiB, 32 entries/64 KiB per source, 64-item drain batch) -> direct admission and transport enqueue when shared shaping is disabled and that session has no backlog, otherwise bounded `LiveServerState::pending_tun_downlinks` (256 packets, 384 KiB, 32 per session, 5-second expiry) -> optional shared token bucket reserves aggregate service capacity -> weighted byte-deficit round robin preserves per-session FIFO and proportional saturated shares -> front-packet-derived visit budget returns immediately when every active session is deferred -> `SessionManager::check_bandwidth()` performs one downlink admission/accounting decision -> `send_masque_downlink()` -> path-aware retry or socket flush. Shared or per-session rate denials stay bounded and retryable; already admitted transport retries do not double-charge the session; failed transport admission refunds the shared reservation; daily/monthly quota denials are terminal for the packet; TUN reader/channel/write/send faults stop the owner and reach server readiness/health; queue, scheduler, bandwidth, audit, and exact terminal-drop metrics retain the outcome.
29. Server-generated MASQUE response pressure path: ICMP routing responses and asynchronous DNS interception -> `core::MasqueDownlinkQueue` (128 packets, 192 KiB per connection) -> `drain_masque_downlink_responses()` -> connection-owned retry slot on `ConnectionError::DgramQueueFull` -> subsequent housekeeping or packet pass; Prometheus telemetry reports retry, packet-capacity, byte-capacity, terminal-send, and shutdown outcomes.
30. Standalone dual-stack TCP diagnostic path: `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh` receiver trial boundary -> persisted start/end window plus client exit status -> `scripts/tests/utils/summarize-throughput-boundaries.py` observes encrypted client-to-server and server-to-client UDP at `qf523h1` and `qf523hs` -> per-window counts and gaps, including explicit zero return traffic. `scripts/tests/utils/udp-socket-evidence.py` snapshots `/proc/net/udp` before/after each trial and fails on a nonzero drop delta: server socket selected by local port 4433, client socket selected by remote port 4433 with local and remote endpoint continuity required.
    Exact ARM64 harness `57a2eed` has a clean full-run proof for all four observed boundaries and zero server socket drops. Its retained clean opt-in timeout also has equal forward counts of 7,086 and equal reverse counts of 6,072 at both host-veth boundaries with a zero server socket-drop delta. Exact ARM64 source `681705d` adds 18 zero-delta client socket summaries across all completed clean trials; child one passed the full gate, while children two and three later failed only in their deliberate black-hole recovery. On a future heartbeat failure, the harness-specific `QUICFUSCATE_CLIENT_RECV_DIAGNOSTICS=1` path records socket receipt, outer Core receive result, and transport `last_activity` advancement without changing ordinary runtime behavior. Exact source `a3ced4d` reproduced a clean opt-in TCP timeout before that heartbeat path, after a 12-packet application-space persistent-congestion run; matching encrypted boundary counts and zero client/server socket drops remain retained. Exact source `36a97d0` shows that all three reproduced client decisions had one triggering ACK, twelve declared losses, and a terminal time-threshold loss, with retained runs of 133, 219, and 107 ms. The next diagnostic boundary is ACK progression and time-threshold loss provenance before its transport-side decision.

31. Telemetry resource-sampling path: every connection's one-second maintenance -> `crates/qf-telemetry/src/lib.rs::refresh_resource_metrics_if_due()` -> disabled fast return or process-wide lock-free one-second admission -> current-PID memory-only `sysinfo` refresh plus owner-installed global-pool gauges. Explicit shutdown `flush()` remains unthrottled. Feature-gated orchestrator sampling returns before system access when its runtime owner is absent; otherwise the connection-retained current-PID sampler refreshes CPU, process memory, and host RAM -> `DeepIntegrationOrchestrator`.
32. Production logging path: CLI `--config` -> pre-runtime `EngineConfig::from_file()` plus `validate()` -> `LoggingConfig::effective()` -> one `logging::init()` global facade owner -> bounded `qf-log-writer` queue -> rotating file, stderr, RFC 5424 UDP, and admin-buffer sinks -> acknowledged `FlushGuard` shutdown barrier; persisted admin modes adjust the facade filter only and never replace sink ownership. The production runtime and `qf-logging-probe` each make one initialization call; TODO-674 removed the probe duplicate while preserving its process-level sink and admin-record proof. When global logger installation fails, TODO-812 sends worker shutdown and joins the temporary writer before returning the typed error.
33. Retained-secret erasure path: server or desktop token input -> `QKeyToken`/`SecretBytes` owner -> QKey serialization or zeroizing decoded JSON -> zeroizing binary decode -> SHA-256 verifier only in `QKeyRegistry`; client import -> typed config/profile -> live connection -> drop wipe. TLS installation/cache -> zeroizing private-key read, copied 1-RTT secret, ticket, and master owner -> replacement/eviction/drop wipe; AES header protection and AEGIS wrapper key/IV plus local derived state wipe before their owner is released. Test-only observers inspect the zeroed live ranges before clear/deallocation.
34. QKey auth abuse-policy path: validated `QUICFUSCATE_AUTH_*` environment -> `ServerConfig.auth_policy` -> `LiveServerState.auth_rate_limiter` -> pre-registry Initial admission -> pending `QKeyAuthState` attempt ID -> established QUIC/TLS connection starts the one-shot encrypted-H3 bearer deadline -> success/failure, timeout, connection close, or internal abandonment -> exactly-once completion -> backoff/block state, metrics, audit, and bounded housekeeping prune.
35. QKey auth process-proof path: `scripts/tests/suites/test-qkey-auth-policy.sh` refuses existing output and product processes -> validates fail-closed pre-resource startup -> creates an isolated CA/leaf/QKey state -> exercises CA-verified H3 auth, exact backoff/block/expiry/reset, secondary-loopback isolation, and idle prune -> runs exactly 100 real Initial attempts -> verifies metric/audit/resource/secret/UI/process contracts -> retains only caller-owned evidence.
36. DDoS admission process-proof path: `scripts/tests/suites/test-ddos-admission.sh` refuses existing evidence -> validates pinned real MaxMind country and city databases through `src/bin/qf-ddos-policy-probe.rs` -> rejects missing, permission-denied, corrupt, invalid-country, and valid non-country activation cases with typed errors -> starts the server with GeoIP enabled -> asserts exact active=1, disabled=0, and failed=0 Prometheus state plus health and Unix-admin truth -> restarts the server with the same verified database and reasserts all three surfaces -> serves a locally controlled certificate-verified HTTPS feed through the bounded custom-CA path -> proves atomic cache restart and failed-refresh last-known-good preservation -> completes a pre-activation no-Retry handshake and continuously exchanges ack-eliciting PING/ACK traffic on that connection -> drives a low baseline plus 800-packet sustained Initial spike -> observes one activation while the established client remains live -> completes one real Retry-protected QKey handshake -> observes one clear -> requires the original client to remain established with positive bidirectional packet counts and no additional Retry -> enforces CPU/RSS, secret, protected-UI, and process-residue bounds.
37. Per-session bandwidth control path: authenticated HTTP `GET|POST /api/clients/{session|remote|assigned-ip}/bandwidth` and `POST /api/clients/{id}/quota/reset` -> `ServerAdminCore` -> `SessionManager` live policy/quota owner. QKey issuance accepts the same complete `BandwidthPolicy`; persisted QKey policy overrides global defaults only after bearer authentication, while later admin mutation overrides the live session without resetting usage.
38. Traffic-analysis policy and timer path: standalone TOML baseline plus QKey and Intelligent ceilings -> validated `TrafficAnalysisPolicy` -> pending QKey request stored before authentication -> encrypted bearer success authorizes the bounded effective policy -> one `TrafficAnalysisScheduler` deadline participates in the Core wakeup minimum -> at most one due slot -> real/ACK/control/recovery/PMTU priority or congestion deferral -> encrypted path-MTU-bounded chaff emission -> idle ramp, reactivation, or terminal cancellation. FullPadding costs use the maximum UDP payload; ConstantRate costs and packet sizes use the configured target capped by that payload.
39. Network-stack fingerprint path: server config or `QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION` plus `QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE` -> one frozen `StealthConfig` snapshot -> TLS/H3 persona and `PacketNormalizer` created together in `QuicFuscateConnection::new_server()` -> decoded MASQUE DATAGRAM, raw capsule, compressed capsule, or `QFT1` framed-H3 packet -> one allocation-free IPv4 and SYN-only TCP normalization pass -> PMTUD-safe ICMP disposition -> authenticated server TUN/fanout callback. Server-generated routing, MTU, and time-exceeded ICMP uses the same frozen profile TTL or hop limit. Client connections, Off mode, sealed QUIC datagrams, fragments, and ordinary server-to-client downlink retain their explicit passthrough boundaries. The active hook records five-profile response vectors and fails closed on missing direction, checksums, IP-ID progression, or transport-byte evidence; it does not imply an exact Nmap classifier match.

## ASCII Repository Tree (curated tracked-source snapshot)

This snapshot intentionally excludes gitignored paths and local generated directories. `assets/web-admin/` is generated output and is intentionally absent; `scripts/build/build-web-admin.sh` creates it before local server or release-bundle use.

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
|   |   |   |   |-- ipc-contracts.ts
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
|   |-- bench_cli
|   |   `-- mod.rs
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
|   |   |-- verify-release-updater.sh
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
|   |   |   |-- test-benchmark-cell-contract.sh
|   |   |   |-- test-release-updater-artifact-contract.sh
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
|   |   |   |           |   |-- ipc-contracts.test.ts
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
|   |   |   `-- seeds                    (tracked curated binary corpus, eight files per target)
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
|   |   |   |-- rt-transpose-parity.rs
|   |   |   |-- rt-udp-batch-send.rs
|   |   |   |-- rt-varint-roundtrip.rs
|   |   |   |-- rt-xor-repeating-parity.rs
|   |   |   |-- rt-xor-parity.rs
|   |   |   `-- rt-xor-sse2-parity.rs
|   |   |-- smoke
|   |   |   |-- smoke-avx10.sh
|   |   |   |-- smoke-bench-example-cli.sh
|   |   |   |-- smoke-engine-example.sh
|   |   |   |-- smoke-netfilter-fastpath.sh
|   |   |   |-- smoke-shell-portability.sh
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
    |-- memory_lock.rs
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
- `ServerConfig` is the effective server-network authority for both runtime forms. `ServerRuntime::new()` accepts only matching optional `EngineConfig.interface` IPv4/IPv6 assertions and rejects conflicts before host-resource startup; embedded `ServerHostResources::start()` projects TUN addresses from `ServerConfig` directly. Standalone `TunConfig` address fields are reconciled to the same server network before validation/open, with missing fields inherited and conflicts rejected. `ServerConfig::assignment_settings()` also rejects reversed, out-of-network, or server-owned client pools, keeping routing/firewall subnet, TUN address/prefix, local ICMP/source ownership, and allocation on one validated network.
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
- Client DNS runtime (`src/implementations/client/dns_runtime.rs`): `ClientDnsRuntime` binds the client DoH proxy on localhost UDP/53, shares one validated `DnsAdmission` across IPv4 plus best-effort IPv6 listeners, configures the active platform resolver with the live TUN interface name, and restores resolver state before connection/TUN teardown. A restore failure retains the runtime for retry and prevents the Engine from reporting `Stopped` or disabling its kill-switch policy. Localhost admission is source-IP scoped because the UDP boundary does not carry process identity.
- macOS: PF policy is available only when the main ruleset exposes the QuicFuscate anchor. Client activation parses an actual `anchor` statement, returns an actionable error when the reference is absent, and rolls back a just-loaded anchor before reporting activation failure; `enable()` clears state after a successful bounded rollback and retains fail-closed ownership only when rollback itself fails. Client cleanup touches only `com.quicfuscate.killswitch` and never disables shared PF. `scripts/install/install-macos-pf-anchor.sh` owns only the exact marked `anchor "com.quicfuscate.killswitch" all` reference in `/etc/pf.conf`, with a mode-0600 state/backup pair and a private lock; it never enables/disables PF or flushes unrelated anchors. Server routing rejects macOS before host mutation and retains only pure rule generation. `scripts/tests/macos-pf-anchor-proof.sh` owns the read-only privileged main-ruleset/anchor/block-rule check, while `scripts/tests/fast/test-macos-pf-anchor-installer.sh` covers the non-privileged file transaction. TODO-548 still owns the privileged packet/coexistence/uninstall proof.
- Windows: `src/implementations/client/killswitch/windows.rs` owns one fixed persistent WFP provider/sublayer plus eight fixed filter slots. Each state replacement transaction deletes and recreates only those identities, then installs higher-weight loopback, exact endpoint, and optional live Wintun-LUID permits before a lower-weight catch-all block at IPv4/IPv6 outbound transport layers. Those layers also classify third-party transports and raw packets without widening the endpoint beyond its UDP address/port tuple. `WfpOwnerState` keeps engine and transaction ownership set after failed close, commit, or abort statuses, records the exact status, permits explicit retry while the owner remains in scope, and makes a bounded `Drop` attempt with durable pending diagnostics. Every WFP status return is checked, and borrowed display, condition, key, and transaction pointers are scoped to their synchronous native calls. Explicit disable and stale cleanup delete the complete identity set plus the two exact legacy `netsh` rules. The legacy `WindowsPlatform` adapter path still fails before host mutation. `src/interface/wintun.rs` remains the only valid native data-plane owner and its WFP test observes the adapter ring instead of treating socket acceptance as packet delivery. Run `30508948149`, job `90764941801` is historical native evidence for Wintun lifecycle, all WFP packet-policy states, process-exit retention, stale cleanup, and zero residue; release run `30533862566` is historical evidence for the signed packaged boundary; Windows-Omega runs `30535603045` and `30536002374` are historical evidence for the authenticated connected-policy data plane and exact cleanup. The current deterministic engine-close and transaction-abort fault tests are wired into the Windows core lane, but current Windows/BFE fault execution and new-failure residue proof remain unclaimed.

### Automatic Loss Ownership
- `Connection::last_activity_elapsed()` (`src/transport/connection/`): Exposes time since the last inbound datagram.
- `ClientRuntime::start_loss_watchdog()` (`src/implementations/client/mod.rs`): Owns one 50 ms remote-close/inactivity loop, records the first `DisconnectReason`, stops the I/O driver, and invokes the loss transition callback once.
- `QuicFuscateEngine::connect()` (`src/engine/engine.rs`): Applies endpoint-only policy before handshake, connected policy after handshake, and installs the runtime watchdog. Callback and event snapshots avoid holding callback locks during user code.
- TUN runtime ownership: `TunInterface::reader_loop_with_shutdown()` owns the cooperative atomic stop and Unix `poll(2)` wait; client and standalone server readers publish cooperative shutdown before dropping their bounded receiver, wake the native Wintun event where required, join their owned `JoinHandle`, and release the TUN descriptor after the thread exits. Unexpected reader termination, channel disconnect, TUN write, and transport send/receive failures publish typed data-plane faults; `Notify` wakes both select loops for queued frames or faults, while adaptive housekeeping uses a 5 ms active floor and 250 ms idle ceiling.
- Generic and native TUN result ownership is now fail-closed across the wrapper and syscall boundaries: `TunInterface` rejects zero or oversized reads before pooled-block slicing, requires complete writes before caller success or accepted-byte telemetry, and applies the same invariant to borrowed and owned readers; TODO-845 adds bounded Linux read/write results, macOS `readv`/`writev` progress and total checks, bounded kernel-name parsing, exact Linux rollback identity, and terminalized close ownership with observable failures. TODO-846 adds a retryable Wintun owner ledger, structured constructor rollback, exact upstream packet-thread-safety wording, and a blocked-reader close assertion. Native privileged execution remains separate.
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

This and every later dated, session, or evidence section are historical evidence snapshots. Current task status and open gates are read from `docs/todo.md` and the linked detail-file frontmatter; historical `open`, `complete`, or `pending` wording below must not be read as a current status claim.

A full source-audit sweep produced TODO-626 through TODO-689 and augmented TODO-570, TODO-584, TODO-587, TODO-592, TODO-615, TODO-576, and TODO-649. The new findings affect the following wiring surfaces and should be reconciled before treating those areas as production-proven:

- **Crypto data plane**: constant-time tag comparison (TODO-626), key/IV length validation (closed by TODO-627), AEGIS mutex/`unwrap` path (TODO-628, resolved by TODO-582), AEAD header-protection sample validation (TODO-629), GHASH dispatch configuration (TODO-630), target-specific `AesGcm128` schedule zeroization (TODO-631), nonce/IV uniqueness (TODO-632), QUIC KDF input validation (TODO-633, local exact-length implementation active), and TODO-681's implementation pass across all seven crypto primitives. Retained and temporary AES schedules, ChaCha nonce/one-time-key material, and constructor copies now have local zeroization owners. The AES table fallback is explicitly not constant-time; x86 GHASH and AArch64 PMULL controls are documented as independent feature-checked release surfaces. TODO-834's exact dispatch delta is reconciled, checked seal-length arithmetic is closed by TODO-716, and primitive AEAD boundaries reject packet numbers above QUIC's 62-bit limit. Native ISA, compiler-erasure, copied-AEGIS-state, and side-channel proof remain open.
- **FEC recovery**: unbounded fountain-decoder storage (TODO-634), adaptive emitted-ID cap (TODO-635), decoder peeling complexity (TODO-636), and Wiedemann buffer reuse (TODO-637).
- **Transport/Stealth**: terminal close priority (TODO-697; first-close-wins idempotency resolved by TODO-606; local close error-kind semantics resolved by TODO-772), ConnectionId clone hot path (TODO-638), StealthShaper RNG fallback logging (TODO-639), H3 masquerade time source (TODO-640), domain fronting jitter (TODO-641), TLS cover zero-key fallback (TODO-642), qftls `munlock` (TODO-643), bounded probe detector history (TODO-644), EscalationState timestamp bound (TODO-808), and brain escalation/histogram/config correctness (TODO-584). Reality session map timer-driven cleanup is resolved by TODO-570.
- **TLS fingerprint metadata**: TODO-595 corrects the Chrome-based `qftls` extension order to use one `server_name`, registered `renegotiation_info` (`0xff01`), one `compress_certificate` (`0x001b`), and no invalid `0x0019`; a regression test enforces uniqueness and the scoped registered-ID set.
- **TLS Cover and persona boundary**: TODO-596 removes the unread `TlsCoverProvider` ClientHello-template and extension-builder machinery, removes the no-op `CombinedProvider` override seed, and keeps rustls as the real ClientHello owner. `CombinedProvider::supports_ch_override()` is false for the cover overlay. TODO-598 removes the dead advanced builder and enforces the no-ChaCha real-TLS policy through one filtered rustls provider shared by client and server connections. Safari uses a dedicated HTTP/3 header template without `sec-fetch-*`, `upgrade-insecure-requests`, or `cache-control`. `TlsClientHelloProfileCatalog` and `FingerprintProfile::client_hello` retain deterministic metadata only for compatibility/audit inspection; TODO-766 removes the former write-only transport storage and setters.
- **MASQUE/DoH ownership**: TODO-597 makes Core H3/MASQUE the sole active CONNECT-UDP/capsule carrier, buffers split capsule DATA, rejects malformed or truncated FIN tails before event delivery, and covers all 1/2/4/8-byte varints including 16,384-byte payloads. The empty `stealth::MasqueManager`, its false-success send path, the stale stealth-local DoH resolver, and their integration test are retired and preserved under `archive/`; shared DoH primitives remain in `src/dns/mod.rs`, while `ClientDnsRuntime` owns the active client resolver path. The server's final DNS hop remains plain UDP by design. TODO-771 completed the runtime wiring.
- **Optimize/Engine/Admin**: engine config reload (TODO-645), io_uring executor ownership (TODO-646), io_uring partial-send disposition (TODO-798), admin HTTP capacity and operation ownership (TODO-647, TODO-661), config write validation (TODO-648), MemoryPool lock release ownership (TODO-516), unsafe raw-pool ownership (TODO-826), safe-pool origin/capacity/TLS/ephemeral accounting (TODO-827), zstd FFI/context synchronization (TODO-828, complete), allocation layouts and recoverability (TODO-829), zero-copy syscall conversion (TODO-830), generic pooled-buffer failure cleanup (TODO-831), FEC pooled-buffer cleanup and symbol lengths (TODO-832, complete), zero-copy DATAGRAM queue return (TODO-833, complete locally), metrics export allocations (TODO-587, TODO-615), and TUN interface unaligned/fcntl safety (TODO-654, TODO-655). Admin-web capacity is CLI-owned with default `16` and maximum `1024`; admission is acquired after `accept()` but before task creation, excess sockets are dropped without a user-space pending queue, and accepted tasks are joined on shutdown. Each accepted request uses a validated `50..=120000` ms operation deadline, a bounded command/result channel, an owned blocking worker `JoinSet`, explicit timeout/cancellation/panic/late-completion counters, and a one-second shutdown drain. Effective operation state is included in runtime admin status and health. TODO-687 closed the io_uring unsafe/lifetime and receive-slot audit boundary; TODO-801 closed the additional Linux kernel evidence boundary.
- **Privilege and secrets**: TODO-651 now stores SecretString in a private String owner, validates the checked SecretBytes-to-SecretString boundary, and retains zeroization on drop; native runtime proof remains environment-specific. TODO-652 validates libc result-pointer identity before `assume_init`, and TODO-653 bounds account-name pointers to the returned lookup buffer and a verified NUL before `CStr::from_bytes_with_nul`; both boundaries have local tests. TODO-643 now owns represented preloaded-key lock/publication lifecycle, including exact rejected-value cleanup and explicit duplicate/conflict results. TODO-849 now closes the public forged-identity and cross-target `CurrentIds` source contracts, adds local FFI safety comments, and rejects malformed `getgroups()` counts; TODO-850 closes the source-level filesystem-ID/post-drop state contract and local standard/Tokio probe assertions; TODO-851 closes process-lock policy propagation and embedded ordering; TODO-852 closes process-lock failure/readiness policy, TODO-853 closes certificate-key correspondence and zeroizing key-output ownership, and TODO-854 closes local deterministic privilege, memory-lock, TLS, ordering, and portability-proof wiring. Native Linux root-regain and Windows native fault lanes remain explicit unavailable boundaries. fsutil TOCTOU is resolved by TODO-591 (duplicate TODO-667).
- **SIMD/time-source**: TODO-816 removed the former AMX `static mut` tile config, unverified raw kernels, and compile-time-absent production branch; TODO-817 removed the external detector process and made AMX product eligibility fail closed. TODO-818 owns an explicit proof lane with exact `+amx-tile,+amx-int8` compilation, Linux x86 `arch_prctl` tile-state evidence, compiler/OS/CPU/source-revision metadata, machine-readable `AVAILABLE`/`UNAVAILABLE`, scalar GF(256) parity, concurrency, malformed-dimension, scratch-reset, and telemetry coverage, plus Full-Suite/Comprehensive-Audit/CI wiring. BF16 is not required. The active Wiedemann path remains scalar and the proof lane remains `UNAVAILABLE` until a verified native AMX arithmetic backend exists. Intel AMX is independent of `X86_P3e`, which is the AVX-512F + GFNI profile; `Apple_M` is a NEON/crypto profile whose current callers use NEON, and its Apple matrix bit is metadata only. TODO-676 closes the current compiled/runtime/OS intersection, scalar-versus-AMX dispatch, and concurrent tile-ownership boundary; TODO-819 closes profile/documentation truth. The complete clock inventory covers direct and implicit Rust/Tokio/browser monotonic and wall-clock reads across transport, H3, core, engine, stealth, qftls, server, client, runtime, telemetry, audit, PKI, Tauri, Svelte, tests, probes, and scripts (TODO-677); TODO-656 closes the PKI validity-time boundary. TODO-820 owns transport/stealth/core, TODO-821 server/client state, TODO-822 Tokio/OS/runtime domains, TODO-823 wall-clock provenance, TODO-824 Rust injection/test isolation, and TODO-825 frontend/browser clocks; TODO-640, TODO-658, TODO-662, TODO-671, TODO-675, TODO-768, TODO-584, and TODO-588 remain narrower owners.
- **SIMD safety hardening**: TODO-593 covers the historical x86 GF(256) matrix, BMI2, header, Reed-Solomon, and Windows SHA boundaries. TODO-835 makes the short-needle load use owned sixteen-byte padding, rejects invalid GF(256) matrix dimensions and slice lengths in release mode, returns zero for undersized BMI2 output, rejects overlong Berlekamp-Massey prefixes, and makes private repeating-key and ChaCha XOR length contracts fail closed. TODO-836 adds local `# Safety` contracts to the current 131 unsafe SIMD declarations, removes the blanket lint suppression, and makes unsupported ISA tests emit explicit `SIMD_SKIP` records. Focused malformed-input and exact-tail tests are added; native x86/Linux, Windows, SVE2, sanitizer, and Miri evidence remains an explicit unclaimed boundary.
- **SIMD audit follow-up**: TODO-679 completed the read-only audit of all 31 SIMD source/test files, the historical 138 unsafe function declarations, 102 historical target-feature attributes, direct callers, tests, audit scripts, documentation claims, and relevant history. TODO-834 completed the exact dispatch-owner audit and implementation of the feature intersections and caller corrections. TODO-835 completed its release-safe boundary implementation and focused malformed-input coverage; remaining vector tails were cross-checked. TODO-836 completes the proof-owner implementation with a source-driven visibility-complete inventory, exact target-feature wording checks, and explicit unsupported-lane accounting. The 2026-08-07 closure reconciliation passed the SIMD feature-contract and cargo metadata gates; the aggregate runtime guardrail retains four pre-existing critical findings and one warning outside this owner. Native x86/Linux, Windows, SVE2, sanitizer, and Miri evidence remains unclaimed.
- **SIMD Reed-Solomon compatibility path**: TODO-594 corrects the standalone x86 AVX2/GFNI Reed-Solomon encode/decode implementations, including cross-shard accumulation, canonical GF(256) coefficients, full matrix inversion, dynamic LUT multiplication, safe vector tails, and runtime shard metadata checks. Rosetta-executed x86 tests pass; production recovery remains wired through `src/fec/`, while the completed FEC/GF16 audit is TODO-686 and GF16 polynomial correctness remains TODO-715. TODO-679's audit confirmed that the old AVX2-to-GFNI delegation claim is stale and split the remaining SIMD work into TODO-834, TODO-835, and TODO-836; FEC-specific SIMD remediation is TODO-855.
- **FEC SIMD contract**: TODO-855 closes the current FEC target-feature and release-safe length implementation boundary. The shared matrix selects distinct VBMI2/VBMI/AVX2/SSE2/SVE2/NEON/scalar levels, private helpers bound lengths in release builds, PCLMUL and compile-time SVE2 paths use runtime matrix gates, and the guardrail inventory includes `src/fec`. TODO-859 retains complete native/negative/differential proof and documentation truth; TODO-715 retains GF16 PCLMUL mathematics.
- **Unsafe memory and pooled-buffer boundaries**: the feature-gated `UnsafeMemoryPool` cache/raw-pointer ownership contract is implemented with synchronized exact-base registry checks and focused `unsafe_rust` coverage under TODO-826; TODO-827 implements the safe `MemoryPool` origin/capacity/TLS/ephemeral ownership and accounting state machine, including bounded TLS-aware shrink, pool/TLS lifetime cleanup, and release-safe cleanup for rejected blocks. TODO-828 implements the checked native/fallback zstd context, mutex-serialized `Sync`, explicit failure typing, checked header lengths, and pool cleanup. TODO-829 provides checked 64-byte layouts, `isize::MAX` capacity bounds, fallible constructors/allocation/resize APIs, partial-construction cleanup, and explicit compatibility-wrapper panic policy. TODO-830 now owns the typed Unix/Windows zero-copy send/receive boundary, exclusive receive borrows, checked iovec/WSABUF conversions, and direct-caller progress policy; its Windows-target gate remains open. Generic pooled-buffer failure cleanup (TODO-831), FEC pooled-buffer cleanup and symbol lengths (TODO-832), and zero-copy DATAGRAM queue return (TODO-833) are complete on the current ARM64 macOS workspace. TODO-826 through TODO-833 close the implementation split; umbrella TODO-678 remains blocked only by unavailable Miri and native Linux/Windows/ISA evidence. TODO-679 is the completed SIMD audit owner; TODO-834's feature-intersection implementation and local ARM64 verification are complete, TODO-835's release-safe unsafe-boundary implementation is complete, TODO-836's shared SIMD safety-contract guardrail is complete, and TODO-855 now closes the FEC-specific matrix, threshold, telemetry, length, and local safety-contract implementation boundary. Native safety proof remains unclaimed. TODO-680's Optimize audit is also complete and recorded the P1f-to-AVX2 reduction route, P4a-to-AVX512 moving-average route, test-only BMI2 bitmap boundary, short-pattern overwrite, overflow-prone pattern positions, SVE2 base64 output coverage, packet-number/VNNI contracts, Linux batch FFI proof gaps, and percentile/profile test gaps. Remediation remains open for the separate owners.
- **Unsafe crypto/transport/interface/privilege**: crypto primitives (TODO-681 source-and-owner reconciliation complete; schedule/transient-state, AES table, GHASH-control, copied-AEGIS-state, and native-proof findings remain; checked lengths, primitive nonce rejection, and the MORUS loader precondition are source-closed), transport batching/UDP/AF_XDP removal/frame-packet/PMTU surfaces (TODO-682 source-and-owner reconciliation complete; TODO-834 resolved the historical AVX2 packet-number endian and exact x86 ACK-dispatch findings, TODO-831 removed the historical temporary batch-pool path, and TODO-839-TODO-842 retain the remaining transport remediation and proof boundaries), interface/Wintun/platform/WFP (TODO-683 audit complete; remediation split into TODO-843-TODO-848), and privilege/mlock/qftls/secret handling (TODO-684 audit complete; TODO-516, TODO-643, TODO-652, and TODO-653 have local remediation, TODO-849-TODO-854 close the current local implementation and proof split, and native Linux/Windows execution remains unclaimed; TODO-651's local String-backed UTF-8 remediation is implemented). No frontend or Tauri implementation crosses these backend boundaries.
- **Unsafe FEC/io_uring/auxiliary**: TODO-686 completed the FEC GF-table/decoder and public-boundary audit; remediation is split across TODO-634, TODO-636, TODO-637, TODO-690, TODO-715, and TODO-855-TODO-860, while TODO-832 closes the pooled-buffer ownership boundary. io_uring/io_driver lifetime ownership is TODO-687, unordered partial-send disposition is TODO-798, audit-file FFI and Windows API boundaries are audited under TODO-688 with remediation TODO-861, and TODO-689 completed the remaining cpu_dispatch/telemetry/cache/lib.rs/tests audit. Auxiliary remediation is TODO-862 through TODO-865; TODO-834 closes the SIMD dispatch implementation boundary, TODO-835 closes the release-safe slice boundary, TODO-836 closes the local SIMD safety-contract and unsupported-ISA guardrail implementation, native SIMD proof remains unclaimed, and environment ownership remains TODO-670/TODO-811.
- **Unsafe QKey/admin**: TODO-685's current-source reconciliation found no raw-memory unsafe operation in QKey registry or admin session logic. QKey registry storage retains one Windows `MoveFileExW` path-encoding and native-proof boundary under TODO-873; current failpoint coverage exercises only the host `rename()` branch and does not prove Windows success, failure, or interior-NUL rejection. TODO-861 owns audit-file FFI, TODO-728 owns audit pathname binding, and TODO-647/TODO-661/TODO-665 own admin session lifecycle and replay contracts.

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
- **Replay protection:** The admin session store uses a timestamped bounded `VecDeque` plus `HashSet`: fingerprints are rejected for the explicit five-minute replay window, expired entries are pruned from the front, and one oldest entry is evicted per insertion beyond 4,096. Reuse after the time window or history-cap eviction is accepted while the sliding session remains valid. The outer store admits at most 256 live sessions, rejects new logins at capacity without silent active-session eviction, exposes active/created/rejected/expired counters, and clears on server shutdown.
- **Environment parsing:** No supported external-process or safe concurrent mutation path establishes a torn-read defect. TODO-670 owns the shared helper's invalid/default/alias/whitespace/snapshot contract and caller coverage; TODO-811 closes the active direct parser authorities, subsystem-specific fallback contracts, and lazy initialization boundaries. The remaining direct readers are typed server/QKey startup loaders or test/build/OS integration variables.
- **File modes:** TODO-671 closes the remaining umask-dependent writer boundaries. Linux resolver targets use `0o644`, resolver locks and backups use `0o600`, rotating operational logs use `0o640` across create/reopen/truncate/rotation, profile temporaries use `0o600`, and direct audit reopens reassert active-file mode `0o600`. `fsutil`, QKey registry, resolver ownership state, routing ownership state, and PKI private-key writers retain their restrictive creation modes; TODO-662 owns profile atomic publication, deterministic serialization, temporary cleanup, and Unix parent-directory durability.
- **Log rotation:** `src/logging.rs` owns FIFO `Rotate` and `Reopen` commands with bounded acknowledgements. Authenticated `POST /api/logs/rotate` force-rotates through the writer owner and emits a typed admin audit event. Unix SIGHUP preserves the validated next-connection-only config reload, then independently reopens the file sink and audits/logs the result. External rename and copytruncate are supported by sending SIGHUP after the pathname operation; reopen refreshes tracked size from the current pathname. TODO-672 is complete; failed logger-installation worker cleanup remains TODO-812.
- **CLI control protocol:** TODO-673 closes the request boundary. The registered Unix-only `quicfuscate-ctl` target builds typed commands with exact arity, rejects invalid/empty/control-character/oversized values before socket I/O, canonicalizes IP and client identities through shared helpers, and emits one newline-terminated JSON frame capped at 8 KiB including the newline. The server retains its five-second bounded reader and revalidates commands, including unknown-field rejection. TODO-617 owns socket identity and framing; TODO-795 owns the bounded typed response contract.
- **Audit persistence:** `AuditLog::flush` bounds the producer acknowledgement wait, and a writer-side watchdog publishes one terminal failure when synchronous `flush` or `sync_data` exceeds the configured deadline. Write/checkpoint failures, terminal event discards, slow flushes, and sticky shutdown failures are counted in `AuditStats` and Prometheus. The shutdown CAS closes event admission before draining in-flight producers and sending the final barrier; a stalled worker remains owned and reports a bounded shutdown timeout instead of false success. TODO-727 and TODO-728 retain existing-file read bounds and pathname binding; TODO-813 closes the shared configuration/probe maxima boundary and TODO-814 closes producer-side dynamic payload bounds.

## Deep Audit Reconciliation (2026-08-02, unsafe and protocol lifecycle)

This pass reconciled the remaining unsafe inventory and the next transport/FEC lifecycle surfaces against the current source. No product implementation was changed.

- **Crypto corrections:** TODO-631's blanket round-key zeroization claim is stale because the AES-NI schedule exists only on x86_64 and is zeroized in its target-specific `Drop`; key and IV zeroization remains cross-target. TODO-642's zero-key fallback claim is stale because TLS cover entropy failure returns a typed crypto error before derivation. TODO-627 closes the constructor key/IV boundary; TODO-629 and TODO-632 retain the independent header-protection and nonce-lifecycle contracts, while TODO-633 now owns the local exact 32-byte KDF boundary and its remaining full-matrix/native proof.
- **AMX:** TODO-816 removes the compile-time-absent AMX branch from `src/fec/parts/decoders.rs`, restores scalar GF(256) SpMV for ordinary and target-feature x86 builds, and removes the uncalled raw kernels and global tile config. TODO-817 removes the external detector process and separates CPU, OS, compiler, and backend eligibility evidence. TODO-818 adds `rt-amx-proof`, the exact target-feature shell lane, explicit `UNAVAILABLE` exit/result semantics, Linux x86 tile-state probing, scalar FEC parity/concurrency/dimension/scratch/telemetry coverage, and audit/full-suite/CI wiring. `WIEDEMANN_AMX_OPS` and AMX scratch telemetry remain reserved and zero in the active path; the native backend marker remains false, so no native AMX arithmetic claim is made. `X86_P3e` remains the AVX-512F + GFNI profile, while `Apple_M` routes current callers to NEON and its Apple matrix bit is metadata only. TODO-676 closes the current race/dispatch/runtime boundary for the inactive production backend; TODO-819 closes profile/documentation truth.
- **Unsafe memory and pooled-buffer boundaries:** `src/optimize/unsafe.rs` calls a field named `tls_cache` through shared `UnsafeCell` state without actual thread-local storage, permits fallback allocations to desynchronize capacity/available counters, and performs block-size-independent prefetch pointer arithmetic. `UnsafeCompressor` exposes a shared mutable zstd context through `Sync`. The active safe `MemoryPool` has separate ephemeral, foreign-origin, TLS-shrink, and counter contracts, while compatibility raw `AlignedBox` boundaries remain explicitly owned; generic, FEC, and zero-copy DATAGRAM paths now use `PooledBlock` for pool-backed ownership. The historical `copy_to_block` inventory is absent from the current source. TODO-678 is the umbrella index; TODO-826 through TODO-833 own the completed split boundaries.
- **SIMD:** TODO-679's current-source pass confirmed that the old AVX-512/GFNI Reed-Solomon delegation claim is stale for the active decoder. TODO-834 completed the dispatch and compiled-surface implementation, including the exact feature intersections, direct FEC/packet callers, and packet-number network-order regression. TODO-835 closes the critical `find_pattern_sse42_short` short-needle load, release-safe matrix/BMI2 dimension/output checks, overlong Berlekamp-Massey rejection, and private-helper caller contracts; remaining vector tails were cross-checked. TODO-836 completes the proof implementation for the current 131 unsafe declarations, source-driven restricted-visibility matching, exact feature wording, and explicit unsupported-ISA accounting. Native x86/Linux, Windows, SVE2, sanitizer, and Miri evidence remain unclaimed.
- **Optimize and UDP:** TODO-680's implementation now rejects reversed and clipped bitmap ranges before SIMD dispatch, preserves exact short-pattern writes and rejects overflowing positions, bounds SVE2 Base64 output predicates to one vector, enforces QUIC packet-number lengths, processes VNNI inputs beyond the active 64-sample window in bounded chunks, defines invalid percentile behavior, validates test-only Linux RPS names and CPU masks, and adds focused safety contracts. TODO-834 closed the former P1f/P4a dispatch routes, BMI2 selection predicate, AVX2 packet-number byte order, and stale SVE2 search symbol; TODO-837 owns the shared UDP result/address/partial-send and caller-fd contract, while native/profile and platform proof remain open. TODO-682 split the remaining shared transport remediation into TODO-838-TODO-842.
- **Interface and platform:** TODO-683's current-source and owner reconciliation covers the full interface, caller, platform-gate, cleanup, test, script, documentation, and history scope. TODO-834 now gates the BMI2 parser with `features_full().bmi2` and scalar fallback, and TODO-654 uses `std::ptr::read_unaligned`; native/negative proof remains open. TODO-844 closes the shared TUN wrapper result contract, and TODO-845 closes the source-level Unix raw-result, progress, bounded-name, rollback, and close-ownership contracts with deterministic fault fixtures and explicit platform runners. TODO-846 closes the Wintun source-level cleanup ledger, startup-owner rollback, and Send/Sync contract; TODO-847 closes source-level WFP engine/transaction ownership with retained failure state, safety contracts, and deterministic status-fault fixtures. TODO-848 now owns the versioned negative-proof manifest, exact host skips, and explicit unavailable native fault lanes. Windows injected Win32/WFP failure execution, privileged residue proof, and cross-target compilation remain unclaimed. No new native test execution was claimed in this audit reconciliation.
- **Privilege and FFI:** TODO-683 completed the full read-only source, caller, platform-gate, cleanup, test, script, documentation, related-TODO, and history pass for interface and platform boundaries. TODO-684 completed the corresponding privilege, memory-lock, qftls, secret, caller, platform, cleanup, test, script, documentation, related-TODO, and history pass. TODO-652 closes returned-pointer identity and TODO-653 closes bounded account-name conversion in `src/privilege/drop.rs`, both with local deterministic tests; TODO-849-TODO-850 now close the source-level final-boundary identity, portable `CurrentIds`, complete filesystem-ID, typed partial-transition, and local probe contracts. TODO-851 closes standalone/embedded policy propagation and ordering, and TODO-852 closes process-lock failure/readiness policy. Pool/key unlock ownership remains TODO-516/TODO-643, and TODO-853 closes certificate/key-output ownership. TODO-854 closes local deterministic privilege, memory-lock, TLS, ordering, and portability-proof wiring. Native Linux root-regain and Windows native fault lanes remain environment-specific and unclaimed.
- **FEC unsafe inventory:** TODO-686 completed the full FEC audit. Active GF(256)/GF(16) wrappers clamp slice lengths before private vector calls; the old public raw-slice and SSSE3 claims are stale. TODO-855 now closes the 12-declaration local `# Safety` inventory, release-safe length bounds, shared PCLMUL/NEON/SVE2 matrix gates, distinct GF16 SIMD levels, threshold mapping, and FEC guardrail scope. TODO-834 closes the shared feature-intersection implementation for FEC/GF16 dispatch; TODO-859 retains native negative/differential proof and documentation truth, while TODO-835/TODO-836 retain their broader SIMD owners. TODO-832 closes pooled production packet ownership and declared-length transfer; TODO-856 now closes direct compatibility-constructor lengths, Decoder4/8/16 dimension and active-block checks, public matrix shape validation, direct wire-helper validation, and source-only small-pool truncation. TODO-857 now closes direct Fountain constructor bounds, source-index admission, symbol-size parity, and propagation validation. TODO-858 now closes direct FEC policy construction, runtime-policy limits, sent/acked/lost tuple invariants, non-finite feedback, and controller conversion boundaries. TODO-860 retains direct counter wrap, interleave-shape arithmetic, sequence narrowing, repair-ID packing, Fountain wire source-ID arithmetic, and decoder/Wiedemann/Fountain size conversions. TODO-816 and TODO-676 close the active AMX kernel, dispatch, and concurrent ownership boundaries; TODO-817-TODO-819 retain detector, proof, and profile owners.
- **io_uring:** The current sender copies payloads into owned slots before publishing pointers and quarantines after submit/protocol errors; SendMsgZc tracks `CQE_F_MORE` and waits for every announced notification, including errored primaries. Receive completion metadata is range-checked, zero-length and error receives are re-armed, and ring destruction precedes pool-block return. Client eventfd reads require exactly eight bytes. TODO-687 closed the unsafe/lifetime boundary and TODO-801 closed the additional Linux kernel evidence boundary. TODO-646 now owns the bounded sender admission, runtime worker, shutdown, and generic client TUN contract; its Linux compile/live-proof gate is blocked by the local macOS toolchain. TODO-798 owns unordered partial-send retry disposition.
- **Auxiliary unsafe surface:** TODO-689 completed the read-only audit of the remaining `cpu_dispatch`, prefetch, Windows NUMA, global-pool/auto-tuner, test-environment, telemetry, crate-root, transport/config, and test-only constant-buffer surfaces. TODO-862's current pass confirms that non-iOS AArch64 `read_volatile` is a faulting load behind a null-only pointer API and the x86 intrinsic argument remains unproved. TODO-863 confirms ignored `GetCurrentProcessorNumberEx` status and node-zero availability semantics. TODO-864 confirms lazy/explicit auto-tuner divergence, a process-global shutdown slot without `GLOBAL_POOL` reset, and telemetry initialization side effects. TODO-865 confirms N-1 capacity, ignored free-list insertion, modulo-zero for N=0, and partial index checking. Remediation is TODO-862 through TODO-865; TODO-670/TODO-811, TODO-834/TODO-835/TODO-836, TODO-841, TODO-843, and TODO-752 retain adjacent ownership. Telemetry, crate-root, and transport/config matches are source-text false positives. No architecture, Windows, lifecycle, or rust-tests gate was run for these reconciliations.
- **FEC solver:** `solve_wiedemann_system` still returns a copy of `rhs` after constructing the Krylov sequence and minimal polynomial; the existing equation check and Gaussian fallback are containment, not a functional solver. The all-feature fixture also uses an inconsistent repair packet identity. TODO-690 owns both mathematical correctness and fixture separation.
- **HTTP/3 control and parser:** The local H3 constructor records a control stream and settings in memory without emitting the stream type or SETTINGS bytes, and the server skips initialization. The frame parser reads a one-byte type, ignores SETTINGS/unknown state, and does not enforce stream-specific legality or push ownership. TODO-691 and TODO-692 own wire initialization and varint/state validation.
- **Transport receive accounting:** STREAM flow control increments connection bytes before overlap/deduplication, so retransmitted bytes consume credit. `take_ack` clears pending ACK state before capacity/write success. Loss detection materializes and sorts a packet-number prefix, while terminal timeout clears connection counters without retiring per-space recovery state. TODO-693 through TODO-696 own these accounting and terminal-owner contracts.
- **Terminal close and queued sends:** Congestion-bypass control flushing can block a later CONNECTION_CLOSE behind an earlier ack-eliciting frame; TODO-606 now suppresses duplicate local close frames and TODO-772 preserves the selected local close kind in typed error state. TODO-698 now stages FEC and DATAGRAM items until the complete write/seal commit, and sealed DATAGRAM telemetry increments only at that commit. Server stop can report `Stopped` while a startup-timeout runtime thread remains live. TODO-697 and TODO-699 remain open for close priority and server thread lifecycle; TODO-559 retains sustained carrier acceptance.

The audit remains open. These reconciliations document current evidence and ownership; they do not constitute implementation or runtime closure of the listed TODOs.

## Deep Audit Reconciliation (2026-08-02, target and scope contracts)

- **Cargo tests:** 71 integration-test targets are declared and all 71 source paths exist. The desktop/web-admin Rust validation suite now invokes five current declared targets; the archived `it-masque-runtime-integration` source is evidence only and is not part of the active Cargo target surface. TODO-774 closed the stale runner edge, while TODO-734 owns the remaining feature and non-vacuity contract.
- **Feature propagation:** All retained declared test targets with crate-level feature cfgs now declare matching Cargo `required-features`. Orchestrator requires `rust-tests,orchestrator`; SIMD self-check requires `rust-tests,simd-selfcheck`; and Linux io_uring targets require `rust-tests,io_uring`. `run_cargo` still injects the baseline `rust-tests` feature for generic test commands, while the targeted desktop, transport, full-suite, and CI lanes now pass the complete feature set explicitly.
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

## Implementation Reconciliation (2026-08-08, TODO-741 release updater completeness)

- **Policy owner:** `scripts/audits/verify-release-updater.sh` is the single release updater contract. `darwin-aarch64`, `linux-x86_64`, and `windows-x86_64` are required; the optional updater set is explicitly empty. The script discovers exactly one non-empty bundle and matching `.sig` per platform, validates HTTPS release URLs and tag/version shape, and refuses to create an empty or partial `latest.json`.
- **Workflow wiring:** `.github/workflows/release.yml` removes desktop `continue-on-error`, changes desktop artifact uploads to hard failure, verifies macOS/Linux signed pairs before upload, sets `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE=true` for every desktop build, and runs the shared contract after artifact download and before `gh release create`.
- **Runtime wiring:** `apps/tauri/src-tauri/src/main.rs` uses `option_env!("QUICFUSCATE_DESKTOP_UPDATER_ACTIVE")` for release builds and keeps debug activation runtime-opt-in. The manifest audit checks this build-bound marker and the updater plugin registration path.
- **Negative proof:** `scripts/tests/fast/test-release-updater-artifact-contract.sh` proves complete manifest generation, missing Windows artifacts, empty signatures, updater-disabled native runtime, workflow hard-failure policy, and frontend-source exclusion. Local native Tauri `cargo check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` pass; the target exceeded 12 GiB during the lane and was cleaned immediately afterward.

## Implementation Reconciliation (2026-08-08, TODO-877 benchmark cell result truth)

- **Shared runner:** `scripts/tests/lib/lib-common.sh` now owns `qf_benchmark_run`, Criterion output validation, cargo-test output validation, and `qf_benchmark_record`. Every requested cell records stable identity, exact argv, environment, target, feature set, command status, bounded reason, status, and a validated metric; duration-bearing rows also expose `duration_sec`. The generic `run` helper treats only `DRY_RUN=1` as dry-run, so the initialized `DRY_RUN=0` state cannot silently suppress real commands.
- **Suite coverage:** FEC, FEC simulation, StealthBrain, optimization, transport, crypto, compression, QPACK, retained crypto, transport fast-path, and Linux send-path suites record per-cell failures instead of coercing empty filters or invalid outputs into timings. Linux-only paths emit named machine-readable `platform_requires_linux` skips, and transport export failure is an explicit failing cell.
- **Regression selection:** `test-performance-regression.sh` selects IDs declared by `ci_regression`, requires the Criterion filter banner and numeric estimate, replaces the stale `simd_xor` probe with `sort_simd/1024_elems`, and treats target-build, filter, baseline, metric, and report-merge failures as non-pass states. The FEC simulation suite uses the actual unqualified test-name filters after a real run exposed stale qualified filters that executed zero tests.
- **Negative and live proof:** `scripts/tests/fast/test-benchmark-cell-contract.sh` covers empty filters, per-cell Criterion failure, export failure, and Linux platform skips. `test-benchmark-fast-mode-contract.sh` and `test-shared-artifact-writer-contract.sh` remain green. The corrected FEC fast matrix passed 4/4 cells and Stealth/Brain passed 1/1 on ARM64 macOS. Frontend paths remain outside this backend-only change.

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

- **Shared result semantics:** `src/dns/mod.rs::resolve_via_dns_upstreams()` and the DoH endpoint loop now return successful upstream packets unchanged, including genuine NXDOMAIN, while resolver, configuration, and endpoint failures remain typed errors. TODO-810 additionally validates DoH QR/opcode, one-question cardinality, bounded canonical QNAME, raw QTYPE/QCLASS, and transaction ID before returning a response; answer and EDNS sections remain opaque.
- **SERVFAIL construction:** `process_dns_query()` returns SERVFAIL for parseable upstream failures and for malformed packets that still contain a transaction ID. Synthesized answers preserve transaction ID, opcode, RD/CD semantics, QCLASS, and the original raw QTYPE; response packets are rejected at the query parser boundary.
- **Server parity:** `src/implementations/server/parts/dns_signals.rs` uses the shared plain-DNS result contract and returns SERVFAIL instead of synthesizing NXDOMAIN or dropping a parseable failure response. TODO-611 now owns the bounded server-TUN admission; its active policy is aggregate and source-IP keyed, not session keyed or per-upstream. TODO-668 retains active client-listener/generic-helper admission plus the source/session and budget boundary, TODO-669 now supplies timeout, response bounds, and measured allocation evidence, TODO-810 closes DoH response semantics beyond transaction ID, and TODO-770 closes complete wire-question preservation and admission hardening.
- **Targeted proof:** `CARGO_BUILD_JOBS=2 cargo test --locked --lib dns::tests -- --nocapture` passed 22/22. The complete server module passed 131/131, including upstream failure and genuine NXDOMAIN passthrough. `cargo fmt --all -- --check` and `git diff --check` passed. Clippy Matrix run `30811429734` passed all eight feature lanes on revision `5b3b8c2`; the broad CI workflow retains separate non-DNS baseline failures.

## Implementation Reconciliation (2026-08-05, DNS query wire admission)

- **Shared parser contract:** `src/dns/mod.rs::parse_dns_query()` admits only supported query flags, exactly one question, bounded RFC 1035 labels and names, and backward-only compression pointers. Reserved prefixes, forward/header/self pointers, pointer loops, and overlong names fail closed.
- **Wire preservation:** Parsed queries retain expanded byte-preserving QNAME bytes for answer owner names and the exact original question section, including casing, compression bytes, non-UTF-8 labels, raw QTYPE, and QCLASS. Synthetic response builders preserve that representation and applicable RD/CD flags.
- **Packet integrity:** Server IPv4 UDP/53 admission enforces exact IP/UDP lengths, rejects all fragments, validates the IPv4 header and present UDP checksums, and retains the legal IPv4 zero-checksum case. IPv6 admission enforces exact lengths, immediate UDP framing, and a mandatory valid UDP checksum.
- **Targeted proof:** DNS parser tests passed 36/36 and the complete server module passed 147/147. Formatting and diff hygiene passed. Native Linux/TUN, Omega, external publication, and TODO-721 UDP transaction matching remain separate gates.

## Implementation Reconciliation (2026-08-03, bounded client fan-out queue)

- **Queue owner:** `live_auth.rs` gives the MASQUE datagram and framed HTTP/3 uplink callbacks one shared `Arc<Mutex<ClientFanoutQueueState>>`; route filtering happens before any payload clone.
- **Admission and drain bounds:** The queue accepts at most 256 entries/384 KiB globally and 32 entries/64 KiB per source socket. `live_state.rs` pops at most 64 FIFO packets per drain and updates total/per-source byte accounting, with no backlog-to-`Vec` materialization; housekeeping drains even without a new UDP datagram.
- **Telemetry and proof:** Rejected fan-out packets increment `quicfuscate_client_fanout_dropped_total`. Four focused tests, 133 server tests, and 2,156 library tests passed locally; all-target checking, formatting, and diff hygiene passed. Strict local Clippy retains only the pre-existing TLS Cover dead-code lint. Remote Clippy Matrix run `30815583508` passed all eight feature lanes on source revision `c216cc5`.

## Implementation Reconciliation (2026-08-03, server TUN DNS intercept admission)

- **Admission owner:** Each standalone server loop creates one `DnsInterceptAdmission` shared by all client MASQUE/TUN uplink callbacks. Before `spawn_blocking`, it requires one of 128 global semaphore permits, one token from the 2,000 PPS global bucket with a 4,000-query burst, and one token from the 100 PPS per-source-IP bucket with a 200-query burst.
- **Drop and lifecycle behavior:** Admission failure returns `true` to consume the DNS packet without generic fan-out or TUN forwarding, records `quicfuscate_dns_intercept_dropped_total`, and emits only a debug log. The semaphore permit is moved into the blocking task and released after upstream resolution and response queue admission. Idle source buckets are pruned after 60 seconds with a five-second prune cadence.
- **Scope boundary:** The optional response cache was evaluated but not introduced because a correct cache requires explicit TTL handling plus transaction-ID and original-question projection. TODO-771 now makes `ClientDnsRuntime` an active `process_dns_query()` caller; TODO-668 owns its explicit listener admission and the server source/session budget semantics. Accepted worker outcome ownership, panic/cancellation telemetry, and shutdown drain remain TODO-650; TODO-810 closes DoH semantic response validation, and TODO-770 retains complete wire semantics. TODO-669 owns the completed transport-size, aggregate-deadline, async-boundary, and allocation-measurement contract.
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
- **TODO-607 root cause:** The historical native residue `/run/quicfuscate/routing/7174756e30.json` came from graceful `RoutingManager::teardown()` reusing the startup-only `reject_active_owner()` guard. The 2026-08-08 routing slice now authenticates the current owner and uses a separate current-owner recovery path; startup stale recovery retains the active-owner refusal. The privileged lifecycle gate still must execute on Linux.
- **TODO-607 follow-up:** The 2026-08-08 teardown ordering authenticates the durable firewall owner and validates the selected resource before any firewall or host-state mutation, then removes the firewall only after exact host-state recovery. TODO-802 now binds fixed iptables/nftables identities to a create-only global owner record and rejects cross-TUN or foreign replacement.
- **TODO-607 evidence gap:** `scripts/tests/tun-e2e-netns.sh` now captures the server-namespace IPv4/IPv6 forwarding baseline, records the selected firewall backend, and asserts durable-owner, TUN-link, forwarding, and selected iptables/nftables residue absence before deleting namespaces. The native zero-residue acceptance remains open only until the privileged Linux lifecycle gate executes these assertions.
- **Audit-runner evidence:** `bash scripts/tests/audits/audit-runtime-guardrails.sh --output-dir /tmp/quicfuscate-audit-guardrails` completed with one Critical and one Warning. The Critical is a checker false negative: its exact-column regex misses the correctly indented `SERVER_PID=$!` assignment inside `start_server()`; the Warning is the known module-wide `dead_code` allowance in `src/simd/x86_ack.rs:3`, owned by TODO-752. TODO-730 owns the guardrail result-integrity repair.
- **Comprehensive audit evidence:** The revision `1b91a55` run is a historical snapshot with exit `1`, `4` Critical classifications, and `7` Warnings; its 22 strict diagnostics are not the current source result. The 2026-08-08 run records separate production, benchmark, and all-feature strict Clippy lanes as `PASS`; the remaining aggregate failures are the unrelated web-admin publish contract, Linux-only all-target integration compilation on macOS, four pre-existing runtime-guardrail findings, and two unavailable native lanes. TODO-730 owns command/result integrity and raw-text heuristic classification, TODO-676 retains the dispatch/runtime boundary, TODO-816 now closes the active kernel-semantics finding, TODO-817 now closes detector process bounds, TODO-818 owns the AMX proof lane, TODO-819 owns profile/documentation truth, and TODO-803 owns the two redundant-clone findings.
- **Readiness and analysis evidence:** On 2026-08-03 at revision `6b18d373da46242c47283ee5093d359e6a0792a0`, `audit-readiness-gates.sh` passed Clippy Strict, Cargo Audit, Cargo Deny, and deny-only Cargo Geiger, while the explicit `--strict-geiger` rerun returned `1` for 31 dependency unsafe surfaces. The static coverage helper reported 7,029 functions and 2,575 test functions without executing coverage; the script-quality helper reported 122 scripts with 10 missing strict-mode cases, 21 missing descriptions, 14 missing help handlers, 24 naming violations, 10 missing usage lines, and 2 unknown-argument cases; the suite matrix found 28 suites, 21 invoked by the full-suite utility, and 7 omitted. The dead-code helper remains incomplete on Darwin because its BSD `sed` dependency scan fails and leaves unterminated JSON. TODO-730 owns these result and scope boundaries; TODO-799 owns the completeness validator's `Blocked` section failure. The project audit is not complete.
- **Suite exclusion evidence:** `test-graceful-shutdown.sh --help` exits on the missing default binary instead of returning usage. `test-fec-all.sh` is a dispatcher with constituent modes already called directly; `test-linux-installer.sh` owns the executable native CI lane and calls its systemd-nspawn guest helper. No executable `.github/workflows` or full-suite invocation is present for `test-ddos-admission.sh`, `test-graceful-shutdown.sh`, `test-qkey-auth-policy.sh`, or `test-qkey-registry-encryption.sh`. TODO-730 owns the open inclusion/exclusion contract and missing live-lane ownership.
- **Omega proof boundary:** Read-only inspection found two remote `main` checkouts: `SOFTWARE/QuicFuscate` at `9b57474` with 97 untracked status paths, 43,722 untracked files, and a running server; `CODE/QuicFuscate` at `d36652d` with 20 tracked modifications and a missing Git object during diff inspection. TODO-804 owns singular checkout selection, Git readability, exact attribution, and bounded remote cleanup. No remote state was modified.
- **Fast full-suite evidence:** `util-run-full-suite.sh --fast` at revision `aab0c51018ad146607f7f4aef885f85ae5cc2521` passed the build check, 2,144/2,144 root library tests, Core Integration, Desktop/Admin validation, Stealth Fast, and Crypto Fast, then exited `1` in `test-optimization.sh` because `environment=json:${COMMAND_ENVIRONMENT_JSON:-{}}` supplied an extra closing brace to the shared JSON writer. TODO-782 owns the three consumer call sites (`test-optimization.sh`, `test-performance-regression.sh`, and `test-security-fuzzing.sh`); TODO-730 owns aggregate result classification. The project audit is not complete.
- **Frontend dependency evidence:** The 2026-08-03 baseline `bun audit --json` exited `1` with `29` advisories across nine locked package keys: `@sveltejs/kit@2.55.0`, `cookie@0.6.0`, `devalue@5.6.4`, `esbuild@0.27.4`, `picomatch@4.0.3`, `postcss@8.5.8`, `svelte@5.53.12`, `undici@7.24.3`, and `vite@7.3.1`. `bun pm scan` was unavailable because no scanner was configured. TODO-805 owns the now-completed local reconciliation and retains the exact advisory inventory and dispositions.
- **Frontend dependency gate:** Before TODO-805, CI installed and built the Bun workspaces but invoked only Cargo dependency auditing. The baseline frontend advisory result therefore had no required CI failure lane. The implementation reconciliation below adds that lane and records the remaining hosted/native boundary.

## Implementation Reconciliation (2026-08-03, crypto key and IV constructor boundaries)

- **Typed boundary:** `src/crypto/aead.rs` owns `KeyMaterialError` plus exact-length helpers. `ChaCha20Poly1305` requires a 32-byte key and 12-byte IV; `AesGcm128`, AEGIS L/X4/X8 wrappers, and `MorusAead` require a 16-byte key and 12-byte IV. Public data-AEAD selection and the benchmark builder enforce the same 16/12 contract before copying into fixed arrays.
- **Header protection:** `AesHp::new` rejects secrets shorter than 16 bytes without a panic. Its documented raw-secret API still consumes the first 16 bytes of a longer secret; all packet setup paths derive the exact 16-byte header-protection key first and use the typed array constructor, so a 32-byte traffic secret is never silently installed as an HP key.
- **Propagation:** QKey registry encryption/decryption, TLS cover ciphers, packet initial/handshake/0-RTT/1-RTT setup, examples, runtime fixtures, property/security fixtures, and the retained backend benchmark all propagate or prove the fallible constructor boundary. No key/IV `unwrap_or(0)` construction fallback remains; QUIC KDF traffic-secret derivation now enforces 32-byte inputs under TODO-633, and header-protection sample handling remains separately owned by TODO-629.
- **Verification:** Locked all-target/all-feature check and strict Clippy passed. Serial crypto tests passed 143/143, QKey registry storage 11/11, packet tests 25/25, baseline/property/security integration targets 6/6, 12/12, and 24/24, and all four retained backend benchmark smokes executed successfully. The Criterion benchmark target compiled with `--no-run`. The full local library passed 2,194/2,196; DNS resolution remains TODO-807 and rustls ClientHello readiness remains TODO-768. The former fuzz manifest path failure is superseded by TODO-758's metadata and target-inventory proof; hosted nightly sanitizer execution remains the external gate.

## Implementation Reconciliation (2026-08-03, header-protection sample and packet-number bounds)

- **Typed sample boundary:** The crypto and transport `HeaderProtector` traits now return errors. `AesHp` requires an exact 16-byte sample and exact 5-byte mask, while the Rustls-backed provider rejects every non-exact sample length and propagates mask-derivation failures as `ConnectionError::CryptoError`; no zero mask or zero-padded sample is synthesized.
- **Receive boundary:** `unprotect_and_decrypt_with_key()` requires the complete 16-byte sample window before reading or mutating the protected header, validates the decoded 1-4 byte packet-number range before mutation, and propagates failures through the 1-RTT fast path, fallback key path, and previous-key candidates. `remove_hp()` has the same sample and packet-number bounds.
- **Send boundary:** `protect_header()` validates packet-number length, offset, and buffer bounds before mutation. `apply_hp()` now propagates sample and packet-number-buffer errors. The short-header sealing path pads to the minimum sample-bearing ciphertext length before AEAD sealing and no longer silently emits an unprotected packet when the payload is short.
- **Regression proof:** The locked all-target/all-feature check and strict Clippy passed; 144/144 Crypto tests, 29/29 packet tests, and baseline/property/security integration targets 6/6, 12/12, and 24/24 passed. Format and diff checks passed. The full local library passed 2,199/2,201; the two unrelated failures remain TODO-807 DNS endpoint resolution and TODO-768 Rustls ClientHello readiness.
- **Scope boundary:** No UI or Omega state was changed. TODO-633's local KDF implementation still awaits its full matrix and native/external proof gates; TODO-758 now owns hosted nightly sanitizer execution after local metadata and inventory closure, and the broader project audit remains open under its existing task owners.

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

- TODO-686 is complete as a read-only audit across every current FEC source and test module, all FEC `unsafe` sites and direct callers, public decoder/matrix/wire/Fountain boundaries, feature gates, malformed-input tests, fuzz and shell/benchmark/netns proof, documentation, related owners, and history. Current reconciliation records TODO-832, TODO-834-836, and TODO-676/816-819 source closures or external proof boundaries; Fountain source-index and `k == 0` progress checks are source-closed.
- The audit separates current product-wire validation from direct public API reachability and does not claim that remaining unsafe contracts, decoder mathematics, native ISA paths, negative proof, or documentation remediation are fixed. Open remediation is tracked by TODO-634, TODO-636, TODO-637, TODO-690, TODO-715, TODO-859, and TODO-860. TODO-855's local FEC SIMD implementation boundary, TODO-856's direct decoder/matrix/wire input boundaries, TODO-857's Fountain constructor and source-index contracts, and TODO-858's FEC configuration/feedback validation contracts are now closed. Shared transport and environment owners remain retained.
- No production implementation, build, test, native probe, privileged network run, commit, or push was performed for TODO-686. The complete findings and current evidence boundary are in `docs/todo/todo-686-fec-unsafe-audit.md`.

## SIMD Dispatch Intersection Wiring (2026-08-06, TODO-834)

- `CpuFeatures::simd_dispatch_matrix()` is the shared runtime truth for target-feature intersections. It prevents AVX-512F-only routing into VL, BW, VBMI2, VPOPCNTDQ, VNNI, VAES/AES, GF16, and FMA kernels; it also requires the exact SSE/AVX prerequisites for PCLMUL and the AVX ChaCha path. Direct GHASH, AEGIS, AES-GCM, and MORUS dispatch uses the exact `features_full()` fields required by each target attribute.
- Profile selection, FEC thresholds and bitslice overrides, ACK canonicalization, string search, neural dot products, AES/ChaCha, SHA-256, GF16, and test-only SIMD wrappers consume the same matrix. Remaining profile consumers are limited to safe policy, sizing, telemetry, or RISC-V-specific selection. AVX-512 XOR no longer uses an AVX2 remainder under an AVX-512F-only target contract.
- Runtime AArch64 varint dispatch checks SVE2 before entering a compiler-enabled SVE2 body and falls back to NEON/scalar otherwise. The former scalar-only pattern dispatch and x86 SHA / ARM GF16 PMULL telemetry claims are removed rather than reported as hardware acceleration.
- Source implementation is complete locally, including exact AVX2 guards in FEC and packet transport and the x86 four-byte packet-number network-order regression fix. ARM64 macOS verification passes the complete serial library suite at `2,440/2,440`, strict library/all-target Clippy, and formatting/diff gates; the final detail is `docs/todo/done/todo-834-simd-feature-dispatch-intersections.md`. Native x86/Linux/Windows ISA execution remains an external proof boundary under TODO-682/TODO-683/TODO-836.

## Audit Reconciliation (2026-08-03, audit-file FFI complete audit)

- TODO-688 is complete as a read-only audit across the complete current audit implementation and tests, the audit probe, direct startup/runtime callers, the limits false-positive source, audit suites and guardrails, documentation, related owners, and relevant history.
- The confirmed inventory is three production FFI sites in `src/audit/mod.rs` (`geteuid`, `chown`, and Windows `MoveFileExW`) plus one Unix-only test guard. No production `unsafe` operation was found in `src/implementations/server/limits.rs`.
- Open remediation is split by boundary: TODO-861 owns local FFI safety contracts, Windows interior-NUL rejection, warning-only permission/ownership failure semantics, and platform-negative proof; TODO-671 owns direct existing-file mode; TODO-675 and TODO-726 own writer lifecycle and terminal admission; TODO-728 owns pathname-to-inode binding; TODO-813 and TODO-814 own configuration and payload bounds.
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
- TODO-754 is active again. This closes the register/schema/Git-scope gate only; TODO-730, TODO-734, TODO-749, TODO-758, TODO-759, TODO-760, TODO-764, TODO-782, TODO-798, TODO-804, TODO-805, and the other named native/runtime/external owners remain open. TODO-761, TODO-762, and TODO-763 are completed audit reconciliations.

## Audit Infrastructure Wiring (2026-08-04, TODO-730)

- `scripts/tests/audits/audit-all-comprehensive.sh` is the strict aggregate entrypoint. It calls `audit-rust-scope.py`, `audit-secret-scope.py`, `analysis-dialect-validation.py`, `audit-runtime-guardrails.sh`, `audit-result-contract.py`, and the dependency/tooling probes, then writes one fail-closed JSON result.
- `scripts/tests/analysis/` owns portable analysis contracts: `analysis-dead-code-report.sh` emits a completed report, `analysis-scripts-quality.sh` emits strict/advisory findings, and `analysis-suite-matrix.sh` accounts for all 28 suite scripts and their seven explicit exclusions.
- `scripts/tests/utils/util-run-full-suite.sh` invokes the comprehensive audit in strict mode and propagates stealth benchmark preflight failure. Optimization, performance-regression, and security-fuzzing suites serialize `COMMAND_ENVIRONMENT_JSON` through the shared JSON writer without malformed default expansion.
- `scripts/tests/audits/audit-readiness-gates.sh` exposes deny-only versus strict Geiger policy, retains dependency-unsafe package names, and classifies unavailable advisory databases as `UNAVAILABLE`. Local PowerShell parser absence is retained by the dialect result rather than treated as a pass.

## Live Audit Gate Recheck (2026-08-07)

- The final `verify-audit-completeness.sh` refresh passes structural register/detail/archive/Git-scope integrity with `graphify=BLOCKED`; stale or missing Graphify evidence fails closed instead of being promoted to green. TODO-759 owns that evidence boundary.
- `audit-all-comprehensive.sh --strict` completes all `38` result objects with `31 PASS`, `3 FAIL`, and `2 UNAVAILABLE` plus an aggregate `FAIL`. The failed checks are strict runtime Clippy, all-target quality Clippy, and runtime guardrails; the unavailable checks are PowerShell parsing and the ARM64-host AMX proof lane. Native, frontend, Omega, privileged, and external evidence remain unclaimed.
- Contract fixtures under `scripts/tests/audits/fixtures/`, `scripts/tests/analysis/fixtures/`, and `scripts/tests/fast/fixtures/` prove failable command status, Rust and secret scope, parser dialects, scoped PID ownership, benchmark propagation, environment JSON, and strict/advisory result semantics.
- Current local proof is deliberately non-green: the complete strict runner returns `FAIL`; readiness returns `UNAVAILABLE` in deny-only mode and `FAIL` in strict-Geiger mode. Product remediation, native/external runtime evidence, Graphify/feature boundaries, and Omega checkout attribution remain with their existing TODO owners.
- Historical post-staging validator snapshot (2026-08-04): `verify-audit-completeness.sh` passed with tracker `769`, Active `1`, Blocked `4`, Queue `189`, Completed `575`, current details `411/411`, tracked paths `956`, ignored paths `28,123`, and zero non-ignored untracked paths. The current live result is recorded above and fails closed on stale Graphify evidence.

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
- **Allocation telemetry:** `crates/qf-telemetry/src/lib.rs` exports separate Wiedemann counters for column buffers, the scalar accumulator, matrix/RHS, Krylov vectors, per-iteration vectors, candidate temporaries, and reserved AMX scratch. The active scalar fallback increments scalar operations only; AMX operation and scratch counters remain zero until a verified backend is introduced.
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
- **Boundary wiring:** TODO-654 is limited to alignment-safe header loading and its regression proof. CPU-profile/BMI2 dispatch and Unix native source contracts are reconciled by TODO-843 and TODO-845; Wintun, WFP, and negative/native platform proof remain TODO-846 through TODO-848-owned boundaries; TODO-844 owns the shared generic TUN result contract.
- **Verification status:** `interface::tests::` passes 11/11 on this ARM64 macOS host and `rt-interface` passes 4/4. Workspace all-target checking passes, strict library Clippy passes, and workspace all-target strict Clippy retains only the three known client backend/DNS-runtime diagnostics. The no-fail-fast workspace matrix executes every target: the library passes 2,220/2,222 with unchanged TODO-807 DNS and TODO-768 Rustls failures, the `quicfuscate` binary passes 41/43 with the two unchanged TODO-800 runtime-reload PMTU fixture failures, and all other targets pass. Formatting and diff hygiene pass. The x86-64 BMI2-specific test is target-gated and was not runnable on this ARM64 host; native x86/Linux and remote publication remain separate closure gates.

## Implementation Reconciliation (2026-08-04, reproducible dependency resolution)

- **Ownership path:** `config/tool-versions.env` owns the exact CI/release versions; `rust-toolchain.toml` pins Rust `1.97.1`. Bun, Cargo, Tauri CLI, audit, fuzz, and benchmark inputs are now reviewed against that source-owned contract. The project policy is pinned-stable-only with no declared or tested MSRV; the nightly fuzz lane and its unresolved manifest path are separate TODO-758 evidence.
- **Workflow path:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/clippy-matrix.yml`, and `.github/workflows/windows-omega-e2e.yml` use frozen Bun installs, locked Cargo operations, exact Rust action toolchains, and exact locked installs for release tools. The release Tauri jobs run locked metadata/check/Clippy before forwarding `--locked` to packaging.
- **Verification path:** `scripts/audits/verify-reproducible-dependencies.sh` performs static workflow checks plus two-run Cargo and Bun resolution probes. The local gate passes with the stable Bun lock hash `10111F769AB0DF7E-c8bf34ac712c2681-9B1E6056451B6CA1-bfc42866eebd8464`.
- **Native boundary:** The Tauri host locked check, all-target strict Clippy, and 41-test host suite pass on ARM64 macOS. Linux/Windows packaging, updater signing, hosted CI, and remote release publication remain external evidence gates; no UI or remote state was changed.

## Implementation Reconciliation (2026-08-04, Tauri dependency advisory closure)

- **Desktop dependency path:** `apps/tauri/src-tauri/Cargo.toml` -> `apps/tauri/src-tauri/Cargo.lock` -> locked Cargo metadata/check/Clippy/test and Tauri packaging. The lockfile updates only vulnerable or patchable transitive releases and retains the pinned Tauri 2.10.2 line.
- **Security path:** `scripts/audits/verify-tauri-dependencies.sh` -> locked metadata reverse graph -> `cargo audit` JSON -> exact warning inventory and reachability classification -> locked `cargo deny check`. It fails on any vulnerability, warning inventory drift, direct warning dependency, patched release that was not upgraded, or lockfile mutation.
- **Policy path:** `config/deny-tauri.toml` -> workspace-scoped transitive unmaintained/unsound handling, explicit MPL-2.0 license allowance, and reviewed Tauri/GTK/legacy duplicate-version exceptions. The root `deny.toml` remains scoped to the root graph. The Tauri deny result is `advisories ok, bans ok, licenses ok, sources ok` with four non-failing informational diagnostics.
- **CI/release path:** `.github/workflows/ci.yml` security-audit and `.github/workflows/release.yml` release-version-contract -> exact Cargo Audit/Cargo Deny installs -> `verify-tauri-dependencies.sh` -> locked Tauri build/lint/package jobs. Root and Tauri lockfiles remain separate evidence surfaces.
- **Proof boundary:** ARM64 macOS local check, all-target Clippy, and 41/41 Tauri host tests pass. Linux/Windows native packaging, updater signing, hosted CI, and external publication remain unproven release gates.

## Implementation Reconciliation (2026-08-04, frontend dependency advisory closure)

- **Dependency ownership:** `package.json` owns the reviewed root overrides; `apps/svelte-admin/package.json`, `apps/svelte-desktop/package.json`, and `packages/ui/package.json` own the direct framework/tool version contracts; `bun.lock` owns the resolved five-workspace graph. The exact 35-advisory mapping is maintained in `docs/todo/todo-805-frontend-dependency-advisories.md`.
- **Build and runtime wiring:** `@sveltejs/kit@2.70.2` and `svelte@5.56.8` feed both static Svelte applications and the shared UI package. `vite@7.3.6` feeds build/dev-server tooling. `cookie`, `esbuild`, `picomatch`, and `postcss` are reviewed root overrides. `undici@7.29.0` remains on the `jsdom@28` test-only path. No `@sveltejs/adapter-node` path is installed; Tauri consumes the generated Desktop static bundle.
- **Security gate wiring:** `scripts/audits/verify-frontend-dependencies.sh` -> Bun version/lock hash -> frozen install -> lifecycle-script check -> `bun audit --json` -> exact manifest/override contract -> machine-readable result. `bun pm scan` is represented as `UNAVAILABLE` only for the exact no-scanner condition. Any lock mutation, advisory, contract drift, unexpected scanner failure, or lifecycle-script failure exits nonzero.
- **Workflow wiring:** `.github/workflows/ci.yml` adds `frontend-dependency-security`; `.github/workflows/release.yml` runs the same gate in `release-version-contract`. Both remain downstream of the source-owned Bun version and frozen lockfile contract.
- **Local proof wiring:** The gate is `PASS` with zero advisories; Admin/Desktop checks are 0/0, unit tests are 285/285 and 370/370, bounded Vite dev-server probes pass on 1430/4173, and the locked ARM64 macOS Tauri host lane passes 41/41. The exact machine-readable payload and all advisory dispositions live in TODO-805.
- **Boundary:** Hosted CI execution of Chromium provisioning and E2E, Linux/Windows native packaging, updater signing, and tagged publication remain open owners or external gates. TODO-756 proves the local browser prerequisite negative path and all 93 local frontend E2E tests. No frontend visual/UI source, remote checkout, or Omega state changed.

## Implementation Reconciliation (2026-08-04, frontend E2E browser prerequisite contract)

- **Version path:** `config/tool-versions.env` -> exact `@playwright/test` `1.58.2` in both frontend manifests -> `bun.lock` -> reproducibility and frontend dependency audits.
- **Prerequisite path:** `test:e2e`, `test:e2e:ui`, and `test:e2e:debug` -> shared `test:e2e:preflight` -> `scripts/tests/frontend/verify-playwright-browser.sh` -> exact CLI-version check -> real headless `channel: "chromium"` launch. Missing or failed launch is one `UNAVAILABLE` result with exit code 2; a version mismatch is `FAIL` with exit code 1.
- **Runtime path:** `test:e2e:install` -> Playwright Chrome-for-Testing `chromium-1208`; both Playwright configs select the same `channel: "chromium"`. CI and the smoke runner consume the package-owned provisioning/preflight contract rather than maintaining a separate browser path.
- **Proof path:** Empty-cache Admin/Desktop preflights stop before preview-server startup. The available-browser path passes Admin 70/70 and Desktop 23/23; checks pass with 0 errors and 0 warnings, and unit suites pass 285/285 and 370/370. Hosted CI execution remains external evidence.

## Graphify Relationship Evidence Wiring (2026-08-05, TODO-759)

- `scripts/audits/verify-graphify-evidence.sh` -> `scripts/audits/verify-graphify-evidence.py` -> source-owned Graphify runtime -> run-scoped `scripts/out/audits/graphify-<UTC>/graphify-evidence.json`, `raw-ast.json`, `normalized-ast.json`, and `GRAPH_REPORT.md`.
- Detection accounts for code, documents, images, sensitive files, and Git ignored/generated/dependency classes. The current run at source revision `f09fc454c24aa6dcc1047d1c3aebf48d27a8cbc3` covers 750 detected files and 1,320,086 words, including 334 Rust files and 146 shell/PowerShell scripts; six detected files without AST nodes remain an explicit unsupported-surface entry.
- Raw AST identity is retained for diagnosis. Normalization maps source paths to repository-relative names, collapses exact duplicate records, generates content-addressed node IDs, and keeps unresolved/ambiguous endpoints as explicit external nodes. The latest run has 15,370 raw nodes and 42,508 raw edges, 13,699 normalized nodes and 42,508 normalized edges, 0 normalized dangling edges, 1,486 raw dangling edges, 385 ambiguous endpoints, and 1,462 unresolved endpoints. It remains `BLOCKED` for incomplete file coverage, unavailable semantics, and stale legacy output.
- `scripts/tests/audits/verify-audit-completeness.sh` validates the latest Graphify evidence schema, source revision and scope provenance, semantic availability classification, normalized graph identity, artifact paths, and stale `graphify-out/graph.json` attribution. It passes structurally while preserving the Graphify result as `BLOCKED`.
- The graph relation edge is evidence-only and does not connect to Rust runtime, frontend UI, Omega checkout, or remote publication paths. TODO-759 remains blocked until the recorded semantic, endpoint, file-coverage, and external/native gates are closed with real evidence.

## SIMD Feature Contract Wiring (2026-08-04, TODO-760)

- Cargo no longer declares hardware-named features or a hardware meta-feature. `#[target_feature]` and `RUSTFLAGS`/`target-cpu` own compile-time ISA selection; qf-cpu's `FeatureDetector` owns runtime backend selection; `simd-selfcheck` remains a test-only parity feature.
- `scripts/audits/verify-simd-feature-contract.sh` parses Cargo metadata, scans Rust for accidental hardware `cfg(feature = ...)` consumers, confirms target-feature/runtime-dispatch owners, proves `rust-tests,simd-selfcheck` and `--all-features`, and rejects every removed hardware/meta selector through fail-closed Cargo checks.
- `.github/workflows/ci.yml`, `.github/workflows/clippy-matrix.yml`, and `scripts/tests/audits/audit-all-comprehensive.sh` execute the shared gate. No product, runtime, frontend, UI, Omega, or remote checkout behavior is changed by the feature-contract reconciliation.

## Cargo Feature Taxonomy Wiring (2026-08-04, TODO-763)

- The root `[features]` table has 26 direct entries and Cargo metadata has 29 effective selectors. The additional `rcgen`, `time`, and `maxminddb` selectors are implicit optional-dependency capabilities enabled by `server` or `dev-certs`, not public product groups.
- `scripts/audits/verify-cargo-feature-taxonomy.sh` owns the exact declaration/dependency matrix, validates all Rust `cfg(feature = ...)` and Cargo target `required-features` references, compiles the valid server/client, throughput, test-suite, and experimental profiles, and rejects the retired TODO-176 groups `cpu-simd`, `stealth`, `fec`, `crypto`, `transport`, `test-crypto`, and `simd-all`.
- TODO-176 is explicitly re-scoped: the current architecture retains local runtime, platform, internal, and test selectors plus four small convenience meta-features (`default`, `throughput`, `test-suite`, `experimental`). No broad `cpu-simd`, `stealth`, `fec`, or crypto hierarchy is claimed. TODO-734 owns test-target non-vacuity, TODO-709 owns CI feature-lane coverage, TODO-754 owns tracker/schema truth, and TODO-760 owns hardware/SIMD semantics.
- `.github/workflows/ci.yml`, `.github/workflows/clippy-matrix.yml`, and `scripts/tests/audits/audit-all-comprehensive.sh` execute both the taxonomy gate and the narrower SIMD gate. The reconciliation changes no Rust product behavior, frontend/UI surface, Omega checkout, or remote state.

## Web-Admin Generated Publish Wiring (2026-08-04, TODO-764)

- `apps/svelte-admin/build/` -> `scripts/build/build-web-admin.sh` -> ignored `assets/web-admin/` -> server `--admin-web-root` -> `index.html`/SvelteKit `_app/immutable/*`; the publish tree is not a tracked release input.
- `scripts/audits/verify-web-admin-publish-contract.sh` proves the ignored/generated ownership, frozen Bun build source and destination, server default/static-index contract, local helper and E2E prerequisites, release build-before-bundle ordering, installer/bundle missing-asset guards, and a bounded missing-`index.html` negative bundle probe.
- `scripts/audits/verify-release-updater.sh` owns the required desktop updater platform map, exact non-empty bundle/signature pairing, HTTPS/version validation, build-bound native updater marker, and atomic complete `latest.json` generation before release publication.
- `.github/workflows/ci.yml` release-contract, `.github/workflows/release.yml` release-version-contract, and `scripts/tests/audits/audit-all-comprehensive.sh` execute the gate. A fresh checkout must build the admin tree before local serving or server-bundle creation; the gate deliberately does not build or modify protected UI sources.

## TLS ClientHello Ownership Wiring (2026-08-04, TODO-766)

- `StealthConfig.use_utls` -> `StealthManager::apply_utls_profile` -> browser/OS QUIC persona parameters; `StealthManager::runtime_tls_profile` -> `Connection::configure_tls` -> `RustlsProvider` owns the real ClientHello. No transport configuration field stores a ClientHello byte template.
- `TlsClientHelloProfileCatalog` exposes supported deterministic metadata combinations, and `FingerprintProfile::client_hello` retains generated bytes only for compatibility/audit inspection. The retired `Config::chlo_template`, `set_chlo_template`, `apply_deterministic_tls_hello_template`, `set_custom_tls`, and test-only `inject_*` helpers are absent.
- `scripts/audits/verify-tls-clienthello-contract.sh` proves the source/API/docs/test boundary. `.github/workflows/ci.yml` release-contract, `.github/workflows/release.yml` release-version-contract, and `scripts/tests/audits/audit-all-comprehensive.sh` execute the gate. Current rustls and TLS Cover providers report `supports_ch_override() == false`; the optional provider hook remains explicit and fail-closed.

## Environment Snapshot Wiring (2026-08-05, TODO-670)

- `EnvSnapshot::capture()` in `src/env_utils.rs` copies the Unicode process environment once and exposes trimmed, warning-producing boolean, numeric, finite-float, positive-float, and ordered-alias helpers. Invalid values retain the configured default or skip the invalid override; empty and invalid canonical aliases fall through to the next alias.
- `StealthManager` captures one immutable generation snapshot and passes it through Reality, escalation, stealth overrides, fingerprint construction, TLS Cover, Brain permissions, runtime padding, and transport-facing policy. `QuicFuscateConnection` reuses that snapshot for FEC observer/adaptive-FEC policy, Brain, Reality, stealth, TLS ClientHello overrides, and the intelligent orchestrator.
- `transport::Connection` receives the manager snapshot before first TLS enable and retains it for rustls/TLS Cover provider creation and rebuild, recovery selection, and BBR2/BBR3 minimum-RTT configuration. Standalone constructors capture their own snapshot at their construction boundary.
- Environment mutation after owner construction is unsupported; changed values require reconstruction or restart. Library environment-mutating tests share one process-wide guard; the separate binary test crate remains an independent process boundary with its own guard.
- Direct production environment parsers outside `src/env_utils.rs` are reconciled by TODO-811. Compression, memory-pool, optional zstd, Reality targets, trusted-proxy state, metrics, CLI socket, NUMA, SIMD, and io_uring use immutable snapshot-backed policies; server policy and QKey secret loaders remain validated startup exceptions. No external-process torn-read defect or native/Omega/live-wire proof is claimed by TODO-670.

## Environment Parser Authority Wiring (2026-08-05, TODO-811)

- `EnvSnapshot` -> `CompressionPolicy`, body-pool and dictionary first-use owners -> typed compression/list/path controls; H3 and stealth callers pass their existing connection snapshot into the global policy boundary.
- `EnvSnapshot` -> `MemoryPoolRuntimeConfig` -> NUMA initialization, allocation hints, TLS cache limits, debug bounds, and the auto-tuner. The tuner owns an immutable typed policy and never rereads process environment values.
- `EnvSnapshot` -> `RealityConfig`/`RealityProxy` -> whole-list target validation; any malformed target retains the complete built-in set. `EnvSnapshot` -> `AdminHttpEnvironment` -> trusted-proxy all-or-nothing allowlist and construction-time shutdown/trust flags.
- `EnvSnapshot` -> engine memory sizing, metrics, control CLI, Fastpath, GHASH/ChaCha/FEC-kernel dispatch, and io_uring zero-copy opt-in. Optional zstd FFI uses one first-use snapshot with explicit mode, range, and binary-flag diagnostics.
- Direct `std::env::var`/`var_os` readers are limited to validated server policy loaders, the non-Unicode-preserving QKey secret loader, and test/build/OS integrations. This is an authority classification, not a claim of native, Omega, external-process, or live-wire proof.

## Implementation Reconciliation (2026-08-05, TODO-673 CLI control request contract)

- `Cargo.toml` -> registered Unix-only `quicfuscate-ctl` target -> `prepare_command()` -> typed `AdminCommand` -> bounded `encode_admin_command()` -> Unix admin socket. Exact command arity is enforced before connecting.
- `src/implementations/server/admin.rs` owns the shared 8 KiB complete-frame cap, 256-byte raw-value cap, canonical IP/client-identity helpers, custom unknown-field-rejecting deserializer, and server-side revalidation before dispatch. HTTP normalization and runtime block/kick operations reuse these helpers.
- CLI tests cover arity, typed encoding, JSON escaping, control characters, and oversized input. Unix admin tests cover canonical dispatch, invalid values, unknown fields, frame bounds, and newline termination. The CLI target passes 8/8 focused tests and strict binary Clippy; the serial server filter passes 490/490; the complete library passes 2,372/2,372; default and optional all-target checks pass; and default and optional strict library Clippy pass. The full workspace matrix executes the CLI target at 8/8 and leaves only the two pre-existing `quicfuscate` runtime-reload/PMTU fixture failures at `src/main_parts/late_tests_and_mlock.rs:566,638`.

## Implementation Reconciliation (2026-08-05, TODO-812 logger installation failure ownership)

- `logging::init()` -> temporary bounded `qf-log-writer` worker -> `log::set_boxed_logger()` failure -> `LogCommand::Shutdown` -> synchronous `JoinHandle::join()` -> `LoggerAlreadyInstalled` return. The temporary file, stderr, syslog, and admin-buffer sink owner remains inside the joined worker until cleanup completes.
- Successful installation keeps the existing `LOGGER_CONTROL` publication, maximum-level setup, flush barrier, queue admission, and sink telemetry. No fallback logger or recursive logging path is added.
- The logging unit suite passes 19/19, process integration passes 3/3, and the complete library passes 2,374/2,374. Workspace checks and strict library Clippy pass; the workspace all-target matrix retains only the two existing TODO-800 binary fixture failures and broad strict Clippy retains eight unrelated baseline diagnostics.

## Implementation Reconciliation (2026-08-05, TODO-814 audit event payload bounds)

- **Bounded admission:** `AuditLog::log_typed()` validates exact JSON-encoded UTF-8 sizes for source IP, client ID, reason, and message before any dynamic string clone or channel operation. The ceilings are 128, 512, 512, and 8,192 bytes per field, with an 8,192-byte combined dynamic payload ceiling.
- **Typed outcome:** Over-limit input returns `AuditError::PayloadTooLarge`; `AuditStats.payload_rejections`, Prometheus, and `qf-audit-probe` expose the rejection separately from queue drops and persistence failures. A rejected event consumes no queue slot.
- **Scope boundary:** Existing-file payload/read limits remain TODO-727; terminal producer admission after writer failure remains TODO-726; shutdown admission ordering is closed by TODO-815. Schema-v1/v2 parsing and hash-chain verification are unchanged.
- **Final proof:** The exact pushed Omega checkout at `495d12d8f5ac4450fc281560298f9179bd4d5607` passes the complete library suite `2403/2403`, strict library Clippy with `-D warnings`, and the audit probe `3/3`. The post-push Graphify manifest remains explicitly fail-closed at `scripts/out/audits/graphify-20260805T165808Z/graphify-evidence.json`.

## Implementation Reconciliation (2026-08-05, TODO-815 audit shutdown admission)

- **Lifecycle:** `AuditLog` combines `Open`/`Closing`/`Closed` with an in-flight producer count. The CAS from `Open` to `Closing` is the shutdown linearization point; shutdown drains admitted producers before its final flush barrier and writer join.
- **Outcome and telemetry:** Admission losers receive `WorkerClosing` or `WorkerDisconnected`; lifecycle rejections are counted as dropped events without changing payload-rejection or persistence-error classification. The existing metrics and documentation now describe the full bounded admission contract.
- **Proof:** Focused audit coverage is `28/28`, metrics `1/1`, probe `3/3`, local full library `2381/2381`, and Omega full library `2405/2405`; strict library Clippy passes locally and on Omega. Local format/diff checks pass; Omega has no installed `rustfmt` component.
- **Ownership:** TODO-675 retains synchronous durability/cancellation and sticky shutdown-error semantics; TODO-726 retains writer-terminal admission; TODO-727/TODO-728 retain existing-file reads and path binding; TODO-849 retains broader privilege identity and cross-platform FFI work.

## Implementation Reconciliation (2026-08-05, TODO-816 AMX kernel semantics)

- **Production FEC path:** `src/fec/parts/decoders.rs` now has one checked scalar GF(256) SpMV path for all targets. Scratch storage is always dimension-bounded, output is zeroed before bounded accumulation, and no runtime AMX metadata or compile-time-disabled zero-vector branch remains.
- **AMX boundary:** The former raw tile staging, uncalled signed INT8 kernel, global tile configuration, and scalar-after-tile-load/store GF(256) path are removed. `src/simd/amx.rs` documents the inactive integration boundary; `WIEDEMANN_AMX_OPS` and AMX scratch telemetry remain reserved and zero.
- **Proof and ownership:** Local proof is `4/4` focused Wiedemann tests, `80/80` FEC tests, `2383/2383` library tests, strict library Clippy with `-D warnings`, and passing format/diff checks. The non-identity scalar reference parity covers `16x64` and `17x65` matrix shapes. TODO-676 closes the current scalar fail-closed tile and dispatch ownership; TODO-817 closes detector execution, TODO-818 retains future native AMX proof, TODO-819 closes profile truth, and TODO-690 retains equation correctness.
- **Pushed-source proof:** Isolated Omega commit `afe1d17003464981ab67ca666e7e98ce55114fc6` passes `2407/2407` library tests and strict library Clippy with `-D warnings`; source inventory is clean for `static mut`, former AMX kernel names, and `TILE_CONFIG`. Remote rustfmt is unavailable because the `cargo-fmt` component is missing from toolchain `1.97.1-aarch64-unknown-linux-gnu`; native AMX execution remains TODO-818 evidence.

## Implementation Reconciliation (2026-08-05, TODO-817 AMX detector process contract)

- **Detector boundary:** `FeatureDetector` uses in-process x86_64 AMX feature detection. The former PATH-resolved `cpuid` process and textual output parser are absent.
- **Evidence separation:** `AmxCapability` records CPU instruction support, OS tile-state permission, compiler target-feature flags, and verified product backend eligibility independently. With no OS permission probe or verified backend, `product_dispatch_eligible` remains false.
- **Guardrail and tests:** The runtime guardrail includes `amx_detector_process_free` and passes for the current source. Focused detector tests pass `2/2`; strict library Clippy, format, and diff checks pass. The aggregate runtime-guardrail script remains non-green on three unrelated critical checks plus one existing warning.
- **Full-library boundary:** The default library run executed `2385` tests with `2383` passes and two unrelated Admin HTTP and QFTLS timing failures. Both failed tests passed in isolated `1/1` reruns; the serial aggregate exposed additional existing Admin rate-limit timing flakes and was not treated as green evidence.
- **Pushed-source proof:** Isolated Omega commit `5c635a9c7ecd37d3e904457e22789569f366cea7` passes `2409/2409` library tests and strict library Clippy with `-D warnings`; direct remote source guards pass for the removed detector helper and legacy AMX symbols. Remote rustfmt is unavailable because the `cargo-fmt` component is missing from toolchain `1.97.1-aarch64-unknown-linux-gnu`.
- **Ownership:** TODO-676 closes final compiled/runtime/OS dispatch and tile ownership for the inactive production backend. TODO-817 closes detector execution; TODO-818 retains future native AMX proof; TODO-819 closes profile/documentation mapping; TODO-760 retains Cargo feature semantics.

## Implementation Reconciliation (2026-08-05, TODO-813 audit persistence bounds)

- `AuditOptions::validate()` is the shared owner for queue capacity `1..=65,536`, active segment bytes `1..=128 MiB`, retained segments `1..=64`, and flush/shutdown timeout `1..=60,000 ms`. `AuditConfig::to_audit_options()` and `AuditLog::open_with_options()` use that contract before resource acquisition.
- `qf-audit-probe` adds explicit event `1..=1,000,000`, producer `1..=64`, and `--flush-timeout-ms` validation, then reports effective options, the nominal retained-segment budget, and all ceilings in machine-readable JSON.
- The nominal retained-segment budget is at most 8 GiB. Producer-side event payload limits are closed by TODO-814; bounded reads of already-existing files remain separately owned by TODO-727.
- Audit bound tests pass 24/24, the shared EngineConfig boundary test passes 1/1, and probe boundary tests pass 3/3. A 10,000-event restart/verification probe passes with 17,965 durable events/s, zero drops, zero persistence errors, and `restart_verified=true`.

## Implementation Reconciliation (2026-08-05, TODO-819 AMX profile and documentation truth)

- `X86_P3e` is the AVX-512F + GFNI profile; Intel AMX evidence is independent and does not select that profile.
- `Apple_M` remains a stable Apple Silicon profile marker whose current callers use NEON/ARM paths. `APPLE_AMX` and `CPU_MASK_APPLE_AMX` are platform/profile metadata only, not active Apple AMX arithmetic proof.
- `src/optimize/brain.rs` has no active matrix-multiplication or AMX caller. Wiedemann remains scalar GF(256) SpMV; AMX operation/scratch telemetry remains reserved and zero.
- Source comments, Apple startup logging, canonical documentation, and the AMX contract checker now use the same fail-closed capability language. `verify-amx-proof-contract.sh` passes.
- No AMX backend or profile variant rename was introduced. TODO-676 closes the broader dispatch/tile ownership for the inactive production path, TODO-818 retains native build/runtime proof for any future backend, and TODO-690 retains Wiedemann equation correctness.

## Implementation Reconciliation (2026-08-07, TODO-676 AMX dispatch and tile-state boundary)

- The active AMX boundary is complete and fail-closed. No `static mut`, raw tile kernel, compile-time-absent decoder branch, or process-global tile state remains in production source.
- `AmxCapability::from_signals()` requires CPU AMX-TILE/INT8 support, compiler target features, platform OS permission, and `VERIFIED_BACKEND` before product eligibility. The active FEC path is checked scalar GF(256) SpMV with per-worker `WiedemannScratch`; no tile register ownership or AMX telemetry is claimed.
- The current source passes the AMX contract checker, focused Wiedemann `6/6`, AMX capability/scalar-concurrency `3/3`, and format/diff checks. The x86 proof lane is explicitly unavailable on the ARM64 macOS host; native AMX execution is not inferred.
- TODO-676 closes current compiled/runtime/OS dispatch, scalar fallback, and concurrent tile-ownership boundaries. TODO-817 closes detector execution, TODO-819 closes profile truth, TODO-818 retains future native AMX proof, and TODO-690 retains Wiedemann equation correctness.

## Protocol Clock Wiring (2026-08-05, TODO-820)

- `src/time_source.rs::ProtocolClock` -> `transport::Connection` -> packet-number spaces, Recovery, congestion controllers, path/NAT/anti-replay state, ACK/loss/RTT/migration/idle timestamps, and explicit `CongestionController::update_rtt_at()` sample propagation.
- `transport::Connection::protocol_clock()` -> H3 connection -> push cadence and lifecycle timestamps; `Core` retains the same handle for telemetry, slow-phase diagnostics, HTTP/3 request timing, and engine uptime.
- `QuicFuscateConnection` creates one clock per client/server connection -> `StealthManager::new_with_runtime_owner_and_clock()` -> rate choker, flow shaping, probe history, cover scheduler, chaff lifecycle, fingerprint rotation, escalation deadlines, and server-push cadence.
- The same connection clock -> `qftls` provider construction -> handshake start/readiness, profile jitter deadlines, rebuild/reset, handshake duration, and ticket lifecycle timestamps. `SystemTime` producers remain separate wall-clock owners.
- The only remaining scoped direct monotonic boundary is `src/engine/engine.rs:1235` -> `ClientRuntime::wait_handshake()` at `src/implementations/client/mod.rs:803-816`, where an OS Condvar requires native `std::time::Instant`; TODO-822 owns conversion/injection. TODO-821 owns server/client state, TODO-823 wall clocks, TODO-824 injection/test isolation, and TODO-825 browser clocks.

## Protocol Clock Wiring (2026-08-06, TODO-821 server/client state)

- `QuicFuscateEngine::clock` -> `ClientRuntime::new_with_clock()` and `ServerRuntime::new_initialized_standalone_default_with_clock()`; the server runtime retains one handle for live state, metrics, admin control, accepted connections, and standalone web administration.
- Server state graph: runtime clock -> rate limiter, global limiter, EWMA, blacklist, session/bandwidth managers, DNS admission, TUN pending queue, qkey state, snapshots, and live server connection creation.
- Client state graph: runtime clock -> subsystem initialization, DNS admission, backend connect time, connection construction, quality/bandwidth tracking, I/O receive/assignment timing, metrics, and client uptime.
- Direct native monotonic reads remaining in these call chains are test fixtures or explicit TODO-822 runtime/OS boundaries: the client handshake Condvar, systemd watchdog scheduling, Tokio operation deadlines, DNS forwarding deadlines, and platform timer boundaries. Wall-clock epoch values remain separate TODO-823/TODO-658/TODO-662 owners.
- Local proof after the final constructor cleanup: locked library checking, test-target checking with `rust-tests`, the complete library suite (`2398/2398`), the focused client-backend clock test (`1/1`), strict library Clippy with `--features rust-tests -- -D warnings`, formatting, and diff hygiene pass on ARM64 macOS. The no-feature check retains two unchanged dead-code warnings outside this change; external runtime proof is not claimed.
- Omega proof boundary: clean isolated `/home/ubuntu/CODE/QuicFuscate-verify-dc4de71` is pinned to exact `ff0a2d3b50d55977457e6c654036af770f0f941c`; locked test-target checking and strict library Clippy pass. Remote full and focused test attempts ended with the host closing the SSH connection before a result summary, so they remain unavailable. Dirty `SOFTWARE/QuicFuscate` and `CODE/QuicFuscate` checkouts were untouched.

## Protocol Clock Wiring (2026-08-06, TODO-822 runtime clock-domain boundary)

- Product graph: QUIC release/recovery deadlines in `src/main_parts/runtime.rs` read the connection `ProtocolClock`; only the derived `Duration` enters the Tokio housekeeping timer. Client diagnostic logs use the same product clock for QUIC deadline remaining values and native monotonic time for branch/phase elapsed values.
- Tokio graph: accept drain, admin command/HTTP operations, stealth worker joins, DNS intercept worker reaping, and DoH endpoint fallback use Tokio-owned `Instant` values. Their shutdown and request timers remain live during manual product-clock tests.
- Native graph: server graceful drain, systemd watchdog, engine handshake Condvar, Wintun/native adapter waits, and blocking UDP DNS operations retain native monotonic ownership. Blocking DNS crosses to async cancellation through a remaining `Duration`, not an `Instant` conversion.
- Wall/diagnostic graph: `SystemTime` remains separate for epoch and persistence semantics; instrumentation, harness, FEC telemetry, and benchmark measurements retain native diagnostic timing. TODO-823 owns wall-clock provenance, TODO-824 owns broader injection/test isolation, and TODO-825 owns frontend/browser clocks.
- Scope closure: direct mixed-clock comparisons in the traced client housekeeping/diagnostic, server drain, stealth shutdown, DNS worker shutdown, DoH fallback, and blocking-DNS cancellation paths are removed. Handshake, watchdog, native adapter, accept/admin, and admin HTTP boundaries remain explicit by design.
- Local proof: format, diff hygiene, locked library/test-target checking, strict library Clippy, and the Cargo-built 2,399-test library binary pass on ARM64 macOS. A redundant later relink hit `ld: write() failed, errno=28` after the generated target exhausted the disk budget; the generated target was cleaned and no test failure occurred. Omega exact commit `1d7d56f2e039cfcf2c500fc5948c6f4933273aa7` passes locked test-target checking and strict library Clippy in the clean isolated checkout. The full remote test attempt ended with SSH exit `255` before a summary, so no Omega test pass is claimed.

## Wall-Clock Wiring (2026-08-06, TODO-823)

- `SystemTimeSource`/`now_system()` -> checked `unix_epoch_seconds()` and `unix_epoch_millis()` -> shared `WallClockError` classification for pre-epoch and overflow failures.
- Runtime wall-clock source -> blacklist cache, quota tracker and per-client bandwidth manager, retry-token manager, qkey registry, revocation store, admin log buffer, and admin-auth persistence.
- Quota `ClockUnavailable` -> bandwidth metrics -> TUN admission drop; no quota accounting occurs after a failed wall-clock conversion.
- Client profile connection capture and Tauri persisted-state sanitization -> explicit propagation of wall-clock errors; server and desktop log records -> `timestamp_valid`/`timestamp_error` metadata when conversion is unavailable.
- Audit and RFC3339 logging -> shared checked conversion -> explicit write/format failure; epoch zero is retained only for an actual epoch input or an explicitly marked invalid log record.
- Local proof: root library `2410/2410`, Tauri host `42/42`, locked test-target checking, strict library Clippy, format, and diff hygiene pass. Exact Omega commit `4157892d72ba4a5ab5f15fca871047ec26afa199` passes locked test-target checking, strict library Clippy, and the full library `2434/2434`; its only warning is the unchanged `RoutingManager::pf_rules` dead-code warning.
- Narrower owners remain separate: PKI TODO-656, H3 TODO-640, Reality and Stealth timestamp behavior TODO-584, test isolation TODO-824, and frontend/browser clocks TODO-825.

## Time-Source Wiring (2026-08-06, TODO-824)

- `TimeSource` -> explicit `ProtocolClock` owner contract: production monotonic reads are non-decreasing, manual tests may move backwards, checked deadlines reject overflow, and `SystemTime` remains an independent wall-clock domain.
- Test override wiring: `install_for_test()` -> thread-local nested source -> current-test `ProtocolClock::global()` reads; explicit owner handles and spawned threads do not inherit an unrelated test override. Guard drop restores the previous value during normal return and unwinding.
- Machine-checkable inventory: `scripts/audits/verify-time-source-inventory.py` -> reusable Rust masking/brace detection -> tracked Rust, browser, and shell patterns -> JSON locations with path, line, kind, scope, domain, owner, and evidence -> fail-closed status. Completion snapshot before frontend follow-through: 957 locations, 0 unclassified.
- Scope map: TODO-820 protocol, TODO-821 server/client state, TODO-822 Tokio/native runtime, TODO-823 wall clock, TODO-584 Reality/Stealth timestamps, TODO-640 H3 cookies, TODO-656 PKI, TODO-825 browser; test, benchmark, probe, script, and archive locations are explicitly classified as evidence-only domains.
- Verification: focused time-source tests pass 7/7; the full root-library suite passes 2413/2413 with bounded serial execution; locked test-target checking, default library checking, strict feature Clippy, format/diff hygiene, and the Tauri host suite pass at 42/42. Pushed commit `b2ef7719b94c860446d375486f858135e12bec32` is pinned in the isolated Omega checkout and passes inventory 957/0, locked test-target checking, strict feature Clippy, and full root-library tests `2437/2437`; the only warning is the unchanged `RoutingManager::pf_rules` dead-code warning.

## Frontend Clock Boundary Map (2026-08-06, TODO-825 audit and remediation closure)

- **Inventory:** `verify-time-source-inventory.py` scans tracked Rust, shell, browser, and frontend-test suffixes. The pre-remediation audit baseline is 962 locations, 0 unclassified: browser production 65, frontend tests 390, Rust production 153, benchmarks 58, probes 31, scripts 262, archive 3, and other explicit elapsed/wall conversion locations 68.
- **Tauri to desktop:** `PersistedTunnel.created_at:u64` and `BufferedLogLine.ts_ms:u64` are serialized as Unix milliseconds. Tauri performs checked wall-clock repair and reports timestamp validity/error metadata; the desktop bridge validates those values, preserves invalid-state metadata, and never repairs backend-owned records with browser time. TODO-868 owns this boundary.
- **Admin API consumers:** QKey `created_at`/`expires_at` values are validated as Unix seconds and converted once at the API boundary; admin `ts` log values are validated as Unix milliseconds. Invalid metadata remains structurally visible with unavailable time. TODO-868 owns this boundary.
- **Elapsed graph:** Desktop bridge and admin Dashboard throughput use the shared monotonic `performance.now()` evaluator with a 5,000 ms gap cap, counter rollback handling, and visibility rebasing. Desktop paste suppression uses a timer-owned 400 ms window; ThroughputChart and SmoothTrafficValue reset/cancel on hidden tabs. TODO-869 owns the verified contract.
- **Scheduler graph:** Desktop pollers, serialized root persistence, dialogs, tunnel list, country select, and throughput chart; admin pollers, dialogs, feedback, QKey panel, login, text input, and animation; and shared ConfirmDialog, ripple, toast, and copy-feedback primitives are all classified. `packages/ui/owned-scheduling.ts` owns replaceable timeout and RAF handles, while component cleanup and hidden-tab invalidation close the delayed-callback boundary. TODO-870 closes the lifecycle implementation and browser verification.
- **Identity graph:** Admin CSRF nonce creation uses `crypto.randomUUID()` or secure `crypto.getRandomValues()` bytes and fails closed when neither source exists. Shared toast IDs and Sparkline SVG gradient IDs use monotonic module-owned sequences, while frontend UUID doubles use explicit deterministic sequence identities. Production tunnel IDs retain their direct `crypto.randomUUID()` contract. TODO-871 closes the identity contract; TODO-872 closes the broader fixed-clock and collision matrix.
- **Negative result:** No zero-argument `new Date()`, `performance.timeOrigin`, `performance.mark`, `performance.measure`, `requestIdleCallback`, `cancelIdleCallback`, `queueMicrotask`, `AbortSignal.timeout`, or `setImmediate` was found in active app, package, or frontend-test source. `new Date(value)` consumers are timestamp-unit consumers, not current-clock producers.
- **Closure:** TODO-825 is complete as the parent audit and follow-through owner. TODO-868 through TODO-872 are implemented and verified; the audit itself remained read-only, while the separately authorized successor tasks supplied the frontend checks, builds, Chromium preflight, E2E, and scoped unit/regression evidence.

## Time-Source Inventory Reconciliation (2026-08-07, TODO-677)

- Current tracked-source inventory: `919` locations, `0` unclassified; production `156`, tests `384`, benchmarks `58`, probes `31`, scripts `262`, browser `25`, archive `3`.
- The earlier TODO-824 `957` and TODO-825 `962` counts are historical snapshots before the TODO-868 through TODO-872 follow-through. The current gate is the authoritative source for the current checkout.
- Explicit non-clock runtime delays remain owned by `native-cleanup-runtime` at `src/firewall/cleanup.rs:185` and `qftls-stealth-jitter` at `src/stealth/parts/tls_cover_provider.rs:379`; they are deliberate native delays, not canonical-clock bypasses.
- The post-push Graphify evidence at `scripts/out/audits/graphify-20260807T012815Z/graphify-evidence.json` is explicitly `BLOCKED` for unavailable semantic extraction, incomplete/unsupported coverage, and raw/normalized/legacy relationship limitations.
- TODO-677 closes the umbrella inventory. TODO-820 through TODO-825 and TODO-868 through TODO-872 retain the detailed implementation and proof ownership; unavailable native Linux/Windows/AMX/Miri/Omega evidence remains explicitly unavailable.

## Frontend and Tauri Timestamp Boundary Wiring (2026-08-06, TODO-868)

- `apps/tauri/src-tauri/src/main.rs` -> camelCase Tauri payloads -> `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts` -> `apps/svelte-desktop/src/lib/timestamp-boundary.ts` -> branded desktop `TunnelConfig.createdAt` and `LogEntry.timestamp` values.
- `packages/time/index.ts` is the shared unit/provenance and validation owner: Tauri persisted tunnels, Tauri logs, and desktop-created tunnel timestamps are Unix milliseconds; admin QKey metadata is Unix seconds; admin logs are Unix milliseconds.
- `apps/svelte-admin/src/lib/timestamp-boundary.ts` parses QKey and log API payloads before `QKeyPanel.svelte` and `LogsView.svelte`; `apps/svelte-admin/src/lib/format.ts` owns validated timestamp display and the single seconds-to-milliseconds conversion.
- Invalid backend timestamps are fail-closed at consumers: persisted desktop records are skipped and surfaced through the bridge error; log messages and structurally valid QKey rows remain visible with unavailable timestamp metadata. No browser fallback repairs backend-owned timestamps.
- `AddTunnelDialog.svelte` and `ImportQKeyDialog.svelte` are the explicit browser-owned creation boundary and use `createDesktopCreatedAt()`; this is separate from Tauri persistence repair. TODO-870 through TODO-872 retain lifecycle, identity, and deterministic clock coverage after TODO-869.
- Verification: Admin and Desktop checks report 0 errors and 0 warnings, the Admin/Desktop/shared-UI unit suites pass 292/292, 389/389, and 82/82, both production builds pass, Admin E2E passes 70/70, isolated Desktop E2E passes 23/23, and the Tauri host suite passes 42/42.

## Browser Elapsed and Visibility Wiring (2026-08-06, TODO-869)

- `packages/time/index.ts::evaluateByteRateSample()` -> desktop `startEnginePollers()` and admin `DashboardView.fetchStatus()`; both owners use `performance.now()` and the same 5,000 ms gap, monotonicity, counter, rebase, and zero-rate policy.
- Desktop document visibility -> Tauri bridge throughput sample reset and zeroed throughput; admin visibility -> Dashboard sample/history reset and hidden-response discard. A visible poll establishes a new baseline before a rate is emitted.
- Desktop document visibility -> `ThroughputChart` circular-buffer/smoothing reset and RAF stop/start; `SmoothTrafficValue` cancels hidden animation and snaps to target. QKey dialogs use the shared 400 ms timer-owned paste-click window.
- TODO-870 retains general timer/RAF lifecycle ownership; TODO-872 retains the cross-surface deterministic visibility and suspension matrix.
- Verification: Admin/Desktop checks report 0 errors and 0 warnings; full Admin/Desktop/shared-UI unit suites pass 293/293, 402/402, and 82/82; both builds pass; Chromium 1.58.2 preflight passes; Admin/Desktop E2E pass 70/70 and 23/23; and the post-cleanup dialog regression passes 16/16.

## Browser Identifier and CSRF Entropy Wiring (2026-08-06, TODO-871)

- Admin POST -> `createCsrfNonce()` -> platform `crypto.randomUUID()` or 32-byte `crypto.getRandomValues()` -> sequence-qualified `X-CSRF-Nonce`; missing or throwing secure sources return an explicit unavailable result and stop the request before `fetch()`.
- Shared toast creation -> monotonic module sequence -> `toast-*` state key -> existing `toastTimers` owner map -> matching removal and timer cancellation. Wall time and `Math.random()` are not identity inputs.
- Admin Sparkline instance -> module-scoped monotonic sequence -> `sparkline-grad-*` `<linearGradient>` ID and matching `url(#...)` reference. The loaded component module owns document-level uniqueness.
- Frontend unit setup -> deterministic `test-uuid-*` function only for environments without native `crypto.randomUUID()`; admin API tests independently exercise native UUID, secure-byte fallback, repeated provider output, and unavailable-source failure.
- TODO-871 adds fixed-clock/repeated-random toast and CSRF cases plus concurrent Sparkline instance identity checks. Full unit suites pass Shared UI `89/89`, Admin `307/307`, and Desktop `411/411`; Admin/Desktop checks report 0 errors and 0 warnings; both production builds pass; Chromium `1.58.2` preflight passes; Admin E2E passes `70/70`; Desktop E2E passes `23/23`; the focused API nonce suite passes `15/15`; and `git diff --check` passes. TODO-872 remains the owner for the shared clock/visibility/suspension harness.

## Deterministic Frontend Clock Wiring (2026-08-06, TODO-872)

- Shared unit setup -> `scripts/tests/frontend/test-clock.ts` -> isolated wall-clock, monotonic, fake-timer, RAF, and visibility controls with descriptor, spy, callback, and timer restoration.
- `DashboardView` and Tauri engine poller tests -> the harness -> hidden invalidation, delayed-response disposal, visible restart, monotonic throughput rebasing, and timer advancement.
- `ThroughputChart` and `SmoothTrafficValue` tests -> controlled RAF queue -> explicit frame cancellation and hidden-state snapping without manual global descriptor leakage.
- Elapsed-time test -> independent wall/monotonic controls -> accepted rate sample after a backwards wall-clock jump. Timestamp boundary and TODO-871 identity/CSRF tests remain the unit/provenance and collision owners.
- Playwright fixture constants -> explicit `QKEY_CREATED_AT_SECONDS`, `ADMIN_LOG_TIMESTAMP_MS`, and `BASE_LOG_TIMESTAMP_MS` values; desktop timestamp fixtures -> fixed valid `DEFAULT_DESKTOP_CREATED_AT_MS` value. No timing fixture uses host `Date.now()`.
- Unit verification: Shared UI `92/92`, Admin `307/307`, and Desktop `412/412` pass. Focused harness/owner regressions pass Shared UI `3/3`, Admin `46/46`, and Desktop `21/21`; Admin and Desktop `bun run check` pass with 0 errors and 0 warnings, and both production builds pass. Chromium preflight passes with Playwright `1.58.2`; Admin E2E passes `70/70` and Desktop E2E passes `23/23`; `git diff --check` passes. The Desktop build retains the known Tauri `core.js` dynamic/static import warning. No product or visual UI implementation is part of this wiring task, and no Rust gate is claimed.

## UnsafeMemoryPool Ownership Wiring (2026-08-06, TODO-826)

- `UnsafeMemoryPool::state: Mutex<PoolState>` owns the exact-base allocation registry and the available preallocated block list. `AllocationRecord` binds each address to `Preallocated` or `Fallback` origin and `Available` or `InUse` state; no unsynchronized cache or atomic slot path remains.
- `alloc_uninit()` transitions one available registry record to `InUse` or registers a distinct fallback allocation. `free()` validates alignment, exact pool membership, live state, and origin before either returning a preallocated block to `available` or removing/deallocating a fallback block. `UnsafePacket::from_raw_parts()` consumes the same live ownership proof before exposing a packet view.
- `copy_from_slice()` and `UnsafePacket::extend_from_slice()` use overlap-safe `ptr::copy`; packet length arithmetic is checked. Prefetch offsets are bounded to actual 64-byte lines, so the one-line rounded block cannot be addressed beyond its allocation. Drop deallocates available blocks only and logs/leaks checked-out blocks under the documented no-live-user precondition.
- Focused debug `unsafe_rust` verification passes `24/24` tests, including synchronized cross-thread reuse, foreign/double-free rejection, fallback accounting, runtime constructor invariants, overflow, overlapping copy, and undersized prefetch. The full debug `unsafe_rust` library passes `2437/2437`; the optimized release focused lane passes `24/24`; the optional `compression_zstd_ffi` focused lane passes `24/24`; strict all-target Clippy with `unsafe_rust`, formatting, and diff hygiene pass. Miri is unavailable on the pinned `1.97.1-aarch64-apple-darwin` toolchain, so no Miri result is claimed. The Rust target was cleaned after verification to preserve the disk floor.

## MemoryPool Ownership and Accounting Wiring (2026-08-06, TODO-827)

- `MemoryPool::try_new*()` -> checked effective block size, 64-byte `Layout`, `isize::MAX` total-byte bound, and bounded hard ceiling -> initial NUMA allocations with cleanup on failure. The compatibility `new*()` constructors apply the documented panic policy.
- `MemoryPool` allocation -> `PoolOwnershipLedger::register()` -> exact base address plus `Accounted` or `Ephemeral` origin and `Queue`, `Tls`, or `CheckedOut` location. Accounted records mirror `capacity`, `available`, and `in_use`; ephemeral records never enter those counters or accounted caches.
- Queue/TLS/checked-out transitions -> one ledger mutex; capacity growth/shrink -> the same ownership ledger plus `resize_lock`. Queue admission is registered before publication, queue removal is checked before checkout, and a closed or rejected registration returns the new block instead of retrying without progress.
- `MemoryPool::free()` -> exact length check -> checked-out ledger proof -> zeroization -> direct ephemeral release or accounted TLS/queue return. Foreign, duplicate, mismatched, and already-returned blocks do not enter the pool; known physically released blocks remove stale ledger state, and allocator address reuse repairs a stale record with counter correction.
- Pool drop -> ledger close -> queue drain/current-thread TLS cleanup; each TLS cache retains the ledger and lock ledger until its own drop, so remote cached blocks cannot outlive ownership state silently. Shrink stops when only remote TLS blocks remain and therefore cannot spin indefinitely.
- Boundary and evidence: TODO-767 owns requested-versus-effective block size; TODO-831 owns `PooledBlock` and generic caller cleanup; TODO-832 closes FEC caller cleanup and TODO-833 closes DATAGRAM caller cleanup. Focused debug pool tests pass `13/13`, the four-thread FEC E2E group passes `19/19`, the full default library passes `2419/2419`, and the final isolated release-focused lane passes `13/13` with no pool warning and only the two unrelated `qftls.rs` warnings. Strict all-target Clippy retains 11 unrelated baseline diagnostics outside `memory_pool.rs`.

## MemoryPool Allocation Layout and Recovery Wiring (2026-08-06, TODO-829)

- `MemoryPool::try_new*()` and `UnsafeMemoryPool::try_new()` -> reject zero capacity/size, checked 64-byte rounding and `Layout`, checked capacity multiplication, `isize::MAX` total-byte bound, fallible container reservation, and typed allocation failure before any invalid unsafe layout or exposed pointer.
- Safe-pool partial construction -> queue registration before each node's allocation loop -> ownership-ledger and lock-ledger release of every already allocated block on failure. The safe allocator no longer falls back to alignment `1`; the public 64-byte alignment contract remains intact.
- `try_alloc()`/`try_alloc_from_slice()`/`try_alloc_uninit()`/`try_set_capacity()` -> recoverable allocation or resize result; `alloc()`/`alloc_from_slice()`/`alloc_uninit()`/`set_capacity()` and legacy constructors remain explicit panic-policy wrappers for existing infallible callers. `OptimizationManager::try_alloc_block()` propagates the same result at the manager boundary. TODO-516 remains the mlock/munlock lifecycle owner; TODO-827 remains the runtime origin/counter owner.
- Verification -> safe pool release focus `16/16`, raw `unsafe_rust` focus `31/31`, complete default-feature `unsafe_rust` library `2453/2453`, native `unsafe_rust,compression_zstd_ffi` focus `32/32`, `cargo check --all-targets --features unsafe_rust`, and strict library Clippy all pass; formatting, diff hygiene, locked metadata, and forbidden-path search also pass.

## ZeroCopyBuffer FFI and Transfer Wiring (2026-08-06, TODO-830)

- Send path: immutable caller slices -> checked `ZeroCopyBuffer::new()` -> Unix `iovec` or Windows `WSABUF` array -> one `send`/`send_to` syscall -> `ZeroCopyTransfer` or typed `ZeroCopyError`.
- Receive path: exclusive `&mut [&mut [u8]]` -> checked `ZeroCopyRecvBuffer::new_mut()` -> receive-only raw buffer owner -> one `recv`/`recv_from` syscall -> `ZeroCopyTransfer` plus sender address where requested.
- Progress policy: typed errors cannot be mistaken for negative byte counts; zero and positive partial progress are explicit. The direct connected/send-to datagram callers reject incomplete transfers as `WriteZero`, while the wrapper leaves retry policy outside its synchronous boundary.
- Platform bounds: Unix count admission uses runtime `IOV_MAX` and the signed `msg_iovlen` ceiling; Windows count and element lengths use checked `u32` conversions and successful counts widen to `usize`. Address-length conversion is checked before `WSASendTo`.
- Batch boundary: `optimize::zc_batch` still delegates to `optimize::udp` and retains its `io::Result<usize>` contract. Raw batch/interface FFI and native Linux/Windows evidence remain TODO-682/TODO-683 boundaries, not hidden inside TODO-830.
- Evidence boundary: the source test covers transfer classification, Unix invalid-descriptor and iovec-count checks, and the 64-bit Windows ABI boundary. Executed local evidence covers the cross-platform transfer tests and Unix checks; Windows compilation/runtime remains unavailable on the current ARM64 macOS host.
- Verification on the current revision: release zero-copy focus `18/18`, native `unsafe_rust,compression_zstd_ffi` zero-copy focus `18/18`, default-feature release library `2424/2424`, `unsafe_rust` release library `2455/2455`, all-target checking, strict library/all-target Clippy, formatting, diff hygiene, and locked metadata pass. Linux cross-target compilation is blocked by the missing `x86_64-linux-gnu-gcc`; no Windows target is installed.

## Transport Frame Boundary Wiring (2026-08-08, TODO-750; TODO-840 baseline)

- Frame length admission: `transport::frames::wire_len()` validates malformed ACK ranges, checked QUIC-varint CRYPTO/STREAM/DATAGRAM payload limits up to 64 KiB, New Connection ID length and retirement ordering, and checked aggregate lengths before `to_bytes()` writes anything.
- Parser admission: `Cursor` uses checked varint and byte-tail access; ARM NEON/SVE2 stream parsing validates every decoder-reported byte count and the caller rejects any cursor advance beyond the remaining input before borrowing payload bytes. The parser enforces the Initial/Handshake/0-RTT/1-RTT frame matrix, decodes both RFC 9221 DATAGRAM forms, and consumes no-LEN STREAM payloads through the enclosing packet boundary.
- Receive commit: `Connection::recv()` preflights the complete decrypted frame payload before packet-number, CID, observer, activity, ACK, stream, or establishment state is committed; malformed, truncated, unknown, and packet-space-invalid frames return their typed parser error.
- Output admission: `write_varint_at()` and `write_bytes_at()` centralize checked output tails, while `batch_encode_frames()` validates each cumulative position before slicing the caller buffer. The compatibility `Arc<MemoryPool>` argument remains allocation-free.
- Regression surfaces: malformed ACK, truncated STREAM, invalid New Connection ID, capacity-bound batch, scalar frame round-trip, packet-space/no-length DATAGRAM and STREAM boundaries, exact varint-size payloads, receive preflight malformed suffixes, and ARM parser-boundary cases are present in `crates/qf-transport-frames/src/lib.rs`, `src/transport/frames.rs` (compatibility adapter), `src/transport/connection/parts/tests.rs`, `src/simd/arm_stream.rs`, and `scripts/tests/rust/rt-transport-frames-roundtrip.rs`.
- Current gate boundary: formatting, diff hygiene, frame tests `21/21`, default transport-connection tests `131/131`, `zero_copy_dgram` transport-connection tests `134/134`, all-feature checking, and all-feature strict Clippy pass. The complete all-feature library passes `2,690/2,690`. The two pre-existing Omega project paths are dirty or stale and were not modified.

## Generic Pooled-Buffer Failure Cleanup Wiring (2026-08-06, TODO-831)

- Generic allocation -> `PooledBlock { block, Arc<MemoryPool> }` -> byte-slice dereference for the active operation -> `Drop` -> `MemoryPool::free()` unless the block is deliberately transferred to a pool-aware owner.
- Compression/decompression, H3 stream/capsule paths, TUN reads and `TunPacket`, and the non-FEC copied receive buffer now use the guard across early returns and propagated errors. The pre-FEC `core_parts::connection::send_with_info()` guard transfers only after buffer, QUIC, path-control, stealth, and wire-length checks pass; `FecPacket` then owns the raw block and its originating pool.
- `transport::frames::batch_encode_frames()` retains its compatibility `Arc<MemoryPool>` parameter but no longer allocates an unused intermediate block. The optimization benchmark returns its raw block through `OptimizationManager::free_block()`.
- Exact counter-recovery tests cover guard drop/transfer, basic and dictionary compression/decompression failures, TUN read failures, and zero-copy DATAGRAM queue lifecycle boundaries. FEC buffer ownership is closed by TODO-832; zero-copy DATAGRAM buffer ownership is closed by TODO-833.
- Verification on the current ARM64 macOS revision: default library `2431/2431` in both debug and release profiles, focused compression `27/27`, all-target checking, strict `unsafe_rust` library/all-target Clippy, formatting, diff hygiene, and locked metadata pass. Default strict library Clippy retains four unrelated baseline diagnostics; Linux target checking is blocked by the missing `x86_64-linux-gnu-gcc`, and no Windows target is installed.

## FEC Pooled-Buffer Failure Cleanup Wiring (2026-08-06, TODO-832)

- FEC allocation -> live `PooledBlock` -> checked payload/coefficient/row operation -> `FecPacket::from_pooled_blocks()` only after pool-origin and length validation. Parser, wire, GF4/GF8/GF16 encoder, decoder equation/known storage, and Fountain adapter failure paths therefore retain an explicit owner until commit.
- Decoder maps and equation queues store `PooledBlock` rather than raw `AlignedBox`, so normal teardown and occupied-entry recovery return blocks through the originating `MemoryPool`. Fountain output rejects oversized symbols; `FecPacket::new()` is a crate-internal compatibility boundary for raw/foreign buffers with explicit direct-release behavior.
- GF16 row stride, row extent, coefficient-byte, and even-symbol arithmetic is checked before indexing or transfer. The final FEC matrix passes `252/252`; the complete debug and release libraries pass `2,436/2,436`; strict `unsafe_rust` library and all-target Clippy, formatting, diff hygiene, and locked metadata pass. TODO-833 closes the separate zero-copy DATAGRAM queue owner.

## Zero-Copy Datagram Pool Return Wiring (2026-08-06, TODO-833)

- `Connection::dgram_send()` and the inbound `Frame::Datagram` path use the connection's fixed-size `MemoryPool` contract. Payloads larger than `dgram_pool.block_size()` fail closed before allocation or copy; accepted feature-on payloads cannot be silently truncated.
- `DatagramBuffer { data: PooledBlock, len }` owns every queued block. `dgram_recv()`, `dgram_recv_vec()`, `dgram_purge_outgoing()`, frame serialization success/error, queue rejection, and `Connection` drop all preserve the originating pool owner through direct guard drop or queue reinsertion.
- The feature-on/off byte-equivalence test compiles against both queue representations. Feature-gated counter tests cover send purge, serialization success/error, receive pop/Vec, inbound oversize rejection, send oversize rejection, receive queue full rejection, and connection teardown. The optimization suite's source-level `zero_copy` filter now discovers real `zero_copy_dgram_*` tests; its full release execution is unclaimed after an unrelated telemetry baseline failure and a mandatory disk-floor stop.
- Native Linux/Windows execution remains outside this ARM64 macOS verification boundary and stays owned by TODO-682/TODO-683.

## UDP Batch FFI Result and Ownership Wiring (2026-08-07, TODO-837)

- `crates/qf-transport-udp/src/lib.rs` is the shared Unix owner for bounded `sendmmsg`/`recvmmsg`/`sendmsg_x` counts, complete datagram results, checked receive lengths, and one size/alignment-proven `sockaddr_storage` conversion. `src/optimize/udp.rs` is the root compatibility projection, and `crates/qf-transport-batch/src/lib.rs` reuses those contracts for Linux compatibility receive/fallback paths while preserving valid zero-length datagrams; `src/transport/batch.rs` only projects the historical root namespace.
- `crates/qf-transport-udp/src/fastpath.rs` owns `UdpFastPath`: it delegates Apple batching to the shared owner, rejects short scalar/GSO sends, checks Linux receive metadata before copying or address conversion, and constructs aligned buffers through a fallible overflow-checked path. `src/transport/udpfast.rs` is the root adapter.
- Caller-owned Unix and Windows descriptors are viewed through `ManuallyDrop` in temporary `UdpSocket` wrappers, including early errors. Accelerated `InvalidData` and `WriteZero` results remain terminal at the BatchProcessor and Linux client hotpath callers, preventing a potentially partially executed batch from being retried. ARM64 macOS verification passes the feature-gated library `2448/2448`, Optimize/UDP `8/8`, Unix caller-fd ownership `1/1`, UDP-fastpath `3/3`, `rt-udp-batch-send` `3/3`, `rt-transport-udpfast` `2/2`, and the macOS BatchProcessor branch `1/1`; formatting and diff hygiene pass. The final Linux-only error-propagation change was source-reviewed and formatted but not compiled on this macOS host. Linux-only integration cases, Windows target compilation, all-target rebuilding, and Omega execution remain unclaimed because the prior build reached the disk floor.

## Browser Timer and RAF Lifecycle Wiring (2026-08-06, TODO-870)

- `packages/ui/owned-scheduling.ts` -> admin and desktop delayed actions, login feedback/focus, QKey animation, error feedback, CountrySelect, and root persistence. Each owner cancels replacement work and destroys pending callbacks with its component or root lifecycle.
- Hidden document -> desktop Tauri status/stats/log pollers and admin Dashboard/Logs/Configuration coordinators invalidate stale generations and skip interval work; visible transition triggers a fresh bounded poll. Existing ThroughputChart, SmoothTrafficValue, TextInput, and ResizeObserver visibility/teardown wiring remains the rendering-side owner.
- Shared `ConfirmDialog`, `ripple`, and toast state now clear delayed callbacks, active ripple circles, and toast expiry handles on their own teardown/removal paths.
- Root persistence -> one serialized save owner: debounce, visibility, and before-unload all route through the same queue, preserving an in-flight write and coalescing later state into one follow-up.
- Full TODO-870 unit regressions pass: Shared UI `88/88`, Admin `301/301`, and Desktop `411/411`, including delayed async continuation cases after unmount. Admin/Desktop checks report 0 errors and 0 warnings; both production builds pass; Chromium `1.58.2` preflight passes; Admin E2E passes `70/70`; Desktop E2E passes `23/23`; and `git diff --check` passes.

## Audit Reconciliation (2026-08-07, Solver/H3/Transport ownership)

- Historical snapshot: the 2026-08-07 source pass recorded the Wiedemann right-hand-side return before TODO-690's current closure. The linked detail file and task register are authoritative for the present solver state.
- H3: `src/transport/h3_parts/connection.rs` now emits transactional client/server unidirectional control-stream prologues with SETTINGS, buffers and classifies peer unidirectional prefixes, validates control ownership and SETTINGS/frame legality, and parses full QUIC-varint frame types and lengths. The shared transport writable queue skips drained entries so H3 responses are not starved behind the control stream. TODO-691/TODO-692 are locally complete; native/external proof boundaries remain separate.
- Historical snapshot: receive accounting preceded overlap trimming and ACK state was cleared before capacity/serialization admission before TODO-693/TODO-694 closed those boundaries. The linked detail files retain the current contracts.
- Historical snapshot: loss detection, timeout ownership, and close priority were open before TODO-695/TODO-696/TODO-697 closed those boundaries. The linked detail files retain the current contracts.
- FEC/DATAGRAM commit: TODO-698 now stages both buffered FEC and transport DATAGRAM output and removes queue ownership only after the applicable write or short-header seal succeeds. TODO-831/TODO-832/TODO-833 continue to own pooled-buffer allocation cleanup; TODO-559 retains sustained throughput and native acceptance.
- Evidence boundary: these are source-backed audit findings only. Runtime, native, wire, build, test, and Clippy gates for this slice remain unrun and are not represented as passed.
## Deep Audit Reconciliation (2026-08-07, Platform, Tooling, and Coverage)

- Native transport and interface ownership remains source-audited but not fully cross-platform proven. TODO-837 now implements the bounded UDP batch result, address-length, partial-send, timeout, aligned-buffer, and caller-fd contracts; TODO-845 implements the Unix TUN syscall/name/rollback/close source contracts and static proof wiring; TODO-846 implements the Wintun cleanup ledger, constructor rollback, and lifecycle contract; TODO-847 implements the WFP engine/transaction cleanup ledger and deterministic status-fault seam; TODO-848 implements the versioned negative-proof manifest, explicit host skips, and unavailable native fault-lane declarations; local ARM64 macOS gates pass, while native Linux/Windows/Omega execution remains unclaimed. The AF_XDP experiment is removed under TODO-838. PMTU/prefetch remains owned by TODO-841 and TODO-842; TODO-854 closes local privilege, memory-lock, TLS, ordering, and portability-proof wiring while native Linux/Windows execution remains unclaimed; TODO-844's generic TUN result contract is implemented and statically wired.
- Current operational surfaces retain open fail-closed gaps in server shutdown ownership, installer secret handling, release-version propagation, CI baseline restoration, admin request bounds, macOS kill-switch/DNS state, runtime reload atomicity, blocked-IP durability, benchmark result propagation, release updater completeness, and local UI process readiness. The current owners are recorded in TODO-699 through TODO-748, TODO-782, and TODO-798 through TODO-807; TODO-757 is closed.
- The current TODO register is structurally accounted for: the post-push validator at commit `ea528d9` reports 777 tracker entries, 371 current detail files, 441 archived detail files, 36 explicit archive exceptions, 991 tracked paths, 35,527 ignored paths, and zero unexpected untracked paths. The increase from the preceding snapshot is generated Graphify evidence and related ignored audit output, not production scope. The canonical validator passes register/detail/archive/path integrity while Graphify remains explicitly BLOCKED. The legacy `docs/todo/audit-todo-consistency.sh` was also run and returned 75 obsolete-status violations across the 371 details because its allowlist predates the current canonical status vocabulary; it is not the authoritative structural gate.
- The audit boundary is source and documentation truth, not a release claim. No production implementation, UI change, privileged native run, authenticated live tunnel, or remote Omega mutation was performed in this reconciliation.

## PMTU Validation and Portable Prefetch Wiring (2026-08-07, TODO-841)

- `Config::set_pmtu_policy()` and `PmtuState::new()` share `PmtuPolicy::validate()`. The state constructor returns a typed error, and transport connection construction propagates invalid-policy failures instead of creating an unvalidated PMTU state.
- `PmtuState` admits only probe sizes inside its validated bounds, uses saturating monotonic-time comparison for earlier timestamps, and keeps ACK, loss, and black-hole reset targets inside the configured range with overflow-safe midpoint/reset arithmetic.
- Receive prefetch wiring passes a bounded byte slice into `prefetch_frame_parse_window()`. Empty input returns without a hint, over-bound offsets clamp to the final byte, and no one-past-end pointer is formed. Non-iOS AArch64 now uses the non-dereferencing `prfm` hint; the former volatile-load fallback is removed.
- Deterministic constructor, timestamp, arithmetic, empty-buffer, exact-window, and over-bound-window regressions are present without network setup. Formatting, diff hygiene, and one-job library checking pass with the pre-existing `accounting_snapshot` warning; the focused test-target build was stopped at 1.7 GiB free and cleaned, so no test execution is claimed.

## Transport Malformed-Boundary and Native ISA Proof Wiring (2026-08-07, TODO-842)

- `crates/qf-transport-udp/src/lib.rs` owns direct malformed metadata regressions for syscall counts, receive lengths, partial sends, batch/datagram limits, and address-family conversion; `src/optimize/udp.rs` preserves the root helper paths, and `crates/qf-transport-batch/src/lib.rs` owns the real Linux invalid-caller-fd `EBADF` case while `src/transport/batch.rs` remains the compatibility adapter.
- `scripts/tests/rust/rt-transport-frames-roundtrip.rs` covers malformed ACK ranges, Connection IDs, ARM stream cursors, and cumulative batch capacity. `rt-transport-packet-headers.rs` compares scalar and compile-gated AVX2 packet-number output at an unaligned offset; `rt-packet-number-parity` remains the decode reference lane.
- `scripts/tests/suites/test-transport.sh` executes exact library targets and records explicit ARM, non-Linux, non-x86_64, and no-AVX2 skips. `scripts/tests/audits/audit-runtime-guardrails.sh` checks the new wiring fail-closed. The new checks pass, while the aggregate guardrail retains four pre-existing critical findings and one warning.
- The host is ARM64 macOS. No Linux, Windows, x86_64 AVX2, privileged, or Omega runtime evidence is inferred. AF_XDP feature-on proof is N/A after TODO-838 removed that implementation and target; batch pool-cleanup proof is N/A after TODO-831 made the encoder allocation-free. The focused release library compile reached dependency compilation and was interrupted with exit 130 at approximately 2.0 GiB free before test execution; `cargo clean` restored 2.4 GiB. No test result is claimed.
- `src/engine/config.rs` no longer serializes XDP mode/flag fields. Legacy `InterfaceType::Xdp`, `Tap`, and `RawSocket` values remain parseable only to fail closed during validation; TODO-874 records the resulting TUN-only configuration contract.
- The TODO completeness validator reaches tracker/detail/archive/path coverage and then stops because the existing Graphify evidence manifest is stale relative to the current Git revision. Graphify freshness remains explicitly blocked; no structural TODO failure is inferred.

## Privilege Identity and Cross-Platform FFI Wiring (2026-08-07, TODO-849)

- `ResolvedIdentity` is an opaque account-database result with accessor-only reads. The final privilege boundary revalidates non-root IDs, non-empty selectors/names, and current selector-to-canonical-name/ID mappings before any UID/GID transition; forged root, stale-account, and mismatched-count states fail closed.
- `CurrentIds` has a target-independent type declaration, so the non-Unix `current_ids()` stub no longer references a Unix-only alias. `current_groups()` rejects negative or over-capacity syscall counts before buffer truncation, and every privilege FFI block carries a local pointer/platform/result safety contract.
- Source regressions cover a forged root identity and a `getgroups()` count larger than requested capacity. The new runtime guardrail item is green; formatting, locked metadata, Bash syntax, and diff hygiene pass. The focused privilege unit target passes `19/19`, and the dedicated portable `it-privilege-boundary` target passes `1/1` on ARM64 macOS with `rust-tests`; the broader integration target previously passed `3/3` in the TODO-849/850 evidence. The TODO-854 manifest records native Linux privilege proof as unavailable on this host; Windows compilation is declared in CI and statically guarded, while Windows native privilege proof remains unclaimed.

## Privilege Post-Drop State and Failure Proof (2026-08-07, TODO-850)

- Linux thread status parsing requires exactly four real/effective/saved/filesystem UID and GID fields for every live task. Supplementary groups, effective/permitted/inheritable/ambient capabilities, and `NoNewPrivs` remain part of the same per-thread assertion.
- `PrivilegeTransitionState` records transition progress, and `DropError::PartialTransition` makes failures after validation explicit. The server finalization path remains fail-closed and refuses service exposure for both ordinary verification failures and uncertain partial state.
- The isolated probe clears its standard or Tokio worker/runtime threads before testing both UID and GID root regain. It emits a deterministic `PRIVILEGE_PROBE_STATE` record, while the privileged integration lane asserts complete serialized state for both execution modes. Non-root hosts emit `PRIVILEGE_PROOF_UNAVAILABLE reason=requires_root` and are not counted as proof.
- Non-Linux Unix retains only its actual `setgid`/`setuid` and effective-ID guarantee. The process-wide Linux thread proof returns `NotSupported` outside Linux, so no Linux capability, `/proc`, saved-ID, supplementary-group, or root-regain semantics are implied.

## Embedded Server Memory-Lock Policy and Reload Ownership (2026-08-07, TODO-851)

- **Shared server startup memory-lock policy:** `src/memory_lock.rs::MemoryLockPolicy` is the single mapping from `SecurityConfig.lock_memory`, `SecurityConfig.lock_blocks`, and `SecurityConfig.memory_lock_failure_policy` for standalone and embedded server startup. It preserves the configured values, resets qftls process-coverage state, applies process locking when the boundary permits it, and configures `MemoryPool::set_lock_blocks()` before TLS identity construction.
- Embedded `QuicFuscateEngine::start()` applies the policy before `global_pool()` and before runtime transport creation can load the server TLS identity. Standalone `run_server()` applies the same policy before `load_server_identity()`; with a Linux UID/GID transition it individually protects the TLS key before the transition and applies the deferred process-wide lock after verified privilege state.
- Standalone runtime reload compares current and candidate startup-owned memory-lock settings before `apply_runtime_config_reload()`. Unchanged values are accepted, but changing any of the three fields returns a typed rejection and requires restart, so no submitted value is silently retained or ignored.
- Policy mapping, unchanged-reload, changed-setting rejection, embedded startup pool application, standalone restart reapplication, finite-limit, failure-policy, and process-lock boundary tests are owned by `src/memory_lock.rs`; the real standalone reload fixture passes `2/2` together with the unchanged reload path. The runtime guardrail checks source ordering, the shared policy surface, all regression-test names, removal of the former standalone duplicate helper, both canonical TOML templates, and this documentation.
- Static verification passes `cargo fmt --all -- --check`, Bash syntax, Python TOML parsing for both templates, `git diff --check`, and the new guardrail item. Focused Rust verification passes the memory-lock filter `10/10`, the additional metrics and canonical-config tests, the combined runtime-reload filter `2/2`, and `cargo check --locked --lib --bins --features rust-tests`; only pre-existing compiler warnings remain. The aggregate runtime guardrail retains four pre-existing critical findings and one pre-existing warning outside this owner. Process-lock readiness/failure semantics are closed by TODO-852; TODO-854 closes local deterministic negative-proof wiring, while native Linux root-regain and Windows native fault execution remain unclaimed.

## Process Memory-Lock Readiness and Failure Policy (2026-08-07, TODO-852)

- `SecurityConfig.memory_lock_failure_policy` selects explicit `best-effort` or `fail-closed` startup behavior. Best-effort publishes degraded state after an `RLIMIT_MEMLOCK` query, `mlockall`, or unsupported-platform failure; fail-closed propagates a typed error before TLS identity publication and service readiness.
- `MemoryLockStartupError` preserves the failure kind, observed budget classification, and OS message. Unlimited budgets use current-and-future locking; finite budgets use current-only locking; unknown-budget best-effort fallback is also observable as degraded state.
- `MemoryLockStartupStatus` is copied into runtime Metrics and exposed through admin status/health plus systemd `/health`, `/ready`, and `/live`. Degraded best-effort remains service-ready; deferred and failed states are not ready, while `/live` remains a liveness check with HTTP 200.
- Standalone and embedded startup propagate fail-closed errors before service exposure. The deferred standalone process lock is applied after verified privilege transition and before runtime service readiness. Pool unlock/accounting remains TODO-516/TODO-678; TLS key correspondence and exporter ownership are closed by TODO-853, while lower-level key lock/publication remains TODO-643. TODO-854 closes the local deterministic negative-proof wiring; native Linux root-regain and Windows native fault execution remain unclaimed.
- The process-wide test uses a Drop guard that calls `munlockall()` on every exit path, and deterministic tests cover policy decisions, finite/unlimited/unknown flags, and degraded/not-ready health output.
- The full local library matrix reached `2,499/2,501`: the concurrent audit producer test passed when isolated after one parallel flush-timeout failure, while the deterministic packet-number assertion remains owned by open TODO-839. This unrelated suite result does not change the focused TODO-852 gates.

## TLS Identity Consistency and Secret Output Ownership (2026-08-07, TODO-853)

- `preload_tls_server_identity()` now validates the parsed certificate chain and private key through rustls `ServerConfig::with_single_cert()` before process-global `OnceLock` publication. This reuses rustls' end-entity SPKI correspondence check, so a parseable but mismatched certificate/key pair fails closed before publication.
- The existing same-identity `AlreadyLoaded` and conflicting-identity error contract remains explicit. `LockedKeyMaterial` and rejected `OnceLock` values retain their lower-level zeroize-before-`munlock` ownership under TODO-643; process-wide lock readiness/failure policy remains under TODO-852.
- `SensitiveKeyingMaterial = Zeroizing<Vec<u8>>` is now the `export_keying_material()` result through the public trait, combined provider, rustls provider, and wrapper. Rustls receives and returns the same erasing owner, and the exporter audit found no production caller outside `qftls` that could discard the owner.
- Focused qftls verification passes `24/24`, including the isolated mismatch/duplicate/conflict preload contract and the zeroization-before-drop regression. TODO-854 adds a dedicated qftls negative-proof target and explicit unavailable native-lane reporting; pooled-block unlock/accounting remains TODO-516/TODO-678.

## Privilege, Lock, and TLS Negative-Proof Guardrails (2026-08-07, TODO-854)

- `scripts/tests/suites/test-privilege-memory-tls-proof.sh` runs the deterministic proof targets and emits `quicfuscate.privilege_memory_tls_negative_proof.v1`. The corrected local run passed privilege `19/19`, memory-lock `11/11`, qftls `19/19`, the portable privilege integration target `1/1`, and the embedded/standalone source-order checks.
- The proof manifest records host, architecture, exact filtered commands, test results, source-order status, native privilege status, and Windows compile-gate status. The ARM64 macOS run records native Linux root-regain proof as `UNAVAILABLE` with an explicit Linux proc/setxid reason; this is not security proof. The Windows `windows-core-checks` workflow is statically required to run the library compile before the Windows test `--no-run` boundary, but Windows native execution was not performed on this host.
- `src/privilege/drop.rs` adds a pure Linux root-regain errno contract test, while existing TODO-849/TODO-850 malformed FFI, post-drop, filesystem-ID, and partial-transition tests are included through exact filters. `src/memory_lock.rs` adds deferred-state and panic-unwind cleanup proof. TODO-853 qftls mismatch, duplicate/conflict publication, and zeroizing exporter coverage is included through its isolated target.
- `scripts/tests/audits/audit-runtime-guardrails.sh`, `scripts/tests/utils/util-run-full-suite.sh`, and `.github/workflows/ci.yml` inspect and execute the proof wiring. Native Linux root privilege, Windows native fault injection, and cross-target execution remain explicit external boundaries and are not inferred from local or static results.

## XDP Configuration Surface Reconciliation (2026-08-07, TODO-874)

- `InterfaceConfig` is now a TUN-only serialized configuration surface. The stale `xdp_mode` and `xdp_flags` fields, their defaults, and the unused `XdpMode` enum were removed, so generated TOML cannot advertise an AF_XDP mode.
- `InterfaceType::Xdp` remains deserializable as a legacy value only so existing input receives an explicit validation error stating that AF_XDP was removed. Legacy `Tap` and `RawSocket` values also fail closed because the current runtime dispatch supports only TUN.
- `config/quicfuscate.toml` and `config/server-linux.default.toml` now document the TUN-only contract and no longer contain XDP fields. GSO/GRO comments retain their compatibility/harness boundary without implying an XDP fallback.
- `src/engine/config.rs` contains failable validation and schema regressions for every legacy non-TUN value, removed-field rejection, and default serialization. The runtime guardrail checks the source, tests, and both canonical templates.
- Static verification passes `cargo fmt --all -- --check`, Bash syntax, TOML parsing, `git diff --check`, and the new XDP guardrail item. The aggregate runtime guardrail remains at four pre-existing critical findings and one warning. Rust unit-test execution was not admitted because the local 2.2 GiB free-space boundary would be crossed by a fresh test build; Omega was not used because both permitted QuicFuscate folders exist there and are dirty or revision-mismatched.
- No AF_XDP implementation, Cargo feature, or runtime path was reintroduced. Any future AF_XDP work requires a separate product and kernel-ownership decision.

## Interface BMI2 Dispatch and Profile Proof Wiring (2026-08-07, TODO-843)

- `FeatureDetector` caches the automatic profile derived from one complete `CpuFeatures` snapshot. `profile_from_features()` is the deterministic owner for x86 profile selection, including the explicit `avx2 && bmi2` intersection for P2b; P3a-P3e and P4a/P4b remain independent of BMI2.
- `TunInterface::write_packet()` enters `parse_ip_header_bmi2()` only when the cached profile is an x86 profile and the exact runtime `features_full().bmi2` bit is true. Every other case uses the scalar parser. The parser retains `std::ptr::read_unaligned` for the IPv4 header word.
- Synthetic CPU tests cover every x86 automatic profile selector with BMI2 absent and present. Interface tests cover every x86 and non-x86 profile decision without host-dependent feature detection; the portable unaligned write test is always available, and the direct native BMI2 parser test emits `SIMD_SKIP` when unsupported.
- `scripts/tests/suites/test-core.sh` runs exact library tests for the portable input and synthetic dispatch proof, and records explicit architecture/CPU skips for x86-only lanes. `scripts/tests/audits/audit-runtime-guardrails.sh` fails closed when the profile cache, gate, tests, or suite wiring disappears.
- Formatting, Bash syntax, diff hygiene, the BMI2 guardrail, and one-job `cargo check --lib --features rust-tests` pass with the pre-existing `memory_pool.rs:1071` dead-code warning. The exact focused unaligned test build was stopped with exit 130 at 1.5 GiB free before test execution; `cargo clean` removed 390.6 MiB and left 1.7 GiB free. Local ARM64 macOS can prove the source and portable path but cannot execute native x86 BMI2. The native x86 lane and broader negative/platform proof remain unclaimed under TODO-848; no external or Omega execution is inferred.

## Generic TUN I/O Result Contract (2026-08-07, TODO-844)

- `TunDevice::read()` now has an explicit `1..=buf.len()` result contract; `WouldBlock` represents no packet. `TunDevice::write()` must report exactly the input length for a complete packet write. Zero or oversized reads and zero, short, or oversized writes fail with typed `io::ErrorKind` values at `TunInterface`.
- `read_block()` validates before exposing the pooled block, borrowed and owned reader loops share that invariant, and `TunPacket` no longer clamps an invalid length. `write()` and `write_packet()` validate before accepted-byte telemetry or caller success.
- Fault-injection backends representing external-factory results cover zero and oversized reads, zero, short, and oversized writes, the client `write_packet()` path, and owned-packet oversized construction. `test-core.sh` wires exact library targets; runtime guardrail 4h is green.
- Static format, Bash syntax, diff hygiene, and guardrail checks pass. Rust test execution is not claimed because local free space is below the 2-GiB safety boundary and both Omega checkouts are dirty or revision-mismatched. Native Linux/macOS syscall progress and raw `readv`/`writev` semantics are implemented by TODO-845 below, but privileged/native execution remains unclaimed.

## Unix TUN Syscall Boundaries (2026-08-07, TODO-845)

- `src/interface.rs` centralizes raw Unix read and write-result validation. Linux rejects zero, negative-after-errno, and oversized reads; Linux full-packet writes reject zero progress and results larger than the remaining source before advancing the offset.
- macOS `utun` parsing requires the kernel-reported length to stay inside the 64-byte buffer, end at a NUL, contain no interior NUL, and decode as UTF-8. `readv` validates the combined header/payload result before subtracting the four-byte AF header; `writev` rebuilds bounded iovecs for every partial result and rejects zero, oversized, and out-of-packet progress.
- Linux native and compatibility backends retain the exact kernel interface bytes after `TUNSETIFF`, reject malformed or mismatched identity, close the owned descriptor through one terminal ownership helper, and attempt rollback against the same raw name. Unknown or malformed identity cannot be reported as clean rollback. macOS setup closes through the same helper and, after connection, requires a known interface name before claiming absence; unknown identity returns an explicit proof error.
- `TunHandle`, native `Drop` implementations, and the macOS compatibility guard surface close failures through typed returns or structured error logs. The descriptor number is terminalized before `close(2)` so an `EINTR`-style error is never retried against a potentially reused descriptor.
- Deterministic tests cover raw zero/oversized counts, bounded and terminated names, close-failure ownership, compatibility handle teardown, Linux malformed kernel identity, and macOS partial `writev` iovec construction. `test-core.sh` wires exact library targets and records unsupported-platform skips; runtime guardrail 4i is green.
- `cargo fmt --all -- --check`, Bash syntax, `git diff --check`, and static guardrails pass. Rust test execution is not claimed because local free space is below the 2-GiB safety boundary; native privileged Linux/macOS execution and Omega proof remain unclaimed. TODO-846 owns the Wintun native proof boundary; TODO-847 owns WFP; TODO-848 owns remaining negative/native proof.

## Unix TUN and Platform Core Suite Continuation (2026-08-10, TODO-845/TODO-846/TODO-848)

- After the mandated `cargo clean`, the guarded release core suite executed the deterministic Unix raw-result, bounded-name, close-ownership, compatibility-handle, and macOS `writev` regressions. It recorded `37` passed tests, `0` failed, and `5` explicit host/ISA skips.
- Evidence: `scripts/out/tests/test-core-20260810T-backend-continuation-fixed/results.json`; final target `640,996 KiB`, free disk `19,842,912 KiB`. The target remained below the 12-GiB cleanup threshold and free disk remained above the 2-GiB floor.
- `test-core.sh` fails closed when a named test body is not executed and records the Windows-only Wintun cleanup-state fixture as `SKIP` on non-Windows hosts. The versioned negative-proof manifest separates executed portable contracts from target-gated and native-unavailable evidence.
- Native privileged Linux/macOS syscall execution, Windows compilation and Win32/WFP fault injection, verified-DLL residue, and Omega proof remain external boundaries and are not inferred.

## Wintun Cleanup Ownership (2026-08-07, TODO-846)

- `src/interface/wintun.rs` now tracks shutdown signaling, session end, adapter close, shutdown-event close, and DLL unload as independent owner states. Session and adapter teardown run only after the operation lock drains; event and module failures remain pending and are retried by explicit `close()` calls. `Drop` performs one bounded retry and records pending resources instead of marking a failed close as complete.
- Constructor failures use `WintunStartupOwner`, which retains every acquired adapter, session, shutdown event, and module owner through rollback. Loader export failures use a temporary module rollback guard and include unload failure in the returned error while retaining a Drop retry.
- The manual `Send`/`Sync` contract is tied to the upstream Wintun packet API guarantees, the local operation/close locks, and the shutdown wakeup ordering. Deterministic state-failure and compile-contract tests are wired into `test-core.sh`; the privileged blocked-reader native test asserts a complete owner ledger after close.
- `cargo fmt --all -- --check`, Bash syntax, `git diff --check`, and runtime guardrail 4j pass. Rust tests, Windows compilation, injected Win32 failure execution, and privileged residue proof were not run: the pre-test storage check reported 1.1 GiB below the 2-GiB floor, the host is macOS ARM64, and no Windows administrator/DLL environment is available. A later static-only check reported 4.8 GiB with `target/` absent; no Rust build was started. TODO-848 now owns the versioned negative-proof manifest and the remaining explicit native-fault boundary.

## WFP Cleanup Ownership (2026-08-07, TODO-847)

- `src/implementations/client/killswitch/windows.rs` now models engine and transaction release through `WfpOwnerState`. Failed `FwpmEngineClose0`, commit, and abort statuses retain the native owner and exact status; explicit close/abort calls can retry while the owner remains in scope, and `Drop` makes one bounded final attempt with durable pending diagnostics.
- Every WFP status return remains checked. Safety comments bind engine/transaction handle lifetimes and keep UTF-16 buffers, filter-condition arrays, GUID pointers, and nested WFP descriptors alive through their synchronous calls only; no wrapper pointer escapes its call scope.
- `wfp_engine_close_fault_retains_native_handle_for_retry` and `wfp_transaction_abort_fault_retains_active_state_for_retry` inject failure and recovery statuses through the production ownership transition. The Windows CI core lane runs the `wfp_` test filter, and runtime guardrail 4k checks the implementation, tests, safety contract, and CI wiring.
- `cargo fmt --all -- --check`, Bash syntax, `git diff --check`, and static runtime guardrails are the available local gates. Windows compilation, BFE fault execution, current WFP packet-policy/residue execution, and elevated native evidence remain unclaimed because this host is macOS ARM64 and no Windows/BFE environment was available. Historical WFP evidence predates these injected-failure tests.

## Interface and Platform Negative Proof (2026-08-07, TODO-848)

- The existing exact library targets cover generic external-factory result faults, Unix raw result/name/close contracts, Wintun cleanup state and Send/Sync, WFP engine/transaction status ownership, and synthetic BMI2 profile intersections. `test-core.sh` records Linux/macOS and x86/BMI2 skips explicitly rather than treating unsupported hosts as green native proof.
- `interface-platform-negative-proof.json` uses schema `quicfuscate.interface_platform_negative_proof.v1` to separate executed local fixtures from `UNAVAILABLE` Wintun and WFP native cleanup fault lanes. The Windows core workflow emits the same schema with administrator, verified-DLL, BFE, and native-fault prerequisites visible; it does not claim native fault injection that is not implemented.
- Runtime guardrail 4l checks both manifest producers, exact unavailable statuses and reasons, Windows CI wiring, and documentation. The aggregate guardrail remains at four pre-existing critical findings and one warning outside this owner; the new negative-proof matrix item is green.
- Available local verification is formatting, Bash syntax, metadata, diff hygiene, and static guardrails. Rust test/build execution, Windows compilation, BFE fault injection, privileged residue proof, and Omega execution remain unclaimed.

## Optimize unsafe-boundary remediation (2026-08-07, TODO-680)

- `bitmap_set_range` now validates empty, reversed, out-of-range, and overflowing bounds once before selecting BMI2, NEON, SVE2, or scalar execution. The BMI2 helper repeats the boundary contract before mask arithmetic. `decode_packet_number` accepts only QUIC's 1..=4-byte lengths and returns the expected number unchanged for invalid input. VNNI congestion aggregation processes every public sample in 64-entry scratch chunks instead of truncating after the active connection window.
- Pattern injection uses `complete_pattern_end` before every architecture-specific slice or pointer offset. The SSE2 short-pattern path copies exactly the requested bytes, and malformed positions including `usize::MAX` are ignored. SVE2 Base64 chooses `vl/4` groups so the 4-byte output predicate stays within one vector; boundary-length parity covers the scalar reference.
- Percentile selection validates finite values in 0..=100, clamps the 100th percentile to the final element, returns `0.0` without mutation for invalid input, and passes one checked index into every architecture helper. Linux test-only RPS configuration rejects path components and CPU masks beyond 128 bits before touching sysfs.
- `sort` TypeId casts, NEON local-array operations, SSE2 XOR helpers, UDP sockaddr/syscall blocks, and the touched SIMD helpers now carry explicit safety contracts. Runtime guardrail 4m checks the source contracts, malformed-input tests, parity fixtures, and documentation. Rust tests, native SVE2/x86/Linux execution, and full platform proof remain unclaimed on the ARM64 macOS host.

## FEC Decoder, Matrix, and Wire Input Boundaries (2026-08-07, TODO-856)

- Direct compatibility packet lengths are bounded without unbounded upsizing; checked packet constructors reject lengths beyond backing storage or the pool block, stream flags and systematic/repair coefficient metadata are fail-closed, and cloning cannot allocate from attacker-controlled coefficient lengths.
- All direct block decoder dimensions are bounded to the supported source/depth contract. Decoder8/Decoder4 reject overlong coefficient vectors and invalid anchors. Decoder16 establishes an active repair anchor, retains only active-window IDs, rejects unrelated systematics/repairs, and requires active-window membership for completion. Lazy and interleaved wrappers normalize invalid capacity inputs to an inert bounded decoder while preserving compatibility signatures.
- The public matrix helper now returns typed shape errors for empty, ragged, mismatched, and overflowed dimensions. Wire profile division has a checked API and non-panicking compatibility wrapper; coefficient widths, systematic repair ordinals, and GF4/GF8/GF16 arithmetic are bounded. Source-only receive maps pool-block overflow to `ResourceExhausted` rather than truncating.
- Focused evidence is green: `cargo check` and `cargo clippy`, stream/decoder `17/17`, Wire FEC `24/24`, and malformed matrix `1/1`, with only pre-existing compiler warnings. Tests run with `--test-threads=1` to avoid environment-variable races between parallel tests. The host is ARM64 macOS; native x86/SVE2, sanitizer/Miri, privileged, and Omega proof are not inferred.

## Runtime Policy Generation and Snapshot Wiring (2026-08-08, TODO-876)

- Standalone reload publication -> `RuntimePolicyGeneration` write lease -> transport private-copy commit -> FEC/optimization/stealth shared-state commit -> one generation advance. Profile rotation takes the same lease before changing stealth state.
- New-client construction -> `RuntimePolicySnapshot::capture()` read lease -> generation-tagged transport/FEC/optimization/stealth clones -> `LiveClientInit.runtime_generation`; concurrent readers cannot cross the writer boundary.
- TODO-794 owns complete `EngineConfig` validation and strict adapter projection. UI generation fields are intentionally deferred because frontend files are frozen for the current backend-only continuation.

## Fuzz Contract (2026-08-08, TODO-758)

- `scripts/tests/fuzz/Cargo.toml` resolves the root crate through `../../..` and exposes exactly six targets. `cargo metadata --no-deps --format-version 1 --locked` and local `cargo fuzz list --fuzz-dir scripts/tests/fuzz` are the available host proofs.
- `.github/workflows/ci.yml` covers pull requests and main pushes with 60/120-second target budgets; `.github/workflows/fuzz-scheduled.yml` covers the extended Sunday lane with a 1,800-second budget. Both lanes require nightly, explicitly set AddressSanitizer, call `run-ci-fuzz.sh`, and upload crash artifacts on failure.
- The tracked seed corpus is curated to eight files per target. Generated `corpus/` and `artifacts/` directories remain ignored and are populated only in the runtime lane.
- The crypto target distinguishes all public configuration spellings from the internal AEGIS width backends and documents the intentional fallback path. Frontend files and surfaces are outside this backend-only task.

## Strict Panic and Invariant Contract (2026-08-08, TODO-757)

- `scripts/tests/audits/audit-all-comprehensive.sh` records separate production, benchmark, and all-feature strict Clippy lanes. The production feature set excludes test-only surfaces, `server,benches` is the explicit benchmark class, and the all-feature `--lib --bins` command remains the aggregate coverage lane.
- Typed failure propagation now owns GF table setup, shared FEC buffers, packet stealth transitions, server-domain and MASQUE setup, replay-window fixed-width conversion, PEM encoding, probe worker failures, DDoS refresh results, and FEC benchmark packet construction.
- Narrow compatibility dispositions remain only at HKDF/HMAC fixed-size contracts, benchmark setup, validated legacy constructors, infallible memory-pool/optimization-manager wrappers, standalone live-state accessors, and `LiveServerState::default`; every site documents the invariant and points callers to a fallible API where available.
- Evidence: default `cargo test --lib --features rust-tests` passes `2,659/2,659`; all-feature `cargo test --all-features --lib` passes `2,701/2,701`; `cargo check --all-features`, formatting, diff hygiene, and all three strict Clippy lanes pass. The comprehensive audit's unrelated frontend publish, Linux-only integration, runtime-guardrail, and native-host boundaries remain explicitly non-pass. The completeness validator reaches coverage but fails closed on stale Graphify provenance for the current revision. Frontend paths are unchanged.

## io_uring Per-Slot Send Disposition (2026-08-08, TODO-798)

- `src/optimize/uring_batch.rs` now exposes `BatchSendDisposition` (`Sent`, `Failed`, `NotSubmitted`, `Quarantined`) and `BatchSendResult` through detailed connected and unconnected sender/worker APIs. Legacy count methods delegate to the detailed contract.
- Standard SendMsg and SendMsgZc completion maps preserve out-of-order successes instead of returning a contiguous prefix. Submission, CQ overflow, completion mismatch, cancellation, timeout, and dropped-response boundaries retain full-width fail-closed disposition. The synchronous server compatibility helper also has a detailed disposition surface.
- `src/implementations/client/io_driver.rs` and `src/implementations/server/parts/live_auth.rs` build fallback subsets from unsent slot indices. sendmmsg prefixes are relative to that subset, and individual socket sends skip slots already accepted by io_uring. Telemetry increments use actual per-slot ownership.
- Deterministic coverage proves `[Sent, Failed, Sent]` remains exact and quarantined slots are never retryable. ARM64 macOS passes all-feature check, strict all-feature library/bin Clippy, format, diff hygiene, and the all-feature library suite `2,701/2,701`; no frontend file changed.
- The installed `x86_64-unknown-linux-gnu` target remains unavailable for source compilation because this macOS host has no GNU/Linux C sysroot. Clang reaches `ring` and `zstd-sys` but fails on missing `assert.h`, `string.h`, `stdio.h`, and `stdlib.h`; Linux kernel duplicate-delivery proof remains an external gate.

## Server Firewall Ownership and Routing Teardown (2026-08-08, TODO-607/TODO-802)

- Linux server routing supports one QuicFuscate firewall owner per network namespace. The fixed iptables identities (`QUICFUSCATE_RT`, `QUICFUSCATE_NAT`, including the dual-stack `ip6tables` families) and the fixed nftables identity (`inet quicfuscate_rt`) are reserved through the mode-0600 create-only `/run/quicfuscate/routing/firewall-owner.json` record. The owner record is bound to the schema-3 per-TUN routing record, selected backend, complete routing/firewall configuration, boot ID, PID, process start time, and a TUN-specific generation.
- Setup claims the global owner before host/firewall mutation, rejects any other durable TUN record, live or stale owner record, and any pre-existing fixed iptables chain/jump or nftables table. Fixed firewall resources are never replaced blindly. iptables cleanup requires exactly one parent jump and the complete expected owned-chain rule sequence; nftables cleanup requires the owner table marker, required fragments, per-rule JSON owner comments, and the exact expected rule count.
- Graceful teardown authenticates the current owner before mutation and uses a current-owner host-state recovery path; startup stale recovery retains the active-owner refusal. Any absent, externally changed, or generation-mismatched firewall resource leaves the durable records in place and fails closed. Legacy per-TUN rule cleanup is limited to a validated durable owner.
- Deterministic routing regressions cover generation binding, cross-TUN/live/stale/resource collision decisions, owner-shape tampering, nftables replacement refusal, owner markers, and expected rule shape. Privileged Linux iptables/nftables collision, process-loss, and zero-residue evidence remains unavailable on the ARM64 macOS host and is not inferred.
- Evidence: ARM64 macOS passes `cargo test --features rust-tests --lib` (`2,663/2,663`), all-feature `cargo test --all-features --lib` (`2,705/2,705`), and routing focus (`26/26`). `cargo check --all-features`, strict all-feature library/bin Clippy with panic/unwrap/expect denied, formatting, and diff hygiene pass. The installed `x86_64-unknown-linux-gnu` target reaches `ring` but stops because this host has no GNU/Linux sysroot (`assert.h`); privileged Linux iptables/nftables collision, process-loss, zero-residue, and Linux source-compile evidence remain unavailable and are not inferred.

## Managed macOS PF Anchor Installer and Proof Boundary (2026-08-08, TODO-548)

- `scripts/install/install-macos-pf-anchor.sh` -> exact marked main-ruleset reference -> atomic `/etc/pf.conf` update -> `pfctl -f` reload -> active-reference postcondition -> mode-0600 state/backup publication. Remove reverses the same owner transaction and refuses any modified, foreign, symlinked, or incomplete resource.
- `--root PATH` skips `pfctl` and maps the production paths into a hermetic fixture. `scripts/tests/fast/test-macos-pf-anchor-installer.sh` proves idempotence, unrelated-rule preservation, marker/state tamper refusal, foreign exact/wildcard-anchor refusal, lock exclusion, cleanup, and symlink rejection. `MACOS_PF_ANCHOR` is the runtime source constant for the same fixed identity.
- The read-only privileged proof remains `scripts/tests/macos-pf-anchor-proof.sh`; native packet/coexistence/crash-retention/stale-cleanup/uninstall evidence is unavailable on the current ARM64 macOS host and is not inferred. Frontend files and UI fields remain outside this backend slice.

## Workspace Seam Contract (2026-08-08, TODO-880)

- `scripts/audits/audit-workspace-seams.py` records the current Rust package, target, feature, source-size, top-level import-edge, SCC, and protected-path state without compiling product code. It includes tracked and untracked Git paths in the protected frontend/Tauri check and refuses to overwrite an existing JSON report.
- Live evidence at `a485a898bc6e5a93a8d26d91bc2a66efb9e72db0`: one workspace member, `quicfuscate` v0.4.4, 50 dependencies (48 normal and 2 dev), 29 features, 95 targets, 234 Rust files, 203,361 lines, 159 cross-module edges, and one 16-module SCC. The report is `scripts/out/audits/workspace-seams-20260808T211032/workspace-seams.json`; protected changes are empty.
- TODO-881 owns the first `qf-common` leaf extraction for `env_utils`, `time_source`, `rng`, and `secret`. TODO-562 remains the owner of higher-order cycle contracts until each measured boundary receives its own independently buildable child task. No frontend or Tauri path is part of this migration.

## Common Workspace Contract Crate (2026-08-08, TODO-881)

- `crates/qf-common/` now owns the four leaf contracts: environment snapshots, protocol time, secure randomness, and zeroizing secret wrappers. Its manifest has exactly three leaf dependencies (`getrandom`, `log`, `zeroize`) and no transport, crypto, FEC, stealth, UI, or Tauri dependency.
- The root package depends on `qf-common` through one normal Cargo edge. `src/env_utils.rs`, `src/time_source.rs`, `src/rng.rs`, and `src/secret.rs` remain explicit compatibility surfaces: production and root test builds re-export the common crate, while qf-common's `rust-tests` feature gates deterministic entropy-failure and erasure-observer hooks. Secret owners and observers remain root-private; no root `#[path]` duplicate implementation remains.
- The workspace-aware seam audit now inventories root and `crates/*/src` sources and emits package summaries plus workspace dependency edges. The resulting inventory is two workspace packages (`quicfuscate` and `qf-common`), root 51 dependencies (49 normal and 2 dev), qf-common 3 dependencies, 29 root features, 95 root targets, 239 Rust files, 203,446 source lines, 159 product-module edges, and the unchanged 16-module product SCC. The only workspace edge is `quicfuscate -> qf-common`; no reverse edge exists and protected frontend/Tauri changes are empty.
- Proof: `cargo check -p qf-common --all-targets --locked`, qf-common strict Clippy, qf-common tests `28/28`, root default library tests `2,663/2,663`, root `rust-tests` library tests `2,663/2,663`, root default and `rust-tests` library Clippy with `-D warnings`, root library check, `cargo fmt --all -- --check`, and the protected-path audit pass. No frontend field or UI projection was required or changed; any later projection remains a separate frontend task.

## Control-plane Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-control-plane/` is the second independently buildable leaf boundary. It owns the bounded assignment codec, address-family validation, authenticated reconnect-generation receiver, duplicate/conflict handling, and typed failure surface with no external dependencies.
- `src/lib.rs` preserves `quicfuscate::control_plane` as a direct compatibility re-export. Existing client, server, and runtime callers therefore retain their source paths while Cargo enforces the one-way edge `quicfuscate -> qf-control-plane`.
- The extracted crate does not touch any Svelte, Tauri, package, asset, or generated frontend path. Any future UI projection remains a separate frontend task.
- Workspace check, strict all-target Clippy with `rust-tests`, formatting, and the complete all-target `rust-tests` suite pass after correcting two protocol-invalid integration assertions: CRYPTO is exercised in Initial packets, and the first client request correctly accepts stream ID `0`.

## Error Contract Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-error/` owns the std-only `ConnectionError` contract, including display, `std::error::Error`, and string conversions. The root `quicfuscate::error` module re-exports it without changing existing caller paths.
- Root-only adapters convert `crypto::aead::KeyMaterialError` and `transport::h3::Error` into the shared error type. The child has no product dependency; the only workspace edge is `quicfuscate -> qf-error` and no reverse edge exists.
- The refreshed workspace audit reports `quicfuscate`, `qf-common`, `qf-control-plane`, and `qf-error`, with 240 Rust files, 203,474 source lines, the same 16-module product SCC, and an empty protected frontend/Tauri change set.
- Workspace all-target check, strict all-target Clippy with `rust-tests`, formatting, and the full all-target `rust-tests` suite pass with 28 `qf-common`, 8 `qf-control-plane`, 2 `qf-error`, and 2,655 root library tests plus green integration targets. Frontend field projection remains deferred.

## Instrumentation Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-instrumentation/` owns the std-only global metrics registry and health/Prometheus exporters. The root `quicfuscate::instrumentation` path remains a compatibility re-export, so engine, client, and server producers keep their existing API paths.
- The extracted leaf has no product dependency and carries its five unit tests. Cargo enforces the one-way edge `quicfuscate -> qf-instrumentation`; no reverse edge or frontend/Tauri path is involved.
- The latest seam report contains five workspace packages, 240 Rust files, 203,476 source lines, and the same 16-module product SCC. The complete root-to-leaf edge set is `quicfuscate -> qf-common`, `qf-control-plane`, `qf-error`, and `qf-instrumentation`.
- Workspace all-target check, strict all-target Clippy with `rust-tests`, formatting, and the full all-target `rust-tests` suite pass with 28 `qf-common`, 8 `qf-control-plane`, 2 `qf-error`, 5 `qf-instrumentation`, and 2,650 root library tests plus green integration targets. Frontend field projection remains deferred.

## Privilege Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-privilege/` owns privilege inspection, account resolution, capability validation, irreversible post-bind dropping, per-thread verification, and the Linux root-regain proof. The root `quicfuscate::privilege` path remains a direct compatibility re-export.
- The extracted crate has only its libc/serde platform dependencies and keeps all 23 existing unit tests. Cargo enforces `quicfuscate -> qf-privilege` with no reverse edge; frontend and Tauri paths remain outside the boundary.
- The latest seam report contains six workspace packages, 240 Rust files, 203,478 source lines, the same 16-module product SCC, and an empty protected frontend/Tauri change set. The root-to-leaf edge set is `qf-common`, `qf-control-plane`, `qf-error`, `qf-instrumentation`, and `qf-privilege`.
- Workspace all-target check, strict all-target Clippy with `rust-tests`, formatting, and the full all-target `rust-tests` suite pass with 28 `qf-common`, 8 `qf-control-plane`, 2 `qf-error`, 5 `qf-instrumentation`, 23 `qf-privilege`, and 2,627 root library tests plus green integration targets. Frontend field projection remains deferred.

## Omega Proof Ownership Preflight (2026-08-08, TODO-804)

- `scripts/audits/verify-omega-proof-ownership.py` plus its shell entrypoint perform a read-only SSH preflight. They discover every candidate `QuicFuscate` checkout under the declared remote roots, inspect Git status/diffs/object connectivity, bind source/bundle/binary/runtime/evidence provenance, and refuse to overwrite a local JSON report.
- The preflight has no remote write, process-control, checkout-reset, or cleanup operation. Any ambiguous checkout set, dirty state, unreadable Git object/diff, unowned matching runtime, or missing proof binding produces `UNAVAILABLE`, never a green exact proof.
- Live evidence at `scripts/out/audits/omega-proof-ownership-20260808T195315Z/ownership.json` is `UNAVAILABLE`: two remote checkouts exist; SOFTWARE has 43,722 untracked paths; CODE has 20 tracked modifications and missing object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1`; runtime PID `1363976` is not owned by the preflight. No remote state was changed. TODO-804 remains blocked pending explicit ownership/cleanup authorization and a clean immutable proof root.

## PKI Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-pki/` is the sixth independently buildable backend leaf. It owns the former `src/pki/mod.rs` CA hierarchy, certificate validation, safe PEM writers, quarantine flow, and PKI tests; `src/lib.rs` preserves `quicfuscate::pki` through a compatibility re-export.
- The child depends on `qf-common` for canonical wall-clock reads and on its explicit PKI libraries only. Root `server` and `dev-certs` forward the child `rcgen` feature, preserving the public root feature contract. No frontend or Tauri path is in this boundary.
- Post-commit seam evidence at revision `e61c21ea6edeca608ce239d315ef941815f4cc21` in `scripts/out/audits/workspace-seams-20260808T212716Z/workspace-seams.json` records seven packages (root plus six leaves), 240 Rust files, 203,481 source lines, root edges to all six leaves, one `qf-pki -> qf-common` edge, the unchanged 16-module SCC, and no protected changes.
- Independent leaf checks, workspace all-target check, strict all-target Clippy with `rust-tests`, formatting, and the full all-target `rust-tests` matrix pass. The package test counts are `qf-common=28`, `qf-control-plane=8`, `qf-error=2`, `qf-instrumentation=5`, `qf-pki=19`, `qf-privilege=23`, and root `2608`, with all integration targets green. The touched qf-pki dev rebuild is `0.75s` real time.
- The all-feature all-target Clippy lane remains unavailable on this macOS host because `scripts/tests/rust/rt-transport-uring.rs:8` intentionally rejects non-Linux compilation. The release binary gate is locally green: the default release binary builds, `--help` returns the canonical CLI, and its 9,815,328-byte SHA-256 is `002a79251e7469930412e295c17306ced9996b282abb105c122f85ba2a14f61b`. A pre/post SHA-256 manifest over all 149 protected Svelte/Tauri paths is identical. Post-commit Graphify evidence is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T212644Z/graphify-evidence.json`. CI, native Linux/Omega proof, and higher-order SCC decomposition remain TODO-562 gates.

## REALITY Workspace Crate (2026-08-08, TODO-562)

- `crates/qf-reality/` is the seventh independently buildable backend leaf. It owns the former `src/reality.rs` REALITY proxy, target override validation, cover-handshake cache/capture, raw TLS-flight parser, and all 23 existing unit tests; `src/lib.rs` preserves `quicfuscate::reality` through a compatibility re-export.
- The child depends on `qf-common` for the canonical environment and clock contracts plus its explicit Tokio/TLS runtime libraries. Root stealth lifecycle callers use the child snapshot, cleanup, and shutdown APIs; the child has no reverse product edge and no frontend/Tauri boundary.
- Root test and production paths now share qf-common's `EnvSnapshot` and `ProtocolClock` types. Deterministic pair construction, manual time sources, and thread-local test-clock overrides are available only through `rust-tests` feature wiring for test targets, avoiding duplicate root implementations or default production API widening.
- Isolated qf-reality checking and `23/23` tests pass. Workspace default/all-target and `rust-tests` checks plus strict `rust-tests` Clippy pass; the target guard cleaned 13.9 GiB once during the feature matrix. Post-commit seam evidence is `scripts/out/audits/workspace-seams-20260808T235531/workspace-seams.json` at revision `88cbcb67fd916ec6b91ef1f191e947f5b2164546`: eight workspace packages, 240 Rust files, 203,473 source lines, eleven dependency edges, the unchanged 16-module SCC, and `protected_changes=[]`. The full all-target `rust-tests` workspace run completed without failures with qf-common=28, qf-control-plane=8, qf-error=2, qf-instrumentation=5, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,570 tests, plus green integration targets. The release gate is green with canonical `--help`, a 9,832,176-byte binary, SHA-256 `086eb07262347ae0f686eb872831c44428dacec09282512bb299868a100e6bf5`, and an empty protected frontend/Tauri path diff. Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T215553Z/graphify-evidence.json`.

## DNS Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-dns/` is the eighth independently buildable backend leaf. It owns the former `src/dns/mod.rs` parser, wire-preserving response builders, DoH/UDP forwarding, transaction and question binding, aggregate deadlines, and bounded admission policy; `src/lib.rs` preserves `quicfuscate::dns` through a compatibility re-export.
- The child uses qf-common's canonical `ProtocolClock` and feature-gated manual clock helpers, with explicit `log`, `parking_lot`, `reqwest`, `tokio`, and `url` dependencies. Client runtime callers retain their existing root paths and no frontend/Tauri boundary changed.
- Isolated qf-dns checking and `41/41` tests pass. Workspace default/all-target and `rust-tests` checks plus strict `rust-tests` Clippy pass; formatting and diff hygiene are clean. Post-commit seam evidence is `scripts/out/audits/workspace-seams-20260809T001834/workspace-seams.json` at revision `26bc6bb08fa15d63c0b6c408d33382ed51ab447d`: nine workspace packages, 240 Rust files, 203,467 source lines, fourteen dependency edges, the unchanged 16-module SCC, and `protected_changes=[]`. The full all-target `rust-tests` workspace run completed without failures with qf-common=28, qf-control-plane=8, qf-dns=41, qf-error=2, qf-instrumentation=5, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,522 tests, plus green integration targets. The release gate is green with canonical `--help`, a 9,865,392-byte binary, SHA-256 `23bf3bea7b26dc21c6db12b3669a6d9d44c561d3918a7bf3ad9c1efbd459480b`, and an empty protected frontend/Tauri path diff. The all-feature Clippy lane is blocked only by the existing Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8`; Graphify is fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T221834Z/graphify-evidence.json`.

## Firewall Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-firewall/` owns the backend selection implementation and the root-independent serde/default `FirewallConfig` contract alongside iptables/nftables command operations, platform-specific cleanup, owned-resource inspection, and the existing firewall regression tests. Root `quicfuscate::firewall` and `engine::FirewallConfig` remain compatibility reexports, preserving internal `crate::firewall` caller paths.
- The current configuration-owner verification passes `29/29` qf-firewall tests, root all-target checking, strict root Clippy, and root `EngineConfig` tests `39/39`. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-firewall-config/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,341 source lines, 128 product-module edges, 94 Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`. No frontend field/API projection is required.
- The child has a narrow dependency boundary (`log`, `serde`, and `serde_json` for Linux nftables ownership inspection) and no dependency on frontend, Tauri, transport, crypto, or implementation modules. Isolated all-target/all-feature checking, strict qf-firewall Clippy, workspace default/all-target and all-feature checks, and workspace `rust-tests` Clippy pass. The serial all-target `rust-tests` workspace run is green with qf-common=28, qf-control-plane=8, qf-dns=41, qf-error=2, qf-firewall=28, qf-instrumentation=5, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,494 tests, plus green registered integration targets. The all-feature all-target Clippy lane remains platform-blocked only by the existing Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8`; neither guard was weakened. The release gate is green: `cargo build --release --bin quicfuscate --locked --offline` succeeded, canonical `--help` returned, the binary is 9,865,472 bytes, and SHA-256 is `921f2764de6714e4cfbb41651896b35805a45d7ac929cf765016b528e243417d`. Post-documentation-commit seam evidence is `scripts/out/audits/workspace-seams-20260808T224804/workspace-seams.json` at revision `2c318c43eca2b6646275c39432acf7879fbc5bd4`: ten workspace packages, 240 Rust files, 203,558 source lines, 155 product-module edges, the unchanged 16-module product SCC, fifteen Cargo workspace dependency edges including `quicfuscate -> qf-firewall`, and `protected_changes=[]`. The protected frontend/Tauri path diff is empty. Graphify remains fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T224826Z/graphify-evidence.json` with exit 2; no semantic extraction or relationship proof is inferred.

## Audit Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-audit/` owns the former `src/audit/mod.rs` implementation and the root-independent serde/TOML `AuditConfig` projection: bounded hash-chained NDJSON persistence, rotation and checkpoint recovery, tamper verification, concurrent producer admission, durability watchdogs, and fail-closed Unix/Windows file hardening. The root `quicfuscate::audit` module is a compatibility re-export, while `engine::AuditConfig` is a compatibility re-export and maps child validation errors into the historical engine error surface.
- The child has one product dependency on `qf-common::time_source` and explicit `crossbeam-channel`, `libc`, `log`, `serde`, `serde_json`, and Windows `windows-sys` dependencies. It has no dependency on transport, crypto, implementations, frontend, or Tauri; Cargo records `qf-audit -> qf-common` and `quicfuscate -> qf-audit`. Isolated qf-audit checking, `41/41` historical tests, and strict all-target Clippy pass; root `quicfuscate` compatibility tests pass `2,453/2,453`, workspace all-target checking and `rust-tests` Clippy pass, formatting is clean, and the protected frontend/Tauri path diff is empty.
- Post-code-commit seam evidence is `scripts/out/audits/workspace-seams-20260808T225943/workspace-seams.json` at revision `74d4a7afb079312094ada4c09175a705ae5edb52`: eleven workspace packages, 240 Rust files, 203,587 source lines, 154 product-module edges, the unchanged 16-module product SCC, seventeen Cargo workspace dependency edges including `qf-audit -> qf-common` and `quicfuscate -> qf-audit`, and `protected_changes=[]`. The serial all-target `rust-tests` workspace run is green with qf-audit=41, qf-common=28, qf-control-plane=8, qf-dns=41, qf-error=2, qf-firewall=28, qf-instrumentation=5, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,453 tests, plus green registered integration, binary, and example targets. The release gate is green: `cargo build --release --bin quicfuscate --locked --offline` succeeded, canonical `--help` returned, the binary is 9,915,456 bytes, and SHA-256 is `e84e06d257ae768c3770c58f8644505f1d55187740988459ed1215267854e404`. The all-feature all-target Clippy lane remains platform-blocked only by the existing Linux guard at `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. Graphify remains fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T225944Z/graphify-evidence.json` with exit 2; no semantic extraction or relationship proof is inferred. The target stayed below the 12-GiB cleanup threshold during this cycle.
- The current configuration-owner verification adds `AuditConfig` coverage to qf-audit (`42/42` tests), root `EngineConfig` tests remain `39/39`, root all-target checking and strict root Clippy pass, and the child preserves the exact millisecond wire shape and shared option bounds. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-audit-config/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,397 source lines, 129 product-module edges, 94 Cargo workspace dependency edges, the unchanged 9-module product SCC, `qf-audit -> qf-common`, `quicfuscate -> qf-audit`, and `protected_changes=[]`. No frontend field/API projection is required.

## Logging Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-logging/` owns the former `src/logging.rs` implementation and the complete root-independent serde/default/validation `LoggingConfig`, `LoggingMode`, and `LogFormat` contracts: bounded producer admission, structured text/JSON output, rotating/reopenable private file sinks, RFC 5424 syslog, flush barriers, and worker statistics. The root `quicfuscate::logging` module keeps the historical generic projection trait as a compatibility adapter that clones the child-owned config; `engine::LoggingConfig`, `engine::LoggingMode`, and `engine::LogFormat` are compatibility reexports. `AdminLogBuffer` implements the child `LogSink` in the server runtime, so the child has no reverse dependency on implementations.
- The child depends on `qf-common::time_source`, `crossbeam-channel`, `log` with its explicit `std` feature, `serde`, and `serde_json`; Unix test hardening uses a target-only `libc` dev dependency. It has no dependency on transport, crypto, implementations, frontend, or Tauri. Cargo records `qf-logging -> qf-common` and `quicfuscate -> qf-logging`; the protected frontend/Tauri path diff is empty.
- Isolated qf-logging checking, `20/20` tests, and strict all-target Clippy pass. The serial all-target `rust-tests` workspace run is green with qf-audit=41, qf-common=28, qf-control-plane=8, qf-dns=41, qf-error=2, qf-firewall=28, qf-instrumentation=5, qf-logging=20, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,433 tests, plus green registered integration, binary, and example targets. Workspace all-target checking and workspace `rust-tests` Clippy pass.
- The release gate is green: `cargo build --release --bin quicfuscate --locked --offline` succeeded, canonical `--help` returned, the binary is 9,932,512 bytes, and SHA-256 is `0c321b42971d41c358af586a07a60df6293cb2e15d00dec3ab0ef33a99d249e8`. The all-feature all-target Clippy lane remains platform-blocked only by the existing Linux guards at `scripts/tests/rust/rt-transport-uring.rs:8` and `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`; neither guard was weakened. The target was proactively cleaned at 11,782,076 KiB before release, removing 12.8 GiB; the release cycle ended at 493,588 KiB.
- Post-code-commit seam evidence is `scripts/out/audits/workspace-seams-20260808T233130/workspace-seams.json` at revision `634e1e34aac32329633795510d73dd40d88a98aa`: twelve workspace packages, 241 Rust files, 203,743 source lines, 152 product-module edges, the unchanged 16-module product SCC, nineteen Cargo workspace dependency edges including `qf-logging -> qf-common` and `quicfuscate -> qf-logging`, and `protected_changes=[]`. Graphify remains fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260808T233131Z/graphify-evidence.json`; no semantic extraction or relationship proof is inferred.
- The current configuration-owner verification passes `22/22` qf-logging tests, root `EngineConfig` tests `39/39`, root all-target checking, and strict root Clippy. Seam evidence is `scripts/out/audits/workspace-seams-20260809T-logging-config-full/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,331 source lines, 128 product-module edges, 94 Cargo workspace dependency edges, the 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`), `qf-logging -> qf-common`, `quicfuscate -> qf-logging`, and `protected_changes=[]`.

## Metrics Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-metrics/` owns the former `src/metrics.rs` telemetry HTTP server: bounded request reads, `/telemetry` classification, plain-text exporter responses, 404 handling, socket shutdown, and a 32-connection admission semaphore. The root `quicfuscate::metrics` module remains a compatibility wrapper with the original no-argument API and injects `crate::telemetry::export_telemetry_text` into the child, so qf-metrics has no reverse dependency on root telemetry.
- The child depends on `qf-common` for the captured environment snapshot, `tokio` for the bounded TCP server, and `log`; its test target uses qf-common's `rust-tests` environment lock. Cargo records normal and dev `qf-metrics -> qf-common` edges plus `quicfuscate -> qf-metrics`. No transport, crypto, implementation, frontend, or Tauri dependency crosses the boundary.
- Isolated qf-metrics all-target/all-feature check, `4/4` tests, and strict Clippy pass. Workspace all-target check and strict `rust-tests` Clippy pass. The complete serial all-target `rust-tests` workspace suite is green with 96 result blocks and package counts qf-audit=41, qf-common=28, qf-control-plane=8, qf-dns=41, qf-error=2, qf-firewall=28, qf-instrumentation=5, qf-logging=20, qf-metrics=4, qf-pki=19, qf-privilege=23, qf-reality=23, and root=2,429; the dedicated `/telemetry` HTTP integration target is `1/1` green. Formatting, diff hygiene, and the protected frontend/Tauri path check are clean.
- The release gate is green: `cargo build --release --bin quicfuscate --locked --offline` succeeded, canonical `--help` returned, the binary is 9,949,040 bytes, and SHA-256 is `b83aa18d6a856cbd6ca6a491ffc833ac32c52147e6ef35b804dd189a4ae575b8`. The all-feature all-target Clippy lane remains platform-blocked only by the existing Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. Post-code-commit seam evidence is `scripts/out/audits/workspace-seams-20260808T235059Z/workspace-seams.json` at revision `4d98426e2d81cd01217c8e50c56e38c7aef70e88`, recording thirteen workspace packages, 242 Rust files, 203,750 source lines, 151 product-module edges, 22 Cargo dependency edges, the unchanged 16-module product SCC, and `protected_changes=[]`. Graphify is fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260808T235107Z/graphify-evidence.json`; no semantic extraction or relationship proof is inferred. The target ended at 5,863,848 KiB, below the 12-GiB cleanup threshold.

## Harness Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-harness/` owns the former `src/harness.rs` developer CLI and benchmark orchestration for QPACK and UDP throughput. The root `quicfuscate::harness` module re-exports `Cli`, `Command`, and the backend contracts while preserving `run_cli`, `run_from_args`, and `run_from_env`; no root caller or registered harness target changes its API.
- The child depends only on `clap`. Its `QpackEncoder`, `UdpSender`, and `UdpSenderFactory` contracts invert the two root-owned production backends: the root adapter supplies SIMD QPACK dispatch and `transport::udpfast::UdpFastPath`. Cargo records the one-way edge `quicfuscate -> qf-harness`; no transport, crypto, implementation, frontend, or Tauri dependency crosses into the child.
- Isolated qf-harness all-target/all-feature checking and strict Clippy pass. The real root harness integrations are green (`rt-harness-cli=1/1`, `rt-harness-udpfast=1/1`), workspace all-target checking and strict `rust-tests` Clippy pass, and the complete serial all-target `rust-tests` workspace suite is green with 97 result blocks and root `2429/2429`; all other registered package, binary, example, and integration targets are green. Formatting, diff hygiene, and the protected frontend/Tauri path check are clean.
- The release gate is green: canonical `--help` returned, the binary is 9,949,232 bytes, and SHA-256 is `8cd9d37e8df25edb983af7874817b806bea1133cd1ebe7fb236e7615746c8ef3`. The all-feature all-target Clippy lane remains platform-blocked by the existing Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8`; the current run stopped at the first guard and neither was weakened. Post-code-commit seam evidence is `scripts/out/audits/workspace-seams-20260809T000524Z/workspace-seams.json` at revision `04d0b964d7befd586a4c2c77c422d2cbfc894cc8`: fourteen workspace packages, 243 Rust files, 203,783 source lines, 151 product-module edges, 23 Cargo dependency edges, the unchanged 16-module product SCC, and `protected_changes=[]`. Graphify remains fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260809T000529Z/graphify-evidence.json`; no semantic extraction or relationship proof is inferred. The target ended at 9,195,100 KiB, below the 12-GiB cleanup threshold.

## Compatibility Seam Reconciliation (2026-08-09, TODO-562)

- `src/logging.rs` now exposes a generic `LoggingConfigProjection` contract. The engine implements the projection in `src/engine/config.rs`, so the root logging compatibility namespace no longer imports `engine`; existing `quicfuscate::logging::init(&engine.logging)` callers and logging behavior remain unchanged.
- `src/accelerate.rs` remains the public compatibility namespace for test and tooling consumers, while runtime owners import `crate::optimize` directly for brain, compression, FEC, stealth, transport, and core acceleration. No implementation is duplicated or moved; the compatibility module is now outside the product cycle.
- Post-code seam evidence is `scripts/out/audits/workspace-seams-20260809T002504Z/workspace-seams.json` at revision `99643a084a6167e510ba7f3a902576950a22cfa0`: fourteen workspace packages, 243 Rust files, 203,784 source lines, 145 product-module edges, 23 Cargo dependency edges, and a 14-module product SCC (`brain`, `compress`, `core`, `crypto`, `engine`, `fec`, `implementations`, `interface`, `memory_lock`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). `accelerate -> optimize` is one-way, `engine -> logging` and `implementations -> logging` are non-cyclic, and `protected_changes=[]`.
- Workspace all-target checking, strict `rust-tests` Clippy, and the complete serial all-target `rust-tests` suite pass with exit status 0, 97 result blocks, no failures, and root `2429/2429`; formatting and diff hygiene pass. The release gate is green: canonical `--help` returned, the binary is 9,949,312 bytes, and SHA-256 is `ef9a6d84072683643a97eb6f8b57b0815c7bc9a8311eff1149019a7a69adc4bb`. All-feature all-target Clippy remains blocked only by the existing macOS-incompatible guard at `scripts/tests/rust/rt-transport-uring.rs:8`. Graphify is fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260809T002535Z/graphify-evidence.json`; no semantic relationship proof is inferred.

## Common Compatibility Hook Reconciliation (2026-08-09, TODO-562)

- `src/rng.rs` and `src/secret.rs` now re-export qf-common for both production and root test builds. qf-common's `rust-tests` feature owns deterministic entropy-failure injection and erasure observation, removing the former root `#[path]` duplicate implementations without widening the default production API.
- qf-common's canonical tests remain green at `28/28`; the root library remains green at `2423/2423`, with six duplicate root copies no longer compiled because their canonical child tests already execute. The complete workspace all-target run is green with `97` result blocks and no failure markers. Workspace check, strict `rust-tests` Clippy, formatting, and diff hygiene pass.
- Working-tree seam evidence is `scripts/out/audits/workspace-seams-20260809T025044/workspace-seams.json` (base revision `d69e10446c92be684346387d613c28340f18b25f` plus the four compatibility-hook source edits): fourteen workspace packages, 243 Rust files, 203,765 source lines, 145 product-module edges, the same 14-module product SCC, and `protected_changes=[]`.
- The remaining backend seam audit finds no additional safe leaf: `profile.rs` is a one-way compatibility alias over `simd::CryptoAeadPlan`, so a separate crate would add a wrapper without removing a product-cycle node; the other non-SCC contracts are already extracted or canonicalized. The 14-module SCC remains the next decomposition boundary and requires a coordinated cycle-breaking design.
- The release gate is green: `target/release/quicfuscate --help` returned the canonical CLI, the binary is 9,949,312 bytes, and SHA-256 is `ef9a6d84072683643a97eb6f8b57b0815c7bc9a8311eff1149019a7a69adc4bb`. The target was cleaned at 12,004,968 KiB before the release rebuild and ended at 494,116 KiB. All-feature all-target Clippy remains platform-blocked by the existing macOS-incompatible Linux guard at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`.
- Latest Graphify evidence is fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260809T005700Z/graphify-evidence.json`; semantic extraction, complete language coverage, and relationship proof remain unavailable.

## Memory-Lock Workspace Crate Reconciliation (2026-08-09, TODO-562)

- `crates/qf-memory-lock/` now owns the former `src/memory_lock.rs` implementation: `MemoryLockFailurePolicy`, process-lock status and error contracts, `mlockall` limit classification, startup policy application, pooled-block lock state, and future-allocation coverage state. The root `src/memory_lock.rs` is a compatibility adapter that maps `SecurityConfig` into the child policy; engine and server implementation callers use the child directly, while qftls and `MemoryPool` compatibility setters delegate to the same child-owned flags.
- The post-code seam report is `scripts/out/audits/workspace-seams-20260809T011935Z/workspace-seams.json` at base revision `d69e10446c92be684346387d613c28340f18b25f`: fifteen workspace packages, 244 Rust files, 203,881 source lines, 141 product-module edges, 24 Cargo workspace dependency edges, and a 13-module product SCC (`brain`, `compress`, `core`, `crypto`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). `qf-memory-lock` has only the one-way edge `quicfuscate -> qf-memory-lock`; `protected_changes=[]`.
- Isolated qf-memory-lock tests pass `11/11`; the root library passes `2,413/2,413`; the complete serial workspace all-target `rust-tests` run passes 98 result blocks with 2,999 passed, 0 failed, and 6 ignored. Workspace all-target checking, strict `rust-tests` Clippy, formatting, and diff hygiene pass. The release gate passes: `target/release/quicfuscate --help` returned, the binary is 9,949,296 bytes, and SHA-256 is `b2dbf04613e5ccb666e41a65b1442e91f54dfd402842ecc76be4af419ed18fa0`.
- Each extracted backend leaf now has an independent all-target/all-feature check and strict all-target/all-feature Clippy pass: `qf-audit`, `qf-common`, `qf-control-plane`, `qf-dns`, `qf-error`, `qf-firewall`, `qf-harness`, `qf-instrumentation`, `qf-logging`, `qf-memory-lock`, `qf-metrics`, `qf-pki`, `qf-privilege`, and `qf-reality`. Touching `crates/qf-memory-lock/src/lib.rs` and rebuilding that crate completed in `0.85s` real time on this Apple Silicon host.
- All-feature all-target Clippy remains platform-blocked by the existing Linux-only compile guard at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`; no platform guard was weakened. Latest Graphify evidence is fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260809T011953Z/graphify-evidence.json`; semantic extraction and complete relationship proof remain unavailable.
## Telemetry Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-telemetry/` owns the former `src/optimize/telemetry.rs` implementation and the root-independent serde/default `TelemetryConfig` contract: counters, gauges, plain-text export, CPU-profile mask publication, memory-usage refresh, and the existing telemetry tests. Root `engine::TelemetryConfig`, `quicfuscate::telemetry`, and `quicfuscate::optimize::telemetry` remain compatibility paths.
- The child depends only on `sysinfo`. `CpuProfileId` is the narrow child contract; the optimize adapter maps the existing `CpuProfile`. Pool refresh is an owner-installed callback, so the child has no reverse optimizer dependency and preserves the no-side-effect metrics observation behavior.
- The current configuration-owner verification adds serde/default `TelemetryConfig` coverage to qf-telemetry: `16/16` child tests, root `EngineConfig` tests `39/39`, root all-target checking, and strict root Clippy pass while preserving the exact engine schema and validation error. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-telemetry-config/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,413 source lines, 129 product-module edges, 94 Cargo workspace dependency edges, the unchanged 9-module product SCC, `qf-telemetry` inbound leaf edges only, and `protected_changes=[]`. No frontend field/API projection is required.
- Isolated qf-telemetry all-target/all-feature checking, `15/15` tests, and strict Clippy pass. Root library compatibility tests pass `2,398/2,398`. The complete serial workspace all-target `rust-tests` run passes 99 result blocks with 2,999 passed, 0 failed, and 6 ignored; workspace all-target checking and strict `rust-tests` Clippy pass. The release gate is green: canonical `--help` returned, the binary is 9,949,296 bytes, and SHA-256 is `62b12fb50dc3aefd2bdb75c823f339e6e388d098ac20b3af886f3d002b6a0970`. Full all-feature/all-target Clippy is platform-blocked by the existing Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. The post-code seam report is `scripts/out/audits/workspace-seams-20260809T015627Z/workspace-seams.json` with sixteen workspace packages, 245 Rust files, 203,986 source lines, 141 product-module edges, 25 Cargo workspace dependency edges, the unchanged 13-module product SCC, `quicfuscate -> qf-telemetry`, and `protected_changes=[]`. Graphify remains fail-closed `BLOCKED` with exit 2 at `scripts/out/audits/graphify-20260809T015552Z/graphify-evidence.json`; no semantic relationship proof is inferred. The target ended at 6,710,076 KiB, below the 12-GiB cleanup threshold. The protected frontend/Tauri path diff is empty.

## Crypto Workspace Crate Reconciliation (2026-08-09, TODO-562)

- `crates/qf-crypto/` owns the former `src/crypto/` implementation: AEGIS, MORUS, AES, ChaCha20, AES-GCM, Poly1305, HKDF, QUIC key derivation, header protection, data-plane AEAD selection, and the root-independent `DataAeadPreference` plus `CryptoConfig` serde/default/validation contracts. The root `src/crypto/mod.rs` remains a compatibility adapter; transport-facing header protection and packet AEAD contracts are owned by qf-crypto, while `engine::AeadPreference` and `engine::CryptoConfig` are compatibility reexports and the root `DataAeadConfig` trait is only the runtime adapter.
- qf-crypto depends only on `qf-common`, `qf-cpu`, `qf-error`, and `qf-telemetry` among workspace crates. Root feature forwarding covers `rust-tests`, `benches`, `std`, `prefetch`, `aggressive_inline`, and `internal_avx10_preview`. No frontend or Tauri path changed, and this backend cut requires no frontend field/API addition.
- Isolated qf-crypto tests pass `136/136`; strict all-target/all-feature Clippy and root all-target compatibility checking pass. The complete serial workspace all-target `rust-tests` run previously passed 102 result blocks with `3,005` passed, `0` failed, and `6` ignored; qf-crypto contributed `135/135` before the configuration-owner test was added. Formatting and workspace `rust-tests` Clippy pass for the current code.
- The CI Clippy matrix invokes `cargo clippy --workspace --all-targets` for every covered feature combination, so extracted leaves are linted with the root package.
- Warning-free release verification with `RUSTFLAGS=-Dwarnings` passes: canonical `--help` returned, the binary is `9,966,912` bytes, and SHA-256 is `b833e97790379c46eaffa531e771dacce8850a5859fd77aa6ba6a9063aa49857`. The target ended at `8,359,384 KiB`, below the `12,582,912 KiB` cleanup threshold.
- Current seam evidence is `scripts/out/audits/workspace-seams-20260809T062828Z/workspace-seams.json`: nineteen workspace packages, 247 Rust files, 204,125 source lines, 136 product-module edges, 35 Cargo workspace dependency edges, and a 12-module product SCC (`brain`, `compress`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). The root `crypto` adapter has only one-way incoming compatibility edges and `protected_changes=[]`. This is the first measured cycle reduction after the qf-crypto extraction.
- The current crypto configuration-owner seam is independently verified by `scripts/out/audits/workspace-seams-20260809T-crypto-config/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,427 source lines, 129 product-module edges, 94 Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`); `protected_changes=[]`. Isolated qf-crypto tests pass `136/136`, root `EngineConfig` tests pass `39/39`, root all-target checking and strict Clippy pass, and no frontend field/API addition is required.
- Full all-feature/all-target Clippy remains platform-blocked by the existing macOS-incompatible Linux guards, currently stopping at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and also covering `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. The latest Graphify evidence remains fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260809T015552Z/graphify-evidence.json`; no semantic relationship proof is inferred.

## CPU Workspace Crate Reconciliation (2026-08-09, TODO-562)

- `crates/qf-cpu/` owns the former `src/optimize/parts/cpu_dispatch.rs` implementation, the former `src/simd/planner.rs` module, the former compression SIMD helpers from `src/optimize/compress.rs` and `src/optimize/simd/compress.rs`, the former `src/optimize/iter.rs` and `src/optimize/sort.rs` implementations, and the runtime substring-search implementation formerly in `src/optimize/string.rs`: CPU feature detection, cache hierarchy, prefetch policy, SIMD dispatch contracts, FEC bitslice dispatch, AEAD planning, byte classification, histograms, pattern search, f32/u32/u64 iterator reductions, sorting, argsort, and accelerated `string_contains`. Root `optimize` and `simd` paths retain compatibility imports while test/rust-tests-gated Base64 helpers remain root-owned.
- The child depends only on `qf-common` for environment snapshots, `qf-telemetry` for selection counters, `libc`, and `log`. Root feature selectors forward `prefetch`, `aggressive_inline`, `internal_avx10_preview`, and `rust-tests` to the child; the obsolete root `cpufeatures` direct dependency was removed. No frontend or Tauri path changed.
- The sort slice is now included in qf-cpu. Isolated combined-leaf verification passes `58/58` all-target/all-feature tests with strict all-target/all-feature Clippy. Root all-target checking, root strict `rust-tests` Clippy, the complete workspace all-target `rust-tests` suite (`3,005` passed, `0` failed, `6` ignored), and formatting pass.
- Warning-free release verification with `RUSTFLAGS=-Dwarnings` passes: canonical `--help` returned, the binary is `10,016,880` bytes, and SHA-256 is `1d24166193651e304bfa580fa338ea4dde8889c834f8721ca95094dbf79ba87b`. The target ended at `10,831,616 KiB`, below the `12,582,912 KiB` cleanup threshold; qf-cpu still has only `qf-cpu -> qf-common` and `qf-cpu -> qf-telemetry` workspace edges.
- The qf-cpu extraction removes direct crypto-to-optimize coupling and preserves the root `crate::optimize`/`crate::simd` compatibility surface; runtime guardrails resolve qf-cpu, qf-crypto, qf-privilege, qf-memory-lock, and qf-instrumentation owners directly. The current guardrail audit is clean apart from the existing fail-closed AMX native proof blocker at `scripts/out/audits/runtime-guardrails-20260809T090900Z/results.json`; no guard was weakened. Full all-feature/all-target Clippy remains platform-blocked by the existing Linux-only guards, stopping at `scripts/tests/rust/rt-transport-uring.rs:8` in this run and also covering `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`, while the all-feature library/binary Clippy lane passes. Graphify remains fail-closed `BLOCKED` at `scripts/out/audits/graphify-20260809T015552Z/graphify-evidence.json`; semantic extraction and complete relationship proof remain unavailable. Current seam evidence is `scripts/out/audits/workspace-seams-20260809T082400Z/workspace-seams.json`: twenty-one workspace packages, 253 Rust files, 204,103 source lines, 134 product-module edges, 45 Cargo workspace dependency edges, and the unchanged 11-module product SCC; `protected_changes=[]`. No frontend or Tauri path changed.
## Transport Types Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-types/` is the dependency-free transport contract leaf. It owns `ConnectionId`, `RecvInfo`, `SendInfo`, `EcnMark`, `CongestionControlAlgorithm`, `Frame`, `EcnCounts`, `Stats`, `PathStats`, and `MAX_CONN_ID_LEN`; root `quicfuscate::transport` re-exports them unchanged. Isolated `6/6` tests, strict all-target/all-feature Clippy, root compatibility checking, and formatting pass. The complete workspace suite passes 102 result blocks with 3,005 passed, 0 failed, and 6 ignored; workspace strict `rust-tests` Clippy is green. The post-cycle-break release gate passes with canonical `--help`, a 9,966,912-byte binary, and SHA-256 `b833e97790379c46eaffa531e771dacce8850a5859fd77aa6ba6a9063aa49857`; the target ended at 8,359,384 KiB, below the 12-GiB cleanup threshold. Current seam evidence is `scripts/out/audits/workspace-seams-20260809T062828Z/workspace-seams.json`: nineteen workspace packages, 247 Rust files, 204,125 source lines, 136 product-module edges, 35 Cargo workspace dependency edges, a 12-module product SCC, `quicfuscate -> qf-transport-types`, and `protected_changes=[]`. This prepares the next transport/FEC cycle break and does not claim cyclic transport implementation extraction; no frontend field/API addition was needed.

## Memory-Pool Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-memory-pool/` is the compatibility-preserving owner of the former `src/optimize/parts/memory_pool.rs` implementation: adaptive allocation, exact ownership/accounting ledgers, TLS and locked caches, NUMA policy/classification, and Unix/Windows zero-copy buffers.
- Root `quicfuscate::optimize` re-exports the pool and zero-copy contracts. The Linux UDP batch adapter remains root-owned because it calls the transport UDP implementation, so no artificial reverse dependency is introduced.
- The child has only backend workspace dependencies (`qf-common`, `qf-cpu`, `qf-memory-lock`, and `qf-telemetry`) and no frontend/Tauri surface. NUMA classification tests moved with the implementation; isolated `23/23` tests, strict Clippy, root compatibility checks, and formatting pass. Seam evidence is `scripts/out/audits/workspace-seams-20260809T050634Z/workspace-seams.json` with twenty workspace packages, 247 Rust files, 204,066 source lines, 136 product-module edges, 40 Cargo workspace edges, the unchanged 12-module product SCC, and `protected_changes=[]`.

## Compression Workspace Crate (2026-08-09, TODO-562)

- `crates/qf-compress/` owns the former `src/compress.rs` implementation: analysis and policy, zstd pooled and dictionary frames, entropy/chunk heuristics, persona dictionary registry/persistence, and the large-body pool. Root `quicfuscate::compress` remains a compatibility projection with a private adapter for the root-only snapshot call site.
- qf-compress depends only on backend leaves (`qf-common`, `qf-cpu`, `qf-memory-pool`, `qf-telemetry`) plus `zstd` and `log`. The qf-cpu leaf owns the SIMD classification, histogram, pattern-search, iterator-reduction, sorting, argsort, and runtime substring-search implementations. Isolated qf-compress all-target/all-feature checking, `17/17` tests, strict Clippy, root compatibility checking, root strict Clippy, formatting, and the complete workspace all-target `rust-tests` suite (`3,005` passed, `0` failed, `6` ignored) pass; qf-cpu contributes `58/58` isolated tests after the sort slice. Current seam evidence is `scripts/out/audits/workspace-seams-20260809T082400Z/workspace-seams.json`: twenty-one workspace packages, 253 Rust files, 204,103 source lines, 134 product-module edges, 45 Cargo workspace dependency edges, and an 11-module product SCC. No frontend/Tauri surface is involved.
- The final warning-free release verification is the same canonical binary: `10,016,880` bytes with SHA-256 `1d24166193651e304bfa580fa338ea4dde8889c834f8721ca95094dbf79ba87b`; the target ended at `10,831,616 KiB`, below the 12-GiB cleanup threshold.

## Transport Anti-Replay Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-anti-replay/` owns the former `src/transport/anti_replay.rs` strike register. `src/transport/anti_replay.rs` is now a compatibility projection, preserving `quicfuscate::transport::anti_replay::{AntiReplayConfig, StrikeRegister}` for transport, server, configuration, and integration-test callers.
- `crates/qf-transport-anti-replay/src/config.rs` also owns the operator-facing `AntiReplaySection` serde/default/validation contract. `src/engine/config.rs` re-exports it through the historical `quicfuscate::engine::AntiReplaySection` path and maps child validation errors into `ConfigError::Validation`; no duplicate root owner remains.
- The child boundary is `qf-common::time_source::ProtocolClock` plus `parking_lot`, `serde`, and `sha2`. The strike-register baseline passed `11/11`; after the configuration leaf, the child passes `14/14` with strict all-target/all-feature Clippy, root compatibility gates, and the root configuration projections still green. The historical release binary evidence remains `10,017,024` bytes with SHA-256 `b422f25c19e3fc7ccc9eddbe914682488d4cbb06df2687d69ae16d11d31fe357`; current target usage is recorded below.
- The current child boundary adds serde for the moved configuration contract. qf-transport-anti-replay tests pass `14/14`; root EngineConfig tests pass `39/39` and AppConfig projection tests pass `2/2`. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-anti-replay-config/workspace-seams.json`: `35` packages, `307` Rust files, `205,427` source lines, `129` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`; target usage is `8,739,040 KiB` with `9,848,312 KiB` free. No frontend/Tauri path changed.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T065128Z/workspace-seams.json`: twenty-two workspace packages, 254 Rust files, 204,107 source lines, 134 product-module edges, 47 Cargo workspace dependency edges, one 11-module product SCC, and `protected_changes=[]`. The runtime guardrail audit is fully green with zero critical failures and zero warnings at `scripts/out/audits/runtime-guardrails-20260809T065928Z/audit-runtime-guardrails.log`; the AMX checker now follows qf-cpu ownership and no frontend/Tauri path changed.
- Full all-feature/all-target Clippy remains blocked only by the explicit macOS-incompatible Linux guard at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`; all-feature library/binary Clippy passes and no guard was weakened.

## CPU Profile Compatibility Owner (2026-08-09, TODO-562)

- `crates/qf-cpu/src/profile.rs` now owns the former root `src/profile.rs` `Aegis128Profile` implementation. The root `profile` namespace is a compatibility re-export, preserving the public path and eliminating the duplicate root owner.
- The child retains only its existing backend boundary (`qf-common`, `qf-telemetry`, `libc`, and `log`). Isolated qf-cpu verification passes `64/64` all-target/all-feature tests and strict Clippy; root all-target checking with `rust-tests`, root strict Clippy, and the complete workspace all-target `rust-tests` suite exit 0 with root `2,148/2,148` and zero registered-target failures. Formatting, diff hygiene, and the protected frontend/Tauri check pass. No frontend or Tauri field/API addition is needed.
- The guarded workspace test run ends at `8,260,072 KiB` target usage with `4,115,300 KiB` free, below the 12-GiB cleanup threshold.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T071500Z/workspace-seams.json`: twenty-two workspace packages, 255 Rust files, 204,112 source lines, 134 product-module edges, 47 Cargo workspace dependency edges, one unchanged 11-module product SCC, and `protected_changes=[]`. This is a compatibility-owner reconciliation, not a claim that the cyclic transport core is extracted.
- Warning-free release verification for this code state passes: canonical `--help` exits 0, the binary is `10,017,024` bytes, SHA-256 is `0551220247adb5954ebee8dc5bb48e42c7e802a5d8256e9054a18e9cd3a8226c`, and the target ends at `7,052,724 KiB` with `6,365,800 KiB` free.
- The complete all-feature/all-target workspace Clippy lane remains intentionally platform-blocked at `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64; the all-feature library/binary lane is green and no Linux guard was weakened. The guarded blocked run ended at `8,696,056 KiB` target usage with `3,677,400 KiB` free.

## ASCII Classifier Compatibility Owner (2026-08-09, TODO-562)

- `qf-cpu::count_ascii_printable` now owns the former scalar ASCII classifier from `src/accelerate.rs`; the root `accelerate::count_ascii_printable` path is a compatibility re-export, so existing integration callers retain their API.
- The move is backend-only, adds no dependency, and does not require any frontend or Tauri field/API addition. Isolated qf-cpu all-target/all-feature tests pass `66/66`, the root `rt-stealth-ascii-count` target passes `2/2`, and root all-target checking plus strict `rust-tests` Clippy pass.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T073000Z/workspace-seams.json`: twenty-two workspace packages, 255 Rust files, 204,122 source lines, 134 product-module edges, 47 Cargo workspace dependency edges, one unchanged 11-module product SCC, and `protected_changes=[]`.
- The complete workspace all-target `rust-tests` suite exits 0 with root `2,148/2,148` and zero registered-target failures; the guarded run ends at `8,973,544 KiB` target usage with `4,355,628 KiB` free.
- Warning-free release verification for the combined profile and ASCII-owner state passes: canonical `--help` exits 0, the binary is `10,017,024` bytes, SHA-256 is `0d43551fbf1de91721fa93d335d515456613ce77218ce9b3d59b69b2799232e4`, and the target ends at `8,973,568 KiB` with `4,312,636 KiB` free.
- The refreshed runtime guardrail audit is fully green with zero critical failures and zero warnings at `scripts/out/audits/runtime-guardrails-20260809T074500Z/audit-runtime-guardrails.log`; no platform guard was weakened and no frontend/Tauri path changed.

## Transport Version Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-version/` is the canonical owner for QUIC v1/v2 constants, support selection, Version Information transport parameters, negotiation state, GREASE/reserved versions, and long-header type mapping. The root `src/transport/version.rs` adapter preserves the existing `transport::version` and `PacketType` API without a duplicate implementation.
- The child now also owns the root-independent `QuicVersion` configuration enum and its V1/V2 wire mapping; `src/engine/config.rs` re-exports it through the historical engine path. The child depends on `qf-common`, `qf-error`, and serde. The low-frequency Version Information path uses a private scalar varint codec; packet-number and H3 encoding continue using the root SIMD-dispatched codec. No frontend, Tauri, or visible API field changes are required.
- Isolated child tests are `7/7` with strict all-feature Clippy green; root all-target checking, strict `rust-tests` Clippy, and EngineConfig tests pass `39/39`. The full all-feature/all-target Clippy command remains platform-blocked by the explicit Linux-only guard at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64.
- Historical release proof remains `target/release/quicfuscate --help` exit 0, `10,017,104` bytes, SHA-256 `93b4d4ae832af30c57788d196b99f93bfed772ce64b3571faf764f4113f30bca`. Fresh seam proof after the configuration-owner cut is `scripts/out/audits/workspace-seams-20260809T-quic-version-config/workspace-seams.json`: `35` packages, `307` Rust files, `205,449` source lines, `129` module edges, `94` Cargo workspace edges, unchanged 9-module product SCC, and `protected_changes=[]`; target usage is `9,924,628 KiB` with `7,133,388 KiB` free. Runtime guardrails remain green and no frontend/Tauri path changed.

## Transport Congestion-Control Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-cc/` now owns the former `src/transport/cc/` implementation: Reno, CUBIC, BBR2, BBR3, the `CongestionController` contract, enum dispatch, browser-profile stealth shaping, and all 92 existing controller tests. The root `src/transport/cc/mod.rs` is a compatibility projection, so `Recovery` and existing `quicfuscate::transport::cc` callers retain their paths.
- The child also owns the root-independent `Algorithm` serde/default contract used by engine configuration; `src/engine/config.rs` re-exports it as `engine::CcAlgorithm` without retaining a duplicate enum. The child boundary is `qf-common`, `qf-transport-types`, serde, and log; no frontend, Tauri, or visible API field projection is required.
- Isolated qf-transport-cc all-target/all-feature checking, `92/92` tests, and strict all-target/all-feature Clippy pass. Workspace all-target checking, workspace strict `rust-tests` Clippy, full workspace all-target `rust-tests` (exit 0, qf-transport-cc `92/92`, root `2051/2051`), workspace all-feature library/binary Clippy, formatting, diff hygiene, and runtime guardrails pass. Full all-feature/all-target Clippy remains platform-blocked at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; no guard was weakened.
- Current seam evidence is `scripts/out/audits/workspace-seams-20260809T101650/workspace-seams.json`: 24 workspace packages, 258 Rust files, 204,266 source lines, 134 module edges, 52 Cargo workspace dependency edges, and the unchanged 11-module product SCC. The only qf-transport-cc workspace dependencies are `qf-transport-cc -> qf-common` and `quicfuscate -> qf-transport-cc`; `protected_changes=[]`.
- Runtime guardrail evidence is `scripts/out/audits/runtime-guardrails-20260809T101650/audit-runtime-guardrails.log` with Critical 0 and Warnings 0. Warning-free release verification passes with `target/release/quicfuscate --help` exit 0, a 10,017,344-byte binary, SHA-256 `92f290a44b67e4f227e58e1c391cdda1834d1586b58e166391647371bd151fe3`, and current target usage of 1,238,596 KiB, below the 12-GiB cleanup threshold. Frontend/Tauri paths remain untouched.
- Fresh seam evidence after the configuration-owner cut is `scripts/out/audits/workspace-seams-20260809T-cc-config/workspace-seams.json`: `35` packages, `307` Rust files, `205,437` source lines, `129` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`; qf-transport-cc remains `92/92`, root EngineConfig remains `39/39`, and target usage is `11,159,236 KiB` with `6,981,680 KiB` free. No frontend/Tauri path changed.

## Transport Path Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-path/` now owns the former `src/transport/path.rs` and `src/transport/path_scheduler.rs` implementations: `PathManager`, `PathState`, path scoring, validation-aware selection, and round-robin, lowest-latency, and weighted-proportional scheduling, with all 27 existing path tests. The root modules remain compatibility projections, so existing `quicfuscate::transport::path` and `quicfuscate::transport::path_scheduler` paths retain their APIs.
- The child depends only on `qf-common` for the protocol clock and `qf-transport-cc` for the congestion-controller trait and Reno test fixture. Its `rust-tests` feature forwards the test hooks of both backend leaves. No frontend, Tauri, or visible API field projection is required.
- Isolated qf-transport-path all-target/all-feature checking, `27/27` tests, strict all-target/all-feature Clippy, root compatibility checking, root strict `rust-tests` Clippy, formatting, and diff hygiene pass. The complete workspace all-target `rust-tests` suite exits 0 and the all-feature library/binary Clippy lane passes; qf-transport-path contributes `27/27` tests. Full all-feature/all-target Clippy remains platform-blocked at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; no guard was weakened.
- Warning-free release verification passes: `target/release/quicfuscate --help` exits 0, the binary is `10,017,344` bytes, SHA-256 `58846405405c870c076b0001fcef6a1a4bb0271d3e83fac3a8b1d36c3fb5b7a9`, and current target usage is `7,120,912 KiB`, below the 12-GiB cleanup threshold.
- Current seam evidence is `scripts/out/audits/workspace-seams-20260809T103120/workspace-seams.json`: 25 workspace packages, 261 Rust files, 204,279 source lines, 134 module edges, 55 Cargo workspace dependency edges, and the unchanged 11-module product SCC. qf-transport-path depends only on `qf-common` and `qf-transport-cc`; `quicfuscate -> qf-transport-path`; `protected_changes=[]`.
- Runtime guardrail evidence is `scripts/out/audits/runtime-guardrails-20260809T103120/audit-runtime-guardrails.log` with Critical 0 and Warnings 0. Frontend/Tauri paths remain untouched.

## Transport NAT Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-nat/` now owns the former NAT traversal implementation from `src/transport/nat.rs`, the engine-facing `NatTraversalSection`, and the `NatTraversalMode`, `NatDiscoveryReason`, and `NatTraversalConfig` contracts formerly embedded in `src/transport/config.rs`: STUN/TURN message codecs, ICE candidate selection, bounded NAT path discovery, serialized section validation/conversion, and the baseline NAT tests. Root `engine::NatTraversalSection`, `transport::config`, and `transport::nat` remain compatibility projections, preserving existing public paths.
- The child depends only on `qf-common` for the protocol clock, `qf-error` for address-parse errors, and direct `rand`, `serde`, `tokio`, and `log` runtime dependencies. No frontend, Tauri, or visible API field projection is required.
- The earlier NAT runtime slice passed qf-transport-nat `35/35` tests, workspace all-target checking with `rust-tests`, workspace strict `rust-tests` Clippy, the all-feature library/binary Clippy lane, and the complete workspace all-target `rust-tests` suite; the suite recorded qf-transport-cc `92/92`, qf-transport-nat `35/35`, qf-transport-path `27/27`, and root `1,989/1,989` with no failures. Full all-feature/all-target Clippy remained intentionally platform-blocked at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; no guard was weakened.
- Warning-free release verification passes: `target/release/quicfuscate --help` exits 0, the binary is `10,017,488` bytes, SHA-256 is `f4b85b8f51e1079e1bc03176249a22ce421a9a7aa51dada6952ad6dd64094f73`, and the target ends at `6,477,840 KiB` with `4,959,620 KiB` free. The mandatory initial `cargo clean` and the second cleanup after isolated NAT Clippy crossed the local 2-GiB free-space floor were completed before this final verification; the target stayed below the 12-GiB cleanup threshold.
- Current seam evidence is `scripts/out/audits/workspace-seams-20260809T105633/workspace-seams.json`: 26 workspace packages, 264 Rust files, 204,296 source lines, 134 module edges, 58 Cargo workspace dependency edges, the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`), and `protected_changes=[]`. qf-transport-nat depends only on `qf-common` and `qf-error`; `quicfuscate -> qf-transport-nat` is the only product-to-leaf edge.
- The configuration-owner follow-up passes qf-transport-nat `38/38` tests, root all-target `rust-tests` checking, strict root `rust-tests` Clippy, and EngineConfig tests `39/39`; no frontend or Tauri path changed.
- Follow-up seam evidence is `scripts/out/audits/workspace-seams-20260809T-nat-config/workspace-seams.json`: 35 workspace packages, 307 Rust files, 205,394 source lines, 128 module edges, 94 Cargo workspace dependency edges, the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`), and `protected_changes=[]`.
- Runtime guardrail evidence is `scripts/out/audits/runtime-guardrails-20260809T105633/audit-runtime-guardrails.log` with Critical 0 and Warnings 0. No frontend or Tauri path changed, and no frontend field/API projection is required. TODO-562 remains blocked for the coordinated cyclic product-core split and external Linux/native/CI acceptance gates.

## Transport Packet-Number Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-pn/` owns packet-number spaces and ACK scheduling, connection-ID sets, adaptive ACK ranges, stream reassembly buffers, and transport random helpers formerly embedded in `src/transport/pn.rs`. Root `transport::pn` remains a compatibility projection; the SIMD-dispatched varint codec remains root-owned because it depends on the root SIMD transport backend.
- The child depends only on `qf-common` and `qf-transport-types`. Isolated all-target/all-feature checking, `23/23` tests, strict all-target/all-feature Clippy, and root library compatibility checking pass. The complete workspace all-target `rust-tests` suite exits 0 with qf-transport-pn `23/23`, root `1,966/1,966`, and no failure markers across the remaining registered targets. No frontend or Tauri field/API projection is involved.
- The all-feature/all-target Clippy lane reaches the repository-owned Linux-only guard `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and exits 101 on this macOS ARM64 host; no guard was weakened. The all-feature library/binary Clippy lane remains green.
- Warning-free release verification passes: `target/release/quicfuscate --help` exits 0, the binary is `10,034,256` bytes, SHA-256 is `bb3c71e359016dd592d5b1bc3dbdf9257767fe6a204c44a3a83207c6dd6c18ae`, and current target usage is `1,486,848 KiB`, below the `12,582,912 KiB` cleanup threshold. The final release build was run after the post-suite `cargo clean` removed `10.2 GiB`.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T111927/workspace-seams.json`: 27 workspace packages, 265 Rust files, 204,304 source lines, 134 module edges, 61 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). qf-transport-pn depends only on `qf-common` and `qf-transport-types`; `quicfuscate -> qf-transport-pn`; `protected_changes=[]`.
- The refreshed runtime guardrail audit is fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T111927/audit-runtime-guardrails.log`. The final protected-path check is empty, so no frontend or Tauri path changed and no frontend field/API projection is required.

## Transport Recovery Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-recovery/` owns the RFC 9002 recovery implementation formerly embedded in `src/transport/recovery.rs`: packet-number-space tracking, bounded sent-packet retention, ACK/loss accounting, PTO and time-threshold timers, persistent-congestion evidence, path-migration recovery, and the migration policy contract formerly defined in `src/transport/config.rs`. The root `transport::recovery` and `transport::config` modules remain compatibility projections.
- The child depends only on `qf-common`, `qf-error`, `qf-memory-pool`, `qf-telemetry`, and `qf-transport-cc`. The existing `with_memory_pool` constructor remains source-compatible while the recovery state no longer stores an unused pool reference, eliminating the reverse dependency on the root `optimize` namespace. No FEC, crypto, SIMD, or frontend behavior was changed.
- Isolated qf-transport-recovery all-target/all-feature tests pass `37/37`; strict all-target/all-feature Clippy passes. Root library compatibility checking, workspace all-target checking with `rust-tests`, workspace strict `rust-tests` Clippy, and the complete workspace all-target `rust-tests` suite pass; the suite records qf-transport-recovery `37/37`, root `1,929/1,929`, and zero registered-target failures. The all-feature library/binary Clippy lane is green.
- The complete all-feature/all-target Clippy lane remains intentionally platform-blocked at the repository-owned Linux-only guard `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64 (exit 101); no guard was weakened.
- Warning-free release verification passes: `target/release/quicfuscate --help` exits 0, the binary is `10,034,560` bytes, SHA-256 is `b93263bce10fe3f2576fd054597f01ecba7a60f49f6bd5da37f8e8e31c887b53`, and current target usage is `7,494,480 KiB`, below the `12,582,912 KiB` cleanup threshold. Free space is `15,848,064 KiB`.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T113613/workspace-seams.json`: 28 workspace packages, 266 Rust files, 204,303 source lines, 133 module edges, 67 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). qf-transport-recovery depends only on the five backend leaves above; `quicfuscate -> qf-transport-recovery`; `protected_changes=[]`.
- Runtime guardrail evidence is fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T113613/audit-runtime-guardrails.log`. The final protected-path check is empty, so no frontend or Tauri path changed and no frontend field/API projection is required.

## CPU Transport Acceleration Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-cpu/src/transport.rs` owns the former `src/optimize/transport.rs` implementation: congestion aggregation with VNNI/AVX2/NEON dispatch, bounded bitmap operations, ECN counting, and packet-number reconstruction. Root `src/optimize/transport.rs` remains a compatibility projection.
- qf-cpu now depends on the dependency-free `qf-transport-types` statistics contract; no root transport, FEC, stealth, crypto, or frontend/Tauri implementation crosses into the child. The runtime guardrail audit follows the child owner path.
- Isolated qf-cpu verification passes `83/83` all-target/all-feature tests and strict Clippy. Root library compatibility checking, workspace all-target checking with `rust-tests`, and workspace strict `rust-tests` Clippy pass. The complete workspace all-target `rust-tests` matrix exits 0 with `3,005` passed, `0` failed, and `6` ignored; qf-cpu contributes `83/83` and root contributes `1,912/1,912`. No frontend/Tauri path or field/API projection is involved.
- The all-feature library/binary Clippy lane passes with `RUSTFLAGS=-Dwarnings`. The complete all-feature/all-target Clippy lane remains intentionally platform-blocked at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64 (exit `101`); no guard was weakened. Warning-free release verification passes with canonical `--help`, a `10,034,544`-byte binary, SHA-256 `8347155450a28671ceda3c8162fbac5a8d6b9eec8df2961e876fbdebe7698e7a`, final target usage `10,988,636 KiB`, and free space `13,233,988 KiB`, below the `12,582,912 KiB` cleanup threshold.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T1148/workspace-seams.json`: 28 workspace packages, 267 Rust files, 204,311 source lines, 133 module edges, 68 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). qf-cpu depends on `qf-common`, `qf-telemetry`, and `qf-transport-types`; `quicfuscate -> qf-cpu`; `protected_changes=[]`.
- Runtime guardrail evidence is fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T1215/audit-runtime-guardrails.log`.

## Transport Frames Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-frames/` owns the former `src/transport/frames.rs` codec: checked frame wire-length admission, serialization, zero-copy parsing, ACK-range canonicalization, packet-space legality, RFC 9221 DATAGRAM forms, no-LEN STREAM boundaries, and the 21 moved unit tests. `crates/qf-transport-types::PacketType` supplies the leaf's packet-space contract.
- The root `transport::frames` module is a compatibility adapter. It injects the existing root SIMD varint codec, x86 ACK canonicalizer, and ARM STREAM-header parser through narrow traits, so the optimized runtime path is preserved without duplicate frame logic. Its `Arc<MemoryPool>` batch parameter remains source-compatible and allocation-free.
- Isolated qf-transport-frames checking, `21/21` tests, and strict all-target/all-feature Clippy pass. Root library checking, workspace all-target checking with `rust-tests`, workspace strict `rust-tests` Clippy, and the complete workspace all-target test command exit 0. The all-feature library/binary Clippy lane passes with `RUSTFLAGS=-Dwarnings`.
- The complete all-feature/all-target Clippy lane remains intentionally platform-blocked at the repository-owned Linux-only guard `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64; no guard was weakened. The target guard triggered `cargo clean` at `13,200,356 KiB` and removed `14.2 GiB`; the post-clean target was `941,468 KiB`.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T101237Z/workspace-seams.json`: 29 workspace packages, 268 Rust files, 204,593 source lines, 133 module edges, 71 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). `protected_changes=[]`.
- No frontend or Tauri path changed, and no frontend field/API projection is required. TODO-562 remains blocked for the coordinated cyclic product-core split and external Linux/native/CI acceptance gates.

## HTTP/3 Header and Event Contract Workspace Ownership (2026-08-10, TODO-562)

- Owner: `crates/qf-transport-types/src/h3.rs` for `Header`, cfg-gated `NameValue`, and `Event`; compatibility projection: `src/transport/h3.rs`.
- Consumers in stealth and server-auth now depend on the root-independent child contract. Concrete H3 connection/error/QPACK implementation remains in the root transport layer.
- Verification: qf-transport-types `33/33`, root H3 filter, strict Clippy, formatting, and diff hygiene pass. No frontend/Tauri path changed; the 9-module product SCC remains open.

## Backend Continuation: TLS Cover and Audit Test Ownership (2026-08-10)

- `crates/qf-stealth/src/tls_cover.rs` -> `TlsCoverCipherSuite` canonical contract; `src/stealth/parts/tls_cover_provider.rs` -> preference parsing and provider installation; `src/stealth/mod.rs` -> historical compatibility reexport.
- `crates/qf-audit/src/lib.rs` -> unique fixture paths plus complete audit-file-set cleanup for tests, covering active files, checkpoints, and rotated segments.
- Evidence: qf-stealth `99/99`, root Stealth `190/190`, qf-audit `42/42`, strict workspace Clippy, all-feature workspace check, formatting, diff hygiene, and full workspace all-target `rust-tests` exit `0`. The all-feature/all-target lanes remain platform-bounded by the unchanged Linux-only guards on macOS ARM64.
- Protected frontend and Tauri paths are unchanged; no frontend field/API projection is required by these backend slices.

## Backend Continuation: Individual Memory-Lock Status (2026-08-10)

- `crates/qf-memory-lock/src/lib.rs` -> `MemoryLockAllocationStatus` canonical contract and diagnostics; `src/qftls.rs` -> `TlsKeyLockStatus` compatibility alias plus TLS identity lifecycle.
- Evidence: qf-memory-lock `12/12`, root qftls `24/24`, child strict all-target/all-feature Clippy, root strict library Clippy, and `git diff --check` pass. No frontend or Tauri path changed.
- Fresh seam report `scripts/out/audits/workspace-seams-20260810T-memory-status-final/workspace-seams.json` records `36` packages, `322` Rust files, `206,306` source lines, `125` module edges, `106` workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`; runtime guardrails report `Critical: 0` and `Warnings: 0` in `scripts/out/audits/runtime-guardrails-20260810T-memory-status-final/audit-runtime-guardrails.log`.
- Workspace all-target `rust-tests`, strict rust-tests Clippy, all-feature workspace check, all-feature library/binary Clippy, formatting, documentation truth, and diff hygiene pass. All-feature/all-target check and Clippy remain bounded only by the unchanged Linux guards on macOS ARM64. Post-gate target usage is `12,068,088 KiB`, below the `12,582,912 KiB` cleanup threshold and above the 2-GiB free-space floor.
- `verify-audit-completeness.sh` fails closed on preserved non-ignored untracked Claude extraction paths; no such path was staged, reverted, deleted, or hidden. This remains a worktree-governance blocker only.

## Optimize and Transport Continuation Verification (2026-08-10)

- TODO-680 local release proof is green: `scripts/out/tests/test-optimization-20260810T-backend-continuation-fast/results.json` records `5/5` suites, `43` executed tests, zero failures, and zero skips. Native x86/BMI2, AVX10/VNNI, SVE2, Linux, sanitizer, Miri, and Omega evidence remains unavailable on this ARM64 macOS host.
- TODO-840 frame regressions pass `8/8`; TODO-841 PMTU/prefetch regressions pass `1/1`; and the TODO-842 transport release matrix passes `56/56` across twelve local integration targets. Raw matrix evidence is `/tmp/qf-transport-release-20260810.log`.
- The local matrix proves malformed frame/packet, ARM cursor, packet-number length, portable unaligned output, UDP batch, connection/config/recovery/H3, PN-space ACK, and harness loopback behavior. Native x86_64 AVX2, Linux kernel/invalid-fd, Windows, privileged, and Omega lanes remain explicit unavailable evidence boundaries.
- Final post-matrix usage is `628,476 KiB` target with `19,980,464 KiB` free, below the 12-GiB cleanup threshold and above the 2-GiB floor. Frontend and Tauri paths remain untouched; no frontend projection is required.

### Comprehensive Transport Runner Continuation

- The corrected `test-transport.sh` release runner passes `407/407` tests with `6` explicit Linux/x86_64 skips. It resolves the UDP syscall-metadata regression against the `qf-transport-udp` workspace leaf and fails closed when a named test body is not executed.
- Evidence is `scripts/out/tests/test-transport-20260810T-backend-continuation-fixed-2/results.json`; final target usage is `2,579,884 KiB` with `18,105,216 KiB` free. Native Linux, Windows, x86_64 AVX2, and Omega proof remain external boundaries.

## Backend Continuation Verification (2026-08-10)

- `qf-engine-types` is the root-independent owner for engine configuration, QKey, lifecycle/statistics, and structured control-plane contracts. Root `src/engine/config.rs`, `src/engine/engine.rs`, and `src/engine/qkey.rs` retain orchestration, encoding/registry, aggregate configuration, and compatibility exports. `qf-crypto` owns the primitive packet-number rejection boundary; `scripts/tests/rust/rt-property-suite.rs` now generates only valid QUIC packet numbers.
- Focused tests pass: qf-engine-types `15/15`, qf-crypto `137/137`, AEAD property suite `12/12`, root engine/config/QKey `77/77`. The full workspace all-target `rust-tests` run is `119` result blocks, `3,093` passed, `0` failed, `6` ignored. Strict workspace check/Clippy, all-feature lib/bin check/Clippy/tests, formatting, shell syntax, and diff hygiene pass.
- All-feature/all-target check and Clippy stop only at the unchanged Linux-only guards `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64. No guard was weakened. Runtime guardrails: `Critical: 0`, `Warnings: 0`, `scripts/out/audits/runtime-guardrails-20260810T-backend-final-docs/audit-runtime-guardrails.log`.
- Final post-run guardrail refresh after the corrected transport runner is green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-backend-final-2/audit-runtime-guardrails.log`.
- The guarded release routing filter passes `24/24` deterministic tests; the
  privileged Linux namespace/forwarding/TUN/firewall residue gate for TODO-607
  remains external and is not inferred locally.
- Seam map: `scripts/out/audits/workspace-seams-20260810T-backend-final/workspace-seams.json`, revision `d69e10446c92be684346387d613c28340f18b25f`, `36` packages, `322` Rust files, `206,258` lines, `125` module edges, `106` Cargo workspace dependency edges, unchanged 9-module product SCC, `protected_changes=[]`.
- Release binary `target/release/quicfuscate` passes `--help`, is `9,991,520` bytes, SHA-256 `72a4a685da7ec419e63392574ab7e8e803a376d1c6db66a8065617a58ba881e8`. The target guard enforced the `12,582,912 KiB` cleanup threshold and `2,097,152 KiB` free-space floor; it cleaned once after `12,638,284 KiB` and removed `14.2 GiB`. Frontend/Tauri paths remain untouched; UI projection is deferred.

## Engine Configuration Contract Workspace Ownership (2026-08-10, TODO-562)

- **Canonical owner:** `crates/qf-engine-types/src/lib.rs` owns the root-independent engine lifecycle/error/event/statistics contracts, `ConfigError` and its `EngineError` conversion, and the serialized `EngineSection`, `SecurityConfig`, `OptimizationConfig`, `TransportConfig`, `ConnectionConfig`, `InterfaceConfig`, client-tunnel address model, `QKeyConfig`/zeroizing `QKeyToken`, and structured engine command/result contracts. `src/engine/config.rs` retains the aggregate `EngineConfig`, `StealthSection`, concrete runtime projections, and builder; `src/engine/engine.rs` and `src/engine/qkey.rs` retain orchestration and QKey encoding/registry behavior while reexporting child contracts.
- **Workspace wiring:** `quicfuscate -> qf-engine-types`; qf-engine-types depends on backend leaves `qf-common`, `qf-cpu`, `qf-firewall`, `qf-fec`, `qf-memory-lock`, `qf-transport-cc`, `qf-transport-recovery`, `qf-transport-types`, and `qf-transport-version`, plus direct `log`, `serde`, `sha2`, and `sysinfo` dependencies. No frontend, Tauri, connection, or concrete transport implementation dependency enters the child.
- **Evidence:** qf-engine-types focused tests pass `16/16`; the root `engine::config` filter passes `38/38`; qf-crypto's current malformed-boundary suite passes `137/137`; the full workspace all-target test command exits `0`; strict child/root Clippy passes. Runtime guardrails remain required at the final audit path, with no frontend/Tauri change.
- **Platform boundary:** the complete `--all-features --all-targets` check and Clippy lanes stop at the explicit Linux-only guard `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; the all-feature library/binary lanes remain green and no guard was weakened.
- **Seam snapshot:** `scripts/out/audits/workspace-seams-20260810T-engine-config-final/workspace-seams.json` records `36` packages, `322` Rust files, `206,215` source lines, `125` module edges, `106` workspace dependency edges, the unchanged 9-module SCC, and `protected_changes=[]`.
- **Release and storage:** `target/release/quicfuscate --help` exits `0`; binary size is `9,991,520` bytes and SHA-256 is `063730bf0d56250b09b3c9098c36517c0064a38e85b58e52e397d6016672e604`. The final target guard is `11,021,556 KiB` with `10,553,436 KiB` free, below the 12-GiB cleanup threshold and above the 2-GiB build floor.
- **Boundary:** the measured product SCC remains `brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, and `transport`; TODO-562 remains blocked for the coordinated cyclic runtime split and external Linux/native/CI gates. No frontend/Tauri field or API projection is required.

## MASQUE Downlink Queue Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/masque.rs` owns the bounded `MasqueDownlinkQueue` and `MasqueDownlinkQueueReject` contracts: packet and byte admission, FIFO pop, byte accounting, and full-discard accounting.
- `src/core_parts/connection.rs` re-exports both types for the historical root API while server DNS interception, live-auth routing, and metrics use `qf_transport_types` directly. The queue has no product-runtime dependency and does not alter the QUIC wire path.
- This is an incremental ownership move inside the existing cyclic product core. `implementations -> core` remains for the concrete connection owner, so the 9-module SCC is expected to remain until that larger abstraction boundary is addressed. Frontend/Tauri paths are outside this backend task.
- Validation: qf-transport-types `22/22` tests and strict Clippy, qf-fec `81/81` tests, qf-transport-cc `94/94` tests and strict Clippy, root core `33/33`, and the complete workspace `118` result blocks with `3,067` passed, `0` failed, and `6` ignored. Workspace strict Clippy, workspace all-feature check, and all-feature library/binary Clippy pass.
- Seam evidence is `scripts/out/audits/workspace-seams-20260810T-connection-stats-final/workspace-seams.json`: `35` packages, `317` Rust files, `205,846` source lines, `127` module edges, `96` Cargo dependency edges, unchanged 9-module product SCC, `implementations -> core` at three references, and `protected_changes=[]`. Runtime guardrails are green at `scripts/out/audits/runtime-guardrails-20260810T-connection-stats-final/audit-runtime-guardrails.log` with Critical `0` and Warnings `0`.
- All-target check/Clippy remain explicitly blocked only by the Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64. Release `--help` exits `0`; binary size is `9,989,968` bytes and SHA-256 is `32cb41223f784570f8be1f09e9dd251957f1f51e563764ae1672e2b232be2caa`. Target is `11,448,400 KiB` with `9,508,052 KiB` free, below the cleanup threshold. No frontend or Tauri path changed.

## FEC, MASQUE Handler, and Connection-Statistics Contract Ownership (2026-08-10, TODO-562)

- `crates/qf-fec/src/state.rs` owns `ActiveFecPolicyChange`; `crates/qf-transport-types/src/handlers.rs` owns `CapsuleHandler` and `DatagramHandler`; and `crates/qf-transport-cc/src/stats.rs` owns `ConnectionStats` with bounded congestion aggregation through qf-cpu. Root core/FEC paths are compatibility re-exports, and existing tests use hidden inspection methods without retaining duplicate implementations.
- The new qf-transport-cc dependency direction is `qf-transport-cc -> qf-cpu -> qf-transport-types`; no child imports implementations, engine, connection runtime, frontend, or Tauri code. No wire format or frontend surface changed.

## TUN and Fastpath Contract Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/tun.rs` owns the shared TUN constants, `TunError`, `TunConfig`, validation, `TunCapabilities`, `TunReadContract`, `TunDevice`, and `TunFactory` contracts. `crates/qf-transport-types/src/fastpath.rs` owns `FastpathMode` and captured-environment parsing.
- `src/interface.rs` re-exports those types unchanged and retains the pooled packet wrapper, native platform backends, factory registry, capability probes, telemetry, and reader lifecycle. Existing root callers and platform implementations therefore keep their historical paths and signatures.
- qf-transport-types remains root-independent and frontend/Tauri-free. qf-transport-types tests pass `27/27` with strict Clippy; the complete workspace all-target `rust-tests` suite exits `0` with `118` result blocks, `3,072` passed, `0` failed, and `6` ignored; strict workspace `rust-tests` Clippy, `cargo check --workspace --all-features`, and all-feature library/binary Clippy pass with `RUSTFLAGS=-Dwarnings`. The root library `rust-tests` filter passes `1,659/1,659`.
- The complete all-target check exits `101` at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`, a repository-owned Linux-only guard that is intentionally inapplicable on macOS ARM64. The all-target Clippy lane remains similarly bounded by the Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened.
- Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-tun-contract-final/audit-runtime-guardrails.log`. Seam evidence is `scripts/out/audits/workspace-seams-20260810T-tun-contract-final/workspace-seams.json`: `35` workspace packages, `319` Rust files, `205,949` source lines, `126` module edges, `96` Cargo dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Warning-free release verification passes with `target/release/quicfuscate --help` exit `0`; the binary is `9,990,080` bytes with SHA-256 `d1c8fdfb35a5936296ba4b3f20efa75440d8477152458a30de79953766ba99a2`. The final target guard records `3,106,692 KiB` with `20,537,516 KiB` free, below the cleanup threshold. No frontend or Tauri field/API projection is required.

## Transport Packet Protocol Contract Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/protocol.rs` owns the root-independent `Epoch`, `PacketType`, decoded transport `Header`, and `TransportError` contracts. `src/transport.rs` re-exports the historical `Epoch`, `PacketType`, and `Header` paths plus `Error` as the compatibility alias.
- The child is independent of connection, packet I/O, crypto, FEC, stealth, engine, implementation, frontend, and Tauri runtime code. The packet parser keeps its separate `transport::packet::Header` wire adapter, so no wire format changes.
- This backend-only contract move preserves public paths and requires no frontend field/API projection. qf-transport-types all-target/all-feature tests pass `30/30` with strict Clippy, the root library `rust-tests` filter passes `1,659/1,659`, and the complete workspace all-target `rust-tests` suite exits `0` with `118` result blocks, `3,072` passed, `0` failed, and `6` ignored; strict workspace `rust-tests` Clippy, `cargo check --workspace --all-features`, and all-feature library/binary Clippy also pass. The complete all-target check/Clippy lanes remain bounded by the Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64.
- Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-protocol-final/audit-runtime-guardrails.log`. Seam evidence is `scripts/out/audits/workspace-seams-20260810T-protocol-final/workspace-seams.json`: `35` packages, `320` Rust files, `205,975` source lines, `126` module edges, `96` Cargo dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Release `--help` exits `0`; the binary is `9,990,080` bytes with SHA-256 `7e7e9cb010ecf8ad973d0d0a99cb55d068a5fe8f2d90d7881cff2f67909b38df`, and target/free-space is `8,485,768 / 13,148,664 KiB`, below the cleanup threshold.

## Engine Contract Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-engine-types/src/lib.rs` owns `EngineMode`/`StealthMode` mode enums, serialized `EngineSection` configuration and validation, the engine-facing `FecMode` adapter, the engine-facing `FecSection` runtime projection and `FecSectionError`, lifecycle state, typed data-plane fault/error, event/callback, atomic statistics, immutable snapshot, and disconnect-reason contracts. `src/engine/engine.rs` and `src/engine/config.rs` re-export the child contracts, preserving historical root paths while concrete orchestration and configuration-owned commands remain root-local.
- The child depends on the root-independent `qf-fec` contract, `serde`, and the standard library and has no client/server runtime, TUN, transport implementation, stealth, frontend, or Tauri dependency. No frontend field/API projection is required.
- qf-engine-types tests pass `8/8` with strict Clippy; the root library `rust-tests` filter passes `1,659/1,659`; the workspace all-target `rust-tests` suite exits `0` with `119` result blocks, `3,083` passed, `0` failed, and `6` ignored; workspace strict Clippy, all-feature checking, and all-feature library/binary Clippy pass. The all-target check/Clippy lanes stop on macOS at the unchanged Linux guards `scripts/tests/rust/rt-transport-uring.rs:8` and `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`.
- Runtime guardrails report `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-fec-section-final/audit-runtime-guardrails.log`. Seam evidence is `scripts/out/audits/workspace-seams-20260810T-fec-section-final/workspace-seams.json`: `36` packages, `321` Rust files, `206,097` source lines, `126` module edges, `98` Cargo dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Release `--help` exits `0`; the binary is `9,990,688` bytes with SHA-256 `3ede1c864adbbe8d8e06d8f46c9ab034f9ba5ddd758b159d83d67ccba59f08b3`, target/free-space `2,827,664 / 20,052,236 KiB`.

## FEC Packet, Decoder, and Zero-Path Ownership (2026-08-09, TODO-562)

- `crates/qf-fec/src/codecs.rs` owns pooled packet storage, mode/control contracts, and GF(2^4)/GF(2^8)/GF(2^16) encoders; `crates/qf-fec/src/decoders.rs` owns the three decoder families, dimension validation, and Wiedemann recovery helpers; `crates/qf-fec/src/zero.rs` owns the bounded zero-overhead path.
- Root `src/fec/parts/codecs_and_observers.rs` and `src/fec/parts/decoders.rs` are compatibility projections for observer, loss-estimator, wrapper, and historical decoder paths. Root adaptive/config code no longer accesses child-private decoder state.
- Seam report: `scripts/out/audits/workspace-seams-20260809T-continuation-fec-zero/workspace-seams.json` records 35 workspace packages, 287 Rust files, 205,105 source lines, 129 module edges, 93 Cargo workspace dependency edges, the 9-module product SCC, and `protected_changes=[]`.
- qf-fec checks/tests/Clippy and the focused root FEC suite are green (`56/56` child tests, `235/235` root FEC tests); no frontend or Tauri path changed and no frontend field/API projection is required.

## FEC Mode-Manager Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/manager.rs` is the canonical owner for root-independent `ModeManager` behavior: bounded loss history, target ranking, hysteresis and dwell-time switching, explicit mode/window parameter resolution, finite-redundancy admission, and protocol-time access through `qf-common`.
- `src/fec/internal.rs` retains encoder/decoder variants, lazy decoding, interleaving, packet orchestration, and product telemetry. The root `src/fec/mod.rs` re-exports `ModeManager` as a compatibility projection for existing adaptive-controller, engine, and test callers.
- The dependency direction remains one-way (`quicfuscate -> qf-fec`); no frontend or Tauri implementation crosses this boundary. qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`56/56`); root compatibility checking, strict `rust-tests` Clippy, and focused root FEC tests pass (`235/235`).
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-manager/workspace-seams.json`: 35 workspace packages, 289 Rust files, 205,121 source lines, 129 module edges, 93 Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`. The target is `4,583,968 KiB` with `13,599,680 KiB` free, below the `12,582,912 KiB` cleanup threshold. The remaining FEC dispatch/adaptive boundary and external acceptance gates remain open.

## FEC Variant-Dispatch Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/variants.rs` is the canonical owner for `EncoderVariant` and `DecoderVariant`: mode-to-codec selection, fountain repair identity allocation, pooled repair/result conversion, and decoder progress telemetry.
- `src/fec/internal.rs` retains `LazyDecoder`, `InterleavedEncoder`, and `InterleavedDecoder` and re-exports the child variants for historical root callers. No frontend or Tauri implementation crosses this boundary.
- Isolated qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`56/56`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, the focused root FEC suite, and `git diff --check` pass (`235/235` focused FEC tests). Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-variants/workspace-seams.json`: 35 workspace packages, 290 Rust files, 205,128 source lines, 129 module edges, 93 Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `4,802,520 KiB` with `12,309,232 KiB` free, below the 12-GiB cleanup threshold.

## FEC Interleaved-Encoder Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/interleaved.rs` owns `InterleavedEncoder`, lane-aware repair identity allocation, represented `(k, n)` shape reporting, and the bounded repair-ordinal constants. `src/fec/internal.rs` re-exports it for historical callers; `LazyDecoder` and `InterleavedDecoder` remain root-owned for the next coupled extraction.
- qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`56/56`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, formatting, `git diff --check`, and focused FEC tests pass (`235/235`). Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-interleaved-encoder/workspace-seams.json`: 35 packages, 291 Rust files, 205,116 source lines, 129 module edges, 93 workspace edges, the unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `5,018,204 KiB` with `13,094,456 KiB` free.
- The boundary is backend-only; no frontend or Tauri field/API projection is required.

## FEC Lazy-Decoder Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/lazy.rs` owns `LazyDecoder`: bounded pending source/repair state, gap and tail-loss detection, streaming repair admission, lazy/full recovery decisions, partial-result draining, fountain-seed propagation, and lazy-skip telemetry. `src/fec/internal.rs` re-exports it for the root `InterleavedDecoder` and historical callers.
- qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`56/56`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, formatting, `git diff --check`, and focused FEC tests pass (`235/235`). Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-lazy-decoder/workspace-seams.json`: 35 packages, 292 Rust files, 205,082 source lines, 129 module edges, 93 workspace edges, the unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `5,258,896 KiB` with `12,844,788 KiB` free.
- The boundary is backend-only; no frontend or Tauri field/API projection is required. Root `InterleavedDecoder` remains the next coupled FEC extraction.

## FEC Interleaved-Decoder Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/interleaved_decoder.rs` owns `InterleavedDecoder`: validated wire-profile construction, lane routing for source and repair identities, full/partial result aggregation, recovery-state queries, seed propagation, and bounded test introspection. `src/fec/internal.rs` re-exports it for wire receive, the adaptive controller, and historical callers.
- qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`56/56`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, formatting, `git diff --check`, and focused FEC tests pass (`235/235`). Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-interleaved-decoder/workspace-seams.json`: 35 packages, 293 Rust files, 205,084 source lines, 129 module edges, 93 workspace edges, the unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `5,510,796 KiB` with `12,330,412 KiB` free.
- The boundary is backend-only; no frontend or Tauri field/API projection is required. The remaining FEC root surface is now the compatibility test layer and adaptive/observer integration.

## FEC Wire Contract Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/src/wire.rs` is the canonical owner for root-independent FEC wire contracts: `WireMode` codec selection, repair coefficients, profile and packet metadata validation, fixed-header serialization/parsing, source-symbol framing, and typed reports/errors. The root `src/fec/wire.rs` keeps the pool-backed `WireFecReceiver`, decoder windows, admission telemetry, and the `FecMode -> WireMode` compatibility adapter.
- `crates/qf-fec/src/policy.rs` is the canonical owner for bounded FEC environment snapshots and runtime-policy parsing; the root keeps only the compatibility alias used by decoders, observers, and adaptive control. It depends on `qf-common` and child wire limits, without an engine or transport dependency. Final post-extraction tests, audits, Clippy, and release gates are green below.
- The product edge remains one-way (`quicfuscate -> qf-fec`); no frontend or Tauri implementation crosses into the leaf, and receiver/decoder ownership remains root-local.
- Isolated qf-fec all-target/all-feature tests pass `56/56`; strict qf-fec Clippy, workspace `rust-tests` checking, strict workspace `rust-tests` Clippy, and the complete workspace all-target `rust-tests` matrix pass. The complete workspace matrix exits 0 with `118` result blocks, `3,016` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-qf-fec-policy-final/workspace-seams.json`: `35` workspace packages, `281` Rust files, `205,012` source lines, `130` module edges, `92` Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`); `protected_changes=[]`.
- Runtime guardrails are fully green at `scripts/out/audits/runtime-guardrails-20260809T-qf-fec-policy-final/audit-runtime-guardrails.log` with `Critical: 0` and `Warnings: 0`; AMX proof and SIMD feature contracts pass. The all-feature library/binary Clippy lane passes with `RUSTFLAGS=-Dwarnings`; the full all-feature/all-target Clippy lane remains blocked by the repository-owned Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64, with no guard weakened. Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,937,216` bytes with SHA-256 `45920bab75912c1602a7b4bb1c105e48bd21f6c20cf028900c2440edc21edac5`, and final target usage is `3,635,400 KiB` with `19,307,396 KiB` free, below the 12-GiB cleanup threshold.
- No frontend or Tauri field/API projection is required by the completed backend slices; any later UI projection remains explicitly deferred to the frontend phase.

## Stealth Utility Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-stealth/` is the canonical owner for root-independent domain-fronting and flow-shaping helpers formerly included from `src/stealth/parts/domain_fronting.rs` and `src/stealth/parts/flow_shaping.rs`: atomic CDN rotation, explicit random fallback, provider catalogs, bounded packet-history retention, jitter, and handshake-flight pacing. The root stealth module keeps compatibility projections; no frontend or Tauri implementation crosses into the child.
- qf-stealth depends only on `qf-common` and `rand`; `quicfuscate -> qf-stealth` is one-way. The child consumes qf-common's `ProtocolClock` and owns `FlowShaper`, `StealthPacketClass`, `CdnProvider`, and `DomainFrontingManager` as doc-hidden compatibility contracts.
- Isolated qf-stealth all-target/all-feature checking and strict Clippy pass. Workspace all-target checking with `rust-tests`, strict workspace `rust-tests` Clippy, the complete workspace all-target `rust-tests` matrix, and the all-feature library/binary Clippy lane pass. The complete workspace matrix exits 0 with `118` result blocks, `3,011` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-qf-stealth-final/workspace-seams.json`: `35` workspace packages, `279` Rust files, `204,847` source lines, `130` module edges, `91` Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`); `protected_changes=[]`.
- Runtime guardrails are fully green at `scripts/out/audits/runtime-guardrails-20260809T-qf-stealth-final/audit-runtime-guardrails.log` with `Critical: 0` and `Warnings: 0`; AMX proof and SIMD feature contracts pass. The full all-feature/all-target Clippy lane remains blocked by the repository-owned Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64, with no guard weakened. Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,937,120` bytes with SHA-256 `1a647be6e7f9ecdd2a8c46a654b71d8942012796772caade4faaf05db2a371a7`, and final target usage is `9,732,580 KiB` with `4,883,940 KiB` free, below the 12-GiB cleanup threshold.

## Stealth Scheduler Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-stealth/src/chaff.rs` and `crates/qf-stealth/src/probe_detector.rs` are the canonical owners for the former root traffic-analysis chaff and active-probe detector implementations: bounded lifecycle scheduling, jittered and phase-locked cadence, one-slot chaff admission, QUIC PING/PADDING plaintext generation, probe matching, bounded history retention, threshold escalation, and response modes. Root files remain public compatibility projections; H3-coupled `CoverTrafficScheduler` remains root-local.
- qf-stealth depends on `qf-common`, `log`, and `rand`; `quicfuscate -> qf-stealth` remains one-way. No transport, H3, engine, frontend, or Tauri implementation crosses the child, and no frontend field/API projection is required.
- Isolated qf-stealth all-target/all-feature tests pass `16/16`; strict qf-stealth Clippy, root all-target checking with `rust-tests`, workspace strict `rust-tests` Clippy, the complete workspace all-target `rust-tests` matrix, and the all-feature library/binary Clippy lane pass. The complete workspace matrix exits 0 with `118` result blocks, `3,016` passed, `0` failed, and `6` ignored; `protected_changes=[]`.
- The root `rt-stealth-config-toml` target serializes its two global-compression-policy tests with a local mutex after a reproducible parallel race; all nine assertions pass without changing production behavior.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-qf-stealth-chaff-probe-final/workspace-seams.json`: `35` workspace packages, `283` Rust files, `205,034` source lines, `130` module edges, `92` Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`); `protected_changes=[]`.
- Runtime guardrails are fully green at `scripts/out/audits/runtime-guardrails-20260809T-qf-stealth-chaff-probe-final/audit-runtime-guardrails.log` with `Critical: 0` and `Warnings: 0`; AMX proof and SIMD feature contracts pass. The all-feature library/binary Clippy lane passes with `RUSTFLAGS=-Dwarnings`; the complete all-feature/all-target Clippy lane remains blocked by the repository-owned Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64, with no guard weakened.
- Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,937,280` bytes with SHA-256 `892c6c6ab98f68a940cf0a1b27710b2931bcd5467a5056b2e85440ccab8f813c`, and final target usage is `5,192,604 KiB` with `16,495,540 KiB` free, below the 12-GiB cleanup threshold.

## Stealth Persona Enum Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-stealth/src/profiles.rs` is the canonical owner for the root-independent `BrowserProfile` and `OsProfile` persona identifiers, serde/CLI derives, case-insensitive parsers, and legacy macOS aliases. The root `src/stealth/parts/browser_profiles.rs` re-exports the child types; `FingerprintProfile` remains root-local because it couples TLS Cover, environment snapshots, and transport-facing metadata.
- qf-stealth depends on `qf-common`, `clap`, `log`, `rand`, and `serde`; `quicfuscate -> qf-stealth` remains one-way. No engine, transport, H3, implementation, frontend, or Tauri implementation crosses into the child.
- Isolated qf-stealth all-target/all-feature tests pass `19/19`; strict qf-stealth Clippy, root all-target checking with `rust-tests`, root strict `rust-tests` Clippy, and the complete workspace all-target `rust-tests` matrix pass with exit 0. Root contributes `1,748` tests and qf-stealth contributes `19`; the three profile-contract tests are included.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-qf-stealth-profiles-final/workspace-seams.json`: `35` workspace packages, `284` Rust files, `205,067` source lines, `130` module edges, `92` Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`). The only qf-stealth workspace dependency is `qf-stealth -> qf-common`; `quicfuscate -> qf-stealth` is the product edge; `protected_changes=[]`.
- Runtime guardrails are fully green at `scripts/out/audits/runtime-guardrails-20260809T-qf-stealth-profiles-final/audit-runtime-guardrails.log` with `Critical: 0` and `Warnings: 0`; AMX proof and SIMD feature contracts pass. The complete all-feature/all-target Clippy lane remains blocked by the repository-owned Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64, with no guard weakened.
- Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,936,976` bytes with SHA-256 `8630860a0c34109c0f5fa1fc2e487025a6d2213682663fd1ba2b04437fa1ad66`, and final target usage is `3,255,956 KiB` with `18,220,728 KiB` free, below the 12-GiB cleanup threshold.
- No frontend or Tauri path changed, and no frontend field/API projection is required; any later UI projection remains explicitly deferred to the frontend phase.

## FEC Fountain Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-fec/` is the canonical owner for the former `src/fec/fountain_codes.rs` and `src/fec/gf_tables.rs` plus connection-local seed, decode-prefetch, GF16 slice, Brain/FEC hint, and Kalman smoothing primitives: LT encoding, deterministic robust-soliton source selection, HMAC-derived fountain seeds, GF(2^8)/GF(2^16) multiplication and inverse tables, architecture-dispatched GF16 slice kernels, bounded decoder state, belief-propagation peeling, partial indexed recovery, SIMD XOR dispatch, telemetry, and the moved FEC regression tests. Root FEC and Brain modules retain doc-hidden compatibility projections for historical callers.
- qf-fec depends on `qf-crypto`, `qf-cpu`, `qf-memory-pool`, and `qf-telemetry` plus `log`; `quicfuscate -> qf-fec` remains the product edge and qf-fec has the one-way HMAC contract to qf-crypto. It owns `BrainFecHints` and `KalmanFilter` alongside the default fountain seed, source bound, connection-local seed derivation, decode prefetch, Galois tables, GF16 scalar byte helpers, and architecture-dispatched u16 slice multiplication reused by root Brain, wire, and codec paths. No frontend or Tauri surface is involved.
- Isolated qf-fec all-target/all-feature tests pass `51/51`, strict all-target/all-feature Clippy passes, the complete workspace all-target `rust-tests` matrix exits 0 with `117` result blocks, `3,007` passed, `0` failed, and `6` ignored, workspace checking and strict `rust-tests` Clippy pass, and the all-feature library/binary Clippy lane passes.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-brainfec-final/workspace-seams.json`: `34` workspace packages, `278` Rust files, `204,853` source lines, `130` module edges, `89` Cargo workspace dependency edges, and the unchanged 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`); `protected_changes=[]`.
- Runtime guardrails are fully green at `scripts/out/audits/runtime-guardrails-20260809T-brainfec-final/audit-runtime-guardrails.log` with `Critical: 0` and `Warnings: 0`; AMX proof and SIMD feature contracts pass. The full all-feature/all-target Clippy lane remains blocked by the repository-owned Linux-only guard at `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64, with no guard weakened. Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,920,400` bytes with SHA-256 `ecf5255b1137fbbaf5a8fed80f3011c40b7bac9b0b8699ab835124df3874e915`, and final target usage is `6,676,268 KiB` with `9,258,820 KiB` free, below the 12-GiB cleanup threshold.

## SIMD Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-simd/` is the canonical owner for the former `src/simd/` machine room: runtime feature dispatch, core/Galois/FEC/bitstream operations, QPACK Huffman, QUIC varints, header validation, SHA-256/HMAC, ARM/x86 implementations, and all 61 moved SIMD tests. `src/simd.rs` is the root compatibility projection.
- QPACK Huffman tables and scalar codec helpers now live once in `qf-simd::qpack`; the root H3 dynamic-table codec maps the child's narrow `HuffmanError` into the existing transport `Error` contract. Root transport frames consume only doc-hidden ACK and ARM STREAM helper exports.
- qf-simd depends only on `qf-common`, `qf-cpu`, `qf-crypto`, and `qf-telemetry` plus non-Windows `sha2-asm`; root feature forwarding covers `rust-tests`, `benches`, `prefetch`, `aggressive_inline`, and `internal_avx10_preview`. No transport, FEC, stealth, implementations, frontend, or Tauri implementation is imported by the child.
- Isolated qf-simd all-target/all-feature tests pass `61/61`; strict all-target/all-feature Clippy passes; workspace all-target checking with `rust-tests` passes. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T143432-qf-simd-final/workspace-seams.json`: 33 workspace packages, 273 Rust files, 204,747 source lines, 132 module edges, 84 Cargo workspace dependency edges, and a reduced 9-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `qftls`, `stealth`, `transport`). `protected_changes=[]`.
- Workspace strict `rust-tests` Clippy and the complete workspace all-target `rust-tests` suite pass with `116` result blocks, `3,007` passed, `0` failed, and `6` ignored. The all-feature library/binary Clippy lane passes; the complete all-feature/all-target Clippy lane remains blocked by the Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64. Warning-free release verification passes with a `9,919,664`-byte binary, SHA-256 `e2fd68fca63f1674ada98063ad0a1eb3aebd9eb5445e044653422f152405132d`, and target usage `5,039,748 KiB`; runtime guardrails report `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T142109-qf-simd-final/audit-runtime-guardrails.log`. No frontend or Tauri path changed, and no frontend field/API projection is required.

## Transport Batch Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-batch/src/lib.rs` now owns the former `src/transport/batch.rs` implementation: CPU-derived batch sizing, preallocated receive buffers, Linux `sendmmsg`/`recvmmsg` support, portable scalar fallback behavior, socket acceleration setup, checked datagram lengths, and the existing caller-descriptor/error regressions. The root `src/transport/batch.rs` is a cfg-gated compatibility projection for the historical `transport::batch::BatchProcessor` path.
- The child depends only on `qf-cpu`, `qf-telemetry`, and `qf-transport-udp` workspace contracts plus `libc`, `log`, and `socket2`; it is explicitly rust parity/test-only and has no normal runtime call sites. No transport connection, FEC, crypto, stealth, or frontend/Tauri implementation crosses this boundary.
- Isolated qf-transport-batch all-target/all-feature checking, `7/7` tests on ARM64 macOS, and strict all-target/all-feature Clippy pass. The root compatibility library check and strict `rust-tests` Clippy pass. The complete workspace all-target `rust-tests` suite exits 0 with `114` result blocks, `3,007` passed, `0` failed, and `6` ignored; qf-transport-batch contributes `7/7` and the root library contributes `1,875/1,875`.
- The all-feature library/binary Clippy lane passes with `RUSTFLAGS=-Dwarnings`. The complete all-feature/all-target Clippy lane remains intentionally platform-blocked by the repository-owned Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64; no guard was weakened. The release build initially exposed two normal-feature unused imports in the child; cfg-scoping those imports fixed the production-feature warning, after which warning-free release verification passed.
- Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,919,664` bytes with SHA-256 `afceab64d55857dbcf13bfc7fe1b09946459c7277e16d43963c3f7319deb4896`, and target usage is `2,020,240 KiB`, below the `12,582,912 KiB` cleanup threshold. A proactive `cargo clean` removed `13.4 GiB` before the workspace Clippy rebuild when the target approached the threshold.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T111032Z/workspace-seams.json`: 32 workspace packages, 271 Rust files, 204,671 source lines, 133 module edges, 78 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). qf-transport-batch depends on `qf-cpu`, `qf-telemetry`, and `qf-transport-udp`; the root edge is `quicfuscate -> qf-transport-batch`; `protected_changes=[]`.
- The final refreshed runtime guardrail audit is fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T111033Z/audit-runtime-guardrails.log`. No frontend or Tauri path changed, and no frontend field/API projection is required. TODO-562 remains blocked for the coordinated cyclic product-core split and external Linux/native/CI acceptance gates.

## FEC Runtime-Initialization Workspace Ownership

- `crates/qf-fec/src/runtime.rs` is the canonical owner for bounded Rayon thread-cap policy, one-time FEC runtime initialization, Galois-table setup, and `STREAM_ADJUST_MIN_MS`. Root FEC keeps only compatibility re-exports, and the root direct `rayon` dependency is no longer needed.
- qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`81/81`); root all-target checking with `rust-tests`, strict `rust-tests` Clippy, focused FEC tests (`211/211`), formatting, and `git diff --check` pass. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-fec-runtime/workspace-seams.json`: `35` workspace packages, `298` Rust files, `205,096` source lines, `129` module edges, `93` Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `9,849,564 KiB` with `6,619,596 KiB` free, below the `12,582,912 KiB` cleanup threshold and above the `2,097,152 KiB` build floor. No frontend or Tauri path changed and no frontend field/API projection is required; UI projection remains deferred to the frontend phase.

## FEC Matrix Workspace Ownership

- `crates/qf-fec/src/matrix.rs` is the canonical owner for checked GF(2^8) matrix multiplication and its `MatrixError` contract. Root FEC keeps compatibility re-exports and no duplicate matrix owner.
- qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`81/81`); root all-target checking with `rust-tests`, strict `rust-tests` Clippy, focused FEC tests (`211/211`), formatting, and `git diff --check` pass. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-fec-matrix/workspace-seams.json`: `35` workspace packages, `297` Rust files, `205,080` source lines, `129` module edges, `93` Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `8,254,980 KiB` with `7,300,432 KiB` free, below the `12,582,912 KiB` cleanup threshold and above the `2,097,152 KiB` build floor. No frontend or Tauri path changed and no frontend field/API projection is required; UI projection remains deferred to the frontend phase.

## FEC Wire-Receiver Workspace Ownership

- `crates/qf-fec/src/receiver.rs` is the canonical owner for the pool-backed `WireFecReceiver`, bounded receive windows, epoch/profile admission, source and repair framing, coefficient reconstruction, Fountain and streaming admission, and recovery draining. The root `src/fec/wire.rs` is a compatibility projection and retains only the `FecMode -> WireMode` adapter.
- qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`80/80`); root all-target checking with `rust-tests`, strict `rust-tests` Clippy, focused FEC tests (`211/211`), formatting, and `git diff --check` pass. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-fec-wire-receiver/workspace-seams.json`: `35` workspace packages, `296` Rust files, `205,152` source lines, `129` module edges, `93` Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `8,106,792 KiB` with `6,338,748 KiB` free, below the `12,582,912 KiB` cleanup threshold and above the `2,097,152 KiB` build floor. No frontend or Tauri path changed and no frontend field/API projection is required; UI projection remains deferred to the frontend phase.

## FEC Observer Workspace Ownership

- `crates/qf-fec/src/observer.rs` is the canonical owner for connection-local FEC observer state: ACK-delay EWMA, ECN counters, profile/platform resolution, runtime-policy snapshots, Brain hint attachment, streaming cadence, and one-shot redundancy hints. The root keeps only the `TransportObserver` and live-Connection adapter.
- qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`56/56`); root all-target checking with `rust-tests`, strict `rust-tests` Clippy, focused FEC tests (`235/235`), formatting, and `git diff --check` pass. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-fec-observer/workspace-seams.json`: `35` workspace packages, `295` Rust files, `205,140` source lines, `129` module edges, `93` Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `7,279,060 KiB` with `10,410,632 KiB` free, below the `12,582,912 KiB` cleanup threshold. No frontend or Tauri path changed and no frontend field/API projection is required; UI projection remains deferred to the frontend phase.

## FEC Loss-Estimator Workspace Ownership

- `crates/qf-fec/src/loss.rs` is the canonical owner for bounded EMA/Kalman loss smoothing, CUSUM change detection, burst-window classification, clean-link proof, fountain-readiness admission, disturbance reporting, and burst variance. The root FEC module keeps only the compatibility re-export; adaptive control supplies validated product policy and ambient Kalman overrides through the child constructor.
- qf-fec all-target/all-feature checking, strict all-target/all-feature Clippy, and tests pass (`56/56`); root all-target checking with `rust-tests`, strict `rust-tests` Clippy, focused FEC tests (`235/235`), formatting, and `git diff --check` pass. Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-loss-estimator/workspace-seams.json`: `35` workspace packages, `294` Rust files, `205,068` source lines, `129` module edges, `93` Cargo workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `5,697,220 KiB` with `12,349,896 KiB` free, below the `12,582,912 KiB` cleanup threshold. No frontend or Tauri path changed and no frontend field/API projection is required; UI projection remains deferred to the frontend phase.

## FEC Configuration Workspace Ownership

- `crates/qf-fec/src/config.rs` is the canonical owner for `FecConfig`: adaptive-FEC TOML parsing, defaults, product defaults, validation, mode/window policy, and public configuration fields. The root FEC namespace re-exports the type unchanged for engine, implementation, CLI, and test callers.
- `EngineFecMode` and `EngineFecSection` are root-independent qf-fec traits implemented by `qf-engine-types::FecMode` and `qf-engine-types::FecSection`; `src/engine/config.rs` re-exports the engine contracts and `src/fec/mod.rs` preserves historical qf-fec compatibility exports. qf-fec has no engine, transport, implementation, frontend, or Tauri import. The child adds direct `serde` and `toml` dependencies for its parsing owner.
- qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`81/81`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, focused FEC tests (`211/211`), formatting, and `git diff --check` pass. Seam evidence is `scripts/out/audits/workspace-seams-20260809T-fec-config/workspace-seams.json`: `35` packages, `299` Rust files, `205,184` source lines, `129` module edges, `93` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `11,212,088 KiB` with `2,997,980 KiB` free, below the `12,582,912 KiB` cleanup threshold and above the `2,097,152 KiB` build floor. Frontend/Tauri paths remain untouched and UI projection is deferred.

## FEC Runtime-Plan Workspace Ownership

- `crates/qf-fec/src/runtime_plan.rs` owns the root-independent FEC runtime-plan contract: compute-profile snapshots, explicit pool and environment inputs, policy-aware mode/target resolution, CPU-dependent stream cadence, wire-safe `(k, n, depth)` normalization, partial-recovery admission, and loss-estimator construction. The root adaptive controller injects the existing global pool and retains only lifecycle wiring.
- qf-fec depends on qf-cpu, qf-common, qf-memory-pool, and its existing FEC policy/target/loss contracts; it has no engine, transport, implementation, frontend, or Tauri import. Root compatibility re-exports preserve `FecAmbientInputs`, `FecComputeProfile`, `FecRuntimePlan`, and `wire_safe_encoder_params` for existing callers.
- qf-fec all-target/all-feature checking, strict Clippy, and tests pass (`81/81`); root all-target `rust-tests` checking, strict `rust-tests` Clippy, focused FEC tests (`211/211`), formatting, and `git diff --check` pass. Seam evidence is `scripts/out/audits/workspace-seams-20260809T-runtime-plan/workspace-seams.json`: `35` packages, `300` Rust files, `205,214` source lines, `129` module edges, `93` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`.
- Target usage is `12,345,244 KiB` with `3,139,948 KiB` free, below the `12,582,912 KiB` cleanup threshold and above the `2,097,152 KiB` build floor. Frontend/Tauri paths remain untouched and UI projection is deferred.

## FEC State-Contract Workspace Ownership

- `crates/qf-fec/src/state.rs` owns the root-independent `FecTelemetrySnapshot` and `FecPolicyChange` value contracts. The root adaptive controller keeps live counter and policy-transition behavior, while root FEC re-exports preserve existing engine, connection, implementation, and test paths.
- The child state contract depends only on `FecControlPolicy` and `FecMode`; it has no transport, engine, implementation, frontend, or Tauri import. Existing fields and telemetry semantics remain unchanged.

## Adaptive FEC Controller Workspace Ownership

- `crates/qf-fec/src/adaptive_controller.rs` and `gf16_and_config.rs` are now the canonical owners of `AdaptiveFec`: mode transitions, pooled interleaved encode/decode, loss feedback, wire-profile publication, telemetry, SIMD selection, and runtime control deltas. The root `src/fec/mod.rs` keeps the historical type and `FecSwitchReason` projections.
- Product connection construction injects `optimize::global_pool()` through `qf_fec::AdaptiveFec::new_with_snapshot_and_pool`; standalone qf-fec construction uses its explicit child pool. The child has no root, transport, engine, implementation, frontend, or Tauri dependency.
- Existing root FEC test-only field and method paths are retained as hidden compatibility surface until the root test topology is migrated. qf-fec all-target/all-feature tests pass `81/81`; the focused root FEC suite passes `249/249`; workspace `rust-tests` checking, strict workspace `rust-tests` Clippy, the complete workspace all-target `rust-tests` matrix, all-feature library/binary Clippy, formatting, and diff hygiene pass. The complete all-feature/all-target check remains blocked by the Linux-only `rt-transport-uring` guard on macOS ARM64. Runtime guardrails are green with `Critical: 0` and `Warnings: 0`; no frontend/Tauri path changed.
- Fresh seam evidence: `scripts/out/audits/workspace-seams-20260809T-adaptive-fec-final-2/workspace-seams.json` records `35` packages, `308` Rust files, `205,472` source lines, `128` module edges, `94` workspace dependency edges, the unchanged 9-module product SCC, and `protected_changes=[]`.

## Transport Traffic-Policy Workspace Ownership

- `crates/qf-transport-types/src/traffic.rs` owns `TrafficAnalysisDefense` and `TrafficAnalysisPolicy`: parsing, serde aliases, defaults, validation, ceiling intersection, and wire-cost estimation. `src/transport/config.rs` retains the historical namespace through compatibility re-exports.
- The child is independent of connection, FEC, stealth, engine, implementation, frontend, and Tauri code. qf-transport-types now depends on serde for the existing configuration serialization contract. qf-transport-types tests pass `10/10`; root transport configuration regressions pass `50/50`.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T-transport-traffic-policy/workspace-seams.json`: `35` packages, `302` Rust files, `205,269` source lines, `129` module edges, `93` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The storage guard forced a cleanup at `1,555,740 KiB` free; post-clean usage was `0 KiB` with `15,491,160 KiB` free. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Transport Runtime-Control Contracts

- `crates/qf-transport-types/src/runtime.rs` owns the root-independent `FecControlDelta` and `BrainRuntimePermissions` contracts. `src/transport.rs` re-exports them for existing Connection, Brain, StealthManager, engine, and test callers.
- The child has no product, connection, FEC implementation, frontend, or Tauri dependency; default semantics remain unchanged. qf-transport-types tests pass `12/12`, and the root transport test filter passes `312/312`.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T-transport-runtime-contracts/workspace-seams.json`: `35` packages, `303` Rust files, `205,300` source lines, `129` module edges, `93` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `4,497,072 KiB` with `14,902,544 KiB` free, below the cleanup threshold; frontend/Tauri paths remain untouched and UI projection is deferred.

## Transport PMTU-Policy Workspace Ownership

- `crates/qf-transport-recovery/src/lib.rs` is the canonical owner for `PmtuPolicy` defaults and DPLPMTUD bounds/timer validation. `src/transport/config.rs` is a compatibility re-export for the historical `transport::config::PmtuPolicy` path.
- qf-transport-recovery all-target/all-feature tests pass `38/38`; root all-target `rust-tests` checking, strict `rust-tests` Clippy, and the complete root transport filter pass `312/312`. Formatting and `git diff --check` pass.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-pmtu-policy/workspace-seams.json`: `35` packages, `303` Rust files, `205,313` source lines, `129` module edges, `93` Cargo workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The post-gate target guard is `4,854,520 KiB` with `13,195,432 KiB` free, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Transport Stealth-Contract Workspace Ownership

- `crates/qf-transport-types/src/stealth.rs` is the canonical owner for `BrowserProfile`, `StealthRuntimePolicy`, and `StealthRuntimeDelta`. `src/transport.rs` and qf-transport-recovery preserve compatibility re-exports, while qf-transport-cc preserves `cc::stealth_shaper::BrowserProfile`.
- The only new workspace edge is `qf-transport-cc -> qf-transport-types`; the child value contracts contain no connection, FEC, engine, implementation, frontend, or Tauri behavior. qf-transport-types tests pass `14/14`, qf-transport-cc `92/92`, qf-transport-recovery `38/38`, and the complete root transport filter `312/312`; root checking, strict Clippy, formatting, and diff hygiene pass.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-transport-stealth-contracts/workspace-seams.json`: `35` packages, `304` Rust files, `205,336` source lines, `129` module edges, `94` Cargo workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The post-gate target guard is `6,179,472 KiB` with `12,314,976 KiB` free, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Transport PMTU-State Workspace Ownership

- `crates/qf-transport-recovery/src/pmtu.rs` is the canonical owner for DPLPMTUD `PmtuState`; the root connection module consumes it through the recovery leaf and retains only the independent packet-prefetch helpers.
- qf-transport-recovery all-target/all-feature checking, strict Clippy, and tests pass `41/41`; root all-target `rust-tests` checking, strict `rust-tests` Clippy, and the complete root transport filter pass `309/309`. The safe `min_mtu()` query and test-gated setter preserve packetization and compatibility-test behavior without exposing state fields.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-transport-pmtu-state/workspace-seams.json`: `35` packages, `305` Rust files, `205,349` source lines, `129` module edges, `94` Cargo workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The post-gate target guard is `7,276,704 KiB` with `11,557,068 KiB` free, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Stealth Persona Enum Contracts

- `crates/qf-stealth/src/config.rs` is the canonical owner for the root-independent `PaddingStrategy`, `StealthMode`, and `RotationMode` enums, including serde aliases and existing configuration spellings. `src/stealth/parts/config.rs` removes the duplicate definitions, while `src/stealth/mod.rs` preserves the historical root re-export paths.
- The child has no transport, connection, FEC, engine, implementation, frontend, or Tauri dependency. `FecMode` remains root-local because its adaptive FEC behavior is coupled to the root FEC controller.
- qf-stealth all-target/all-feature checking, strict Clippy, and tests pass `22/22`; root all-target `rust-tests` checking, strict `rust-tests` Clippy, and the root Stealth test filter pass `230/230`. Seam evidence is `scripts/out/audits/workspace-seams-20260809T-stealth-enums/workspace-seams.json`: `35` packages, `306` Rust files, `205,385` source lines, `129` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Target usage is `7,538,108 KiB` with `11,221,844 KiB` free, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Stealth TLS ClientHello Catalog Workspace Ownership

- `crates/qf-stealth/src/tls_client_hello.rs` is the canonical owner for `TlsClientHelloProfileCatalog` and its exact 13 browser/OS metadata combinations. `src/stealth/parts/tls_client_hello.rs` remains the compatibility projection; rustls owns the active wire ClientHello and no transport override setter exists.
- The child keeps a one-way dependency on existing root-independent profile contracts and `qf-common`; no connection, transport, FEC, engine, implementation, frontend, or Tauri behavior crosses this seam. The catalog regression covers the curated matrix and rejects Safari/Linux.
- qf-stealth all-target/all-feature tests pass `23/23` with strict all-target/all-feature Clippy. Root all-target `rust-tests` checking, strict root `rust-tests` Clippy, and the root Stealth filter pass `252/252`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T-stealth-tls-final-2/audit-runtime-guardrails.log`.
- Seam evidence is `scripts/out/audits/workspace-seams-20260809T-stealth-tls-catalog-final-2/workspace-seams.json`: `35` workspace packages, `309` Rust files, `205,489` source lines, `128` module edges, `94` Cargo workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Warning-free release verification produced a `9,972,752`-byte binary with SHA-256 `bf108ec19b2e3758ac3be307339b5acde66a649465867bd1c465fe1f83426ad9`; target usage is `11,894,856 KiB` with `5,010,352 KiB` free, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Stealth TLS Cover Builder Workspace Ownership

- `crates/qf-stealth/src/tls_cover.rs` is the canonical owner for the root-independent synthetic TLS record and ClientHello extension builder and its regression tests. `src/stealth/tls_cover.rs` is the compatibility projection; the root `TlsCoverProvider` retains crypto-context installation, entropy/key lifecycle, handshake state, and transport-facing provider behavior.
- The child depends only on existing browser/OS profile contracts and `qf-common::env_utils::EnvSnapshot`; the ultra-mode flag is read from the supplied snapshot. No provider, transport, frontend, or Tauri behavior crosses the seam.
- qf-stealth all-target/all-feature tests pass `85/85` with strict all-target/all-feature Clippy. Root all-target `rust-tests` checking, strict root `rust-tests` Clippy, and the root Stealth filter pass `190/190`. The complete workspace all-target `rust-tests` command exits `0` with no test failures.
- Seam evidence is `scripts/out/audits/workspace-seams-20260810T-stealth-tls-cover-final-2/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` packages, `311` Rust files, `205,524` source lines, `128` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-stealth-tls-cover-final-2/audit-runtime-guardrails.log`.
- The all-feature/all-target check remains platform-blocked on macOS ARM64 by `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4`, which requires Linux. Warning-free release verification produced a `9,973,184`-byte binary with SHA-256 `7bef1cd1c79e42579849b237a1970c16eb02d3ff69eefae710aa46eccfd1e8fd`; post-build target usage is `7,286,392 KiB`, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Stealth Profile Slot Parser Workspace Ownership

- `crates/qf-stealth/src/profiles.rs` canonically owns the pure `browser[@os]` fingerprint rotation-slot grammar, including trimming, default-OS inheritance, legacy-separator rejection, and bounded errors. The parser symbol in `src/stealth/parts/browser_profiles.rs` is only a root compatibility re-export; the TLS-Cover-coupled `FingerprintProfile` remains root-local.
- qf-stealth all-target/all-feature tests pass `89/89` with strict all-target/all-feature Clippy. Root all-target `rust-tests` checking, strict root `rust-tests` Clippy, and the root Stealth filter pass `190/190`. The complete workspace all-target `rust-tests` run has `118` result blocks with `3,051` passed, `0` failed, and `6` ignored.
- Seam evidence is `scripts/out/audits/workspace-seams-20260810T-stealth-profile-slot-final-2/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` packages, `311` Rust files, `205,552` source lines, `128` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-stealth-profile-slot-final-2/audit-runtime-guardrails.log`.
- The all-feature/all-target check remains platform-blocked on macOS ARM64 by `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8`, both Linux-only guards. Warning-free release verification produced a `9,973,232`-byte binary with SHA-256 `ad050ac8e92f6e05c10d992ffc94ac7697834c081538465a407b6d16421f3c25`; post-build target usage is `8,567,272 KiB`, below the cleanup threshold. Frontend/Tauri paths remain untouched and UI projection is deferred.

## Stealth Traffic-State Workspace Ownership

- `crates/qf-stealth/src/traffic.rs` canonically owns `RateChoker`, `ServerPushState`, and `ServerPushTriggerReason`, including token-bucket pacing, saturating cover-byte accounting, and bounded burst-window state. The root stealth module is a compatibility re-export and `StealthManager` consumes the child constructors/methods.
- The child depends only on `qf-common::time_source::ProtocolClock` and the standard library; no transport, FEC, Reality, engine, implementation, frontend, or Tauri behavior crosses the seam.
- qf-stealth all-target/all-feature tests pass `91/91` with strict all-target/all-feature Clippy. Root library `rust-tests` checking, root Stealth tests `190/190`, and strict root library Clippy pass. The complete workspace all-target `rust-tests` run exits `0` with `118` result blocks, `3,053` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260810T-stealth-traffic-final/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` packages, `312` Rust files, `205,631` source lines, `128` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-stealth-traffic-final/audit-runtime-guardrails.log`. Warning-free release verification passes with a `9,973,504`-byte binary, SHA-256 `c0591efd975cd9d8f02a9fc32569e5acc133d927ddf2dc3d0fa3b9b175f13d1d`, CLI help exit `0`, and target usage `5,675,964 KiB` with `19,291,572 KiB` free, below the cleanup threshold. No frontend/Tauri path changed and no frontend field/API projection is required.

## Stealth TLS Profile Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-stealth/src/tls_profile.rs` canonically owns the browser-shaped `TlsProfile` contract and all six supported persona constructors, including AES-GCM cipher policy, ALPN ordering, extension ordering, ECH/GREASE defaults, cosmetic jitter, and derived Edge/Opera/Brave profiles. The root `qftls` module re-exports the child type, so existing `crate::qftls::TlsProfile` callers retain their paths without a duplicate implementation.
- The child profile module uses only the existing qf-stealth `rand` and standard-library surface. `profile_from_fingerprint` remains root-local because `FingerprintProfile` is coupled to TLS Cover and transport metadata; the rustls provider, `QuicTlsProvider`, `Level`, CryptoContext, and all transport-facing lifecycle remain root-owned.
- qf-stealth all-target/all-feature tests pass `95/95` with strict all-target/all-feature Clippy. The root qftls filter passes `24/24`, the focused root Stealth filter passes `190/190`, root library checking and strict root library Clippy pass, and the complete workspace all-target `rust-tests` run exits `0` with `118` result blocks, `3,057` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260810T-stealth-tls-profile-final/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` workspace packages, `313` Rust files, `205,603` source lines, `128` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-stealth-tls-profile-final/audit-runtime-guardrails.log`.
- The all-feature/all-target check remains platform-blocked on macOS ARM64 by the repository-owned Linux-only guard `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. Warning-free release verification passes with `--help` exit `0`, a `9,973,504`-byte `quicfuscate` binary, SHA-256 `c0591efd975cd9d8f02a9fc32569e5acc133d927ddf2dc3d0fa3b9b175f13d1d`, and target usage `6,379,064 KiB` with `18,449,696 KiB` free, below the `12,582,912 KiB` cleanup threshold. No frontend or Tauri path changed, and no frontend field/API projection is required.

## Intelligent Level Hints Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/runtime.rs` canonically owns the connection-local `IntelligentLevelHints` atomic contract: bounded Brain and probe escalation levels, MASQUE preference, effective-level selection, and test injection. `src/brain.rs` keeps the historical `crate::brain::IntelligentLevelHints` path as a compatibility re-export, while StealthManager and escalation state consume the leaf directly.
- The moved contract uses only `std` atomics inside the existing qf-transport-types serialization boundary. It introduces no product dependency and no frontend or Tauri surface. The direct Stealth-to-Brain source edge is removed; Brain and Stealth retain their existing runtime behavior and connection-local isolation.
- qf-transport-types all-target/all-feature tests pass `15/15` with strict Clippy. Root library checking, root strict Clippy, the focused root Stealth filter `190/190`, workspace strict `rust-tests` Clippy, workspace all-feature library/binary Clippy, and the complete workspace all-target `rust-tests` run pass; the complete run has `118` result blocks, `3,058` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260810T-level-hints-final/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` workspace packages, `313` Rust files, `205,633` source lines, `127` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-level-hints-final/audit-runtime-guardrails.log`.
- The all-feature/all-target check remains platform-blocked on macOS ARM64 by the repository-owned Linux-only guard `scripts/tests/rust/rt-transport-uring.rs:8`; no guard was weakened. Warning-free release verification passes with `--help` exit `0`, a `9,990,016`-byte `quicfuscate` binary, SHA-256 `dccbf7430636acc9cbede75f4d42ad2d11eea67d05f1c41ff25d2a1147388657`, and target usage `8,739,000 KiB` at the guarded build checkpoint, below the `12,582,912 KiB` cleanup threshold. No frontend or Tauri path changed, and no frontend field/API projection is required.

## QUIC Encryption-Level Contract Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/lib.rs` is now the canonical owner of the root-independent `QuicEncryptionLevel` contract for Initial, EarlyData, Handshake, and Application encryption levels. `src/qftls.rs` preserves `crate::qftls::Level` through a compatibility re-export, with no duplicate root enum.
- The contract keeps `repr(C)` and discriminants `0..=3` and depends on no connection, rustls, crypto, stealth, frontend, or Tauri implementation. The TLS provider lifecycle and the distinct `crypto::aead::Level` remain root-owned.
- qf-transport-types tests pass `16/16` with strict Clippy, the root qftls filter passes `24/24`, and the full workspace all-target `rust-tests` suite exits `0` with `118` result blocks, `3,059` passed, `0` failed, and `6` ignored. Root checking and strict Clippy pass.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260810T-level-final/workspace-seams.json`: `35` packages, `313` Rust files, `205,646` source lines, `127` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. Runtime guardrails are green at `scripts/out/audits/runtime-guardrails-20260810T-level-final/audit-runtime-guardrails.log` with Critical `0` and Warnings `0`.
- The all-feature/all-target check remains intentionally platform-blocked by `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64; no guard was weakened. Warning-free release verification passes with `--help` exit `0`, a `9,990,016`-byte binary, SHA-256 `b493c25239022bff8fcdbb74df8b34d7e8563a6213c395af79c2ac0f1f7894a4`, and target usage `9,945,572 KiB`, below the `12,582,912 KiB` cleanup threshold. Frontend/Tauri paths remain untouched and no frontend field/API projection is required.

## Stealth Brain Configuration Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/brain.rs` is the canonical owner for `StealthBrainConfig`: the twelve-field adaptive Brain configuration, exact defaults, environment overrides, bounded clamping, cross-field validation, and captured-environment constructors. `src/brain.rs` preserves the historical `crate::brain::StealthBrainConfig` path as a compatibility re-export; Brain sensor fusion, FEC steering, transport mutation, and provider lifecycle remain root-owned.
- The child consumes `qf-common::env_utils::EnvSnapshot` only at the configuration boundary. It has no connection, FEC, stealth runtime, optimizer, frontend, or Tauri implementation dependency, and existing environment variable names, defaults, validation errors, and fallback behavior remain unchanged.
- qf-transport-types tests pass `19/19` with strict Clippy; the focused root Brain filter passes `62/62`; root and workspace strict `rust-tests` Clippy plus all-feature library/binary Clippy pass. The complete workspace all-target `rust-tests` run exits `0` with `118` result blocks, `3,062` passed, `0` failed, and `6` ignored.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260810T-brain-config-final/workspace-seams.json`: source revision `d69e10446c92be684346387d613c28340f18b25f`, `35` packages, `314` Rust files, `205,701` source lines, `127` module edges, `95` Cargo workspace dependency edges, unchanged 9-module product SCC, new `qf-transport-types -> qf-common` configuration edge, and `protected_changes=[]`. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260810T-brain-config-final/audit-runtime-guardrails.log`.
- The all-feature/all-target check remains intentionally blocked by `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; no guard was weakened. Warning-free release verification passes with `--help` exit `0`, a `9,990,144`-byte binary, SHA-256 `9af45c7eb233c6bdcf0f8f89996102ba945726f84af80ebdbfa82f2f18a688eb`, and target usage `1,694,492 KiB` with `21,017,564 KiB` free, below the `12,582,912 KiB` cleanup threshold. The threshold guard reported `release_threshold_clean=not_needed`; the prior workspace gate automatically cleaned at the threshold. Frontend/Tauri paths remain untouched and no frontend field/API projection is required.

## Stealth Network-Fingerprint Normalization Workspace Ownership


- `crates/qf-stealth/src/fingerprint.rs` is the canonical owner of TCP/ICMP fingerprint normalization: `OsFingerprintProfile`, `PacketNormalizer`, IP-ID behavior, bounded TCP option rewriting, incremental IP/TCP checksums, ICMP unreachable policy, and its regression suite. `src/stealth/fingerprint.rs` preserves the historical root path as a compatibility projection, including the connection caller's `required_capacity` contract.
- qf-stealth keeps its existing `qf-common`, `clap`, `log`, `rand`, and `serde` dependency surface; the child consumes only the child-owned `OsProfile` contract. TLS Cover, adaptive FEC, H3, transport, engine, implementation, frontend, and Tauri behavior remain root-local.
- qf-stealth tests pass `69/69`, strict child Clippy passes, root Stealth tests pass `206/206`, the complete workspace all-target `rust-tests` run exits `0` without failures, and the all-feature library/binary Clippy lane passes. Runtime guardrails are green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T-stealth-fingerprint-final-2/audit-runtime-guardrails.log`.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T-stealth-fingerprint-final-2/workspace-seams.json`: `35` packages, `310` Rust files, `205,501` source lines, `128` module edges, `94` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The all-feature/all-target check is intentionally blocked only by `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64.
- Release verification passes with a `9,972,768`-byte binary, SHA-256 `90f00497ea181c76104853196f577a4f18145e9439d3436c5aa38b0b7799f314`, CLI help exit `0`, and final target usage `2,179,060 KiB` with `22,922,776 KiB` free. No frontend/Tauri path changed and no frontend field/API projection is required.

## Transport Observer Policy Contract Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-types/src/observer.rs` owns the root-independent `TransportObserver`, `TransportPolicyTarget`, and `TransportPolicyError` contracts; `src/transport.rs` preserves compatibility exports and `Connection` supplies the concrete adapter.
- Brain and FEC now share the child observer/policy boundary without changing wire behavior. qf-transport-types `35/35`, the root Brain filter `64/64`, strict Clippy, workspace all-feature checking, and the complete all-target `rust-tests` command pass with no failures. No frontend or Tauri path changed.
- Seam evidence is `scripts/out/audits/workspace-seams-20260810T-observer-contract/workspace-seams.json`: `36` packages, `324` Rust files, `206,549` source lines, `125` module edges, `106` workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`. The measured runtime SCC remains open; this slice only removes root coupling from the shared contract surface.

## QKey Codec Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-engine-types/src/qkey.rs` is the canonical owner of the root-independent QKey codec, identifier, bounds, checksum parser, and error contract. `src/engine/qkey.rs` remains the compatibility adapter for `EngineConfig` conversion and historical root paths.
- Child QKey tests pass `18/18`, the root QKey filter passes `88/88`, strict workspace Clippy and all-feature workspace checking pass, and the complete backend workspace all-target test command exits `0` with no failures. No frontend/Tauri path changed.
- Post-push seam evidence: `scripts/out/audits/workspace-seams-20260810T-qkey-codec-postpush/workspace-seams.json`, source revision `f2c95b3ca51d378dee91c108a78fcc259f35f520`, `36` packages, `325` Rust files, `206,581` source lines, `125` module edges, `106` workspace dependency edges, unchanged 9-module product SCC, `protected_changes=[]`.

## Transport Crypto Stream Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-crypto-stream/` owns the former `CryptoStream` implementation embedded in `src/transport/packet.rs`: reliable CRYPTO-frame buffering, ACK/loss range retention, PTO retransmission queues, bounded handshake-flight memory, and out-of-order receive reassembly. The root packet namespace re-exports the child type, so `CryptoContext` and qftls callers retain their existing paths.
- The child depends only on `qf-error` and `log`; no packet parser, crypto context, FEC, stealth, or frontend/Tauri implementation crosses into the leaf. The moved private range-overflow test remains attached to the canonical implementation and passes `1/1`.
- Isolated qf-transport-crypto-stream checking, `1/1` test, and strict all-target/all-feature Clippy pass. Root library checking with `rust-tests` passes after the re-export and private-owner removal. The complete workspace all-target `rust-tests` run exits 0 with 113 result blocks, `3,007` passed, `0` failed, and `6` ignored; qf-transport-crypto-stream contributes `1/1`, qf-transport-frames contributes `21/21`, and the root library contributes `1,890/1,890`. Workspace all-target checking, strict `rust-tests` Clippy, and all-feature library/binary Clippy pass.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T102646Z/workspace-seams.json`: 30 workspace packages, 269 Rust files, 204,577 source lines, 133 module edges, 73 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). `protected_changes=[]`. Runtime guardrails are fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T102646Z/audit-runtime-guardrails.log`.
- The complete all-feature/all-target Clippy lane remains intentionally platform-blocked at the repository-owned Linux-only guard `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` on macOS ARM64; no guard was weakened. Warning-free release verification remains the final gate for this slice.
- Warning-free release verification is green: `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline` succeeded, `target/release/quicfuscate --help` exited 0, the binary is `9,919,696` bytes with SHA-256 `214522993e6026f781beb3ce6093ac57bb5ffeedfd118f4a0933954ee585b8e0`, and the target ended at `7,186,816 KiB`, below the `12,582,912 KiB` cleanup threshold. The mandatory initial and threshold-triggered `cargo clean` cycles remain recorded above.
- No frontend or Tauri path changed, and no frontend field/API projection is required. TODO-562 remains blocked for the coordinated cyclic product-core split and external Linux/native/CI acceptance gates.

## Transport UDP Workspace Leaf (2026-08-09, TODO-562)

- `crates/qf-transport-udp/` owns the former `src/optimize/udp.rs` and `src/transport/udpfast.rs` implementations: bounded Linux `sendmmsg`/`recvmmsg`, Apple `sendmsg_x` with scalar fallback, UDP GSO/GRO probing, the runtime `UdpFastPath`, checked completion and receive metadata, family-safe sockaddr conversion, and the test-gated NIC RPS helper. The roots `src/optimize/udp.rs` and `src/transport/udpfast.rs` are compatibility adapters.
- The child depends on `qf-cpu` for prefetch/inline policy plus `libc`, `smallvec`, and `sysinfo`; its low-level helper exports are hidden compatibility contracts rather than a new product API. No transport connection, FEC, crypto, stealth, or frontend/Tauri implementation crosses this boundary.
- Isolated qf-transport-udp all-target/all-feature checking, `11/11` tests on ARM64 macOS, and strict all-target/all-feature Clippy pass. Root library checking and strict `rust-tests` Clippy pass after adapter wiring. The complete workspace all-target `rust-tests` suite exits 0 with 114 result blocks, `3,007` passed, `0` failed, and `6` ignored; qf-transport-udp contributes `11/11`, qf-transport-batch `7/7`, qf-transport-crypto-stream `1/1`, qf-transport-frames `21/21`, and the root library `1,872/1,872`.
- Fresh seam evidence is `scripts/out/audits/workspace-seams-20260809T112739Z/workspace-seams.json`: 32 workspace packages, 272 Rust files, 204,685 source lines, 133 module edges, 79 Cargo workspace dependency edges, and the unchanged 11-module product SCC (`brain`, `core`, `engine`, `fec`, `implementations`, `interface`, `optimize`, `qftls`, `simd`, `stealth`, `transport`). qf-transport-batch depends on `qf-transport-udp`, qf-transport-udp depends on `qf-cpu`, and the root edge is `quicfuscate -> qf-transport-udp`; `protected_changes=[]`.
- The final refreshed runtime guardrail audit is fully green with `Critical: 0` and `Warnings: 0` at `scripts/out/audits/runtime-guardrails-20260809T114855Z/audit-runtime-guardrails.log`. Its owner-path assertions follow `crates/qf-transport-udp/src/lib.rs` and `fastpath.rs` while preserving both root compatibility adapters. The complete all-feature/all-target Clippy lane remains intentionally platform-blocked by the repository-owned Linux-only guards at `scripts/tests/rust/rt-io-hotpath-kernel-integration.rs:4` and `scripts/tests/rust/rt-transport-uring.rs:8` on macOS ARM64; no guard was weakened. Fresh release verification ended at `8,518,292 KiB` with `12,312,660 KiB` free, below the `12,582,912 KiB` cleanup threshold.
- Warning-free release verification passes with `RUSTFLAGS=-Dwarnings cargo build --release --bin quicfuscate --locked --offline`; `target/release/quicfuscate --help` exits 0, the binary is `9,919,680` bytes with SHA-256 `429b8a783c3ab1db106d39992bfc2409c9b69b608df37f9dcab3056307871542`, and the target ends at `10,354,308 KiB` with `11,885,328 KiB` free, below the `12,582,912 KiB` cleanup threshold.
- No frontend or Tauri path changed, and no frontend field/API projection is required. TODO-562 remains blocked for the coordinated cyclic product-core split and external Linux/native/CI acceptance gates.

## QUIC Varint Codec Workspace Ownership (2026-08-10, TODO-562)

- `crates/qf-transport-pn/src/varint.rs` canonically owns the RFC 9000 variable-length integer codec, including the SIMD-dispatched fast path, fixed-width encoding, bounds, and typed failures. `src/transport/pn.rs` remains the compatibility projection for `transport::pn::varint`.
- `qf-transport-version` reuses this child codec for Version Information parameters instead of carrying a private duplicate. The dependency edge is `qf-transport-pn -> qf-simd` plus the shared `qf-error` contract; no runtime connection or frontend/Tauri implementation crosses the seam.
- qf-transport-pn `27/27`, qf-transport-version `7/7`, root packet-number filter `11/11`, strict workspace Clippy, all-feature workspace checking, formatting, diff hygiene, and the complete workspace all-target `rust-tests` command pass with no failures. Post-push seam evidence is `scripts/out/audits/workspace-seams-20260810T-varint-postpush/workspace-seams.json` at source revision `7ef0e55a1f048e555815801985f5e7c3c45314fa`: `36` packages, `326` Rust files, `206,558` source lines, `125` module edges, `109` Cargo workspace dependency edges, unchanged 9-module product SCC, and `protected_changes=[]`.
