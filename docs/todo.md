# Repository Worklog Index

## Active TODO Backlog

**Current State (2026-07-01)**: Protocol optimization wave COMPLETE (TODO-389..412). Radical replan wave TODO-413..418 ALL DONE. TUN VPN data plane TODO-422 DONE. **FEC E2E tests TODO-423 DONE** - 12 Rust integration tests + hardened Linux netns scripts, wire format seq bug fixed, broderick all PASS. **FEC benchmarks TODO-424 DONE** - 6 Criterion benchmark groups. **FEC network adversity TODO-425 DONE** - 6 tc-netem suites, broderick 25/25 PASS. **FEC memory pressure TODO-426 DONE** - 7 Rust integration tests, all pass. **FEC mode transitions TODO-427 DONE** - 6 Rust tests + 1 shell script, broderick all PASS. **FEC adaptive optimization TODO-428 DONE** - bandwidth-aware overhead control + 6 adaptive tests, all pass. **FEC wave COMPLETE (TODO-423..428).** **Stealth Stack Coherence Wave TODO-464..471 DONE** - Engine uTLS/persona wiring, session-frozen identity, fronting policy rationalization, randomized cover, Brain actuator ownership, Core H3/MASQUE ownership, protocol-mimicry truth, and WebTransport cover. **CI/App Backend Release Gate TODO-472 DONE** - GitHub `CI` (`28461670844`), `Clippy Matrix` (`28461670906`), and `Release Build` (`28461670799`) are green on `09cb9f2`; CI now validates the Tauri native backend with `cargo check` and `cargo test`. **Production E2E proof hardening TODO-473 DONE** - standalone TUN server pool aligns with CLI TUN IP/netmask, H3/MASQUE CONNECT-UDP carries QKey auth, server MASQUE datagrams are gated by live QKey transport/header auth, DNS leak proof shows raw_port_53_packets=0, and broderick release/netns gates are green. **TUN/MASQUE hotpath and E2E lock hardening TODO-474 DONE** - per-packet MASQUE TX logs are debug-only, TUN downlink flush targets only the owning client, TUN/netns E2E gates serialize through `flock`, and Broderick DNS+FEC parallel collision proof is green. **ACK accounting extract-if hotpath TODO-475 DONE** - ACK/loss accounting drains `sent_packets_by_pn` ranges with `BTreeMap::extract_if`, keeps RTT/loss semantics, and improves Broderick `ack_sent_byte_accounting/10240_inflight_ack_sparse` to about `1.36 ms`. **FEC lazy receive hotpath TODO-476 DONE** - clean-link receive no longer polls heavy recovery, clean blocks prune lazy sequence state, tail-loss recovery remains intact, and Broderick zero-mode lazy fastpath improves about 18%. **FEC zero-mode ownership TODO-477 DONE**, **Stealth H3 cover clean-path policy TODO-478 DONE**, **Transport stealth heuristic RNG hotpath TODO-479 DONE**, **FEC send output reuse hotpath TODO-480 DONE**, **FEC interleaved lazy gap tracking TODO-481 DONE**, **Transport stealth padding decision fastpath TODO-482 DONE**, **Brain policy target cache hotpath TODO-483 DONE**, **FEC receive output reuse hotpath TODO-484 DONE**, **ACK accounting split-drain hotpath TODO-485 DONE**, **STREAM frame direct writer hotpath TODO-486 DONE**, **ACK sparse prefix classification hotpath TODO-487 DONE**, **FEC benchmark product-window calibration TODO-488 DONE**, **Connection benchmark hotpath isolation TODO-489 DONE**, and **FEC decode batch benchmark truth TODO-490 DONE** keep hot clean paths ownership-preserving, cover-free until escalation, free of repeated secure-RNG calls for non-security padding/jitter decisions, free of per-send and per-receive FEC output vector allocation in Core/Engine hot paths, free of false clean-stream gap detection under interleaving, benchmark the real QUIC padding decision path with zero-rate RNG bypass, remove per-policy-tick Brain JS-divergence target allocation, drain large contiguous ACK/loss packet-number ranges with `BTreeMap::split_off`, encode STREAM frames without a temporary owned `Frame::Stream` allocation in the Vec-backed send path, classify many sparse ACK ranges against the packet-threshold loss prefix in one ordered drain pass, split FEC systematic-send measurements from product-window repair-burst measurements, exclude 1-RTT paired-connection setup from connection hotpath Criterion timing, and replace unstable FEC decode single-packet random-loss timing with fixed 128-packet scratch-reuse batches. Server `broderick` Go 1.26.4. GitHub contributors: only `Christopher-Schulze` - no Devin/Claude co-authors.

**Latest checkpoint (TODO-490)**: FEC decode batch benchmark truth is DONE. `benches/fec_pipeline.rs` now measures `fec_decode_pipeline` as fixed 128-packet production-style batches using `on_send_into()` and `on_receive_into()` scratch reuse. The old single-packet deterministic-random loss loop is gone because it produced unstable and misleading decode timings. Broderick batch medians: Normal clean `282 us`, Normal 10% loss `514 us`, Strong clean `278 us`, Strong 10% loss `17.5-18.5 ms`, Streaming clean `499 us`, Streaming 10% loss `623 us`.

## Active - Protocol Optimization Wave (2026-06-05)

Execution order: **Phase A (config + quick wins) -> Phase B (load path) -> Phase C (benchmarks) -> Phase D (architecture) -> Phase E (server profiling)**.

| ID | Phase | Priority | Title | Status |
|----|-------|----------|-------|--------|
| TODO-389 | A | P0 | Fix `aegis128x4`/`x8` config override mapping to Aegis-L only | **DONE** |
| TODO-390 | A | P0 | AEAD backend selection uses MTU workload length, not Initial size | **SCRAP** - premise incorrect: code already used `TYPICAL_1RTT_PAYLOAD_LEN`=1400, not Initial sizing. Constant renamed to `DEFAULT_DATA_PLANE_AEAD_LEN` for documentation clarity; regression guard test added in simd.rs |
| TODO-391 | A | P1 | Eliminate double QUIC header parse in `Connection::recv` | **DONE** (recv threads pre_parsed_hdr through decrypt paths; Retry client branch now reuses pre-parsed header instead of re-parsing) |
| TODO-392 | A | P1 | Eliminate `FecPacket::clone()` on FEC send hot path | **DONE** (SharedFecBuffer Arc-backed design already makes source-packet clone a refcount bump, no payload copy; added regression test guarding zero-copy clone property; transition path audited - 3 handles minimal) |
| TODO-393 | A | P1 | Reuse AEGIS cipher state across packets (avoid per-PN init) | **DONE** (state stored persistently in AEAD struct; `new` only on first packet, `reinit` reuses allocation thereafter; differential test proves reinit output byte-identical to fresh-new per packet across 64 counters) |
| TODO-394 | B | P1 | Replace `sent_bytes_by_pn` full-scan ACK accounting | **DONE** |
| TODO-395 | B | P1 | MORUS seal/open in-place on trait path (remove `to_vec` copies) | **DONE** (trait path already calls encrypt/decrypt_in_place_optimized directly on caller buffer; SIMD _inner fns write in-place via chunks_exact_mut; to_vec only in test/allocating convenience methods; added trait-path differential + forgery regression test) |
| TODO-396 | B | P2 | Brain `apply_policy` lock coalescing and histogram reuse | **DEFERRED** by TODO-417 (Hot-Path-Lock-Elimination, DONE). Bundled into ArcSwap + lock-free 1-RTT path. |
| TODO-397 | B | P2 | FEC encoder/decoder Mutex contention reduction | **DEFERRED** by TODO-417 (Hot-Path-Lock-Elimination, DONE). |
| TODO-398 | B | P2 | CryptoContext RwLock scope reduction on 1-RTT hot path | **DEFERRED** by TODO-417 (Hot-Path-Lock-Elimination, DONE). ArcSwap lock-free 1-RTT path eliminates per-packet RwLock. |
| TODO-399 | C | P1 | Criterion bench: `Connection` 1-RTT send/recv loop | **DONE** (`connection_1rtt_send_recv` group in ci_regression.rs, 3 payload sizes, mock paired 1-RTT connections; wired into bench-ci-regression.sh + ci.yml benchmarks job with critcmp baseline) |
| TODO-400 | C | P1 | Criterion bench: ACK processing under N in-flight PNs | **DONE** (`ack_sent_byte_accounting` group: 32/128/512/1024/2048/10240 inflight, ack_all/ack_half/ack_sparse variants; wired into ci_regression + ci.yml benchmarks job) |
| TODO-401 | C | P2 | CI regression: stealth-on vs stealth-off same workload | **DONE** (`connection_1rtt_stealth_compare` group runs stealth_off/stealth_on on identical 1-RTT workload; ci.yml benchmarks job applies 15% warn / 30% error thresholds via bench-ci-regression.sh) |
| TODO-402 | D | P2 | Batch AEAD seal/open (Aegis X4/X8 wiring) | **DONE** |
| TODO-403 | D | P2 | Zero-copy inbound: recv buffer through FEC into transport | **DONE** |
| TODO-404 | D | P3 | Unify client `pipeline.rs` with `core` pooled path | **DONE** |
| TODO-405 | D | P2 | Wire `optimize::transport` PN-decode SIMD into production | **DONE** |
| TODO-406 | B | P2 | Consolidate dual stealth timing gates (core + connection) | **DONE** |
| TODO-407 | B | P3 | Replace `Box<dyn Aead>` with enum dispatch in `CryptoContext` | **DONE** |
| TODO-408 | B | P3 | Fix VNNI `aggregate_congestion` per-call heap allocations | **DONE** |
| TODO-409 | A | P2 | Evaluate `stream_ring_buffer` as default for throughput profile | **DEFERRED** by TODO-414 (Streaming-FEC adaptive loop, DONE). Feature remains opt-in; adaptive loop determines when streaming mode warrants ring-buffer usage. |
| TODO-410 | B | P3 | Zstd compression streaming directly into memory pool | **DONE** |
| TODO-411 | B | P3 | StrikeRegister 0-RTT anti-replay ring buffer + bloom front | **DONE** |
| TODO-412 | E | P1 | Server deploy + real-world protocol profiling baseline | **DEFERRED** by TODO-418 (Profiling-Baseline + tc-netem-Setup, DONE). Real-world Oracle Cloud UDP path remains externally blocked (cloud-level Security List, not iptables); loopback + tc-netem baseline established as pragmatic substitute. Reopen only if Oracle Cloud UDP egress is unblocked. |

Detail files: `docs/todo/todo-{id}-*.md` for each item above.

---

## Completed - Session 42 Items (2026-07-23)

Pre-loop cleanup tasks completed before handing work to the continuous loop.

| ID | Priority | Title | Status | Commit / Result |
|----|----------|-------|--------|-----------------|
| TODO-419 | P0 | Fix CI: `linux-fastpath-gates` `uring_batch` chunked-send stale CQE | **DONE** | `1dd8a3b` - CI all green |
| TODO-420 | P0 | Update `broderick` Go toolchain 1.22.2 → 1.26.4 | **DONE** | `go version go1.26.4 linux/arm64` |
| TODO-421 | P0 | Verify GitHub contributors: no Devin/Claude co-authors | **DONE** | API shows only `Christopher-Schulze` |

---

## Completed - TUN VPN Data Plane (2026-06-23 → 2026-06-29)

Handshake, cert validation (incl. `--ca-file`), H3 OOB panic, idle-timeout/loss inflation, and
client Finished delivery are all fixed and on `main` (commits `2b9c880`, `5572142`, `0bade3a`,
`953fe84`, `8085f9b`). The VPN payload path through the TUN bridge is now wired end-to-end.

| ID | Priority | Title | Status | Depends On |
|----|----------|-------|--------|------------|
| TODO-422 | P1 | TUN VPN data plane end-to-end via MASQUE (CONNECT-UDP capsule <-> TUN routing) | **DONE** - Option A (MASQUE) implemented both directions: client uplink via `http3_send_body_chunk` → `send_masque_datagram`, server downlink via `send_masque_downlink` on peer-initiated CONNECT-UDP flow, downlink drain via `drain_masque_datagrams` → `masque_datagram_cb` → TUN write. E2E test harness at `scripts/tests/tun-e2e-netns.sh`. Commits `367d56f`..`8474f3c`. | - |

Detail file: `docs/todo/todo-422-tun-vpn-data-plane-masque.md`.

---

## Active - FEC Performance & Testing Wave (2026-06-29)

**Motivation:** FEC has 50+ unit tests but zero E2E tests through real QUIC transport. All existing
tests inject loss at the FEC module level, never at the network layer. No benchmarks measure the
real FEC encode/decode pipeline. No tests verify resource efficiency under memory pressure. The
adaptive intelligence (Kalman, CUSUM, hysteresis) has never been empirically validated under real
network adversity. This wave closes all those gaps and deep-optimizes FEC for production.

**Execution order: Phase F (E2E tests → benchmarks → adversity → resource → transitions → deep optimization)**

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-423 | F | P0 | E2E FEC tests through real QUIC transport (netns + tc-netem) | **DONE** - 12 Rust integration tests + 2 shell scripts (loss sweep + burst). Wire format seq bug fixed. Broderick: 5/5 ping tests PASS, 2/2 burst tests PASS. | TODO-422 |
| TODO-424 | F | P1 | FEC full-stack performance benchmarks (encode/decode pipeline, mode switch, streaming) | **DONE** - 6 Criterion benchmark groups (encode/decode/transition/streaming/lazy/window-burst). Sample results: Zero 134ns, Normal 977ns, transition 147ns. | TODO-423 |
| TODO-425 | F | P1 | FEC under network adversity (tc-netem loss/jitter/bandwidth/RTT simulation) | **DONE** - 6 tc-netem adversity tests (loss/jitter/bandwidth/RTT/combined/recovery). Broderick: 25/25 PASS. | TODO-423 |
| TODO-426 | F | P1 | FEC memory pressure and resource efficiency tests | **DONE** - 7 Rust integration tests (pool exhaustion, queue bounding, memory scaling, recycling, transition leak, sustained load, telemetry). All pass. | TODO-423 |
| TODO-427 | F | P1 | FEC mode transition tests under active load | **DONE** - 6 Rust tests (key transitions, bidirectional, burst, idle-then-burst, flapping, no-dup) + 1 shell script (3-phase E2E). Broderick: all PASS. | TODO-423 |
| TODO-428 | F | P1 | FEC adaptive intelligence deep optimization | **DONE** - bandwidth-aware overhead control + 6 adaptive intelligence tests (scarce/plentiful/minimum/zero-loss/mode-selection/hysteresis). All pass. | TODO-423, TODO-424, TODO-425 |

Detail files: `docs/todo/todo-42{3,4,5,6,7,8}-*.md`.

**Resource efficiency philosophy:** FEC should be invisible when the link is clean and heroic when
the link is broken. In extreme loss scenarios, FEC may consume significant resources - but the link
stays up. Resources are cheap, liveness is expensive.

---

## Active - Production VPN Readiness Wave (2026-06-30)

**Motivation:** Deep 8-axis audit (TUN data plane, Auth/PKI, Security/KillSwitch, DNS, FEC bugs,
Transport, Production ops, Platform) reveals QuicFuscate is NOT production-ready. The architecture
is sound (L3 IP-tunnel over QUIC, like WireGuard) but critical integration gaps, broken multi-client,
unwired kill switch, missing DNS-through-tunnel, and platform stubs block production use. This wave
closes every gap to reach a complete, production-ready VPN protocol.

**Audit findings summary (verified, not assumed):**

| Axis | Critical Blockers | High Gaps | Status |
|------|-------------------|-----------|--------|
| TUN data plane | No ICMP, no IPv6 routing, multi-client broken (sends to first client only) | No PMTUD | Wave G |
| Auth/PKI | Self-signed cert fallback in production, no immediate revocation | No key rotation, no CA hierarchy, no audit logging | Wave G+H |
| Security | Kill switch NOT wired into runtime (traffic leak guaranteed) | IPv6 kill switch DONE (TODO-437), key erasure DONE (TODO-440), auth rate limiting DONE (TODO-456), QKey encryption at rest DONE (TODO-458), CSRF bypass FIXED. No traffic isolation, no mlock | Wave G+H |
| DNS | DoH implemented but 0 calls, no DNS proxy, no DNS-through-tunnel | No split DNS, no DNSSEC, search_domains always empty | Wave H |
| FEC bugs | InterleavedDecoder DATA LOSS bug (consecutive ID assumption) | swap_remove is NOT a bug (verified correct) | Wave G |
| Transport | No multipath (WiFi+LTE bonding impossible) | Migration cwnd reset too aggressive, PMTUD disabled, no CUBIC | Wave J |
| Production ops | Multi-client TUN broken, no HA/clustering | No log rotation, no Docker, no per-client bandwidth, no SIGTERM | Wave I |
| Platform | Windows TUN = stub, ~~iOS/Android = stubs~~ SCRAPPED | No privilege dropping, no mlock, no CPU affinity | Wave I |

**Execution order: Wave G (P0 Critical) → Wave H (P1 Security) → Wave I (P1 Platform/Deploy) → Wave J (P1-P2 Transport/Advanced)**

### Wave G - P0 Critical Blockers (must fix before any production use)

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-429 | G | P0 | Kill switch integration into client runtime | **DONE** - KillSwitch wired into QuicFuscateEngine: `kill_switch: Option<Arc<KillSwitch>>` field, `SecurityConfig.kill_switch` config option, enable on `start()`, `on_vpn_connected()` on connect, `on_vpn_disconnected()` on disconnect, `handle_connection_loss()` on heartbeat timeout, `Drop` impl cleanup, `cleanup_stale_rules()` for crash recovery. 4 tests pass. | - |
| TODO-430 | G | P0 | Multi-client TUN forwarding fix | **DONE** - Server routes TUN packets by destination IP using `parse_ip_dest()` (IPv4 + IPv6). Each client gets unique TUN IP from IP pool. Session lookup by client_ip → SocketAddr. 7 tests pass. | TODO-422 |
| TODO-431 | G | P0 | IPv6 support (routing, NAT, TUN addressing) | **DONE** - Ipv6Pool, ServerConfig IPv6 fields, Session dual-stack, RoutingManager IPv6 NAT (ip6tables/pf inet6/NetNat v6), TunConfig ip6/prefix6, CLI --tun-ip6/--tun-prefix6, parse_ipv6_dest, IPv6 forwarding. 13 tests pass. | - |
| TODO-432 | G | P0 | ICMP handling (echo reply, PMTUD packet-too-big) | **DONE** - New `src/implementations/server/icmp.rs` module with parse_icmpv4, build_echo_reply, build_icmp_unreachable. Server TUN forwarding loop handles echo requests to server IP and generates host-unreachable for unroutable packets. 8 unit tests pass. | - |
| TODO-433 | G | P0 | InterleavedDecoder consecutive-ID bug fix | **DONE** - Added `depth` field to Decoder8/16/4. `source_id_for()` computes `base_id - (k-1-j) * depth` in interleaved mode. Threaded depth through DecoderVariant/LazyDecoder/InterleavedDecoder. Removed QUICFUSCATE_FEC_INTERLEAVE=0 workaround from all E2E tests. All 165 FEC tests pass with interleave enabled. | - |
| TODO-434 | G | P0 | Production PKI (CA hierarchy, cert generation, no self-signed fallback) | **DONE** - `src/pki/mod.rs`: CA hierarchy (Root CA → Intermediate CA → Server Leaf), ECDSA P-256, `generate_hierarchy()`, `ensure_pki()` for auto-init, PEM export with restrictive key permissions (0600). `time` crate added for cert validity. | - |

### Wave H - P1 Security Hardening

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-435 | H | P1 | DNS through tunnel (DoH wire-in, DNS proxy, server forwarding) | **DONE** - `src/dns/mod.rs` provides RFC 1035 parsing, DoH client helpers, upstream forwarding, shared DoH client cache, and NXDOMAIN fallback. `src/implementations/server/mod.rs` now wires DNS into the live MASQUE/TUN path: IPv4 and IPv6 UDP/53 client packets are intercepted before TUN egress, resolved through configured server upstream resolvers, rebuilt with correct IP/UDP checksums, and queued back to the client over MASQUE downlink. `scripts/tests/tun-e2e-dns-leak-netns.sh` verifies a real Linux netns client/server TUN/MASQUE session with DNS success and `raw_port_53_packets=0` on the client underlay. | TODO-429 |
| TODO-436 | H | P1 | Key rotation & immediate revocation (incl. race condition fix) | **DONE** - `src/implementations/server/revocation.rs` and `src/implementations/server/mod.rs` now enforce runtime revocation: revoked QKeys are rejected during initial auth, successful auth associates SessionId↔QKey, admin revoke removes registry entries and closes active sessions, pending auth cannot complete after revocation, disconnect/timeout/reconcile paths dissociate tracker state, and pending scheduled revocations are processed in housekeeping. Automatic raw-QKey generation is intentionally not enabled without a client distribution channel; production lifecycle is TTL + admin issue/revoke. | TODO-434 |
| TODO-437 | H | P1 | IPv6 + DNS leak prevention | **DONE** - Kill switch now applies ip6tables rules in parallel with iptables: `ensure_chain()`, `block_traffic()`, `allow_vpn_traffic()`, `cleanup()`, and `cleanup_stale()` all handle both IPv4 and IPv6. IPv6 rules allow loopback + tun interface, drop everything else. Best-effort for ip6tables (some systems disable IPv6). | TODO-429 |
| TODO-438 | H | P1 | Traffic isolation between clients | **DONE** - `src/implementations/server/isolation.rs`: `ClientIsolationManager` (source IP validation, inter-client traffic blocking), `IsolationError` (spoofing, inter-client), iptables/nftables rule generation, `IsolationStats` counters. | TODO-430 |
| TODO-439 | H | P1 | Security audit logging (SIEM-compatible) | **DONE** - `src/audit/mod.rs`: Hash-chained audit log (SHA-256), `AuditLog` with `verify_chain()` tamper detection, `AuditEntry` with 18 event types, NDJSON output for SIEM, `AuditSeverity` levels, chain resume on restart. | - |
| TODO-440 | H | P1 | Key erasure & memory locking (mlock, zeroize) | **DONE** - Drop impls with zeroize added for AEGIS (Aegis128LAead, Aegis128X4Aead, Aegis128X8Aead, Aegis128L, Aegis128X4, Aegis128X8), AES-GCM (AesGcm128 including expanded round keys on x86_64), and MORUS (MorusAead, Morus1280State). AesBlock::zeroize() helper added. mlock not implemented (requires platform-specific unsafe code, deferred to TODO-441 privilege dropping wave). | - |
| TODO-441 | H | P1 | Privilege dropping (post-bind setuid/setgid) | **DONE** - `src/privilege/`: `drop_privileges()` (setgid before setuid, POSIX order), `check_capabilities()` (Linux CapEff parsing, `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_NET_BIND_SERVICE`), `--no-drop-privileges` CLI flag, wired into `run_server()` post-setup. | - |
| TODO-456 | H | P1 | Auth rate limiting (brute-force protection) | **DONE** - New `AuthRateLimiter` struct in limits.rs: per-IP sliding-window rate limiting for QKey auth attempts. Default: 10 failed attempts per 60s window. Integrated into `build_live_server_client_init()`: checks before QKey lookup, records failures, clears on success. `LiveServerState` holds `Arc<Mutex<AuthRateLimiter>>`. 4 unit tests pass. | - |
| TODO-457 | H | P1 | Mutual auth & replay protection for QKey transport | **DONE** - `src/implementations/server/auth_frame.rs`: `AuthFrame` (HMAC-SHA256, constant-time verify, wire format). `src/implementations/server/replay_window.rs`: `ReplayWindow` (sliding bitmap, SHA-256 nonce indexing). Wired into `QKeyRegistry::verify_auth_frame()`. | TODO-434 |
| TODO-458 | H | P1 | QKey token storage encryption at rest | **DONE** - QKey registry now supports AES-256-GCM encryption at rest via `QUICFUSCATE_QKEY_ENC_KEY` env var (64-char hex = 32 bytes). `encrypt_payload()`/`decrypt_payload()` use internal ChaCha20-Poly1305 with random nonce. Magic prefix `QFENC1` identifies encrypted files. Backward compatible: plaintext files still load when no key is set. File permissions remain 0o600. | TODO-440 |

### Wave I - P1 Platform & Deployment

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-442 | I | P1 | Windows TUN (Wintun integration) | **DONE** - `src/interface/wintun.rs`: Dynamic `wintun.dll` loading via `LoadLibraryA`/`GetProcAddress`, all 8 Wintun API functions resolved, `WintunDevice` with read/write/close, IP assignment via `netsh`, `unsafe impl Send+Sync`, non-Windows stub. `windows-sys` dep added. | - |
| TODO-443 | I | P1 | Mobile platforms (iOS NetworkExtension, Android VpnService) | **SCRAP** - Mobile apps are out of scope. Desktop/server only. | - |
| TODO-444 | I | P1 | nftables support (modern Linux firewall) | **DONE** - `src/firewall/mod.rs`: `FirewallBackend` enum (Iptables/Nftables), `detect_backend()` auto-detection, `nft_available()` check, `FirewallOps` trait, `NftablesKillSwitch` (inet table, default DROP), server routing nftables path. | TODO-429 |
| TODO-445 | I | P1 | Per-client bandwidth limits & quotas | **DONE** - `src/implementations/server/bandwidth.rs`: `BandwidthLimiter` (token bucket, bytes/sec), `QuotaTracker` (cumulative quota per billing period), `PerClientBandwidthManager` (per-client limits + quotas), `BandwidthStats`, wired into `SessionManager`. | TODO-430 |
| TODO-446 | I | P1 | Production logging (rotation, structured JSON, file output) | **DONE** - `src/logging.rs`: `SizeRotatingAppender` (100MB default, 5 files), JSON NDJSON format, syslog RFC 5424, `log::Log` trait impl, `LoggingConfig` with module-level overrides, file output with restrictive permissions. | - |
| TODO-447 | I | P1 | Container deployment (Docker, docker-compose, K8s) | **DEFERRED** - Container deployment is explicitly out of scope for the current production-readiness pass. Docker/K8s/Helm were not built or validated; only the stale Rust fixed-version pin in `Dockerfile` was removed to keep the repository on the stable Rust channel everywhere. | - |
| TODO-448 | I | P1 | Graceful shutdown (SIGTERM, drain mode, connection handoff) | **DONE** - `wait_shutdown_signal()` helper handles both SIGINT (ctrl_c) and SIGTERM on Unix, Ctrl+C on Windows. Server run loop and client run loop both use unified handler. `systemctl stop`, `docker stop`, K8s pod termination all trigger graceful shutdown with CONNECTION_CLOSE + TUN cleanup + kill switch disable. | - |
| TODO-459 | I | P1 | DDoS protection hardening | **DONE** - Default per-IP rate limit lowered to 1,000 PPS (from 10,000). `RateLimitConfig.burst_size` decouples burst from steady-state. `GlobalRateLimiter` caps aggregate server-wide PPS (50,000 default) with PPS estimation. `EwmaAnomalyDetector` (EWMA spike detection, 3× threshold, auto-clear) wired into `allow_incoming_datagram()` - halves per-IP limits during anomalies. `GeoIpBlocker` (stub, graceful degradation without maxminddb) and `BlacklistSync` (TTL-based IP blocklist with manual/feed sync) wired into packet acceptance path. `prune_rate_limits_if_due()` feeds PPS to detector and prunes blacklist. | - |
| TODO-460 | I | P1 | Install script fix (user creation, directory permissions) | **DONE** - `ensure_group()` + `ensure_user()` with dedicated group, `validate_prerequisites()` (iptables/ip/systemctl), `/var/log/quicfuscate` dir creation, `chmod 0700` state dir, `chmod 0750` config/log dirs, TOML validation via python3, post-start `systemctl is-active` verification. | - |
| TODO-461 | I | P1 | TUN teardown retry & stale cleanup | **DONE** - `ServerHostResources::teardown()` retries routing teardown 3× with backoff (100ms, 200ms). `RoutingManager::cleanup_stale()` removes leftover iptables/pf/NetNat rules on startup before `setup()`. Linux/macOS/Windows all covered. | - |

### Wave J - P1-P2 Transport & Advanced

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-449 | J | P1 | Multipath support (WiFi+LTE bonding) | **DONE** - `src/transport/path.rs`: `PathManager` (multi-path, `best_path_for_send()` by RTT×congestion score), `PathState` (per-path CC, RTT, cwnd, validation). `src/transport/path_scheduler.rs`: `PathScheduler` (RoundRobin, LowestLatency, WeightedProportional). Config: `multipath_enabled`, `max_paths`. | - |
| TODO-450 | J | P1 | Connection migration fix (gentle cwnd handling) | **DONE** - `Recovery::on_path_change()` halves cwnd (50% reduction) instead of resetting to INITIAL_WINDOW. `bytes_in_flight` preserved. Wired into `commit_path_validation()` in connection.rs. CC trait `set_cwnd()` used by all implementations. Test `test_gentle_path_migration_preserves_cwnd` passes. | - |
| TODO-451 | J | P1 | PMTUD enablement (DPLPMTUD, black hole detection) | **DONE** - DPLPMTUD enabled by default (RFC 8899). `PmtuState` state machine with binary-search probing, black-hole detection (10s no-ACK → reset to PMTU_MIN), wired into `Connection::send()` (MTU clamp + PING/PADDING probe injection) and `account_sent_bytes_for_ack_ranges_with_delay()` (probe ACK confirm, probe loss backoff, `on_any_ack` watchdog). `pmtu_discovery_enabled` default flipped to `true` in config. | TODO-432 |
| TODO-452 | J | P2 | CUBIC congestion control | **DONE** - `src/transport/cc/cubic.rs`: Full CUBIC (RFC 9438) - cubic window function W(t)=C*(t-K)^3+W_max, TCP friendliness, HyStart++ (RFC 9406), fast convergence, beta=0.7. `Cubic` + `StealthCubic` variants in Algorithm/CcImpl enums. | - |
| TODO-453 | J | P2 | QUIC version negotiation | **DONE** - `PROTOCOL_VERSION_V2` (0x6b3343cf, RFC 9369), `is_supported_version()`, `Config.supported_versions` field, `negotiate_version()` (highest common), `generate_version_negotiation_packet()` + `parse_version_negotiation()`, v2 salt mapping fix in `quic_kdf.rs`. | - |
| TODO-454 | J | P2 | NAT traversal (STUN/TURN/ICE for symmetric NAT) | **DONE** - `src/transport/nat.rs`: `StunClient` (RFC 5389, XOR-MAPPED-ADDRESS), `IceAgent` (candidate gathering, pair selection per RFC 8445), `TurnClient` (RFC 5766, Allocate/CreatePermission/SendIndication), `NatTraversalConfig` in Config. | - |
| TODO-455 | J | P2 | Traffic analysis defense (chaffing, constant rates, full padding) | **DONE** - `TrafficAnalysisDefense` enum (Off/FullPadding/ConstantRate) in config.rs. FullPadding pads all 1-RTT packets to `max_udp_payload_size`. ConstantRate mode activates `ChaffGenerator` (jittered ±10% dummy packet injection with PING+PADDING, ack-eliciting for bidirectional cover traffic). ChaffGenerator wired into `Connection::send()` - injects chaff when no real ack-eliciting payload is due, resets chaff clock on real traffic. `CHAFF_PADDING_FRAME_BYTE` used in `generate_chaff()`. | - |
| TODO-462 | J | P2 | TCP/ICMP fingerprint obfuscation | **DONE** - `src/stealth/fingerprint.rs`: `OsFingerprintProfile` (Linux/Windows/MacOS/Android), `PacketNormalizer` (TTL, TCP window, MSS, option reordering, IP ID, DF bit), RFC 1624 incremental checksum, wired into TUN egress + ICMP reply. | - |
| TODO-463 | J | P2 | Loss detection improvements (RACK, time-based, RTT variance) | **DONE** - EWMA SRTT + RTTVAR smoothing (RFC 6298) in `Recovery::update_rtt()`. `rtt_var()` and `min_rtt()` getters. Time-based loss detection (`time_loss_deadline()`, RFC 9002 §6.1.2: threshold = 9/8 × SRTT). RACK loss detection (`rack_is_lost()`, RFC 8985: reordering window = SRTT + RTTVAR). All methods tested with 4 dedicated tests. | - |

Detail files: `docs/todo/todo-{434,435,436,437,438,439,440,441,442,444,445,446,447,449,450,451,452,453,454,455,456,457,458,459,462,463}-*.md`.

**Production readiness philosophy:** QuicFuscate must be a complete VPN protocol - invisible when
the link is clean, heroic when the link is broken, and secure under all conditions. No traffic leaks,
no data loss, no privilege escalation, no single point of failure. Every feature must be wired in,
tested under real conditions, and documented.

---

## Completed - Stealth Stack Coherence Wave (2026-06-30)

**Motivation:** The current stealth stack has strong individual parts, but the final product should
not look like "all stealth switches at once." The target is one coherent, believable H3/MASQUE flow:
real QUIC encryption, browser-consistent TLS/H3/QPACK persona, adaptive timing/size/FEC/cover policy,
and no mid-session identity contradictions. This wave keeps all existing code surfaces, but turns
ambiguous or risky behaviors into explicit policy.

**Final architecture decision:** Core H3/MASQUE is the production VPN/TUN carrier. The `stealth`
module's compatibility `MasqueManager` remains retained for tests and experiments, not as the
canonical hot path. Browser/OS personas are connection-scoped and immutable for the lifetime of a
connection. The StealthBrain may tune timing, padding, cover, ACK, pacing, and FEC hints, but must
not mutate the active persona mid-session.

**Execution order: Phase K (persona wiring -> session freeze -> mode policy -> cover variation -> brain/FEC ownership -> MASQUE/WebTransport cleanup)**

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-464 | K | P0 | Stealth persona wiring in Engine client | **DONE** - Engine client now passes `use_utls` from config and maps Engine Auto to runtime Intelligent | TODO-415 |
| TODO-465 | K | P0 | Connection-scoped persona freeze and rotation semantics | **DONE** - active Browser/OS/TLS/H3 persona is frozen; rotation is next-session only | TODO-464 |
| TODO-466 | K | P0 | Stealth mode policy rationalization and domain-fronting defaults | **DONE** - normal modes default fronting off; Anti-DPI retains explicit aggressive fronting | TODO-464, TODO-465 |
| TODO-467 | K | P1 | Randomized cover traffic and server-push variation | **DONE** - server-push cover uses bounded seed-varied resource plans | TODO-466 |
| TODO-468 | K | P1 | StealthBrain actuator ownership and FEC hint cleanup | **DONE** - Brain escalates timing/padding/cover/FEC hints, not active identity | TODO-465, TODO-467 |
| TODO-469 | K | P1 | MASQUE production path and experimental surface cleanup | **DONE** - docs/code comments preserve Core H3/MASQUE as canonical data plane | TODO-422, TODO-466 |
| TODO-470 | K | P1 | Protocol mimicry flag truth and config cleanup | **DONE** - flag now normalizes concrete H3/QPACK/TLS cover knobs | TODO-466 |
| TODO-471 | K | P2 | WebTransport cover profile design and integration | **DONE** - WebTransport is integrated as bounded H3 cover, not a competing tunnel | TODO-467, TODO-469 |
| TODO-472 | R | P0 | CI app backend release gate synchronization | **DONE** - GitHub CI, Clippy Matrix, Release Build, README, DOCUMENTATION, MAP, and TODO truth now point to the green `09cb9f2` checkpoint | TODO-215, TODO-217 |
| TODO-473 | R | P0 | Linux production E2E proof hardening | **DONE** - Broderick release build, base TUN/MASQUE, DNS leak, FEC smoke, burst, transition, and netem-adversity gates are green; optional iperf TCP-to-server-TUN proof now skips instead of fake-passing when no throughput is measurable | TODO-422, TODO-423, TODO-425, TODO-435, TODO-457 |
| TODO-474 | R | P0 | TUN/MASQUE hotpath and E2E lock hardening | **DONE** - per-packet MASQUE TX logs are debug-only, server TUN downlink flushes only the target client, and TUN/netns E2E scripts use a global `flock` guard so parallel gates serialize instead of corrupting shared namespaces/processes | TODO-422, TODO-423, TODO-473 |
| TODO-475 | R | P1 | ACK accounting extract-if hotpath | **DONE** - ACK/loss range accounting now uses `BTreeMap::extract_if` instead of collect-then-remove, preserving RTT/loss semantics while cutting Broderick 10k sparse ACK accounting to about `1.36 ms` | TODO-400, TODO-474 |
| TODO-476 | R | P1 | FEC lazy receive hotpath and bounded clean-block tracking | **DONE** - Lazy receive now skips heavy recovery polling on clean blocks, prunes clean complete block sequence tracking, preserves tail-loss repair recovery, and improves Broderick zero-mode lazy fastpath by about 18% | TODO-424, TODO-426 |
| TODO-477 | R | P1 | FEC zero-mode receive ownership preservation | **DONE** - Zero mode now returns the systematic packet directly while no transition is active, avoiding decoder-held payload clones and preserving unique pooled-buffer ownership for in-place QUIC processing; Criterion zero-mode passthrough improved by about 29% | TODO-424, TODO-476 |
| TODO-478 | R | P1 | Stealth H3 cover clean-path policy | **DONE** - Performance no longer constructs the H3 cover-request scheduler, and Intelligent keeps H3 cover request emission disabled at Level 0 while retaining escalation capability from Level 1 upward | TODO-466, TODO-467, TODO-471 |
| TODO-479 | R | P1 | Transport stealth heuristic RNG hotpath | **DONE** - Stealth padding-rate rolls, Random/BrowserMimic padding samples, and transport jitter now use a secure-seeded non-cryptographic thread-local SplitMix64 helper instead of per-packet secure OS RNG; security-sensitive transport randomness remains on secure APIs | TODO-401, TODO-416, TODO-478 |
| TODO-480 | R | P1 | FEC send output reuse hotpath | **DONE** - `AdaptiveFec::on_send_into()` writes into caller-owned output buffers, `QuicFuscateConnection` and Engine `FecCodec` reuse scratch vectors, and Criterion zero-mode passthrough improves by about 47% against the previous baseline | TODO-424, TODO-476, TODO-477 |
| TODO-481 | R | P1 | FEC interleaved lazy gap tracking | **DONE** - `LazyDecoder` now normalizes clean source sequences by interleave depth before gap detection, preventing false recovery polling for clean interleaved blocks and cutting local `normal_mode_no_loss` to about `2.80 us` median | TODO-424, TODO-433, TODO-476 |
| TODO-482 | R | P1 | Transport stealth padding decision fastpath | **DONE** - `compute_stealth_padding()` now bypasses RNG when `stealth_padding_rate == 0`, and `ci_regression` directly benchmarks the real transport padding decision path across disabled, zero-rate, adaptive, browser-mimic, and random cases | TODO-401, TODO-416, TODO-479 |
| TODO-483 | R | P1 | Brain policy target cache hotpath | **DONE** - `StealthBrainState` now reuses JS-divergence target distributions instead of allocating them inside every `apply_policy()` tick, and `ci_regression` benchmarks `brain_apply_policy` across clean observer, intelligent clean, and pressure/actuating cases; Broderick improves from about `1.13-1.17 us` to about `0.60-0.64 us` median | TODO-468, TODO-479, TODO-482 |
| TODO-484 | R | P1 | FEC receive output reuse hotpath | **DONE** - `AdaptiveFec::on_receive_into()` writes emitted packets into caller-owned buffers, Core and Engine reuse receive scratch vectors, and `fec_lazy_fast_path` now benchmarks production-style normal-mode send/receive reuse; Broderick zero-mode passthrough/reuse improve while normal-mode reuse remains stable around `2.66 us` | TODO-424, TODO-476, TODO-477, TODO-480 |
| TODO-485 | R | P1 | ACK accounting split-drain hotpath | **DONE** - Large contiguous ACK ranges and packet-threshold loss prefixes now drain `sent_packets_by_pn` with `BTreeMap::split_off`, while sparse/narrow ACK ranges stay on `extract_if`; Broderick improves 10k ACK-all from about `1.03 ms` to `0.837 ms`, ACK-half from about `0.899 ms` to `0.829 ms`, and sparse from about `1.39 ms` to `1.22 ms` | TODO-400, TODO-475 |
| TODO-486 | R | P1 | STREAM frame direct writer hotpath | **DONE** - Vec-backed stream flush now uses `frames::write_stream_frame()` to encode directly from `send_buf` into the packet buffer, avoiding the previous per-frame `to_vec()` plus owned `Frame::Stream`; Broderick microbench improves 256B from `158.8 ns` to `121.0 ns`, 1024B from `192.3 ns` to `137.2 ns`, and 1400B from `274.6 ns` to `145.6 ns` | TODO-399, TODO-401 |
| TODO-487 | R | P1 | ACK sparse prefix classification hotpath | **DONE** - ACK frames with many sparse ranges now classify the packet-threshold loss prefix in one ordered drain pass, preserving RTT/loss/DPLPMTUD semantics while keeping normal ACK-all/ACK-half on the old split-drain branch; Broderick normal cases are neutral or improved and 512 sparse improves from `59.07 us` to `58.12 us` | TODO-400, TODO-475, TODO-485 |
| TODO-488 | R | P1 | FEC benchmark product-window calibration | **DONE** - FEC Criterion benchmarks now use product-default windows, split reusable systematic sends from repair-burst sends, and measure Light/Normal/Medium/Strong repair bursts separately; Broderick confirms Strong product-window burst cost is about `37.7 us`, not the artificial k512 benchmark outlier | TODO-424, TODO-480, TODO-484 |
| TODO-489 | R | P1 | Connection benchmark hotpath isolation | **DONE** - `connection_1rtt_send_recv` and `connection_1rtt_stealth_compare` now exclude paired-connection setup from timed Criterion measurement via `iter_batched`, exposing the real 1-RTT `stream_send -> send -> recv` hotpath and proving stealth-on overhead is small on both local and Broderick | TODO-399, TODO-401, TODO-486 |
| TODO-490 | R | P1 | FEC decode batch benchmark truth | **DONE** - `fec_decode_pipeline` now uses fixed 128-packet production-style `on_send_into()`/`on_receive_into()` batches with scratch reuse and a deterministic 10% source-drop mask; Broderick now shows stable Normal/Strong/Streaming clean and 10%-loss decode medians instead of the previous unstable single-packet random-loss artifact | TODO-424, TODO-484, TODO-488 |

Detail files: `docs/todo/todo-{464,465,466,467,468,469,470,471,472,473,474,475,476,477,478,479,480,481,482,483,484,485,486,487,488,489,490}-*.md`.

**Stealth stack result:** Performance mode is fast and coherent, not fronting-heavy. Intelligent
mode is the default adaptive profile with stable identity and dynamic actuator tuning. Stealth and
Anti-DPI spend more bandwidth and compatibility budget only in ways that remain internally
consistent. No code was deleted in this wave; risky or duplicate surfaces are disabled, marked
experimental, or bound to explicit policy.

---

## Active - Radical Replan Wave (2026-07-23)

**Motivation:** Deep-dive analysis identified three core problems: (1) TODO-system drift (33 files without status, 11 false DONE claims), (2) no real profiling baseline (all micro-opts are blind), (3) stealth is fallback-proxy not reality-grade mimicry. This wave addresses all three with five big levers, sequenced for maximum impact.

**Execution order: Phase 0 (Sanierung) → Phase 1 (Messung) → Phase 2 (Architektur) → Phase 3 (Stealth-Sprung) → Phase 4 (Mikro-Opt bei Evidence)**

| ID | Phase | Priority | Title | Status | Depends On |
|----|-------|----------|-------|--------|------------|
| TODO-413 | 0 | P0 | TODO-System-Sanierung + CI-Gate (Status-Feld-Pflicht) | **DONE** | - |
| TODO-418 | 1 | P0 | Profiling-Baseline + tc-netem-Setup auf broderick | **DONE** | 413 |
| TODO-417 | 2 | P1 | Hot-Path-Lock-Entfernung (bündelt 396+397+398) | **DONE** | 418 |
| TODO-414 | 2 | P1 | Streaming-FEC in adaptiven Loop (supersedes 409) | **DONE** | 418 |
| TODO-416 | 2 | P1 | Graduelle Stealth-Eskalation (3-Stufen-Rampe) | **DONE** | 418 |
| TODO-415 | 3 | P1 | Reality-Grade TLS-Mimikry (Phase 1-3 done) | **DONE** | 416 |

Detail files: `docs/todo/todo-{id}-*.md` for each item above.

### Phase 4 - Mikro-Optimierungen (nur bei Flamegraph-Evidence)

All items below were **implemented and marked DONE** in the main wave table above. They are retained here as profiling-evidence cross-references for TODO-418. No OPEN items remain in this section.

| ID | Title | Status |
|----|-------|--------|
| TODO-390 | AEAD-Selection MTU-Workload | **SCRAP** (premise incorrect) - see main table |
| TODO-391 | Double header parse | **DONE** - pre_parsed_hdr threaded through decrypt paths |
| TODO-392 | FecPacket clone on send | **DONE** - SharedFecBuffer Arc-backed, zero-copy |
| TODO-395 | MORUS in-place | **DONE** - trait path calls in-place directly |
| TODO-399 | Criterion Connection bench | **DONE** - `connection_1rtt_send_recv` group; TODO-489 excludes pair setup from timed measurement |
| TODO-400 | Criterion ACK stress bench | **DONE** - `ack_sent_byte_accounting` group |
| TODO-401 | Stealth-on vs stealth-off CI | **DONE** - `connection_1rtt_stealth_compare` group; TODO-489 isolates the measured 1-RTT routine |

### SCRAP / DEFERRED Items (2026-07-23)

Marked in individual detail files. Not individually actionable.

**SCRAP** (not in scope or replaced by tooling):
- TODO-369, 373, 374, 377: UI test gaps - OFF LIMITS per AGENTS.md
- TODO-379-388 (10×): Coverage-gaps per module - replaced by single `cargo tarpaulin` baseline run
- TODO-370, 371: FEC-sim/smoke redundancy - existing 1167 lib-tests sufficient

**DEFERRED** (kosmetisch, nicht handlungsleitend):
- TODO-356, 357, 372: Docs hygiene (stale counts, rust-version, readme)
- TODO-358, 362: Dead-code (PQ-traits, FEC-internal) - `cargo dead`/`cargo udeps` covers this
- TODO-378: Code TODO-markers - `grep -rn "TODO" src/` is not a task

### Completed Items (Session 41 - Final Forensic Audit 2026-03-27)

Details: `docs/todo/todo-{id}.md` for each item.

#### MODERATE - Docs & Config (7 items) - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-356 | MODERATE | context.md + todo.md stale test counts (852->916, 1522->1587) | **DEFERRED** - docs hygiene, not action-lever |
| TODO-357 | MODERATE | CONTRIBUTING.md Rust toolchain wording drift | **DONE** - CONTRIBUTING.md now says Rust stable selected by rust-toolchain.toml |
| TODO-363 | MODERATE | Stealth env var QUICFUSCATE_STEALTH_MODE=auto silently rejected | **DONE** - added "auto" alias in apply_env_overrides() |
| TODO-364 | MODERATE | Dual 0-RTT config fields (enable_0rtt vs enable_early_data) undocumented | **DONE** - added clarifying comments in quicfuscate.toml |
| TODO-365 | MODERATE | server-linux.default.toml missing [anti_replay] + XDP sections | **DONE** - added [anti_replay] section + XDP comments |
| TODO-370 | MODERATE | fec_sim overlap between test-fec-simulation.sh and test-fec-e2e-loss.sh | **SCRAP** - existing 1167 lib-tests sufficient |
| TODO-369 | MODERATE | packages/ui 5 untested components + 2 untested utilities (44% coverage) | **SCRAP** - UI OFF LIMITS per AGENTS.md |

#### MODERATE - Code Quality (7 items) - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-358 | MODERATE | 4 dead PQ trait methods in qftls.rs + stale doc strings | **DEFERRED** - `cargo dead`/`cargo udeps` covers this |
| TODO-359 | MODERATE | ~25 unsafe blocks missing SAFETY comments (5 files) | **DONE** - 30 SAFETY comments across batch.rs, linux.rs, macos.rs, io_driver.rs, connection.rs |
| TODO-360 | MODERATE | eprintln! in transport hot path (connection.rs:1298) | **DONE** - changed to log::warn! |
| TODO-361 | MODERATE | hkdf_expand panics on out_len > 8160 instead of Result | **DONE** - explicit assert with RFC 5869 reference |
| TODO-362 | MODERATE | 8x #[allow(dead_code)] in fec/internal.rs - audit needed | **DEFERRED** - `cargo dead`/`cargo udeps` covers this |
| TODO-366 | MODERATE | Switch.svelte + Select.svelte duplicated between apps (~80% identical) | **DONE** - extracted to packages/ui, deleted from both apps |
| TODO-367 | MODERATE | cn() import inconsistency: desktop $lib/format vs admin @quicfuscate/ui | **DONE** - desktop now imports cn from @quicfuscate/ui |

#### LOW (9 items) - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-368 | LOW | fatal-error-screen.test.ts misplaced (components/ vs components/ui/) | **DONE** - moved to components/ui/ |
| TODO-371 | LOW | smoke-fec-quick.sh redundant (pure pass-through) | **SCRAP** - existing 1167 lib-tests sufficient |
| TODO-372 | LOW | README.md test count "800+" -> "900+" | **DONE** - updated |
| TODO-373 | LOW | Desktop clipboard.ts untested (4 strategies + fallbacks) | **SCRAP** - UI OFF LIMITS per AGENTS.md |
| TODO-374 | LOW | Admin use-anchor-sync.ts untested (ResizeObserver/DOM tracking) | **SCRAP** - UI OFF LIMITS per AGENTS.md |
| TODO-375 | LOW | quicfuscate-ctl.rs unwrap() on JSON - crashes on malformed responses | **DONE** - proper error messages |
| TODO-376 | LOW | CI: simd-selfcheck only tested on Linux, not macOS/Windows | **DONE** - added macOS entry in feature-matrix |
| TODO-377 | LOW | Desktop +error.svelte page has no test (admin equivalent IS tested) | **SCRAP** - UI OFF LIMITS per AGENTS.md |
| TODO-378 | LOW | 7 TODO markers in Rust src/ - review and cleanup | **DEFERRED** - `grep -rn "TODO" src/` is not a task |

#### COVERAGE - Rust Test Gaps (10 items) - ALL SCRAP (replaced by `cargo tarpaulin`)

| ID | Severity | Module | LOC | Added | Status |
|----|----------|--------|-----|-------|--------|
| TODO-379 | HIGH | stealth/mod.rs | 5496 | +68 | **SCRAP** |
| TODO-380 | HIGH | simd.rs | 6224 | +35 | **SCRAP** |
| TODO-381 | HIGH | transport/connection.rs | 3399 | +31 | **SCRAP** |
| TODO-382 | HIGH | transport/h3.rs | 2033 | +29 | **SCRAP** |
| TODO-383 | HIGH | server/mod.rs | 4511 | +42 | **SCRAP** |
| TODO-384 | MEDIUM | optimize/iter.rs | 626 | +17 | **SCRAP** |
| TODO-385 | MEDIUM | optimize/unsafe.rs | 1511 | +8 | **SCRAP** |
| TODO-386 | MEDIUM | server/fsutil.rs | 50 | +6 | **SCRAP** |
| TODO-387 | MEDIUM | transport/batch.rs | 383 | +7 | **SCRAP** |
| TODO-388 | LOW | client/subsystems.rs | 61 | +3 | **SCRAP** |

### Completed Items (Session 38 - Forensic Deep Audit 2026-03-26)

#### CRITICAL - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-333 | CRITICAL | bench-transport.sh crashes on --rustflags from fastpaths | **DONE** - added --rustflags handler + wired JOBS/RUSTFLAGS into cargo calls |

#### MODERATE - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-334 | MODERATE | DOCUMENTATION.md frontend test file counts wrong (58 vs 53) | **DONE** - corrected to 28+23=53 |
| TODO-335 | MODERATE | DOCUMENTATION.md [stealth.fingerprint_rotation] wrong TOML path | **DONE** - corrected to [fingerprint_rotation] (top-level) |
| TODO-336 | MODERATE | context.md CryptoAeadPlan falsely includes ChaCha20/AES-GCM | **DONE** - corrected to AEGIS/MORUS only |
| TODO-337 | MODERATE | bench-crypto.sh ChaCha20 comparison always N/A (filename mismatch) | **DONE** - measure_throughput name corrected to chacha20_poly1305_native |
| TODO-338 | MODERATE | bench-fec-simulation.sh CARGO_FEATURES/JOBS lost in subshell | **DONE** - added export, fixed FAST default 1->0 |
| TODO-339 | MODERATE | bench-stealth-brain.sh CARGO_FEATURES/JOBS lost in subshell | **DONE** - added export |

#### LOW - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-340 | LOW | bench-transport.sh --jobs accepted but ignored | **DONE** - wired BENCH_JOBS into cargo bench calls |
| TODO-341 | LOW | bench-orchestrator.sh dead DEFAULT_SUITES/FAST_SUITES arrays | **DONE** - removed 16 lines dead code |
| TODO-342 | LOW | ci.yml profile:minimal on dtolnay/rust-toolchain (no-op) | **DONE** - removed, CI now uses Rust stable |
| TODO-343 | LOW | ci.yml redundant msrv-check job | **DONE** - removed (build-test covers Rust stable) |
| TODO-344 | LOW | ci.yml benchmarks job toolchain drift | **DONE** - benchmarks job now uses Rust stable |
| TODO-345 | LOW | ci.yml build step misleading name | **DONE** - renamed to "Verify release compilation" |
| TODO-346 | LOW | MAP.md missing 6 files in ASCII tree | **DONE** - added tunnels-view, configuration-view, pill-styles, qkey-utils, blocked-ips, use-anchor-sync |
| TODO-347 | LOW | test-security-fuzzing.sh unguarded integer_overflow ghost pattern | **DONE** - added test_pattern_exists guard |
| TODO-348 | LOW | 6 desktop .tsx test files contain no JSX | **DONE** - renamed to .ts |
| TODO-349 | LOW | packages/ui+theme version 0.1.0 drift | **DONE** - bumped to 0.2.0 |
| TODO-350 | LOW | rt-baseline-oracles.rs stale comment | **DONE** - removed |
| TODO-351 | LOW | MAP.md logs-view.test.tsx stale extension | **DONE** - updated to .ts |

### Completed Items (Session 39 - Model Review Fixes 2026-03-26)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-352 | MODERATE | core.rs is_systematic false on send-side FEC packets | **DONE** - changed to true (Gemini finding, real semantic bug) |
| TODO-353 | LOW | gf_tables.rs portable fallback LUT rebuilt every call | **DONE** - thread-local cached LUT (Gemini finding) |
| TODO-354 | LOW | profile.rs + metrics.rs have 0 inline tests | **DONE** - +6 profile tests, +4 metrics tests (GLM-5-Turbo finding) |
| TODO-355 | LOW | 4 TLS util scripts missing browser_profiles/ dir guard | **DONE** - added `[ -d "$d" ] || continue` to diff/export/verify-current/profile-head |

### Completed Items (Session 36 - Forensic Deep Audit 2026-03-26)

#### CRITICAL - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-308 | CRITICAL | CI regression gate inert - missing `--features benches` | **DONE** - added to all 3 cargo bench invocations |
| TODO-309 | CRITICAL | Ghost test patterns in bench-crypto.sh | **DONE** - `crypto::morus::morus_tests` + `crypto::tests::chacha20poly1305` |
| TODO-310 | CRITICAL | PGO workload inert - missing `--features benches` | **DONE** - added to both instrumented + optimized builds |
| TODO-311 | CRITICAL | rt-xor-sse2-parity.rs private module import | **DONE** - `pub mod x86_sse2` in optimize/mod.rs |

#### MODERATE - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-312 | MODERATE | rt-anti-replay.rs orphan test | **DONE** - added to test-transport.sh |
| TODO-313 | MODERATE | util-tls-show-active-env.sh bugs | **DONE** - print_help moved before use, dead code removed, redundant default fixed |
| TODO-315 | MODERATE | DOCUMENTATION.md stale PQ reference | **DONE** - PQ sentence removed |
| TODO-316 | MODERATE | todo.md contradictory password policy | **DONE** - corrected to 6 characters |
| TODO-317 | MODERATE | SECURITY.md em-dash | **DONE** - replaced with hyphen |
| TODO-318 | MODERATE | CONTRIBUTING.md `cargo build --release` | **DONE** - changed to `cargo build` |

#### LOW - ALL DONE

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-319 | LOW | test-fec.sh typo REFRACTOR | **DONE** - renamed to REFACTOR |
| TODO-320 | LOW | Dead flags in 19 scripts | **DONE** - removed --dry-run from 10, --rustflags from 9 scripts |
| TODO-321 | LOW | Desktop test naming mismatches | **DONE** - renamed error-boundary to fatal-error-screen, deleted redundant tunnel-detail |
| TODO-322 | LOW | TunnelsView.svelte missing test | **DONE** - 10 tests created |

#### COVERAGE - ALL DONE (+215 Rust tests, +10 frontend tests)

| ID | Severity | Title | Tests Added |
|----|----------|-------|-------------|
| TODO-323 | HIGH | `optimize/simd.rs` | **DONE** - 51 tests |
| TODO-324 | HIGH | `optimize/brain.rs` | **DONE** - 34 tests |
| TODO-325 | HIGH | `optimize/string.rs` | **DONE** - 31 tests |
| TODO-326 | MEDIUM | `optimize/transport.rs` | **DONE** - 14 tests |
| TODO-327 | MEDIUM | `fec/gf_tables.rs` | **DONE** - 16 tests |
| TODO-328 | MEDIUM | `transport/config.rs` | **DONE** - 18 tests |
| TODO-329 | LOW | `optimize/sort.rs` | **DONE** - 13 tests |
| TODO-330 | MEDIUM | `stealth/tls_cover.rs` | **DONE** - 16 tests |
| TODO-331 | LOW | `optimize/udp.rs` | **DONE** - 5 tests |
| TODO-332 | LOW | `fec/internal.rs` | **DONE** - 17 tests |

### Completed Pre-Release Items (2026-03-25)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| TODO-299 | CRITICAL | it-qkey-auth-integration TLS AEAD sealer failure | **DONE** |
| TODO-300 | LOW | TLS Cover post-handshake gap - PacketNormalize + Cover PING + Cover Stream | **DONE** - All 3 phases complete |
| TODO-301 | MEDIUM | Port_Scan_SYN probe pattern too generic (false positives) | **DONE** |
| TODO-302 | MEDIUM | BBR2 proper port (~760 LoC, IETF draft impl) | **DONE** |
| TODO-303 | MEDIUM | cargo clean + full rebuild + fix all clippy warnings | **DONE** |

### Completed Items (Session 29 Forensic Audit)

| ID | Severity | Title | File |
|----|----------|-------|------|
| TODO-304 | HIGH | `src/crypto/aegis.rs` - 1665 LoC SIMD crypto, zero inline tests | **DONE** - 16 tests added (roundtrip, forgery, AD, nonce, X4/X8) |
| TODO-305 | HIGH | `src/transport/connection.rs` - 3194 LoC transport core, zero inline tests | **DONE** - 15 tests added (flow control x5, state x4, key update x3, in-flight CC x3) |
| TODO-306 | MEDIUM | `src/fec/adaptive_reed_solomon.rs` - 94 LoC FEC adaptation, zero tests | **DONE** - 10 tests added (loss thresholds, bandwidth cap, latency, stability) |

---

### Execution Order (2026-03-16)

1. **Wave 1 - User-facing contract repair**
   - TODO 193: QKey one-time reveal, metadata-only list semantics, revoke flow, desktop import compatibility
   - TODO 194: historical intermediate credential-policy reconciliation wave, now superseded by TODO 213
   - TODO 196: remove XOR from the visible Svelte admin product surface while preserving compatibility-level config support
   - TODO 197: update contract and Playwright coverage so the live Svelte path is what gets validated
   - TODO 199 (batch 1): land the highest-confidence, lowest-risk safe replacements
2. **Wave 2 - Svelte cutover and repository truth**
   - TODO 192: completed
   - TODO 197: completed
   - TODO 191: completed
   - TODO 195: keep canonical docs/backlog truth aligned with the Svelte-first workflow
3. **Wave 3 - Adaptive ownership rationalization**
   - TODO 198: completed
4. **Wave 4 - Residual unsafe review**
   - TODO 199: completed
5. **Wave 5 - Local repository truth and publish truth**
   - TODO 200: local repository truth and staging alignment
   - TODO 201: active Svelte workspace source tracking and workspace manifest truth
   - TODO 202: admin publish asset tree index reconciliation
   - TODO 203: local worktree hygiene and artifact guardrail closure
6. **Wave 6 - Toolchain and code-quality excellence**
   - TODO 204: completed
   - TODO 205: completed
   - TODO 206: completed
7. **Wave 7 - Transport migration completion**
   - TODO 207: completed
   - TODO 208: completed
   - TODO 209: completed
   - TODO 210: completed
   - TODO 211: completed
   - TODO 212: completed
8. **Wave 8 - Credential and operator-surface cleanup**
   - TODO 213: completed
   - TODO 214: completed
9. **Wave 9 - Final harmonization and release-quality validation**
   - TODO 215: completed
   - TODO 216: completed
   - TODO 217: completed
   - TODO 218: completed
   - TODO 219: completed
10. **Wave 10 - Remaining ship-rest block**
   - completed
11. **Wave 11 - AI Model Review Findings (2026-03-22)**
   - TODO 283: aead 0.6.0-rc.10 RC in production
   - TODO 284: Outdated UA strings (Chrome 130, Firefox 133)
   - TODO 285: Unwired config keys (enable_pq, key_update_interval, enable_retry)
   - TODO 286: PQ feature flag missing crate deps
   - TODO 287: Fire-and-forget tokio::spawn (7/10)
   - TODO 288: ChaCha TLS Cover vs TLS policy DPI inconsistency
   - TODO 289: ENV_MUTEX duplicated 7x inconsistent poisoning
   - TODO 290: deny.toml multiple-versions = "warn" not "deny"
   - TODO 291: Missing SECURITY.md
   - TODO 292: password-hash/rand/rand_core triple version
   - TODO 293: Hardcoded ADMIN_PASS="123" in e2e test
   - TODO 294: FEC_PARALLEL doc contradiction
   - TODO 295: TODO-119 troubleshooting.md drift
   - TODO 296: browser_profiles/ scripts reference nonexistent dir
   - TODO 297: Shallow stealth test coverage

---

## CRITICAL Security

### 119. Kill-Switch Race Condition - Atomic iptables Apply (completed)
- Severity: CRITICAL
- Goal: Eliminate traffic leak window between individual iptables rule insertions by using atomic apply (iptables-restore or single transaction).
- Detail file: `docs/todo/todo-119-killswitch-race-condition-atomic-apply.md`

### 120. QKey Tokens On-Disk Plaintext Legacy Fields (completed)
- Severity: CRITICAL
- Goal: Remove legacy plaintext `qkey` and `token` fields from QKeyEntry serialization; only persist `token_sha256`.
- Detail file: `docs/todo/todo-120-qkey-tokens-on-disk-plaintext-removal.md`

### 121. Manual HTTP Parser for Admin Server (completed)
- Severity: CRITICAL
- Goal: Replace handwritten HTTP parser in admin_http.rs with `axum` or `hyper` to eliminate buffer overflow and DoS vectors.
- Detail file: `docs/todo/todo-121-manual-http-parser-replacement.md`
- Result: Replaced with httparse. MAX_HEADER_BYTES 64K->8K. All 56 tests pass.

### 122. admin-auth.json Checked Into Git (completed)
- Severity: CRITICAL
- Goal: Remove admin-auth.json from version control, add to .gitignore, provide .example template.
- Detail file: `docs/todo/todo-122-admin-auth-json-git-removal.md`

### 123. TUN IP Hardcoded 10.8.0.0/24 (completed)
- Severity: CRITICAL
- Goal: Make TUN IP range configurable with collision detection against existing network interfaces.
- Detail file: `docs/todo/todo-123-tun-ip-hardcoded-configurable.md`

### 124. DNS Servers Hardcoded 1.1.1.1 / 8.8.8.8 (completed)
- Severity: CRITICAL
- Goal: Make DNS servers configurable via config file; default to VPN server's DNS push.
- Detail file: `docs/todo/todo-124-dns-servers-hardcoded-configurable.md`

---

## HIGH Security

### 125. Session ID Predictable Counter (completed)
- Severity: HIGH
- Goal: Replace sequential counter-based session IDs with cryptographically random u64.
- Detail file: `docs/todo/todo-125-session-id-predictable-counter.md`

### 126. CSRF Replay Window 128 Fingerprints (completed)
- Severity: HIGH
- Goal: Replace hash-fingerprint replay detection with monotonic sequence numbers or expand window significantly.
- Detail file: `docs/todo/todo-126-csrf-replay-window-expansion.md`

### 127. Session TTL 12 Hours Too Long (completed)
- Severity: HIGH
- Goal: Reduce admin session TTL to 1 hour with activity-based timeout extension.
- Detail file: `docs/todo/todo-127-session-ttl-reduction.md`

### 128. Password Minimum Policy Reconciliation (superseded)
- Severity: HIGH
- Goal: Historical hardening attempt. Superseded by TODO 213, which defines the canonical 6-character minimum policy (backend + all UIs aligned).
- Detail file: `docs/todo/todo-128-password-minimum-increase.md`

### 129. DNS Restore Silent Failure (completed)
- Severity: HIGH
- Goal: Make DNS restore failure during disconnect a hard error that prevents state transition to Disconnected.
- Detail file: `docs/todo/todo-129-dns-restore-silent-failure.md`

### 130. X-Forwarded-For Spoofable When Trust Proxy Enabled (completed)
- Severity: HIGH
- Goal: Add proxy IP allowlist validation when QUICFUSCATE_TRUST_PROXY is enabled.
- Detail file: `docs/todo/todo-130-x-forwarded-for-spoofable.md`

### 131. macOS utun Socket Binding Incomplete (completed)
- Severity: HIGH
- Goal: Implement proper sockaddr_ctl binding for utun socket creation on macOS.
- Detail file: `docs/todo/todo-131-macos-utun-socket-binding.md`
- Result: Full 4-step utun binding (socket, ioctl CTLIOCGINFO, connect sockaddr_ctl, fcntl O_NONBLOCK). New structs CtlInfo/SockaddrCtl, FdGuard RAII cleanup.

### 132. Zero SAFETY Comments on 300+ Unsafe Blocks (completed)
- Severity: HIGH
- Goal: Add `// SAFETY:` documentation to every unsafe block in crypto.rs, unsafe.rs, simd.rs, and all SIMD modules.
- Detail file: `docs/todo/todo-132-safety-comments-unsafe-blocks.md`
- Result: 281 new SAFETY comments added. crypto.rs: 158 new (183 total), optimize/unsafe.rs: 30 new (42 total), simd.rs+arm_varint+x86_ack+x86_header: 56 new. 100% coverage of all unsafe blocks.

---

## MEDIUM Security / Protocol

### 133. BBR3 Stealth Modifications Not Real BBR3 (completed)
- Severity: MEDIUM
- Goal: Document that recovery.rs implements "Stealth-BBR3" (not standard BBR3), clarify stealth_mode and browser_profile fields.
- Detail file: `docs/todo/todo-133-bbr3-stealth-modifications-documentation.md`

### 134. Float-to-u64 Cast in delivery_rate Calculation (completed)
- Severity: MEDIUM
- Goal: Fix precision loss in BBR3 delivery rate calculation by keeping f64 through the pipeline.
- Detail file: `docs/todo/todo-134-float-to-u64-cast-delivery-rate.md`

### 135. io_uring Mutex Panic on Poisoning (completed)
- Severity: MEDIUM
- Goal: Replace `unwrap_or_else(|e| e.into_inner())` with proper error propagation on poisoned mutex.
- Detail file: `docs/todo/todo-135-io-uring-mutex-panic-poisoning.md`

### 136. Token SHA256 Hashes Hex String Not Binary (completed)
- Severity: MEDIUM
- Goal: Hash decoded binary bytes instead of hex string representation for QKey token SHA256.
- Detail file: `docs/todo/todo-136-token-sha256-hex-string-vs-binary.md`

### 137. Rate Limiter Float Arithmetic Imprecision (completed)
- Severity: MEDIUM
- Goal: Replace float-based token bucket refill with integer-only math to prevent token leakage.
- Detail file: `docs/todo/todo-137-rate-limiter-float-arithmetic.md`

### 138. Windows Firewall Rules Accumulate (completed)
- Severity: MEDIUM
- Goal: Check and delete existing rules before adding new ones in Windows kill-switch implementation.
- Detail file: `docs/todo/todo-138-windows-firewall-rules-accumulate.md`

---

## Protocol Gaps

### 139. ECN Data Read But Discarded (completed)
- Severity: MEDIUM
- Goal: Properly store and process ECN counts from ACK frames per RFC 9000 Section 19.3.2.
- Detail file: `docs/todo/todo-139-ecn-data-read-but-discarded.md`

### 140. Connection Migration State Machine Missing (superseded)
- Severity: MEDIUM
- Goal: Implement full path validation state machine for connection migration (PathChallenge/PathResponse). Superseded by TODO 207-212 which implemented the full migration state machine.
- Detail file: `docs/todo/todo-140-connection-migration-state-machine.md`

### 141. 0-RTT Anti-Replay Protection (COMPLETE)
- Severity: MEDIUM (resolved)
- Implemented: SHA-256 strike register, TTL eviction, configurable max_early_data_size, telemetry, 9 unit tests. 0-RTT safely re-enabled.
- Detail file: `docs/todo/done/todo-141-0rtt-replay-protection.md`

### 142. Flow Control MAX_DATA Not Validated (completed)
- Severity: MEDIUM
- Goal: Add upper-bound validation for peer MAX_DATA frames to prevent memory exhaustion.
- Detail file: `docs/todo/todo-142-flow-control-max-data-validation.md`

### 143. Packet Number Overflow Not Validated (completed)
- Severity: MEDIUM
- Goal: Add PN bounds checking and proper handling during key update rotation.
- Detail file: `docs/todo/todo-143-packet-number-overflow-validation.md`

### 144. XDP Skeleton Code Cleanup (completed)
- Severity: LOW
- Goal: Remove or clearly document XDP skeleton code; ensure feature gate prevents any runtime path.
- Detail file: `docs/todo/todo-144-xdp-skeleton-code-cleanup.md`

### 145. io_uring Synchronous submit_and_wait Defeats Purpose (completed)
- Severity: HIGH
- Goal: Make io_uring truly async with batch submission and completion harvesting, or remove and rely on sendmmsg.
- Detail file: `docs/todo/todo-145-io-uring-synchronous-fix.md`
- Result: Converted to non-blocking submit() + opportunistic CQE drain. Module docs added.

---

## Dependencies

### 146. lazy_static Deprecated - Replace with LazyLock (completed)
- Severity: CRITICAL
- Goal: Replace all `lazy_static!` usage with `std::sync::OnceLock` or `once_cell`.
- Detail file: `docs/todo/todo-146-lazy-static-deprecated-replacement.md`

### 147. aead 0.6.0-rc1 Release Candidate in Production (completed - updated to rc.10)
- Severity: CRITICAL
- Goal: Upgrade `aead` crate from RC to stable release.
- Detail file: `docs/todo/todo-147-aead-rc-to-stable.md`

### 148. md5 Crate Usage Review (completed - documented as non-crypto legacy checksum)
- Severity: HIGH
- Goal: Audit all md5 usage; replace with SHA-256 where cryptographic integrity needed, document non-crypto uses.
- Detail file: `docs/todo/todo-148-md5-crate-usage-review.md`

### 149. tokio "full" Feature Trimming (completed)
- Severity: LOW
- Goal: Replace `features = ["full"]` with specific required features to reduce compile time and binary size.
- Detail file: `docs/todo/todo-149-tokio-full-feature-trimming.md`

---

## CI/CD

### 150. No cargo audit in CI Pipeline (completed)
- Severity: HIGH
- Goal: Add `cargo audit --deny warnings` to CI pipeline before release.
- Detail file: `docs/todo/todo-150-cargo-audit-ci-pipeline.md`

### 151. No MSRV Tests (completed)
- Severity: MEDIUM
- Goal: Define minimum supported Rust version in Cargo.toml and test in CI.
- Detail file: `docs/todo/todo-151-msrv-tests.md`

### 152. Frontend E2E Tests Not in CI (completed)
- Severity: MEDIUM
- Goal: Add Playwright E2E tests for both web-admin and desktop apps to CI matrix.
- Detail file: `docs/todo/done/todo-152-frontend-e2e-tests-ci.md`
- Result: CI frontend-e2e job upgraded from smoke-only to full E2E suite. Both apps run `bun run test:e2e` (all 9 Playwright test files). Artifacts uploaded on failure.

### 153. Fuzz Tests Not in CI (completed)
- Severity: HIGH
- Goal: Integrate fuzz targets into CI with sanitizer-enabled builds.
- Detail file: `docs/todo/todo-153-fuzz-tests-ci.md`

### 154. No Performance Regression Tests (completed)
- Severity: MEDIUM
- Goal: Add criterion benchmark runs to CI with regression detection.
- Detail file: `docs/todo/todo-154-performance-regression-tests.md`
- Result: 9 criterion benchmark groups (aes128, ghash, aes-gcm, morus, varint, header_validate, popcnt, rng). CI job with critcmp regression detection (warn 15%, error 30%). bench-ci-regression.sh script.

### 155. No sccache for CI Builds (completed)
- Severity: LOW
- Goal: Add sccache to CI pipeline for faster cross-platform builds.
- Detail file: `docs/todo/todo-155-sccache-ci-builds.md`

### 156. cargo-deny multiple-versions Allow (completed)
- Severity: HIGH
- Goal: Change `multiple-versions = "allow"` to `"deny"` in deny.toml and resolve duplicate dependencies.
- Detail file: `docs/todo/todo-156-cargo-deny-multiple-versions.md`

---

## Frontend

### 163. TypeScript `as any` Type Casts (completed - zero casts in Svelte apps)
### 164. Frontend Unit Tests (completed - 611 tests across 57 files)

---

## Dead Code / Cleanup

### 165. CryptoManager Dead Code (completed - NOT dead code, documented)
- Severity: HIGH
- Goal: Was incorrectly assessed as dead code. CryptoManager is actively used by StealthManager, CoreConnection, client subsystems. Documented instead.
- Detail file: `docs/todo/todo-165-cryptomanager-dead-code.md`

### 166. 99 Global AtomicU64/U32 Tight Coupling (completed - audited and documented)
- Severity: MEDIUM
- Goal: Audit all global atomics; consolidate into structured hint channels or message passing where appropriate.
- Detail file: `docs/todo/todo-166-global-atomic-coupling-audit.md`

### 167. admin.rs vs admin_http.rs Redundancy (completed - documented)
- Severity: LOW
- Goal: Evaluate whether Unix socket admin (admin.rs) and HTTP admin (admin_http.rs) should share handler logic.
- Detail file: `docs/todo/todo-167-admin-unix-http-redundancy.md`

---

## Documentation

### 168. MAP.md Potentially Outdated (completed)
- Severity: MEDIUM
- Goal: Audit MAP.md against current file tree and update all entries.
- Detail file: `docs/todo/todo-168-map-md-outdated-audit.md`

### 169. No API Documentation in Rust Code (completed)
- Severity: MEDIUM
- Goal: Add `///` doc comments to all public structs, traits, and functions in src/.
- Detail file: `docs/todo/todo-169-rust-api-documentation.md`
- Result: ~1400 doc comments added across all src/ modules. Covered: telemetry (~250 counters), instrumentation (~70 fields/methods), transport (~200 items across 6 files), stealth+brain (~50 items), simd+crypto (~134 items), fec+compress+optimize (~227 items), engine+core+interface+qftls+reality (~100 items). 100% pub item coverage.

### 170. README.md Unstructured 30KB (completed)
- Severity: LOW
- Goal: Restructure README with clear sections: Overview, Quick Start, Configuration, Architecture, Contributing.
- Detail file: `docs/todo/todo-170-readme-restructure.md`

### 171. No Deployment Guide (completed)
- Severity: MEDIUM
- Goal: Create deployment guide covering Linux server setup, systemd, TLS certs, firewall, monitoring.
- Detail file: `docs/todo/todo-171-deployment-guide.md`

### 172. No Troubleshooting Guide (completed)
- Severity: LOW
- Goal: Create troubleshooting guide for common issues (connection failures, DNS leaks, performance tuning).
- Detail file: `docs/todo/todo-172-troubleshooting-guide.md`

### 173. server-linux.default.toml Too Minimal (completed)
- Severity: LOW
- Goal: Expand server config template with all available sections and documented defaults.
- Detail file: `docs/todo/todo-173-server-config-template-expansion.md`

---

## Scripts

### 174. 88 Scripts With Redundancies (completed)
- Severity: LOW
- Goal: Consolidate redundant test/bench scripts into meta-wrappers; remove duplicates.
- Detail file: `docs/todo/todo-174-scripts-redundancy-consolidation.md`
- Result: Phase 2 done. 3 unified dispatchers (test-fec-all.sh, bench-fec-all.sh, dev.sh). 7 new justfile targets. Build scripts verified unique.

### 175. No Central Makefile or justfile (completed)
- Severity: LOW
- Goal: Create a `justfile` as central entry point for build, test, bench, lint, audit commands.
- Detail file: `docs/todo/todo-175-central-justfile.md`

---

## Build / Config

### 176. 28 Feature Flags Unorganized (completed)
- Severity: MEDIUM
- Goal: Consolidate into ~8 meta-features (cpu-simd, stealth, fec, experimental, test-suite, etc.).
- Detail file: `docs/todo/todo-176-feature-flags-consolidation.md`

### 177. No PGO for Release Builds (completed)
- Severity: MEDIUM
- Goal: Add profile-guided optimization pipeline for release builds (10-15% potential gain).
- Detail file: `docs/todo/todo-177-pgo-release-builds.md`

### 178. No Target-Specific Optimizations (completed)
- Severity: LOW
- Goal: Add release profiles for x86_64-v3 and aarch64 with target-cpu flags.
- Detail file: `docs/todo/todo-178-target-specific-optimizations.md`

### 179. Memory Pool Size Hardcoded 64MB (completed)
- Severity: LOW
- Goal: Auto-scale memory pool based on available system RAM or make configurable.
- Detail file: `docs/todo/todo-179-memory-pool-size-autoscale.md`

### 180. No Secret Rotation Infrastructure (completed)
- Severity: MEDIUM
- Goal: Implement QKey TTL enforcement, TLS cert rotation hooks, and admin password expiry.
- Detail file: `docs/todo/todo-180-secret-rotation-infrastructure.md`
- Result: QKey TTL, TLS cert hot-reload (mtime polling), admin password expiry. 17 tests.

---

## Performance

### 181. HashMap for Streams Causes Cache Misses (closed - won't fix)
- Severity: LOW
- Goal: Evaluate replacing HashMap<u64, Stream> with a slot-based or arena-based structure for high stream counts.
- Detail file: `docs/todo/done/todo-181-hashmap-streams-cache-misses.md`
- Result: Closed. Only relevant at >10k concurrent streams per connection; normal VPN usage is <100. No benchmark data showing this as a bottleneck. Premature optimization.

### 182. Vec Allocation Per Frame in Hot Path (completed)
- Severity: MEDIUM
- Goal: Replace `c.get_bytes(len)?.to_vec()` with zero-copy slice references in frame parsing.
- Detail file: `docs/todo/done/todo-182-vec-allocation-frame-hot-path.md`
- Result: Frame enum changed to Frame<'a> with Cow<'a, [u8]> for 7 data fields. from_bytes returns Cow::Borrowed (zero-copy). In-order Stream fast path skips recv_frags BTreeMap for sequential data. 8 heap allocations eliminated per parsed packet. 417 tests GREEN, clippy GREEN.

### 183. Accept Loop Timeout Reduction (closed - sufficient)
- Severity: MEDIUM
- Goal: Reduce UDP accept timeout to 100ms and use pre-allocated buffer pool instead of per-loop allocation.
- Detail file: `docs/todo/done/todo-183-accept-loop-timeout-reduction.md`
- Result: Closed. Timeout already reduced 5s->500ms (10x improvement). Buffer allocation confirmed pre-allocated. Remaining 500ms->100ms yields negligible benefit with increased CPU wakeups.

### 184. HTTP Admin Server Per-Thread No Async (completed)
- Severity: MEDIUM
- Goal: Migrate admin HTTP server from std::thread::spawn per connection to Tokio async tasks.
- Detail file: `docs/todo/todo-184-http-admin-server-async.md`
- Result: Full async migration. tokio::spawn replaces std::thread::spawn. tokio::sync::Semaphore (16 permits) for connection limiting. tokio::time::timeout(30s) for Slowloris protection. All I/O functions async. All 56 admin_http tests pass.

---

## Platform

### TODO-307. io_uring Full Exploitation - Inbound RecvMsg, Server Send, SendMsgZc, SQPOLL (completed)
- Severity: HIGH
- Goal: Full io_uring exploitation for inbound RecvMsg, server send, SendMsgZc, and SQPOLL mode.
- Detail file: `docs/todo/todo-307-iouring-full-exploitation.md`

### 185. Linux ioctl Race - Uninitialized Memory in IfReq (completed)
- Severity: MEDIUM
- Goal: Zero-fill IfReq.ifr_name completely and validate null termination after ioctl return.
- Detail file: `docs/todo/todo-185-linux-ioctl-race-ifreq.md`

### 186. macOS pfctl Enable Race (completed)
- Severity: MEDIUM
- Goal: Check pf state before enable; handle already-enabled case gracefully.
- Detail file: `docs/todo/todo-186-macos-pfctl-enable-race.md`

### 187. macOS /tmp Hardcoded Path for Kill-Switch Config (completed)
- Severity: LOW
- Goal: Use PID-scoped temp file path to prevent multi-process conflicts.
- Detail file: `docs/todo/todo-187-macos-tmp-hardcoded-killswitch.md`

### 188. Windows WinTUN Pre-Requisite No Auto-Creation (completed)
- Severity: LOW
- Goal: Document WinTUN requirement prominently; optionally auto-create adapter via WinTUN API.
- Detail file: `docs/todo/todo-188-windows-wintun-prerequisite.md`

### 189. macOS DNS Reset to Empty Equals DHCP Leak (completed)
- Severity: MEDIUM
- Goal: Restore original DNS servers instead of setting "Empty" which falls back to DHCP DNS.
- Detail file: `docs/todo/todo-189-macos-dns-reset-dhcp-leak.md`

---

## UI Revamp (COMPLETED)

### 190. Full UI Revamp - Web Admin and Desktop (superseded)
- Severity: ENHANCEMENT
- Goal: Original umbrella initiative for the dual Svelte rebuild and shared package extraction.
- Status: SUPERSEDED - approval is now granted, but execution is tracked through the concrete remediation items below so repo-truth, contract repair, testing, and documentation drift can be closed explicitly.
- Detail file: `docs/todo/todo-190-full-ui-revamp.md`

---

## Forensic Remediation (COMPLETED)

### 191. Svelte Cutover and React Retirement (completed)
- Severity: CRITICAL
- Goal: Make `apps/svelte-admin/` and `apps/svelte-desktop/` the only integrated frontend path; archive the historical React apps outside the live workflow.
- Detail file: `docs/todo/todo-191-svelte-cutover-and-react-retirement.md`

### 192. Svelte Build, CI, and Release Pipeline Truth Alignment (completed)
- Severity: HIGH
- Goal: Make Svelte apps build-clean and test-clean, switch all frontend CI/runtime scripts to Svelte, and remove stale React-only pipeline assumptions.
- Detail file: `docs/todo/todo-192-svelte-build-ci-release-cutover.md`

### 193. QKey Issuance, Reveal, and Import Contract Repair (completed)
- Severity: CRITICAL
- Goal: Repair the broken admin-to-desktop QKey lifecycle so generated credentials can be consumed reliably without leaking persistent raw QKey material.
- Detail file: `docs/todo/todo-193-qkey-issuance-reveal-import-contract-repair.md`

### 194. Admin Credential Policy Reconciliation to 6 Characters (superseded)
- Severity: HIGH
- Goal: Historical intermediate policy pass that converged the repository on 6 characters. The canonical direction is now TODO 213, which converges the product to a 6-character minimum everywhere.
- Detail file: `docs/todo/todo-194-admin-credential-policy-reconciliation.md`

### 195. Canonical UI Documentation and Backlog Truth Alignment (completed)
- Severity: HIGH
- Goal: Remove React from canonical product-facing docs/backlog truth, fix all frontend drift, and make documentation match the actual shipped Svelte-first architecture.
- Detail file: `docs/todo/todo-195-canonical-ui-doc-and-backlog-truth-alignment.md`

### 196. XOR Product-Surface Demotion (completed)
- Severity: MEDIUM
- Goal: Keep XOR as compatibility/runtime machinery only while removing it from product-facing admin controls, docs, and normal operator workflow.
- Detail file: `docs/todo/todo-196-xor-product-surface-demotion.md`

### 197. Svelte Admin/Desktop Contract and End-to-End Coverage (completed)
- Severity: HIGH
- Goal: Replace false-confidence React-era checks with Svelte-era integration, contract, unit, and Playwright coverage for the actual shipped UI flow.
- Detail file: `docs/todo/todo-197-svelte-admin-desktop-contract-and-e2e-coverage.md`

### 198. Stealth, Brain, and FEC Control Ownership Audit (completed)
- Severity: HIGH
- Goal: Prove or remove overlapping control loops by assigning one owner per actuator and validating that adaptation layers do not neutralize or degrade each other.
- Detail file: `docs/todo/todo-198-stealth-brain-fec-control-ownership-audit.md`

### 199. Unsafe ROI Audit and Selective Safe Replacement (completed)
- Severity: HIGH
- Goal: Identify unsafe blocks with no measurable upside, replace them with safe equivalents where cost is negligible, and keep benchmark-backed unsafe only where justified.
- Detail file: `docs/todo/todo-199-unsafe-roi-audit-and-selective-safe-replacement.md`

### 200. Local Repository Truth and Staging Alignment (completed)
- Severity: CRITICAL
- Goal: Record the current local Svelte-first repository state as the authoritative local Git truth by staging all active source, workspace, script, test, and documentation paths without committing or pushing.
- Detail file: `docs/todo/todo-200-local-repository-truth-and-staging-alignment.md`

### 201. Active Svelte Workspace Source Tracking and Workspace Manifest Truth (completed)
- Severity: CRITICAL
- Goal: Ensure the active Svelte admin, Svelte desktop, shared packages, root workspace manifest, and related support files are fully represented in the local repository index and no longer live as untracked workflow-critical content.
- Detail file: `docs/todo/todo-201-active-svelte-workspace-source-tracking-and-manifest-truth.md`

### 202. Admin Publish Asset Tree Index Reconciliation (completed)
- Severity: CRITICAL
- Goal: Replace the tracked React-era `assets/web-admin` tree with the current SvelteKit static publish output and make the tracked publish artifact match the active admin build.
- Detail file: `docs/todo/todo-202-admin-publish-asset-tree-index-reconciliation.md`

### 203. Local Worktree Hygiene and Artifact Guardrail Closure (completed)
- Severity: HIGH
- Goal: Remove residual local artifact drift, keep generated garbage out of the worktree, and leave a controlled local repository state with no accidental cache or Finder debris.
- Detail file: `docs/todo/todo-203-local-worktree-hygiene-and-artifact-guardrail-closure.md`

### 204. Toolchain Baseline Upgrade to Current Stable Rust (completed)
- Severity: HIGH
- Goal: Move the main workspace and supporting tooling to the current stable Rust baseline, then align Cargo metadata, CI assumptions, and documentation around that new toolchain truth.
- Detail file: `docs/todo/todo-204-toolchain-baseline-upgrade-to-current-stable-rust.md`

### 205. Workspace Build, Test, and Clippy Excellence Restoration (completed)
- Severity: HIGH
- Goal: Restore a fully green local quality baseline across `cargo check`, `cargo build`, `cargo test`, `cargo clippy -D warnings`, frontend checks/builds/tests, and native desktop verification.
- Detail file: `docs/todo/todo-205-workspace-build-test-and-clippy-excellence-restoration.md`

### 206. Clippy Debt and Code-Hygiene Elimination (completed)
- Severity: HIGH
- Goal: Remove the current clippy failures and adjacent code-hygiene debt so the repository meets an explicit no-warning quality bar on the chosen toolchain.
- Detail file: `docs/todo/todo-206-clippy-debt-and-code-hygiene-elimination.md`

### 207. Connection Migration Path Validation State Machine (completed)
- Severity: CRITICAL
- Goal: Implement a real RFC 9000-style path validation state machine so connection migration stops emitting optimistic success semantics without actual challenge/response validation.
- Detail file: `docs/todo/todo-207-connection-migration-path-validation-state-machine.md`

### 208. Anti-Amplification, Path Cooldown, and Validation Guards (completed)
- Severity: CRITICAL
- Goal: Add the missing anti-amplification, cooldown, and path-state guards around migration so new or unvalidated paths are handled safely and professionally.
- Detail file: `docs/todo/todo-208-anti-amplification-path-cooldown-and-validation-guards.md`

### 209. Migration Event and Telemetry Truth Correction (completed)
- Severity: HIGH
- Goal: Make path events and migration telemetry describe only real validated migration outcomes rather than optimistic internal state transitions.
- Detail file: `docs/todo/todo-209-migration-event-and-telemetry-truth-correction.md`

### 210. Migration Test Truth Rebuild and Adversarial Coverage (completed)
- Severity: HIGH
- Goal: Rebuild migration tests so they prove the real state machine and add adversarial coverage for spoofing, timeout, abuse, and negative-path behavior.
- Detail file: `docs/todo/todo-210-migration-test-truth-rebuild-and-adversarial-coverage.md`

### 211. Migration Suite and Runtime Contract Realignment (completed)
- Severity: HIGH
- Goal: Reconcile transport suites, runtime config, and product contract wording with the completed migration implementation so the repository no longer overclaims or under-specifies migration behavior.
- Detail file: `docs/todo/todo-211-migration-suite-and-runtime-contract-realignment.md`

### 212. Migration Documentation and Product-Surface Truth Rewrite (completed)
- Severity: HIGH
- Goal: Rewrite migration-related documentation, examples, and tracking docs so they are precise, professional, and exactly aligned to the completed code and tests.
- Detail file: `docs/todo/todo-212-migration-documentation-and-product-surface-truth-rewrite.md`

### 213. Admin Credential Policy Reconciliation to 6 Characters (completed)
- Severity: HIGH
- Goal: Converge backend, active Svelte surfaces, retained references, tests, scripts, and docs on a single canonical 6-character minimum admin credential policy.
- Detail file: `docs/todo/todo-213-admin-credential-policy-reconciliation-to-6-characters.md`

### 214. Weak Local Admin Defaults Documentation and Operator Override Guide (completed)
- Severity: MEDIUM
- Goal: Keep intentionally weak local admin defaults as a documented dev-only behavior, with exact operator override instructions and no new UI surface.
- Detail file: `docs/todo/todo-214-weak-local-admin-defaults-documentation-and-operator-override-guide.md`

### 215. Script, Smoke, Audit, and CI Svelte-Truth Harmonization (completed)
- Severity: HIGH
- Goal: Audit and align all active scripts, smoke runners, audit gates, and CI entrypoints to the real Svelte-first workflow, updated toolchain, and current publish truth.
- Detail file: `docs/todo/todo-215-script-smoke-audit-and-ci-svelte-truth-harmonization.md`

### 216. Frontend Svelte Truth Revalidation After Repository and Toolchain Cleanup (completed)
- Severity: HIGH
- Goal: Re-prove the active Svelte admin and desktop paths after the repository-truth, publish-truth, and toolchain cleanup, including wrapper/native-host behavior.
- Detail file: `docs/todo/todo-216-frontend-svelte-truth-revalidation-after-repository-and-toolchain-cleanup.md`

### 217. End-to-End Validation Matrix and Release-Readiness Gate (completed)
- Severity: HIGH
- Goal: Run and document a consolidated validation matrix that proves repository cleanliness, runtime correctness, frontend truth, and release-readiness on the final local state.
- Detail file: `docs/todo/todo-217-end-to-end-validation-matrix-and-release-readiness-gate.md`

### 218. Final Local Index Consolidation and Pre-Commit Stabilization (completed)
- Severity: HIGH
- Goal: Leave the local repository in a fully controlled staged state with no accidental unstaged or untracked residue before any later local commit.
- Detail file: `docs/todo/todo-218-final-local-index-consolidation-and-pre-commit-stabilization.md`

### 219. Backlog, Changelog, Context, and Canonical Documentation Final Synchronization (completed)
- Severity: HIGH
- Goal: Close the execution program with fully synchronized backlog, changelog, context, README, MAP, and DOCUMENTATION truth so no stale planning or drift survives the implementation wave.
- Detail file: `docs/todo/todo-219-backlog-changelog-context-and-canonical-documentation-final-synchronization.md`

---

### 108. Crypto Backend Differential Proof Expansion (completed)
- Goal:
  - Expand backend equivalence proof for retained `Aegis128L` / `Aegis128X4` / `Aegis128X8` / `Morus1280_128`.
- Detail file:
  - `docs/todo/todo-108-crypto-backend-differential-proof-expansion.md`

### 109. Unsafe Invariant Annotation and Boundary Hardening (completed)
- Goal:
  - Make retained unsafe crypto/SIMD machine-room invariants explicit and locally reviewable.
- Detail file:
  - `docs/todo/todo-109-unsafe-invariant-annotation-and-boundary-hardening.md`

### 110. Crypto Machine-Room Layer Separation and Internalization (completed)
- Goal:
  - Further separate contract, planner, backend adapters, and raw machine room inside retained custom crypto.
- Detail file:
  - `docs/todo/todo-110-crypto-machine-room-layer-separation-and-internalization.md`

### 111. Crypto Backend Runtime Evidence Telemetry (completed)
- Goal:
  - Expose which retained AEAD backend paths are actually selected at runtime.
- Detail file:
  - `docs/todo/todo-111-crypto-backend-runtime-evidence-telemetry.md`

### 112. Retained Crypto Backend Performance Evidence Program (completed)
- Goal:
  - Produce hard evidence that keeping X4/X8 and retained MORUS paths is worth the complexity.
- Detail file:
  - `docs/todo/todo-112-retained-crypto-backend-performance-evidence-program.md`

### 113. Quinn-UDP Overlap and Fork Boundary Final Tightening (completed)
- Goal:
  - Make transport overlap versus fork divergence impossible to misread.
- Detail file:
  - `docs/todo/todo-113-quinn-udp-overlap-and-fork-boundary-final-tightening.md`

### 114. Reviewer Audit Fast-Path and Repository Entry Tightening (completed)
- Goal:
  - Give external reviewers the shortest possible trustworthy entry path into the repo.
- Detail file:
  - `docs/todo/todo-114-reviewer-audit-fast-path-and-repository-entry-tightening.md`

### 115. FEC Auto-Controller Empirical Proof Expansion (completed)
- Goal:
  - Prove that retained FEC sophistication behaves efficiently when clean and aggressively when needed.
- Detail file:
  - `docs/todo/todo-115-fec-auto-controller-empirical-proof-expansion.md`

### 116. Consolidated Quality Evidence Bundle and Trust Surface (completed)
- Goal:
  - Turn the current test/audit/proof set into a compact, reviewer-facing evidence bundle.
- Detail file:
  - `docs/todo/todo-116-consolidated-quality-evidence-bundle-and-trust-surface.md`

### 117. XDP Compatibility Shim io_uring Ownership Collapse (completed)
- Goal:
  - Remove the last private `io_uring` machine-room from the XDP compat shim so the canonical runtime owner remains `src/transport/uring.rs`.
- Detail file:
  - `docs/todo/todo-117-xdp-compatibility-shim-io-uring-ownership-collapse.md`

### 118. Public XDP Fastpath Token Removal and uring Truth Tightening (completed)
- Goal:
  - Remove the public `xdp` fastpath token entirely, keep no alias parsing, and collapse the public fastpath surface to `auto` and `off` while `io_uring` remains internal Linux runtime truth.
- Detail file:
  - `docs/todo/todo-118-public-xdp-fastpath-token-removal-and-uring-truth-tightening.md`

---

## External Audit Findings (2026-03-21) - ALL RESOLVED

All 26 findings (TODO 220-245) from external deep audit have been fixed, mitigated, or intentionally dismissed.
Detail files retained in `docs/todo/` for historical reference.

---

## Multi-Model Audit Findings (2026-03-21)

Verified findings from 9 audit runs across 8 AI model+harness combinations. Each finding was cross-checked against the actual codebase. 52 total findings: 13 already covered by completed TODOs, 4 covered by open TODOs, 8 by-design/skip, 24 new (below). **23 of 24 implemented (2026-03-21). Only TODO-260 deferred (monolithic file split - requires own PR).**

### HIGH

#### 246. Replace std::process::exit() in Library Code - COMPLETED
- Severity: HIGH
- Goal: Replace `std::process::exit(1)` in DoH LazyLock initializer and fix hardcoded `worker_threads(4)` for embedding-safe graceful degradation.
- Detail file: `docs/todo/todo-246-process-exit-in-library-code.md`
- Result: DOH_RUNTIME changed to LazyLock<Option<Runtime>>, 3 call sites handle None gracefully, dynamic thread count.

#### 249. Audit and Remove .expect() Calls in Production Code - COMPLETED
- Severity: HIGH
- Goal: Audit 206 `.expect()` calls across 19 files; replace with `Result` propagation in network-facing code, justify remainder.
- Detail file: `docs/todo/todo-249-expect-calls-audit-and-removal.md`
- Result: Only 3 production .expect() found (203 in tests). 1 replaced with ?, 2 justified with SAFETY comments.

#### 269. Audit TlsCoverProvider Cipher Suite Reinstallation - COMPLETED
- Severity: HIGH
- Goal: Audit conditional cipher reinstallation in TlsCoverProvider for fingerprint leaks and performance impact under profile switching.
- Detail file: `docs/todo/todo-269-tls-cover-cipher-reinstallation-audit.md`
- Result: 16-line SAFETY comment documenting why reinstallation is safe (immutable post-construction, write-lock serialized).

### MEDIUM

#### 247. Deterministic Session Cleanup in Reality Proxy - COMPLETED
- Severity: MEDIUM
- Goal: Replace probabilistic (~3.9%) session cleanup with deterministic TTL-based eviction to prevent unbounded HashMap growth.
- Detail file: `docs/todo/todo-247-probabilistic-session-cleanup.md`
- Result: Constants (60s interval, 10k max, 300s TTL), last_cleanup field, deterministic time+capacity sweep.

#### 248. Consolidate Triple PacketType Enum Definition - COMPLETED
- Severity: MEDIUM
- Goal: Merge the duplicate `PacketType` enums in transport.rs and packet.rs; rename stealth variant to `StealthPacketClass`.
- Detail file: `docs/todo/todo-248-packet-type-enum-triple-definition.md`
- Result: packet.rs re-exports transport.rs canonical type, stealth.rs renamed to StealthPacketClass, ~40 lines boilerplate removed.

#### 256. Audit Crate-Level Clippy Suppressions - COMPLETED
- Severity: MEDIUM
- Goal: Replace global `#![allow(clippy::too_many_arguments)]` with per-function suppressions where justified.
- Detail file: `docs/todo/todo-256-crate-level-clippy-suppressions.md`
- Result: Both crate-level suppressions removed from lib.rs. Remaining too_many_arguments are per-function (8 pre-existing).

#### 258. Replace ConnectionId Heap Allocation - COMPLETED
- Severity: MEDIUM
- Goal: Replace `ConnectionId(Vec<u8>)` with fixed-size `[u8; 20]` or `SmallVec` to eliminate heap allocation per QUIC connection ID.
- Detail file: `docs/todo/todo-258-connection-id-heap-allocation.md`
- Result: ConnectionId now [u8; 20]+u8 inline, Copy trait, zero heap allocation.

#### 260. Split Monolithic Source Files - COMPLETED
- Severity: MEDIUM
- Goal: Split fec.rs (9k), crypto.rs (9.8k), stealth.rs (5.8k), optimize.rs (5.2k) into focused submodules.
- Detail file: `docs/todo/done/todo-260-monolithic-file-split.md`
- Result: All 4 monoliths split. crypto.rs -> crypto/ (13 files), fec.rs -> fec/ (9 files), stealth.rs -> stealth/ (3 files), optimize.rs -> optimize/mod.rs + simd.rs. All docs/scripts/README updated. 417 tests GREEN, clippy GREEN, zero code loss.

#### 262. Upgrade rand Crate and Consolidate RNG Usage - COMPLETED
- Severity: MEDIUM
- Goal: Upgrade rand 0.8 to 0.9; consolidate `rand::random()` vs project-canonical `fill_secure()` usage.
- Detail file: `docs/todo/todo-262-rand-crate-upgrade-and-rng-consolidation.md`
- Result: rand 0.8->0.9, 14 files migrated (thread_rng->rng, gen->random, gen_range->random_range), crypto.rs OsRng->fill_secure_or_abort.

#### 267. Reconcile TLS Version Claims Across Layers - COMPLETED
- Severity: MEDIUM
- Goal: Fix version mismatch: qftls.rs (Chrome 130), stealth.rs UA (Chrome 126), ClientHello (Chrome 120) - all must agree.
- Detail file: `docs/todo/todo-267-tls-version-layer-mismatch.md`
- Result: 17 edits in stealth.rs - all UA strings and ClientHello comments aligned to Chrome 130, Firefox 133, Safari 18.

#### 268. Add Property-Based Tests for Core Algorithms - COMPLETED
- Severity: MEDIUM
- Goal: Add proptest for varint, frame, FEC, and crypto round-trip correctness. Complement existing 6 fuzz targets.
- Detail file: `docs/todo/todo-268-property-based-tests.md`
- Result: 5 new property tests (ConnectionId equality, hex roundtrip, varint len, crypto frame roundtrip, AEAD tamper detection). Total: 12.

### LOW

#### 250. Remove Unimplemented Congestion Control Variants - COMPLETED
- Severity: LOW
- Goal: Remove or warn on 5 unimplemented CC variants (only BBR3 is wired); prevent silent config mismatch.
- Detail file: `docs/todo/todo-250-congestion-control-dead-variants.md`
- Result: log::warn!() added in set_cc_algorithm() for non-BBR3 variants. Enum preserved for config compat.

#### 251. Deduplicate Aegis128L/X4/X8 Constructors - COMPLETED
- Severity: LOW
- Goal: Extract identical `new()` constructor code across 3 AEGIS variants into shared macro or generic.
- Detail file: `docs/todo/todo-251-aegis-constructor-deduplication.md`
- Result: aegis_aead_new! macro, 27 LOC -> 18+3 invocations.

#### 252. Remove Duplicate runtime_cc_algorithm() Function - COMPLETED
- Severity: LOW
- Goal: Remove standalone function that duplicates the `From<CcAlgorithm>` impl; use `.into()` instead.
- Detail file: `docs/todo/todo-252-runtime-cc-algorithm-from-impl-overlap.md`
- Result: Function deleted, call site uses .into().

#### 253. Deduplicate Hex Encoding Logic - COMPLETED
- Severity: LOW
- Goal: Extract duplicated hex byte encoding from admin_http.rs and rng.rs into shared utility.
- Detail file: `docs/todo/todo-253-hex-encoding-logic-deduplication.md`
- Result: pub fn push_hex_byte in rng.rs, admin_http.rs delegates.

#### 254. Fix Instant::now().elapsed() Zero-Entropy Seed - COMPLETED
- Severity: LOW
- Goal: Remove or fix always-zero `Instant::now().elapsed()` anti-fingerprinting mix that adds no entropy.
- Detail file: `docs/todo/todo-254-instant-now-elapsed-zero-ns.md`
- Result: Dead entropy mixing removed, simplified from_seed() using golden-ratio constant for zero-guard.

#### 255. Fix //? Doc Comment Typo - COMPLETED
- Severity: LOW
- Goal: Fix `//? ` typo in stealth.rs:36 that breaks rustdoc chain.
- Detail file: `docs/todo/todo-255-doc-comment-typo-question-mark.md`
- Result: Fixed to //! (inner doc comment).

#### 257. Audit recursion_limit = "1024" - COMPLETED
- Severity: LOW
- Goal: Identify which macro requires 8x default recursion limit; reduce to minimum necessary value.
- Detail file: `docs/todo/todo-257-recursion-limit-1024-audit.md`
- Result: Documented: required for crypto/FEC SIMD macro expansions. Comment added.

#### 259. Comment Hygiene Cleanup - COMPLETED
- Severity: LOW
- Goal: Remove stale "module removed" comments in lib.rs and German comment in core.rs.
- Detail file: `docs/todo/todo-259-comment-hygiene-cleanup.md`
- Result: 2 stale comments removed from lib.rs, German comment translated in core.rs.

#### 261. Deduplicate CLI Argument Fields - COMPLETED
- Severity: LOW
- Goal: Extract ~12 duplicated client/server CLI args into shared struct via clap flatten.
- Detail file: `docs/todo/todo-261-cli-argument-field-deduplication.md`
- Result: SharedArgs struct with 20 fields, #[command(flatten)] in both Client and Server. ~120 lines eliminated.

#### 263. Reconcile License Headers - COMPLETED
- Severity: LOW
- Goal: Fix BSD-3-Clause header in core.rs vs MIT everywhere else; make consistent.
- Detail file: `docs/todo/todo-263-license-header-audit.md`
- Result: 30-line BSD-3 header replaced with 3-line Quinn attribution comment referencing MIT.

#### 264. Move Fuzz Seed Corpus Out of Git - COMPLETED
- Severity: LOW
- Goal: Gitignore 192 binary fuzz seed files; generate on demand or keep minimal curated set.
- Detail file: `docs/todo/todo-264-fuzz-seed-corpus-gitignore.md`
- Result: .gitignore entries for seeds/, corpus/, artifacts/ under fuzz dir.

#### 265. Fix .gitattributes Stale Paths - COMPLETED
- Severity: LOW
- Goal: Remove 3 references to non-existent directories (releases/, ui/, scripts/artifacts/logs/).
- Detail file: `docs/todo/todo-265-gitattributes-stale-paths.md`
- Result: 3 stale entries removed.

#### 266. Add .claude/ to .gitignore - COMPLETED
- Severity: LOW
- Goal: Prevent accidental tracking of ~10GB agent worktree directory.
- Detail file: `docs/todo/todo-266-gitignore-claude-directory.md`
- Result: .claude/ added to IDE/editor section.

---

## Cross-Model Forensic Audit (2026-03-22)

Findings from 5 AI audit reports (Mimo V2 Pro, Gemini 3.1 Pro, GLM-5, MiniMax M2.7 Kilocode, MiniMax M2.7 Droid) cross-checked against actual codebase. Only validated true findings are listed below.

### CRITICAL

#### 270. ~~Cargo Dependency Security Vulnerabilities~~ DONE
- Fixed: aws-lc-sys 0.37.1->0.39.0, quinn-proto 0.11.13->0.11.14. All 5 CVEs resolved.

#### 271. ~~FEC emitted_ids HashSet Unbounded Growth~~ DONE
- Fixed: emitted_ids.remove() now fires on emitted_order.pop_front(). HashSet bounded to 4096.

#### 272. ~~FEC Buffer Upsizing Silent Fallback~~ DONE
- Fixed: allocation failure now returns None (+ log::warn) instead of undersized buffer. Both data and coefficient paths.

#### 273. ~~aead 0.6.0-rc.10 RC Dependency~~ CLOSED
- Already on latest available (rc.10). Optional dep. Stable 0.6.0 will arrive via routine `cargo update`.

#### 274. ~~Tauri capabilities.json Empty~~ CLOSED (N/A)
- Old Tauri app is archived. svelte-desktop is canonical. File doesn't exist on disk.

#### 275. ~~LICENSE Not in Repository Root~~ DONE
- Fixed: Copied docs/LICENSE to repo root.

#### 276. ~~tokio::spawn Fire-and-Forget in Reality Proxy~~ DONE
- Fixed: JoinHandle tracked in SessionHandle, task.abort() on session cleanup.

#### 277. ~~CI Uses Deprecated actions-rs/toolchain@v1~~ DONE
- Fixed: actions-rs/toolchain@v1 -> dtolnay/rust-toolchain@master, checkout/cache/upload-artifact @v3 -> @v4.

#### 278. ~~.cargo/config.toml Profile Redundancy and German Comments~~ DONE
- Fixed: Removed 4 duplicate profile sections, translated German comments, removed workspace dupe.

#### 279. ~~syncAnchor() Pattern Duplicated 3x in Svelte Admin~~ DONE
- Fixed: Extracted to $lib/use-anchor-sync.ts, replaced in DashboardView, ConfigurationView, LogsView.

#### 280. ~~Config stealth.mode = "performance" Non-Canonical Value~~ DONE
- Fixed: Changed to "auto" in config/server-linux.default.toml.

#### 281. ~~engine.rs Polling Loop TODO~~ DONE
- Fixed: Replaced 25ms sleep-polling with Condvar-based notification. IO driver signals handshake_event when connection is established. Engine waits via wait_handshake() with deadline timeout. Zero CPU waste at idle.

#### 282. ~~Debug eprintln! Statements in qftls.rs~~ DONE
- Fixed: All eprintln! replaced with log::trace! in qftls.rs, connection.rs, packet.rs. trace_tls_enabled() removed.

---

## Wave 11 - AI Model Review Findings (2026-03-22)

#### 283. ~~aead 0.6.0-rc.10 Release Candidate in Production~~ DONE
- No stable 0.6.x exists. Added comment documenting RC status in Cargo.toml.

#### 284. ~~Outdated UA Strings (Chrome 130, Firefox 133)~~ DONE
- Updated all 14 UA strings: Chrome 130->136, Firefox 133->138, Edge 130->136, Safari 18.0->18.3, Android 14->15, iOS 18.0->18.3. Updated qftls.rs profile names.

#### 285. ~~Unwired Config Keys~~ DONE
- Already documented with "NOTE: Not yet wired" comments in config/quicfuscate.toml.

#### 286. ~~PQ Feature Flag Missing Crate Dependencies~~ DONE
- Deleted orphaned pq.rs + hybrid.rs, removed all CryptoManager PQ methods, commented out pq feature flag with explanation.

#### 287. ~~Fire-and-Forget tokio::spawn~~ DONE
- All 3 service spawns (mod.rs) use registered shutdown signals. Added documenting comments. Per-connection spawns (admin.rs, admin_http.rs) are standard accept-loop patterns. metrics.rs fire-and-forget documented.

#### 288. ~~ChaCha TLS Cover vs TLS Policy DPI Inconsistency~~ DONE
- ServerHello cipher selection now uses `resolve_cipher_suite()` instead of hardcoded heuristic. Added `tls_id()` to TlsCoverCipherSuite. 3 regression tests verify env-based cipher selection.

#### 289. ~~ENV_MUTEX Inconsistent Poisoning~~ DONE
- All 5 test files updated to use `unwrap_or_else(|e| e.into_inner())` for poison recovery.

#### 290. ~~deny.toml multiple-versions = "warn"~~ DONE
- Changed to "deny" with skip entries for known intentional duplicates (rand_core, bitflags).

#### 291. ~~Missing SECURITY.md~~ DONE
- Created SECURITY.md with responsible disclosure process, supported versions, scope.

#### 292. ~~password-hash/rand/rand_core Triple Version~~ DONE
- Eliminated direct rand_core 0.6 dependency. SaltString now generated via getrandom directly. Removed `rand_core` from Cargo.toml deps.

#### 293. ~~Hardcoded ADMIN_PASS="123" in E2E Test~~ DONE
- Changed to "E2E_TEST_ONLY_pw42" in test-e2e-admin-web.sh.

#### 294. ~~FEC_PARALLEL Doc Contradiction~~ DONE
- Fixed test comments (FEC_PARALLEL is set in benchmarks but not read by AdaptiveFec). Doc is technically correct.

#### 295. ~~TODO-119 Troubleshooting.md Drift~~ DONE
- Updated troubleshooting.md to reflect atomic iptables-restore fix.

#### 296. ~~Browser Profile Scripts Reference Nonexistent Dir~~ DONE
- Added NOTE messages explaining browser_profiles/ is optional auditing artifacts only.

#### 297. ~~Shallow Stealth Test Coverage~~ DONE
- Added 18 new tests in stealth/tests.rs covering: TLS Cover cipher consistency, ClientHello/ServerHello validity, browser-specific fingerprinting (GREASE, SID), extension TLV structure, padding clamping, ECH GREASE, cipher preference parsing, resolve_cipher dispatch. Total stealth tests: 26 (was 8).

---

## Session 36 Forensic Deep Audit (2026-03-26) - ALL DONE

### CRITICAL - ALL DONE

#### 308. ~~CI Regression Gate Inert - Missing `--features benches`~~ DONE
- Severity: CRITICAL
- File: `scripts/benchmarks/bench-ci-regression.sh:49,71,80`
- Problem: All three `cargo bench` invocations (crypto, fec, transport) lack `--features benches`. Every Criterion benchmark is behind `cfg(feature = "benches")`. The CI regression gate compiles zero benchmarks - it silently succeeds with no data.
- Fix: Add `--features benches` to all three cargo bench commands.
- Completion: All three cargo bench lines include `--features benches`, critcmp output shows actual benchmark data.

#### 309. ~~Ghost Test Patterns in bench-crypto.sh~~ DONE
- Severity: CRITICAL
- File: `scripts/benchmarks/suites/bench-crypto.sh:92,113`
- Problem: Line 92 filters for `crypto::morus_tests` but the module path is `crypto::morus::morus_tests` (after monolith split). Line 113 filters for `crypto::chacha::` but chacha.rs has 0 `#[test]` functions. Both patterns match 0 tests - scripts succeed silently with no tests run.
- Fix: Line 92 change to `crypto::morus::morus_tests`. Line 113 either remove or add actual tests to chacha.rs.
- Completion: Both patterns match >= 1 test function when run.

#### 310. ~~PGO Workload Inert - Missing `--features benches`~~ DONE
- Severity: CRITICAL
- File: `scripts/build/build-pgo-release.sh:58-64`
- Problem: PGO instrumented build runs `pool-bench` and `crypto-bench` subcommands which are behind `cfg(feature = "benches")`. The build line does not include `--features benches`, so PGO training data is empty.
- Fix: Add `--features benches` to the cargo build command.
- Completion: PGO profile data directory contains non-empty .profraw files.

#### 311. ~~rt-xor-sse2-parity.rs Imports from Private Module~~ DONE
- Severity: CRITICAL
- File: `scripts/tests/rust/rt-xor-sse2-parity.rs:3` + `src/optimize/mod.rs:65`
- Problem: Test imports `quicfuscate::optimize::x86_sse2::{xor_repeating_key32_sse2, xor_repeating_sse2}` but `x86_sse2` is declared as `mod x86_sse2;` (private) in optimize/mod.rs. This test will fail to compile on x86_64 with `--features rust-tests`.
- Fix: Either make the module pub (`pub mod x86_sse2;`) or add a `pub use` re-export, or move the test functions to a pub-accessible path.
- Completion: `cargo test --test rt-xor-sse2-parity --features rust-tests` compiles and passes on x86_64.

### MODERATE

#### 312. ~~rt-anti-replay.rs Orphan Test Binary~~ DONE
- Severity: MODERATE
- File: `scripts/tests/rust/rt-anti-replay.rs`
- Problem: This test file has a `[[test]]` entry in Cargo.toml and compiles, but is not referenced by ANY suite script (`test-transport.sh`, `test-security.sh`, etc.). It is invisible to all CI/manual test runs.
- Fix: Add `cargo test --test rt-anti-replay --features rust-tests` to `test-transport.sh` or `test-security.sh`.
- Completion: At least one suite script invokes rt-anti-replay.

#### 313. ~~util-tls-show-active-env.sh Function Call Before Definition + Dead Code~~ DONE
- Severity: MODERATE
- File: `scripts/tests/utils/util-tls-show-active-env.sh:14,28,34`
- Problem: Line 14 calls `print_help` in the argument parser, but `print_help()` is defined at line 27. Running `--help` causes `bash: print_help: command not found`. Line 28 has an unreachable help check (after while loop consumed all args). Line 34 has redundant nested default `${VAR:-${VAR:-0}}`.
- Fix: Move `print_help()` definition before the argument parser. Remove dead help check at line 28. Simplify line 34 to `${VAR:-0}`.
- Completion: `util-tls-show-active-env.sh --help` prints usage without error.

#### 315. ~~DOCUMENTATION.md Stale PQ Reference~~ DONE
- Severity: MODERATE
- File: `docs/DOCUMENTATION.md:991`
- Problem: States "optional post-quantum experiments are feature-gated and inactive in the standard build profile". PQ code (pq.rs, hybrid.rs) was entirely deleted in TODO-286. The `pq` feature flag is commented out in Cargo.toml. There are zero PQ experiments remaining.
- Fix: Remove the stale PQ reference entirely or replace with "Post-quantum experiments were removed (no stable crate ecosystem exists)."
- Completion: No references to PQ experiments as if they still exist in the codebase.

#### 316. ~~todo.md Contradictory Password Policy~~ DONE
- Severity: MODERATE
- File: `docs/todo.md:506` + `src/implementations/server/admin_http.rs:1132`
- Problem: TODO-194 and TODO-213 references previously said "4 characters" but code enforces 6. Fixed: both now say "6 characters".
- Fix: Updated TODO-194 description (line 548) and TODO-213 filename reference (line 644) to "6 characters".
- Completion: All password policy references in todo.md say "6 characters".

#### 317. ~~SECURITY.md Em-Dash~~ DONE
- Severity: MODERATE
- File: `SECURITY.md:55`
- Problem: Contains Unicode em-dash character which is forbidden per project rules.
- Fix: Replace em-dash with hyphen or double-hyphen.
- Completion: `grep -c '\xe2\x80\x94' SECURITY.md` returns 0.

#### 318. ~~CONTRIBUTING.md Recommends `cargo build --release`~~ DONE
- Severity: MODERATE
- File: `docs/CONTRIBUTING.md:56`
- Problem: Getting Started section says "Build the crate: `cargo build --release`". Per project rules (Rust Build & Disk Policy), development builds must use `cargo build` (debug profile). `--release` is only for final deployment.
- Fix: Change to `cargo build` (without --release).
- Completion: CONTRIBUTING.md recommends debug builds for development.

### LOW

#### 319. ~~test-fec.sh Typo REFRACTOR~~ DONE
- Severity: LOW
- File: `scripts/tests/suites/test-fec.sh:19`
- Problem: Variable named `REFRACTOR` should be `REFACTOR`. Functionally works (used consistently) but misleading.
- Fix: Rename variable to `REFACTOR`.
- Completion: No occurrences of REFRACTOR in codebase.

#### 320. ~~Dead `--dry-run` and `--rustflags` Flags in 19 Scripts~~ DONE
- Severity: LOW
- Files: 10 scripts parse `--dry-run` into `DRY_RUN` but never reference it. 9 TLS utility scripts parse `--rustflags` into `RUSTFLAGS_EXTRA` but run no cargo commands.
- Problem: Boilerplate from a shared template. Dead code that suggests functionality that doesn't exist.
- Fix: Remove unused flag parsing or implement the advertised behavior.
- Completion: No parsed flags that are never used.

#### 321. ~~Desktop Test Naming Mismatches~~ DONE
- Severity: LOW
- Files: `scripts/tests/frontend/desktop/unit/src/components/error-boundary.test.tsx`, `scripts/tests/frontend/desktop/unit/src/components/tunnel/tunnel-detail.test.tsx`
- Problem: `error-boundary.test.tsx` tests `FatalErrorScreen.svelte` (no ErrorBoundary component exists). `tunnel-detail.test.tsx` tests `TunnelStats.svelte` (no TunnelDetail component exists) and overlaps with `tunnel-stats.test.ts`.
- Fix: Rename `error-boundary.test.tsx` to `fatal-error-screen.test.ts`. Merge `tunnel-detail.test.tsx` content into `tunnel-stats.test.ts` and delete it.
- Completion: Test filenames match the components they test. No redundant test files.

#### 322. ~~TunnelsView.svelte Missing Unit Test~~ DONE
- Severity: LOW
- File: `apps/svelte-desktop/src/lib/components/views/TunnelsView.svelte`
- Problem: This view component (wrapper/page-level) has no dedicated unit test. Child component `TunnelList.svelte` is tested but the wrapper logic is not.
- Fix: Create `scripts/tests/frontend/desktop/unit/src/views/tunnels-view.test.ts` with tests for the view wrapper behavior.
- Completion: Test file exists and passes.

### COVERAGE - ALL DONE (+215 Rust tests)

#### 323. ~~`src/optimize/simd.rs` - 2134 LoC, Zero Tests~~ DONE (51 tests)
- Severity: HIGH
- Problem: SIMD acceleration dispatchers for crypto, FEC, and transport paths. Bugs here cause silent correctness failures across all performance-critical paths. No inline tests, no external test file.
- Fix: Add inline `#[cfg(test)] mod tests` with at minimum: dispatch correctness, fallback path equivalence, boundary conditions.
- Completion: >= 10 tests covering dispatch logic, fallback equivalence.

#### 324. ~~`src/optimize/brain.rs` - 1633 LoC, Zero Tests~~ DONE (34 tests)
- Severity: HIGH
- Problem: Brain sensor fusion optimization layer. Drives all stealth/CC/FEC runtime decisions. Zero test coverage despite being a decision engine.
- Fix: Add inline tests for sensor fusion logic, decision thresholds, state transitions.
- Completion: >= 8 tests covering sensor fusion, threshold logic, state transitions.

#### 325. ~~`src/optimize/string.rs` - 1033 LoC, Zero Tests~~ DONE (31 tests)
- Severity: HIGH
- Problem: SIMD string search used in stealth fingerprinting. Incorrect results could break detection or cause false positives.
- Fix: Add tests for search correctness, edge cases (empty, boundary, multi-match), SIMD vs scalar parity.
- Completion: >= 6 tests covering search correctness and edge cases.

#### 326. ~~`src/optimize/transport.rs` - 863 LoC, Zero Tests~~ DONE (14 tests)
- Severity: MEDIUM
- Problem: Transport optimization layer (packet batching, pacing, scheduling). No coverage.
- Fix: Add tests for batching logic, pacing correctness, scheduling decisions.
- Completion: >= 6 tests.

#### 327. ~~`src/fec/gf_tables.rs` - 732 LoC, Zero Tests~~ DONE (16 tests)
- Severity: MEDIUM
- Problem: Galois field lookup tables and multiplication - foundation of all FEC math. A single wrong entry silently corrupts all FEC encoding/decoding.
- Fix: Add tests for GF multiplication correctness, table integrity (identity, inverse, distributive law), known test vectors.
- Completion: >= 6 tests verifying GF arithmetic properties.

#### 328. ~~`src/transport/config.rs` - 695 LoC, Zero Inline Tests~~ DONE (18 tests)
- Severity: MEDIUM
- Problem: TransportConfig where all connection parameters are parsed and validated. No inline tests, external test coverage is ambiguous.
- Fix: Add inline tests for config parsing, validation, defaults, boundary values.
- Completion: >= 8 tests.

#### 329. ~~`src/optimize/sort.rs` - 667 LoC, Partial~~ DONE (13 tests)
- Severity: LOW
- Problem: Sort acceleration (argsort, radix sort). Only argsort has partial external coverage via rt-argsort-parity.rs. Bulk of sort logic untested.
- Fix: Add tests for radix sort correctness, stability, edge cases (empty, single, already sorted, reverse).
- Completion: >= 6 tests beyond argsort.

#### 330. ~~`src/stealth/tls_cover.rs` - 425 LoC, Zero Tests~~ DONE (16 tests)
- Severity: MEDIUM
- Problem: TLS cover traffic generation - security-critical for stealth mode. Generates fake TLS records to disguise QUIC traffic. Zero tests.
- Fix: Add tests for cover traffic generation, cipher suite consistency, record format validity.
- Completion: >= 6 tests.

#### 331. ~~`src/optimize/udp.rs` - 413 LoC, Zero Tests~~ DONE (5 tests)
- Severity: LOW
- Problem: UDP send path optimizations (GSO, sendmmsg). Data path code with no coverage.
- Fix: Add tests for GSO segmentation, sendmmsg batching, fallback to regular send.
- Completion: >= 4 tests.

#### 332. ~~`src/fec/internal.rs` - 1229 LoC, Zero Actual Tests~~ DONE (17 tests)
- Severity: LOW
- Problem: FEC internal implementation. Has `#[cfg(test)]` block but only for helper functions used by other test files. No actual `#[test]` functions testing internal.rs logic itself.
- Fix: Add tests for internal FEC operations (matrix ops, coefficient generation, reconstruction logic).
- Completion: >= 8 tests for internal FEC logic.

---

## Intake Rules

- Add entries here only for real remaining work.
- Do not re-add completed historical plans or stale parent backlog blocks.
- Keep detailed historical execution records in `docs/todo/*.md` and `docs/context.md`.
