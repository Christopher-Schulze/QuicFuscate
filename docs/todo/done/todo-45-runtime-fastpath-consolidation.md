# TODO 45: Runtime Fastpath Consolidation

## Scope
- Runtime transport fastpath wiring in:
  - `src/implementations/client/io_driver.rs`
  - `src/transport/batch.rs`
  - `src/transport/udpfast.rs`
  - `src/transport/xdp.rs`
  - `src/optimize.rs` (fastpath-related integration surface)

## Problem Statement (Audit Evidence, 2026-03-05)
- Active client runtime outbound path uses `sendmmsg`/`io_uring` directly via `io_driver` and does not route through `transport::batch::BatchProcessor`.
  - Evidence: `src/implementations/client/io_driver.rs:101`, `:125`, `:129`, `:371`, `:405`
- `BatchProcessor` appears effectively test-only right now.
  - Evidence: production references not found; test reference in `scripts/tests/rust/rt-transport-batch-processor.rs:3`
- `UdpFastPath` is mostly used in harness/tests, not in primary runtime data path.
  - Evidence: `src/harness.rs:207`; tests under `scripts/tests/rust/rt-transport-udpfast.rs`
- `FastPathTransport` in `src/transport/xdp.rs` is not integrated into primary runtime flow.
  - Evidence: only local module/test references (`src/transport/xdp.rs:801`, `:995`)

## Objectives
- Establish one canonical fastpath runtime architecture.
- Remove shadow/parallel implementations that are not part of the canonical path.
- Keep optional paths only when they are wired, tested, and documented as such.

## Work Breakdown
### A. Canonical Architecture Definition
- [x] Document the single production fastpath path (dispatch, fallbacks, telemetry). [x] 2026-03-08
- [x] Define which modules are authoritative vs compatibility/test-only. [x] 2026-03-08
- [x] Define ownership boundaries for `io_driver`, `transport/*`, and `optimize/*`. [x] 2026-03-08

### B. Runtime Wiring Cleanup
- [x] Remove or rewire `BatchProcessor` if not part of production path. [x] 2026-03-05
- [x] Remove or rewire orphan `FastPathTransport` usage patterns. [x] 2026-03-08
- [x] Consolidate duplicated server runtime surfaces (`implementations/server::ServerRuntime` vs `main::run_server`) into one canonical data path. [x] 2026-03-08
- [x] Ensure no parallel code path can silently diverge from canonical behavior. [x] 2026-03-08

### C. Telemetry and Observability Alignment
- [x] Ensure telemetry counters represent only active runtime paths. [x] 2026-03-08
- [x] Remove misleading counters that are tied only to dormant paths. [x] 2026-03-08
- [x] Add explicit telemetry tags for fallback reason and selected fastpath. [x] 2026-03-08

### D. Regression Coverage
- [x] Add tests proving the canonical path is exercised in runtime loops. [x] 2026-03-08
- [x] Add tests proving removed paths cannot be reintroduced unnoticed. [x] 2026-03-08

## Acceptance Criteria
- [x] Exactly one canonical fastpath runtime path exists per platform mode. [x] 2026-03-08
- [x] Dormant parallel fastpath implementations are removed or explicitly test-only. [x] 2026-03-08
- [x] Telemetry reflects real runtime behavior. [x] 2026-03-08
- [x] CI/tests fail if runtime fastpath wiring drifts. [x] 2026-03-08

## Deliverables
- [x] Code cleanup PR touching runtime transport modules. [x] 2026-03-08
- [x] Updated docs section describing canonical fastpath architecture. [x] 2026-03-08
- [x] Regression tests guarding against shadow-path reintroduction. [x] 2026-03-08

## Progress Notes
- 2026-03-08: Narrowed the broad `transport::udpfast` public surface without touching the retained harness/rust-test behavior:
  - `AlignedBuffer` is no longer public product surface; rust parity now uses the narrow helper `aligned_buffer_len_for_rust_tests(...)`.
  - `UdpFastPath` no longer exposes raw public atomic counters; rust parity now reads the narrow helper `counters_for_rust_tests()`.
  - leftover helper-only socket metadata access (`local_addr`) is now module-test-only instead of part of the broad runtime/test feature surface.
- 2026-03-08: Removed the remaining orphan zerocopy compatibility shadow:
  - deleted the unused `optimize::zerocopy` shim from `src/optimize.rs`
  - deleted the now-fully-orphaned test-only `optimize::udp::ZeroCopySocket`
  - canonical zerocopy behavior remains on the active `optimize::udp` runtime helpers plus transport/io_uring completion flow, with no extra compatibility owner left behind
- 2026-03-08: Continued narrowing the `udpfast` compatibility contract:
  - removed dead `udpfast` counter/constant exports with no external readers (`BATCHED_SENDS`, `BATCHED_RECVS`, `GSO_SEGMENTS`, `MAX_GSO_SEGMENTS`, `MAX_VECTORED_IO`)
  - reduced `send_single(...)` and `recv_single(...)` to internal implementation helpers
  - retained public `UdpFastPath` only for the still-real harness/rust-test and XDP-compat owners
- 2026-03-08: Updated `docs/DOCUMENTATION.md` to match the narrowed fastpath truth:
  - `transport::batch` is documented as rust parity/test-only
  - `udpfast` is documented as a narrowed compatibility layer, not broad runtime API
  - zerocopy wording no longer references the removed optimize-side zerocopy wrapper/shim
  - XDP/fastpath wording now reflects the compatibility-alias posture more precisely
- 2026-03-08: Tightened the remaining private XDP compatibility owner:
  - `FastPathTransport` was already private
  - its construction/enable/receive helpers are now private too
  - the only retained external entry stays the narrow smoke/probe surface on the transport root
- 2026-03-08: Extended runtime guardrails for the narrowed fastpath contract:
  - fail if `udpfast::AlignedBuffer` becomes broad public surface
  - fail if `udpfast::send_single(...)` or `recv_single(...)` regain visible surface
  - fail if optimize-side zerocopy shadow surface (`optimize::zerocopy`, orphan `ZeroCopySocket`) reappears
  - runtime guardrail audit stays green after the new checks
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: Live packet rate limiting is now wired directly into `main::run_server` receive path; architectural duplication between `ServerRuntime` and `main::run_server` remains tracked for consolidation.
- 2026-03-05: Rewired Linux client hotpath adapter to call centralized `transport::batch::init_socket_acceleration` + `optimize::zc_batch::sendmmsg` directly; `BatchProcessor` remains compatibility/test-oriented and no longer carries runtime outbound ownership.
- 2026-03-05: Removed unused `BatchProcessor::batch_send_connected` after runtime detachment; outbound connected sendmmsg path is now owned by `io_driver` via `optimize::zc_batch`.
- 2026-03-05: Simplified `transport::xdp::FastPathTransport` by removing dead NUMA/memory-pool buffering branch; constructor no longer requires `MemoryPool`, and call sites/tests now use `FastPathTransport::new()` directly.
- 2026-03-05: Consolidated duplicated fastpath mode fallback logic in `FastPathTransport::enable_fastpath_from_env` behind centralized helpers (`try_enable_uring_fastpath`, `enable_uring_or_udp_fallback`) to prevent mode-specific drift.
- 2026-03-05: Reduced `FastPathTransport` API surface by making internal fields and `BatchedPacket` private and dropping unused packet metadata (`ecn`, `timestamp`), keeping behavior unchanged.
- 2026-03-05: Centralized server rate-limiter env configuration loading in `implementations/server/limits.rs` (`load_rate_limit_config_from_env`) and removed duplicate parser/config code from `main.rs`, so CLI server boot now uses the same source-of-truth limit loader as server module code.
- 2026-03-05: Moved QKey auth runtime contract (`require_qkey_for_new_clients`, `QKeyAuthState`, timeout policy) from `main.rs` into `implementations/server/mod.rs` and rewired `run_server` to consume the centralized server-side definitions.
- 2026-03-05: Moved QKey domain-fronting policy resolution (`QKeyDomainFrontingPolicy`, SNI mode constants, validation/normalization helpers) out of `main.rs` into `implementations/server/mod.rs`; admin handlers now resolve and fall back through the centralized server policy surface.
- 2026-03-05: Centralized QKey issuance in `implementations/server/mod.rs` (`issue_unix_admin_qkey`, `issue_http_admin_qkey`) so Unix admin and HTTP admin no longer maintain separate nonce/token/preset/remote-resolution pipelines in `main.rs`.
- 2026-03-05: Marked `implementations/server/admin.rs::DefaultAdminHandler` as `test/rust-tests`-only and removed its re-export from the production surface; it contains placeholder-style behavior and is not part of the real server runtime path.
- 2026-03-05: Centralized atomic server-side file writes in `implementations/server/fsutil.rs` and rewired blocked-IP persistence, admin auth persistence, config/logging writes, and QKey registry persistence away from duplicated local temp-file helpers.
- 2026-03-05: Extracted shared `ServerAdminCore` so Unix admin and HTTP admin now share one implementation for base status, client snapshots, action dispatch, blocked-IP mutations, and QKey issuance instead of maintaining parallel handler logic.
- 2026-03-05: Moved `ServerAdminCore` and `AdminAction` ownership from `main.rs` into `implementations/server/mod.rs`, so admin orchestration state/action dispatch now belongs to the server module rather than the CLI entrypoint.
- 2026-03-05: Moved standalone live-connection lifecycle helpers for DCID-based path rebinding and closed-client reconciliation out of `main.rs` into `implementations/server/mod.rs` (`try_rebind_live_client_by_dcid`, `reconcile_live_clients`), reducing more runtime bookkeeping drift between CLI loop code and server module ownership.
- 2026-03-05: Added centralized `implementations/server::open_server_tun(...)` and rewired both `ServerRuntime::start()` and `main::run_server` to use the same validated server-TUN open path, eliminating a runtime requirement drift between the two server entry surfaces.
- 2026-03-05: Wired `implementations/server::AcceptLoop` into `main::run_server` for live accept decisions, per-IP tracking, backpressure handling, close accounting, and address-migration bookkeeping, replacing another shadow acceptance path that previously lived only in `main.rs`.
- 2026-03-05: Quarantined the unused `optimize::zerocopy` compatibility shim behind `cfg(any(test, feature = "rust-tests"))`; runtime zerocopy ownership remains centralized in `optimize::udp` and the `accelerate::transport_io` alias.
- 2026-03-05: Quarantined `optimize::udp::NicParallelism` behind `cfg(any(test, feature = "rust-tests"))`; the RPS helper had no runtime callers and was another unowned performance surface in production code.
- 2026-03-05: Fixed engine/server runtime stat drift by making `engine::QuicFuscateEngine::refresh_stats()` pull bytes/packets/session-count from `ServerRuntime` when the engine runs in server mode instead of reporting only global transport counters.
- 2026-03-05: Unified the server per-IP connection default to `DEFAULT_MAX_CONNECTIONS_PER_IP = 3` and rewired both `AcceptLoop::default()` and `ServerRuntime`'s `ConnectionLimiter` to the same constant, removing a silent 5-vs-3 drift between CLI and engine server paths.
- 2026-03-05: Quarantined the unused `implementations::server::GlobalMetricsServer` behind `cfg(any(test, feature = "rust-tests"))`; the active runtime/admin path only uses `MetricsServer`, so the global-server variant was another unowned public surface.
- 2026-03-05: Moved the live `ClientSnapshot` model and snapshot-to-`ClientInfo` projection out of `main.rs` into `implementations/server/admin.rs`, so admin-visible client state no longer depends on a CLI-local server data model and client listings are now deterministically sorted by remote address.
- 2026-03-06: Moved standalone live-packet handling from `main.rs` into `implementations/server::process_live_server_client_datagram(...)`, so recv/auth/TUN-forward/flush bookkeeping now belongs to the server module instead of the CLI loop body.
- 2026-03-06: Moved standalone live housekeeping into `LiveServerState::run_housekeeping_tick(...)` and folded path-rebind admission behind `LiveServerState::handle_incoming_path_update(...)`, further reducing CLI-loop ownership of server runtime policy.
- 2026-03-06: Wired standalone live accepts and cleanup through a shared `LiveServerDomain` using `SessionManager`, `IpPool`, and `ConnectionLimiter`, so the standalone loop now carries server-domain state instead of keeping a fully separate client-only truth.
- 2026-03-06: Collapsed `ServerRuntime::accept_client` / `remove_client` onto the same shared domain helper logic used by the standalone `LiveServerDomain`, further reducing duplicated server-lifecycle code paths.
- 2026-03-06: Collapsed standalone and embedded session-expiry cleanup onto the same shared domain removal path, further shrinking server lifecycle drift between `main.rs` and `ServerRuntime`.
- 2026-03-06: Moved Linux multi-packet `udpfast::UdpFastPath::send_batch(...)` onto shared `optimize::udp::send_batch_maybe_zerocopy(...)`, so per-packet `sendmmsg` address conversion and zerocopy fallback now live in one canonical helper while `udpfast` keeps local prefetch, telemetry, and completion-drain behavior.
- 2026-03-06: Moved Linux `udpfast::UdpFastPath::send_single(...)` onto a `transport::uring::try_send_to(...)` first-attempt before falling back to `socket.send_to(...)`; `udpfast` still retains local GSO handling and completion draining, but the normal single-datagram path now aligns with the canonical io_uring send story.
- 2026-03-06: Collapsed duplicated `IoUringDatagram` completion handling behind shared internal helper `submit_and_complete(...)`, so connected and destination-addressed io_uring datagram sends now share one canonical submit/wait/completion path while preserving zerocopy thresholding and errqueue drain only on the connected path.
