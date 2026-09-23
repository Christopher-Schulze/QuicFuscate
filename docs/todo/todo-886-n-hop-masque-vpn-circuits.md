---
id: TODO-886
title: Implement bounded N-hop MASQUE VPN circuits
severity: HIGH
phase: T
priority: P0
status: BLOCKED
created: 2026-08-11
depends_on: [TODO-866, TODO-867]
---

# TODO-886: Implement Bounded N-Hop MASQUE VPN Circuits

## Objective

Implement production multi-hop VPN circuits in which the client can chain multiple independently authenticated QuicFuscate relays before reaching an exit. Product support must prove one, two, and three hops. The core must represent generic N-hop circuits and enforce a configurable resource and PMTU bound instead of hardcoding three into transport logic.

The architecture must preserve performance and stealth by using QUIC DATAGRAM and MASQUE rather than ordered stream tunneling, while making every relay non-open, bounded, authenticated, observable, and safe to tear down.

## Privacy and Product Claim

- Entry relay sees the client network address and the next relay, but not the final destination carried inside deeper encrypted layers.
- Intermediate relay sees only its predecessor and successor plus opaque inner QUIC datagrams.
- Exit sees destination traffic but receives it from the preceding relay, not directly from the client.
- No relay receives the full configured circuit in protocol messages.
- Timing and volume correlation remain possible. The feature must not claim Tor-level anonymity, global-passive-adversary resistance, or protection against relay collusion.
- The client must surface hop count, establishment state, and degraded state without exposing secrets.

## Verified Current Boundaries

- `ConnectionConfig` owns one remote endpoint, one local bind, one SNI, and one QKey identity/token pair.
- `ClientConnection` owns exactly one `QuicFuscateConnection` and one remote/local address pair.
- `IoDriver` owns the physical UDP boundary and batching policy.
- `QuicFuscateConnection` owns one locally initiated `masque_stream_id` and one peer stream.
- H3 CONNECT-UDP uses one connection-local Flow-ID and current TUN routing treats accepted MASQUE payloads as raw IP after packet normalization.
- The current server accepts authenticated CONNECT-UDP for the canonical TUN carrier. It is not yet a general relay that opens a bounded UDP association to the requested next hop.
- TODO-866 and TODO-867 own authenticated assignment and canonical MASQUE carrier truth. This task extends them without reopening their completed single-hop guarantees.

## Target Topology

```text
Client TUN
  -> Hop 1 QUIC over physical UDP
  -> authenticated CONNECT-UDP association to Hop 2
  -> Hop 2 QUIC datagrams carried inside Hop 1 MASQUE DATAGRAMs
  -> authenticated CONNECT-UDP association to Hop 3
  -> Hop 3 QUIC datagrams carried through the prior circuit
  -> authenticated CONNECT-IP final tunnel at the exit
  -> destination network
```

Inter-relay links use RFC 9298 CONNECT-UDP and RFC 9297 HTTP Datagrams/Capsules. The final IP tunnel targets RFC 9484 CONNECT-IP. The existing raw-IP-over-CONNECT-UDP carrier remains a migration-compatible single-hop path only until CONNECT-IP has equivalent proof.

## Configuration Model

### Circuit and Hop Types

- Introduce one canonical `CircuitConfig` with an ordered non-empty hop list.
- Introduce one canonical `HopConfig` containing endpoint, SNI/persona, CA/trust policy, public QKey ID, secret-token reference, role, optional relay metadata, timeouts, and per-hop policy overrides.
- Roles are `relay` and `exit`. Exactly one exit is required and it must be last.
- Keep the legacy singular connection fields as a one-hop migration shorthand, not a second runtime model.
- Reject simultaneous ambiguous use of legacy and circuit fields.
- Default product maximum is three hops.
- Allow a configurable hard maximum up to eight only when recursive datagram budgeting still admits QUIC's minimum datagram size and runtime resource limits.
- Reject zero hops, duplicate endpoint identities, repeated QKey identities, loops, exit-before-last, untrusted relay roles, invalid address families, impossible MTU, and unsupported policy combinations.
- Secret tokens remain redacted, zeroizing, non-serializable to diagnostics, and unique per hop by default.

### Route Diversity Policy

- Reject exact endpoint and resolved-address reuse inside one circuit.
- Support optional operator-supplied provider, region, jurisdiction, and failure-domain labels.
- Support required diversity constraints without adding an implicit third-party geolocation dependency.
- Resolve and pin endpoint sets with DNS-rebinding protection before association.
- Revalidate address policy on refresh and refuse a newly forbidden target.
- Detect authenticated circuit loops with a bounded circuit identifier and hop budget without revealing the full path to relays.

## Client Circuit Architecture

### Virtual Datagram Link

- Separate `QuicFuscateConnection` packet production/consumption from physical UDP through one typed datagram-link contract.
- Hop 1 uses the existing physical UDP/I/O driver.
- Hop N uses a virtual link backed by the authenticated CONNECT-UDP flow of hop N-1.
- Inner QUIC datagrams remain opaque bytes to prior hops. They must bypass raw-IP packet normalization, TUN dispatch, compression, and application payload parsing.
- Route accepted MASQUE payloads by typed flow purpose: `TunIp`, `NextHopUdp`, or `Control`.
- Remove the current assumption that every accepted MASQUE DATAGRAM contains raw IP.
- Use bounded zero-copy or pooled-buffer ownership through each encapsulation layer where it produces a measured benefit.
- Do not recursively copy the full datagram for every hop when ownership can move or slice safely.

### Circuit Orchestrator

- Own an ordered vector of hop sessions with explicit lifecycle states.
- Establish hop 1 first, authenticate it, create its relay flow, then establish hop 2 through that flow. Continue sequentially because each next-hop transport depends on the preceding association.
- Establish the final CONNECT-IP tunnel only after every relay hop is authenticated and ready.
- Publish the circuit as usable only after the exit assignment and route policy are complete.
- Pump outbound inner connection packets from deepest to outermost and inbound carrier packets from outermost to deepest without recursive async call stacks.
- Use one bounded iterative scheduler with fair per-hop budgets and backpressure.
- Keep packet, timer, PTO, ACK, key-update, and close ownership connection-local for every hop.
- Tag telemetry with bounded hop indexes and circuit generations only.

## Relay Architecture

### Real CONNECT-UDP Association

- Parse the RFC 9298 target template strictly and preserve IPv4, IPv6, hostname, and port semantics.
- Store target and flow ownership by authenticated connection, CONNECT stream, context/Flow-ID, and generation.
- Open one bounded UDP socket or pooled association to the validated next hop.
- Forward client MASQUE DATAGRAM payloads to that socket and socket responses back through the same authenticated flow.
- Preserve UDP datagram boundaries exactly.
- Reject unsolicited source addresses unless the association policy explicitly permits them.
- Close and join every socket/task on stream close, connection close, auth revocation, idle timeout, quota breach, server shutdown, or process lifecycle transition.

### No Open Proxy

- Relay mode is disabled by default.
- Require successful TLS and QKey authentication before target resolution or socket creation.
- Require an explicit allowlist of relay identities, hostnames, ports, and resolved network ranges.
- Reject loopback, link-local, multicast, broadcast, unspecified, documentation, metadata-service, local-control, and private ranges unless explicitly owned and allowlisted for a deployment.
- Validate every resolved address, pin the selected address, and prevent DNS rebinding between validation and connect.
- Deny arbitrary internet destinations at intermediate relays.
- Apply per-principal connection, flow, packet-rate, byte-rate, queue, DNS, socket, and idle limits before allocation.
- Bound error responses and amplification before address validation.
- Audit association create, reject, close, quota, and policy events without logging QKeys or payloads.

### CONNECT-IP Exit

- Implement strict RFC 9484 request, address assignment, route advertisement, IP version, and datagram context handling.
- Bind the exit tunnel to the authenticated circuit principal.
- Enforce source-address assignment, anti-spoofing, client isolation, firewall, NAT/routing, DNS, quota, ICMP/PTB, and teardown contracts already owned by the single-hop runtime.
- Keep the old raw-IP CONNECT-UDP path as explicit compatibility, not an invisible fallback from failed CONNECT-IP.

## MTU and Encapsulation Budget

- Compute the confirmed UDP payload budget independently for every physical segment.
- Subtract exact QUIC short-header, packet-number, authentication-tag, DATAGRAM frame, Flow-ID/context, and relay encapsulation overhead at each layer.
- Derive each inner hop's maximum datagram from the complete prior carrier budget.
- Reject a configured circuit before activation when any inner hop cannot emit the required QUIC minimum datagram.
- Run DPLPMTUD per hop with connection-local probe ownership.
- Propagate Packet Too Big information inward without accepting unauthenticated MTU reduction.
- Never rely on IP fragmentation for correctness.
- Expose effective TUN MTU and per-hop budgets in bounded diagnostics.
- Recompute or rebuild the circuit after path migration changes a carrier budget.

## Congestion, FEC, Timing, and Stealth Policy

- Measure nested congestion-control interaction instead of assuming independent controllers compose cleanly.
- Keep QUIC DATAGRAM as the relay carrier. Do not replace it with ordered H3 DATA streams for convenience.
- Apply FEC per measured lossy segment and prevent redundant repair amplification across every layer by default.
- Bound total FEC, padding, cover-traffic, and capsule overhead as a percentage of payload bytes per circuit.
- Use independent per-hop randomness, connection IDs, TLS exporters, QKeys, personas, timing seeds, and key epochs.
- Avoid synchronized keepalives, rotations, padding bursts, and cover traffic that create a circuit-wide fingerprint.
- Preserve browser-coherent QUIC/H3 appearance on every public relay-to-relay segment.
- Do not expose circuit depth in visible packet fields or deterministic timing.
- Benchmark whether entry-only, per-hop, or adaptive cover policy has the best stealth/performance frontier and freeze one bounded default.
- Integrate TODO-885 advanced AEAD per hop only after its negotiation is independently complete. Standard mode must support the full circuit first.

## DNS, Routing, and Leak Prevention

- Bootstrap resolution may occur only for hop 1 under the existing endpoint policy.
- Resolve later relay targets through the authenticated predecessor association or use pinned addresses, according to the configured privacy policy.
- Route application DNS through the final exit.
- Bind the kill switch to the physical entry endpoint plus explicitly required bootstrap services only.
- Never fall back from a failed circuit to direct application traffic.
- A direct single-hop fallback is allowed only as an explicit operator policy and must remain inside the VPN path.
- Ensure IPv4, IPv6, DNS, ICMP, and non-TCP/UDP traffic follow the same final exit.
- Prove no route or firewall residue remains after partial establishment or teardown.

## Reliability and Circuit Lifecycle

- States: `Idle`, `Resolving`, `EstablishingHop`, `AuthenticatingHop`, `EstablishingExit`, `Ready`, `Degraded`, `Draining`, `Closed`, and `Failed`.
- Give each state an owner, timeout, cancellation path, joined tasks, and cleanup invariant.
- Fail the circuit if any required hop fails. Never bypass the missing hop.
- Support make-before-break circuit rotation with a new generation, readiness barrier, route swap, old-generation drain, and bounded overlap.
- Support prebuilt alternate circuits after the primary is ready, within explicit resource limits.
- Preserve flow ordering within one circuit. Do not spray one flow across circuits unless a separately proven multipath policy owns it.
- Re-establish from the failed hop outward only when doing so cannot accidentally change route privacy; otherwise rebuild the complete circuit.
- Revoke one hop credential without leaving deeper sockets or routes alive.
- Close deepest-to-outermost while retaining the entry kill-switch allowance until all traffic owners are gone.

## Product and Operator Surfaces

- TOML, CLI, engine, admin API, desktop persistence, and UI must share one validated circuit schema.
- UI must compose existing design-system components and show ordered hops, role, endpoint label, status, latency, MTU budget, and failure without revealing tokens.
- Provide add, remove, reorder, validate, connect, rotate, and standard single-hop migration flows.
- Prevent saving an invalid circuit.
- Export/import redacts secret tokens and uses keychain/secret references.
- Health and metrics distinguish connection health from circuit readiness.
- Logs identify circuit generation and hop index, not destination payload data.

## Implementation Plan

1. Re-read current engine config, client runtime, I/O driver, Core connection, H3/MASQUE, live auth, server runtime, TUN, routing, firewall, DNS, PMTU, FEC, telemetry, UI/API, and native harness signatures.
2. Freeze the circuit/hop schema, legacy migration, validation, lifecycle, flow-purpose, and relay ACL contracts.
3. Introduce the virtual datagram-link seam without changing single-hop behavior.
4. Make MASQUE flow purpose typed and bypass raw-IP normalization for next-hop UDP.
5. Implement authenticated, bounded real CONNECT-UDP relay associations.
6. Implement client hop orchestration and two-hop inner QUIC establishment.
7. Generalize iteratively to N hops and enforce default three/hard resource limits.
8. Implement RFC 9484 CONNECT-IP at the final exit and migrate single-hop through the same typed circuit model.
9. Implement recursive PMTU, backpressure, lifecycle, kill-switch, DNS, routing, failover, and rotation.
10. Integrate admin/desktop/API surfaces from the canonical schema.
11. Add deterministic in-memory, native namespace, cross-platform client, security, leak, chaos, and performance proof.
12. Integrate TODO-885 per-hop advanced mode after standards-mode acceptance is green.
13. Update canonical docs, MAP wiring, config examples, operational guidance, and task truth in one pass.

## Acceptance Criteria

- Legacy one-hop configuration migrates to the circuit model without behavior loss.
- One-hop, two-hop, and three-hop product configurations establish and carry bidirectional IPv4, IPv6, DNS, TCP, UDP, and ICMP traffic.
- Generic N-hop code has no hardcoded three-hop branches and rejects resource/PMTU-invalid depth before route activation.
- Intermediate MASQUE flows carry opaque inner QUIC datagrams without TUN normalization.
- Relays open real bounded UDP associations only after authentication and ACL validation.
- No test can use an intermediate relay as an arbitrary open proxy.
- Final exit uses CONNECT-IP with strict address and anti-spoofing ownership.
- Each hop has independent TLS identity, QKey, key material, connection ID, packet numbers, and lifecycle.
- Effective MTU is correct at every depth and no path depends on fragmentation.
- Circuit failure never leaks direct traffic or leaves routes, firewall rules, sockets, tasks, DNS state, or TUN ownership behind.
- Make-before-break rotation changes the circuit only after a readiness barrier and drains the old generation.
- Packet captures show each relay only talks to its predecessor/successor and do not expose deeper plaintext or circuit depth.
- Standard packet protection supports the complete circuit.
- TODO-885 advanced protection, when available, negotiates independently per hop and passes the same matrix.
- Three-hop throughput, CPU, latency, jitter, loss, FEC, padding, and memory remain within explicit measured release thresholds recorded before promotion.
- Documentation states the privacy limits honestly.

## Verification Matrix

- Config serialization, migration, validation, secret redaction, duplicate/loop, role, and depth tests.
- Virtual datagram-link unit tests with real packet bytes and bounded queues.
- H3 target-template, Flow-ID/context, flow-purpose, CONNECT-UDP, and CONNECT-IP parser tests.
- Relay ACL, DNS rebinding, SSRF, reserved-address, quota, amplification, source-spoof, auth-before-allocation, and cleanup tests.
- Deterministic in-process 1/2/3/N-hop handshake and packet tests.
- Linux network-namespace topology with client, three relays, exit, destination, DNS, dual stack, PTB, and packet capture.
- Loss, jitter, reordering, duplication, bandwidth, MTU black hole, relay crash, credential revocation, reconnect, rotation, and shutdown chaos.
- Leak tests for direct route, DNS, IPv6, ICMP, kill-switch, startup failure, partial circuit, and teardown.
- Native macOS and Windows client to Linux relay-chain proof where environments are available.
- Standard-only, mixed-version, TODO-885 auto, and advanced-required matrices.
- Performance comparison for one, two, and three hops with status-bearing artifacts.
- Workspace format, strict Clippy, relevant tests, runtime guardrails, documentation truth, frontend checks/build/E2E, and diff hygiene.

## Primary Files and Owners

- `crates/qf-engine-types/src/lib.rs`
- `src/implementations/client/connection.rs`
- `src/implementations/client/io_driver.rs`
- `src/implementations/server/`
- `src/core/connection.rs`
- `src/transport/h3/connection.rs`
- `src/transport/connection/`
- `crates/qf-transport-path/`
- `crates/qf-transport-udp/`
- `crates/qf-firewall/`
- `crates/qf-dns/`
- `crates/qf-telemetry/`
- `apps/svelte-admin/`
- `apps/svelte-desktop/`
- `apps/tauri/`
- `scripts/tests/`
- `scripts/benchmarks/`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `config/`

## Sub-Tasks

- [x] Freeze canonical circuit, hop, role, diversity, credential-reference, depth, and recursive PMTU contracts in `qf-engine-types`, including strict legacy one-hop projection.
- [x] Add typed MASQUE request targets, flow purposes, CONNECT-UDP and CONNECT-IP stream ownership, and remove unconditional raw-IP normalization.
- [x] Add the virtual datagram-link boundary and iterative per-hop circuit scheduler with bounded queues, timers, and lifecycle states.
- [x] Add authenticated relay policy, strict target resolution/pinning, SSRF and rebinding rejection, quotas, real UDP associations, and joined teardown.
- [x] Establish standard-mode one-hop, two-hop, three-hop, and bounded generic N-hop client circuits with final CONNECT-IP exit ownership.
- [x] Propagate recursive PMTU, DPLPMTUD, PTB, DNS, routing, kill-switch, failover, rotation, telemetry, health, admin, desktop, and import/export contracts.
- [!] Add deterministic, native namespace, chaos, leak, security, cross-platform, and performance proof, then run the complete repository gate matrix. Local proof is green; privileged Linux and native cross-platform execution are unavailable on this host.
- [x] Update `DOCUMENTATION.md`, `MAP.md`, configuration examples, operational guidance, and task truth in one consolidated pass.

## Notes

- The transport boundary now owns strict RFC 9298 target parsing, quarter-stream Flow-IDs, `TunIp`/`NextHopUdp`/`Control` purposes, and RFC 9484 CONNECT-IP request recognition. Opaque next-hop datagrams bypass raw-IP normalization and TUN dispatch.
- The client now owns an iterative vector of independently authenticated QUIC hop sessions. Only hop zero reaches physical UDP; deeper packets traverse bounded purpose-bound MASQUE queues from deepest to outermost.
- Relay admission now occurs after QKey authentication and before the HTTP success response. Admission resolves once, enforces CIDR/port/special-use policy and association quotas, pins one address, opens a connected UDP socket, and preserves datagram boundaries through bounded ingress and response queues.
- RFC 9484 ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT capsules are emitted before the private operational assignment. The client parses them strictly and rejects state that disagrees with the authenticated address assignment.
- Per-hop QUIC send/receive and DPLPMTUD ceilings now decrease by the recursive carrier budget. Runtime effective TUN MTU also follows the live physical path MTU.
- Focused proof is green: `qf-control-plane` 11 tests, `qf-engine-types` 62 tests, and the real loopback UDP relay association test under `rust-tests`.
- Entry resolution is now pinned once and shared by client socket and kill-switch ownership. Inner hop construction and credential resolution are lazy and sequential: a successor is not created until its authenticated predecessor CONNECT-UDP link is ready.
- The make-before-break path prebuilds and health-checks one alternate generation while retaining the active TUN. The engine health owner now promotes a ready alternate after typed connection loss, restores a fail-closed state when no standby is ready, and replenishes the configured standby after promotion. Tauri status/stat polling and the circuit CLI runtime both service this owner.
- Desktop circuit persistence carries canonical trust, timeout, per-hop policy, primary, and alternate-circuit contracts without visual changes. The existing approved Rotate control remains unchanged and swaps persisted primary/alternate ownership only after successful promotion. Desktop Svelte checking passes with zero errors and warnings; native Tauri checking and the focused secret/policy circuit roundtrip test pass.
- A TOML configuration containing `circuit` now routes the CLI client through `QuicFuscateEngine` instead of the legacy single-connection loop. The legacy CLI path remains unchanged for configurations without a canonical circuit.
- Relay quotas now cover aggregate request and response packets/bytes. Hostname resolution is additionally bounded per authenticated session per minute, while IP literals correctly bypass the DNS counter; completed associations release circuit ownership and saturated association queues cannot block the relay manager.
- Nested carrier scheduling now applies a bounded 64-datagram/256-KiB fair budget per hop and drive cycle in both directions. A saturated outer QUIC DATAGRAM queue preserves the already-produced inner packet in one link-owned retry slot and reports typed backpressure instead of converting queue pressure into a fatal generic H3 error or silently dropping the packet. A focused queue test proves ordering plus datagram and byte admission bounds.
- Current local gates after the runtime hardening: root `cargo check` passes, strict all-feature Clippy passes, all six relay policy/real-UDP/quota tests pass, all eight circuit-filtered root tests pass, all 47 MASQUE-filtered root tests pass, the complete all-feature library suite passes with 1,750 tests executed: 1,749 passed, zero failed, and one ignored, and the full non-io_uring Rust test-binary invocation exits `0`. Root test linking uses `RUSTFLAGS=-C debuginfo=0` solely to preserve the mandatory 2 GB free-disk reserve; test logic and features remain unchanged.
- `config/circuit-client.example.toml` is a schema-validated three-hop deployment template using secret references and independent hop trust/identity policy. `scripts/tests/tun-multihop-e2e-netns.sh` owns isolated one-, two-, and three-hop Linux namespace topologies, real relay/exit processes and QKeys, bidirectional IPv4/IPv6 ICMP, TCP, UDP, DNS, canonical CLI-path, receiver-verified TCP throughput with byte/SHA-256 identity and a 70% configured-rate floor, adjacent-only underlay capture, exclusive optional evidence artifacts, graceful process, TUN, firewall, and forwarding-state teardown proof. Bash syntax and ShellCheck pass locally, while privileged Linux execution remains open.
- Canonical circuit validation now rejects empty, over-128-character, or control-character hop labels, duplicate secret references within one circuit, and secret-reference reuse across primary and standby circuits. Standby promotion matching covers every operator-controlled topology, trust, timeout, diversity, FEC, padding, timing, cover, and credential-reference field while intentionally excluding runtime-only resolved bearer tokens and DNS pins. The `qf-engine-types` suite passes all 70 unit tests plus one ignored documentation example; strict all-feature Clippy and focused rotation-control tests pass.
- `allow_single_hop_fallback=true` is valid only for a multi-hop primary with `max_parallel_circuits = 2`. The engine derives a VPN-contained direct-to-exit standby, promotes it only after authenticated readiness, marks the circuit degraded, retains the kill switch, and never falls back to direct application traffic.
- Make-before-break promotion requires the active and replacement exits to assign the same address families, addresses, and DNS identity so the live TUN and existing flows remain valid. A replacement with a smaller authenticated path or assignment MTU now lowers the live TUN MTU before the route owner changes; a failed native MTU update closes the standby and leaves the active circuit untouched.
- The Linux namespace gate now supports bounded MTU, delay, jitter, loss, reordering, and duplication impairment; verifies tunnel loss, RTT, jitter, throughput integrity, aggregate runtime CPU, peak RSS, adjacency-only captures, selected entry/middle/exit failure, fail-closed behavior, and zero residue; and emits one JSON performance artifact per hop depth. Syntax, ShellCheck, CI YAML parsing, diff hygiene, and the runtime guardrail audit pass locally. Privileged Linux execution and native macOS/Windows-to-Linux proof remain open environment gates.
- Direct execution on the current macOS session was attempted with `bash scripts/tests/tun-multihop-e2e-netns.sh` and exited `1` before any namespace, route, firewall, TUN, process, or artifact mutation: `FAIL: root is required`. This is an explicit unavailable native gate, not a product-test failure or a pass claim.
- Private-control bootstrap ordering is covered across the circuit boundary: the authenticated
  server installs the control owner after accepting `TunIp`, `NextHopUdp`, or other peer MASQUE
  flows, while the client primes the private-control tick after QKey assignment for the direct
  connection and each active circuit hop. The runtime guardrail audit rejects a source-order
  regression. These are local source and focused-test gates; privileged Linux namespace,
  cross-platform, packet-capture, leak, and performance evidence remain unavailable here.
- GitHub CI run `31813857526` proved the native one-hop circuit end to end, but its two-hop phase
  failed closed before assignment readiness because the then-current TLS payload advertisement
  and packetization did not honor the nested peer ceiling. That failure is historical: the current
  `src/qftls/rustls_provider.rs` advertises the configured ceiling, and
  `src/transport/connection/lifecycle/tls_and_crypto.rs` plus
  `src/transport/connection/send.rs` apply the authenticated peer limit before packetization.
  `peer_transport_limit_clamps_datagram_packetization` and the version-restart regressions cover
  the local boundary. A fresh exact-revision privileged two-hop run must still prove that this
  repair clears the observed assignment failure; the old failed run is not a current bug proof.

## Fail-Closed Rules

- Never create a relay socket before successful authentication and target authorization.
- Never treat opaque next-hop QUIC as raw IP.
- Never fall back to direct traffic.
- Never reuse credentials, connection state, packet numbers, or exporter material across hops.
- Never claim anonymity beyond the explicit threat model.
- Never allow circuit depth to violate the minimum QUIC datagram budget.
- Never mark a native, privileged, cross-platform, or multi-hop gate passed from an in-memory test.

## Out of Scope

- Onion routing with relay-blind next-hop instructions.
- Global traffic-correlation resistance.
- Multipath flow spraying across independent circuits.
- Mobile multi-hop before the desktop/server circuit is complete.
- More than the configured hard resource maximum.

## Deviations

None.
