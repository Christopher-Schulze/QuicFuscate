---
id: TODO-523
title: Complete multi-client dual-stack TUN and ICMP runtime contract
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-22
depends_on: [TODO-430, TODO-431, TODO-432, TODO-534]
---

# TODO-523: Complete Multi-Client Dual-Stack TUN and ICMP Runtime Contract

## Why

Destination-based IPv4/IPv6 routing, address pools, platform setup code, IPv4 echo replies, unknown-host ICMP generation, and an isolated `ClientIsolationManager` helper exist. The isolation helper has no production caller and only generates command strings. The legacy contracts still lack source-IP enforcement, kernel-rule lifecycle, three-client isolation proof, an explicit opt-in client-to-client policy, broadcast fan-out, dual-stack and IPv6 NAT evidence, ICMP packet-too-big and time-exceeded runtime wiring, ICMPv6 handling, and ICMP routing metrics.

## Acceptance

- Implement explicit IPv4 broadcast/multicast and required IPv6 multicast routing policy without cross-client unicast leakage.
- Make source-IP validation and default-deny client isolation part of every production TUN and MASQUE uplink boundary for IPv4 and IPv6; malformed, spoofed, cross-client, broadcast, and multicast outcomes must be typed and measurable.
- Replace inert firewall command-string generation with owned, idempotent Linux rule lifecycle tied to session allocation/release and stale startup cleanup; default policy isolates clients, while any client-to-client traffic requires an explicit configuration opt-in.
- Wire IPv4 packet-too-big and TTL-expiry responses at the production forwarding boundaries using the real effective path MTU.
- Implement the minimal ICMPv6 echo, packet-too-big, and neighbor-discovery behavior required by the dual-stack TUN contract.
- Add typed routing and ICMP counters for local, unicast, fan-out, unknown, PTB, time-exceeded, and ICMPv6 outcomes.
- Prove three simultaneous clients receive only owned unicast traffic, reject spoofing and default client-to-client access, route client-to-client traffic only under explicit opt-in, and receive intended fan-out traffic with tcpdump isolation evidence.
- Prove simultaneous IPv4/IPv6 ping, unique IPv6 allocation, IPv6 NAT/forwarding state, and measured IPv6 throughput on Omega; no skipped throughput assertion counts as proof.
- Verify macOS and Windows platform rule generation in native gates and report any privileged live-proof boundary honestly.
- Pass full local Rust gates, relevant native CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [x] Extract the TUN forwarding decision into a testable typed policy boundary.
- [x] Complete broadcast, PTB, TTL, ICMPv6, and metrics behavior.
- [x] Build the three-client dual-stack netns proof harness.
- [x] Execute local, native, and Omega gates after TODO-534 closes the effective tunnel MTU contract.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-430, TODO-431, and TODO-432 reconciliation. No product code changed during classification.
- Live-path sweep confirmed that `ClientIsolationManager` has no production caller: authenticated MASQUE datagrams and HTTP/3 body packets currently reach `TunInterface::write` without session-bound IPv4/IPv6 source validation.
- `LiveClientRuntime` carries a session ID but not the assigned addresses, so the forwarding boundary cannot currently prove packet ownership without a second lookup.
- Standalone TUN startup opens the device but does not own a `RoutingManager`; Linux routing/NAT setup and teardown are only attached to the embedded runtime. The standalone server therefore cannot satisfy an owned firewall lifecycle until routing ownership is unified.
- The production TUN downlink handles owned unicast only. Broadcast and multicast destinations fall through to the IPv4 unknown-host response, and the existing IPv4 PTB builder is not wired to a forwarding MTU decision.
- Implementation order is source-verified: introduce one typed packet/policy boundary in `isolation.rs`, carry assigned dual-stack addresses with each live runtime client, enforce it before DNS interception and every TUN write, then reuse the same parsed decision for downlink fan-out, ICMP, metrics, and routing lifecycle.
- Typed boundary implemented: `AssignedClientIps`, `UplinkRoute`, and `UplinkDrop` validate strict IPv4/IPv6 headers and authenticated source ownership. The assigned-address hot path uses an `ArcSwap<HashSet<IpAddr>>` snapshot, so packet classification has no read lock; allocation and release publish immutable snapshots.
- Production integration implemented for both decoded MASQUE datagrams and raw-IP HTTP/3 body packets before DNS interception, normalization, or `TunInterface::write`. Missing sessions, malformed packets, spoofed sources, default-denied client unicast, internet unicast, broadcast, and multicast are exported through `quicfuscate_routing_packets_total{outcome=...}`.
- Explicit client-to-client unicast opt-in is exposed as server-only `--allow-client-to-client`; the default remains fail-closed.
- Linux routing ownership is now shared by embedded and standalone runtimes. Startup resolves the configured WAN device against the active network namespace, cleans stale state, installs one atomic dual-stack nftables table or symmetric iptables/ip6tables rules, and fails closed on setup failure. Shutdown owns the matching teardown with bounded retries.
- Kernel routing permits only IPv4 directed/limited broadcast, IPv4 multicast, and IPv6 multicast before the same-TUN default-deny rule. Explicit `--allow-client-to-client` replaces that final deny with an opt-in accept; user-space source ownership remains fail-closed at both authenticated uplink boundaries.
- IPv4 TTL/PTB and IPv6 hop-limit/PTB responses use the server TUN address and the effective QUIC/FEC MASQUE payload ceiling. ICMPv6 echo and neighbor-advertisement behavior is checksum-covered. TUN downlink routing now handles local, owned unicast, fan-out, unknown, malformed, and per-connection PTB outcomes.
- Server `--tun-ip6` and `--tun-prefix6` now reach the standalone runtime and derive a bounded dense IPv6 client pool. A `/64` with server `::1` deterministically allocates `::2` through `::fe` rather than constructing an impractical full-prefix allocator.
- Windows rule generation is now honest: IPv4 WinNAT generation remains idempotent, while dual-stack WinNAT fails before side effects because Windows NetNat does not provide the required IPv6 NAT contract. Legacy `_v6` cleanup remains best-effort for stale historical state.
- `scripts/tests/tun-e2e-multi-client-dual-stack-netns.sh` creates one server plus three client namespaces and retains exact tcpdump, metrics, routing, ping, and iperf3 evidence. It hard-fails on spoof leakage, default client unicast, missing fan-out, skipped/zero IPv6 throughput, missing NAT/forwarding state, or failed explicit opt-in.
- Local evidence so far: server-focused Rust tests passed `316/316`; routing rule tests passed `10/10`; the final macOS `cargo check --all-targets --features rust-tests` passed after lifecycle wiring, and strict Clippy passed before the final lifecycle delta; the new harness passes `bash -n` and ShellCheck. Native Linux gates remain active.
- Local Linux cross-check is unavailable without pretending: the GNU path lacks `x86_64-linux-gnu-gcc`; the Clang path reaches the Linux target but lacks a Linux sysroot, target OpenSSL, and standard headers required by `ring`. Native Linux compilation and execution therefore remain assigned to CI/Omega.
- Omega proof work remains isolated under `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo523`; the checkout at `f85f63b` and all historical `runtime-*` directories remain untouched. With explicit approval, `build-essential`, `pkg-config`, `libssl-dev`, and `iperf3` were installed system-wide instead of retaining brittle Zig compatibility wrappers.
- Native ARM64 format, all-target check, strict all-target Clippy, 319 server tests, 15 Linux kill-switch tests, and the added Linux TUN netmask regressions pass with Rust 1.97.1. The current optimized AArch64 binary is `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo523/build/release/quicfuscate`, SHA-256 `a86dcbf921fd304af22ab1d43c7a0aa357850362231421d9cc450e993f3f6e86`.
- The first live attempt exposed that the Linux `TunConfig` contract did not apply addresses, MTU, or link state. The Linux backend now validates contiguous masks and dual-stack pairing, applies idempotent `ip address replace` state before returning the device, and fails closed on configuration errors. The second run proved all addresses and three simultaneous sessions but exposed a cold first-datagram measurement race; a failable dual-stack readiness barrier now precedes the strict zero-loss measurement. The third run passed readiness, simultaneous dual-stack ping, owned unicast isolation, default-deny client traffic, and spoof rejection, then proved that kernel same-TUN rules do not themselves reflect broadcast/multicast into the downlink reader. Authenticated broadcast/multicast now enters an explicit server fan-out queue for delivery to other authenticated compatible sessions.
- The fourth Omega run proved IPv4 directed-broadcast, IPv4 multicast, and IPv6 multicast fan-out to both non-source clients with zero tcpdump drops. The sixth retained evidence set at `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo523/evidence-run6` also proves all six simultaneous IPv4/IPv6 ping streams at `5/5`, zero loss. Every live run cleaned its namespaces and processes; the product checkout remains at `f85f63b` and historical runtime directories remain untouched.
- Live packet-too-big proof is blocked after three distinct attempts. A server-local oversized source conflicted with the router-local source address; a real client uplink reached the negotiated MASQUE datagram ceiling first and fell back with `InternalError`; an isolated `192.0.2.1/32` server-side source with temporary TUN MTU 1500 transmitted a 1,378-byte DF packet but received no PTB. The effective MASQUE payload ceiling is lower than the configured 1,280-byte TUN MTU, while raw HTTP/3 body fallback has no explicit IP-packet framing/reassembly contract. Repeated retries are stopped pending an MTU/framing scope decision; TODO-523 must not be closed from unit-only PTB evidence.
- Scope decision approved: TODO-534 is the active hot-switch and owns the negotiated effective tunnel MTU, local PTB, and framed fallback implementation. TODO-523 resumes automatically after TODO-534 closes; the existing multi-client implementation and retained Omega evidence remain part of the final combined closure.
- Final closure uses the exact TODO-534 run35 AArch64 binary SHA-256 `d985c254fb55792afc9d2e1bc88d14b68b8737a3bfcb7507961fc8b1a1c09888`. Retained evidence under `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo534/evidence/run35/live` proves three simultaneous clients, unique IPv4/IPv6 allocation, six zero-loss dual-stack ping streams, IPv6 forwarding/NAT state, strict source ownership and spoof rejection, default-deny plus explicit opt-in client unicast, IPv4 broadcast/multicast and IPv6 multicast fan-out, and client/server IPv4 and IPv6 PTB.
- The same exact artifact completes all three regular 1280-floor and 1500-confirmed IPv6 throughput trials with exactly five positive intervals per five-second run. Median throughput is 6.454 Mbit/s at 1280 and 8.961 Mbit/s at 1500. No namespace, product process, heartbeat failure, or runtime crash remains after cleanup.

## Deviations

- Per-session address membership is published and removed synchronously through the lock-free user-space policy at session allocation/release. The kernel same-TUN rule is intentionally server-lifecycle-owned rather than mutated per session: retaining `CAP_NET_ADMIN` after privilege drop solely for dynamic firewall edits would expand the compromise blast radius without adding enforcement beyond authenticated source validation. Direct root startup with automatic privilege drop now cleans routing and fails closed; production uses the unprivileged systemd user with AmbientCapabilities, while the isolated netns proof uses explicit `--no-drop-privileges`.
