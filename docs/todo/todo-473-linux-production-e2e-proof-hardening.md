---
id: TODO-473
title: Linux production E2E proof hardening
severity: HIGH
phase: "R"
priority: P0
status: DONE
created: 2026-06-30
depends_on: [TODO-422, TODO-423, TODO-425, TODO-435, TODO-457]
---

# TODO-473: Linux production E2E proof hardening

## Goal
Turn the Linux production proof from "unit and script confidence" into a real, falsifiable, root-level network-namespace validation of the production H3/MASQUE/TUN path. The proof must exercise QKey-authenticated CONNECT-UDP, server/client TUN routing, DNS leak prevention, FEC under loss, burst loss, live FEC transitions, and broad netem adversity on the `broderick` Linux server.

## Implemented State

- `src/main.rs` now aligns standalone server runtime config with explicit `--tun-ip` / `--tun-netmask`: `ServerConfig.server_ip`, `server_netmask`, and the IPv4 client pool are derived from the configured TUN subnet instead of silently keeping the default `10.8.0.0/24` pool. This fixes downlink routing for standalone netns deployments using `10.0.1.1/24` and `10.0.1.2/24`.
- `src/transport/h3.rs` exposes `connect_udp_with_headers()` and keeps `connect_udp()` as the default wrapper. CONNECT-UDP can now carry extra headers such as `x-qf-auth`.
- `src/core.rs` injects the QKey auth header into the production MASQUE CONNECT-UDP open path, so the HTTP/3 carrier proves QKey possession at the same layer as regular H3 requests.
- `src/implementations/server/mod.rs` validates the QKey token from both encrypted QUIC transport parameters and H3 headers. MASQUE DATAGRAM delivery to TUN is gated on the live auth state, and the callback is rebound on each processing pass so a stale unauthenticated gate cannot permanently drop later valid datagrams.
- `scripts/tests/tun-e2e-netns.sh` now fails hard on missing QKey, missing handshake, and non-zero tunnel ping loss. It also emits useful failure diagnostics and supports `QF_E2E_KEEP_ON_FAIL=1` for live namespace inspection.
- `scripts/tests/tun-e2e-dns-leak-netns.sh` and the FEC netns scripts use dynamic repository roots and `--no-drop-privileges`, so they can run from `/root/QuicFuscate-git` on `broderick` without hidden path or system group assumptions.
- `scripts/tests/tun-e2e-fec-netns.sh` no longer fake-passes optional iperf3 TCP checks when the server-local TUN TCP target has no measurable throughput. Those checks are reported as skipped unless actual throughput is observed.

## Broderick Evidence

All commands were run on `broderick` from `/root/QuicFuscate-git` after `cargo build --release --bin quicfuscate` completed successfully.

| Gate | Result | Evidence |
|---|---:|---|
| Release build | PASS | `Finished release profile [optimized] target(s) in 1m 32s` |
| Base TUN/MASQUE netns | PASS | `5 packets transmitted, 5 received, 0% packet loss`, MASQUE TX and MASQUE downlink TX present |
| DNS leak netns | PASS | `dig_exit=0`, `status: NXDOMAIN`, `raw_port_53_packets=0` |
| FEC smoke netns | PASS | `3 passed, 0 failed, 2 skipped`; 0%, 5%, and 10% loss ping gates passed; optional TCP iperf checks skipped due no measurable server-local TUN TCP throughput |
| FEC burst netns | PASS | `2 passed, 0 failed`; 10%/25% burst had 2% tunnel loss, 20%/50% burst had 1% tunnel loss |
| FEC transition netns | PASS | `1 passed, 0 failed`; clean 0%, loss phase 22%, recovered 0% |
| FEC netem adversity | PASS | `25 passed, 0 failed, 0 skipped`; loss sweep through 50%, jitter through 500ms, bandwidth through 1Mbit, RTT through 300ms + 5% loss, mobile adversity, and clean-loss-clean recovery |

## Notes

- TCP iperf3 to `10.0.1.1` is not a valid server-local TUN proof today because the live server intentionally handles ICMP to its own TUN IP locally and ignores non-ICMP packets addressed to the server TUN IP. The optional iperf3 section is retained only as a future canary and must not be counted as production evidence unless throughput is actually measurable.
- The meaningful production data-plane proof is the authenticated MASQUE/TUN packet path plus DNS leak assertion and netem loss/adversity behavior.
- The repeated `Killed` lines in netns script output are cleanup of previous server/client processes between scenarios, not runtime crashes; each scenario starts fresh namespaces and validates handshake before measuring.

## Acceptance

- [x] Standalone CLI TUN IP/netmask controls the runtime server IP and client pool used by session routing.
- [x] MASQUE CONNECT-UDP carries QKey auth material.
- [x] Server MASQUE DATAGRAM to TUN delivery is gated on current authenticated QKey state.
- [x] DNS-through-tunnel has real tcpdump proof of zero raw client-underlay port 53 traffic.
- [x] Linux root netns gates pass on `broderick` for base tunnel, DNS leak, FEC smoke, FEC burst, FEC transition, and FEC netem adversity.
- [x] Optional invalid TCP/iperf evidence is not counted as PASS when it measures zero throughput.
