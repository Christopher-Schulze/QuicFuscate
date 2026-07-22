---
id: TODO-523
title: Complete multi-client dual-stack TUN and ICMP runtime contract
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-430, TODO-431, TODO-432, TODO-521]
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

- [ ] Extract the TUN forwarding decision into a testable typed policy boundary.
- [ ] Complete broadcast, PTB, TTL, ICMPv6, and metrics behavior.
- [ ] Build the three-client dual-stack netns proof harness.
- [ ] Execute local, native, and Omega gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-430, TODO-431, and TODO-432 reconciliation. No product code changed during classification.

## Deviations

None.
