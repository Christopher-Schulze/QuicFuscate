---
id: TODO-1057
title: Shape the outer IP and UDP header to the claimed OS
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1047]
---

# TODO-1057: Shape the outer IP and UDP header to the claimed OS

## Why

The censor sees the outer IP/UDP header of the client. TTL, DF, and IP ID are cheaper tells than the ClientHello. The current normalizer edits the inner TCP packet and ICMP. That affects what the destination sees after exit, not what the censor sees on the client link.

## Current code

- `crates/qf-stealth/src/fingerprint.rs`: `PacketNormalizer`, `OsFingerprintProfile`, incremental IP/TCP checksum updates.
- `StealthConfig.enable_network_fingerprint_normalization` applies to decoded server-side tunnel ingress (inner packets).
- `suppress_icmp_unreachable` drops non-PMTUD ICMP.
- Outer UDP send uses the host stack. TTL and DF are whatever the OS emits.

## Target

Two sites, two jobs.

- Client outer datagram, before send: set TTL, DF, and IPv4 ID policy to the persona OS (Windows, macOS, iOS, Android, Linux). IPv6 has no ID; only hop limit. Do this with socket options. Do not parse the inner TCP for this.
- Server exit, inner packet: keep the current normalizer so the destination does not see "Linux VPN" while the client persona is "iPhone".
- ICMP suppression stays an exit policy. It is not client-path stealth.

## Non-goals

- No new raw-socket requirement. Platforms that cannot set `IP_TTL` / `IP_DF` skip and log once.
- No frontend visual change.

## Design

1. A table `OsOuterHeader { ttl, df, ip_id }` per `OsProfile`, taken from a cited capture. If a value is not in the capture, leave the OS default and record the gap in Notes.
2. Apply with `setsockopt` on the UDP socket at connect and after migration (TODO-1056), because a new socket forgets the options.
3. Prefer socket options over rewriting headers after the kernel checksum.

## Sub-Tasks

- [ ] Table from captures, with dates.
- [ ] Apply on the client UDP socket.
- [ ] Re-apply after migration.
- [ ] Test: requested TTL and DF differ for an iOS persona and a Linux persona.
- [ ] Inner normalizer tests stay green.

## Acceptance

- Client send path sets socket options from the persona.
- Server ingress normalizer behavior stays.
- Platforms without the sockopt do not fail the connection.

## Risks

- Some stacks overwrite TTL. One real socket test on Linux or macOS must sit next to the mock. The mock only proves the call.
