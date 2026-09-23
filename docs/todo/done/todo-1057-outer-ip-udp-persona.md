---
id: TODO-1057
title: Shape the outer IP and UDP header to the claimed OS
severity: MEDIUM
phase: S
priority: P2
status: DONE
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

- [x] Table from captures, with dates — see Notes: no usable capture existed;
      values rest on p0f OS defaults (TTL) and documented QUIC stack DF
      behavior. Recorded as a documented gap instead of inventing evidence.
- [x] Apply on the client UDP socket.
- [x] Re-apply after migration.
- [x] Test: requested TTL and DF differ for an iOS persona and a Linux persona.
- [x] Inner normalizer tests stay green.

## Acceptance

- Client send path sets socket options from the persona. — `apply_outer_header_logged`
  on the bound client UDP socket at connect and after every disguise
  migration rebind (`StealthManager::persona_os` is the live source).
- Server ingress normalizer behavior stays. — untouched.
- Platforms without the sockopt do not fail the connection. — outcome-based
  fail-soft; one process-wide `warn!`, then `debug!` only.

## Risks

- Some stacks overwrite TTL. One real socket test on Linux or macOS must sit
  next to the mock. — done: `real_socket_accepts_persona_ttl_and_df` and
  `real_socket_ios_df_is_cleared` bind a real UDP socket and verify the
  kernel-visible values via `getsockopt` on both platforms.

## Notes (2026-09-21 resolution)

- Implementation: `src/stealth/outer_header.rs` (`OsOuterHeader`,
  `outer_header_for`, `apply_outer_header`, `apply_outer_header_logged`).
- TTL table: Windows 128; macOS/iOS/Linux/Android 64 (p0f OS defaults —
  stable, documented values; no project capture was available to cite).
- DF table: `Some(true)` for Windows/macOS/Linux/Android personas — the
  claimed QUIC client is Chromium-family, which runs PMTUD and emits DF=1;
  `Some(false)` for iOS — the Apple stack does not set DF on UDP and iOS
  browsers run no native QUIC client. Linux uses
  `IP_MTU_DISCOVER=IP_PMTUDISC_DO`/`_DONT`; macOS uses `IP_DONTFRAG`.
- IPv6: hop limit only (`IPV6_UNICAST_HOPS`); IPv6 has no DF flag and no ID.
- IPv4 ID gap: not socket-controllable on Linux/macOS. With DF=1 the kernels
  emit ID=0 anyway (matches QUIC captures); the Windows global-increment ID
  cannot be shaped without raw sockets — stays a documented non-goal.
- No independent packet capture backs the table; the honest evidence basis
  is recorded in DOCUMENTATION.md instead of fabricated capture claims.
