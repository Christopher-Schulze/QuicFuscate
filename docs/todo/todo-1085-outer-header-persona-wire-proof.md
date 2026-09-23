---
id: TODO-1085
title: Prove claimed outer IP and UDP persona on the wire
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1057, TODO-1082]
---

# TODO-1085: Outer-header persona wire proof

## Why and evidence

TODO-1057 is DONE after `getsockopt` checks for TTL and DF on macOS. Those
checks prove socket configuration, not emitted IP/UDP headers, browser
equivalence, or migration reapply. IPv4 ID remains uncontrolled yet the task
title and documentation describe a shaped outer header.

## Target contract

- Define the exact supported outer-header fields per OS, address family,
  browser persona, and network mode: IPv4 TTL, DF, ID behavior, DSCP/ECN,
  IPv6 hop limit, UDP source-port behavior and packet lengths where visible.
  Separate socket-controlled, kernel-controlled and unsupported fields.
- Derive expected values from the matching browser/OS captures owned by
  TODO-1082, accounting for path hops when comparing observed TTL. Do not
  infer a browser fingerprint solely from p0f defaults or `getsockopt`.
- Keep the current socket-option path only where it measurably improves
  fidelity. If IPv4 ID cannot be controlled without raw sockets, explicitly
  remove it from the guarantee; do not add raw-socket privilege by default.

## Implementation and proof

- [ ] Capture the app's outgoing packets on macOS and Linux for each supported
      address family and persona before and after a successful port migration.
- [ ] Compare field-by-field with current browser captures, document kernel
      and path differences, and verify error behavior when a socket option
      is unavailable.
- [ ] Narrow TODO-1057 and `docs/DOCUMENTATION.md` wording to verified
      wire fields; expose unsupported platform/persona combinations.

## Acceptance

- Every claimed outer-header field has a raw packet capture comparison;
  zero claims rely only on `getsockopt` or a p0f default.
- A post-migration capture proves reapplication where supported. Unsupported
  IPv4 ID control and platform behavior are stated as limitations, not
  silently counted as persona fidelity.
