---
id: TODO-1056
title: Persona change via connection migration, not a 120 s handshake
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1047]
---

# TODO-1056: Persona change via connection migration, not a 120 s handshake

## Why

The ClientHello is finished after the handshake. Rotating a User-Agent inside the tunnel does not change the outer flow. A new handshake every 120 s is a burst a classifier can lock onto. Browsers do change UDP ports when NAT rebinds. QUIC connection migration is that event.

## Current code

- `fingerprint_rotation_interval` (stealth max uses 120 s) and `RotationMode` on `StealthConfig`.
- `enable_fingerprint_rotation` rotates the in-memory persona. It does not open a new rustls handshake.
- `qf-transport-path` and recovery already have path-migration primitives. They are not driven by the stealth rotation timer.

## Target

- Delete the 120 s timer as a behavior. Config values that mean "new handshake on a timer" fail validation.
- While the connection lives: at a jittered interval between 2 and 10 minutes, or on a real path change, issue a QUIC connection-ID rotation and migrate to a new local UDP port. No new ClientHello. Packet sizes stay on the current wire image (TODO-1059).
- A new persona (different browser) happens only when the client opens a new connection. That connection uses TODO-1047. The old connection drains. It is not reset on a timer.
- `off` and `performance` do not migrate for disguise.

## Non-goals

- No multipath scheduler rewrite.
- No frontend visual change.
- No AEAD change.

## Design

1. `RotationMode` stops calling a mid-connection persona swap.
2. New timer, off in speed modes, on in `stealth`, `Stealth MAX`, and `dynamic`. Period is drawn once per connection from 2 to 10 minutes.
3. The timer calls the existing path-migration API with a new local port and a new connection ID. If migration fails, keep the old path and count. Do not fall back to a new handshake.
4. Persona swap remains for the next dial only.

## Sub-Tasks

- [ ] Validation rejects timer-driven handshakes.
- [ ] Migration timer uses the existing path API.
- [ ] Test: advancing 120 s does not start a new ClientHello.
- [ ] Test: one migration changes the local port and connection ID and keeps the same TLS keys.

## Acceptance

- No code path starts a handshake because a rotation timer fired.
- A stealth connection can change UDP port without a new Initial.

## Risks

- Some NATs break on port change. Failure must keep the old path, not drop the tunnel.
- Migrating every RTT is itself a pattern. The 2 to 10 minute draw is the cap.
