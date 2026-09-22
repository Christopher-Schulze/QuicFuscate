---
id: TODO-1056
title: Persona change via connection migration, not a 120 s handshake
severity: MEDIUM
phase: S
priority: P2
status: DONE
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

- [x] Validation rejects timer-driven handshakes.
- [x] Migration timer uses the existing path API.
- [x] Test: advancing 120 s does not start a new ClientHello.
- [x] Test: one migration changes the local port and connection ID and keeps the same TLS keys.

## Outcome (2026-09-27)

- Mid-connection timer removed: `StealthManager::maybe_rotate_fingerprint`,
  `profile_pool`/`profile_index`/`last_rotation`, `runtime_rotation_rate`, and
  the escalated 30 s rotation hack are gone. The only surviving rotation is the
  next-session persona cursor (`StealthRuntimeOwner::spawn_profile_rotation`
  mutates `initial_browser`/`initial_os` read by the next dial — never the live
  connection). No config value can express a mid-connection handshake timer;
  `enable_fingerprint_rotation`/`fingerprint_rotation_interval` field docs now
  state next-session semantics explicitly.
- New disguise-migration draw on `StealthManager`: enabled for `stealth`,
  `stealth_max`, `dynamic`; off for `off`/`performance`. Uniform 120..=600 s
  draw per connection and per event (`draw_disguise_migration_delay`),
  `disguise_migration_due()`, `note_disguise_migration()` (redraw on success,
  failure, and every real `Validated` path event — real NAT rebinds count as
  the disguise event).
- `QuicFuscateConnection`: `disguise_migration_due()`,
  `begin_disguise_migration(new_local)` -> `conn.migrate` (PATH_CHALLENGE via
  the existing path-validation API), `take_disguise_migration_outcome()`,
  `disguise_migration_pending()`, `note_disguise_migration_attempt()` (redraw
  on start failures — no 5 ms retry storm).
- Client runtime loop: housekeeping tick binds an ephemeral UDP socket via
  `bind_connected_udp_socket` (extracted shared helper), swaps it in, and keeps
  the old socket as `standby_socket` until validation settles — `Validated`
  commits, `FailedValidation` rolls back to the standby socket so the old path
  survives (plus `DISGUISE_MIGRATION_FAILURES` counter + Prometheus export).
- DCID stays stable across the port change — there is no NEW_CONNECTION_ID
  machinery; the wire event is a source-port change, matching a real NAT
  rebind. Documented honestly.
- Tests: `disguise_migration_never_due_for_speed_profiles`,
  `disguise_migration_fires_once_per_draw_for_stealth`,
  `elapsed_rotation_interval_starts_no_handshake_and_keeps_persona`,
  `begin_disguise_migration_changes_local_port_and_keeps_persona`.
- Server side needs no timer: peer port changes are adopted through
  `observe_incoming_path` (PeerPath validation) as before.

## Acceptance

- No code path starts a handshake because a rotation timer fired.
- A stealth connection can change UDP port without a new Initial.

## Risks

- Some NATs break on port change. Failure must keep the old path, not drop the tunnel.
- Migrating every RTT is itself a pattern. The 2 to 10 minute draw is the cap.
