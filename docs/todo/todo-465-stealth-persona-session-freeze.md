---
id: TODO-465
title: Connection-scoped persona freeze and rotation semantics
severity: HIGH
phase: K
priority: P0
status: DONE
created: 2026-06-30
depends_on:
  - TODO-464
---

# TODO-465: Connection-scoped persona freeze and rotation semantics

## Goal

Freeze the browser/OS/TLS/H3/QPACK persona for the lifetime of each connection. Rotation remains
available only as a next-connection or explicit reconnect policy.

## Current State

- The documentation and config surface mention profile sequences and profile intervals.
- Runtime stealth escalation can alter several live policy knobs.
- Mid-session profile rotation is dangerous because TLS-visible identity, H3 headers, QPACK policy,
  ACK style, transport parameters, and browser semantics can drift apart.

## Problem

Real browser sessions do not become a different browser and operating system in the middle of one
connection. Changing persona mid-session can create a stronger fingerprint than not rotating at all:
the TLS handshake remains old while later H3/QPACK/headers look new.

## Implementation Plan

1. Identify the active persona state owner and all mutation paths:
   - CLI profile selection;
   - Engine profile selection;
   - `StealthManager::maybe_rotate_fingerprint`;
   - Brain escalation paths;
   - HTTP/3 masquerade header generation;
   - TLS cover profile selection.
2. Introduce an explicit connection persona snapshot if no equivalent immutable structure already
   exists.
3. Bind TLS cover, ClientHello profile, HTTP/3 masquerade headers, QPACK indexing, ACK policy, and
   transport parameter mimicry to that snapshot.
4. Change interval/sequence rotation semantics:
   - current connection: no browser/OS mutation;
   - reconnect/new connection: select next persona from the configured sequence;
   - manual operator reconnect: allowed to select new persona.
5. Keep runtime Brain escalation limited to actuator intensity: timing, padding, cover, ACK/FEC
   hints, and pacing.
6. Add tests for same-session stability and next-session rotation.

## Files To Inspect

- `src/stealth/mod.rs`
- `src/stealth/tests.rs`
- `src/qftls.rs`
- `src/core.rs`
- `src/transport/connection.rs`
- `src/transport/h3.rs`
- `src/brain.rs`
- `src/implementations/client/profile.rs`
- `src/main.rs`

## Acceptance Criteria

- A live connection has one immutable persona snapshot.
- Runtime policy changes cannot change the active browser or OS persona on an established connection.
- Profile sequence and interval settings apply to the next connection or reconnect only.
- Tests prove:
  - a current connection keeps its original profile after a rotation tick;
  - a new connection can use the next configured profile;
  - Brain escalation changes actuator intensity but not persona identity.
- Documentation is updated to describe the new rotation semantics honestly.

## Implementation Result

- `StealthManager::maybe_rotate_fingerprint` advances next-session bookkeeping only; it never mutates the active fingerprint.
- `start_profile_rotation` is retained as a compatibility API but logs next-session semantics instead of changing in-flight sessions.
- Probe escalation no longer rewinds `last_rotation` or rotates fronting hosts inside an active connection.
- Focused tests: `active_persona_does_not_rotate_mid_session` and `stealth::tests::test_escalate_to_level_2_full_overhead`.

## Non-Goals

- Do not remove profile rotation support.
- Do not disable Brain adaptation.
- Do not change UI copy or controls.
