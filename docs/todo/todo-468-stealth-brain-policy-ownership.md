---
id: TODO-468
title: StealthBrain actuator ownership and FEC hint cleanup
severity: HIGH
phase: K
priority: P1
status: DONE
created: 2026-06-30
depends_on:
  - TODO-465
  - TODO-467
---

# TODO-468: StealthBrain actuator ownership and FEC hint cleanup

## Goal

Make StealthBrain the policy brain, not an identity mutator. It should own adaptive decisions for
ACK strategy, pacing, timing, padding, cover intensity, and FEC hints while the owning subsystems
apply those decisions.

## Current State

- `StealthBrain` observes transport signals and emits ACK/FEC hints plus runtime stealth deltas.
- `StealthManager` owns many concrete stealth actuators.
- FEC consumes global hints from Brain.
- Current documentation is close, but the persona/fingerprint rotation boundary must be tightened.

## Problem

Brain adaptation is powerful only when ownership is clean. If Brain can implicitly change persona,
fronting posture, cover semantics, and FEC behavior without clear boundaries, the resulting traffic
can become inconsistent or hard to test.

## Implementation Plan

1. Read the exact Brain policy output structs, observer hooks, FEC hint globals, stealth runtime
   delta types, and connection application points before editing.
2. Define the allowed Brain actuator set:
   - ACK threshold and ACK policy;
   - external pacing hint;
   - timing jitter magnitude;
   - padding rate/granularity/strategy bias;
   - cover intensity/escalation hint;
   - FEC interval and redundancy hints.
3. Define the forbidden Brain actuator set:
   - browser profile mutation on active connection;
   - OS profile mutation on active connection;
   - blind domain-fronting activation without mode/config permission.
4. Rename or document ambiguous fields where they imply identity changes.
5. Ensure FEC remains the implementation owner of redundancy and packet repair behavior. Brain emits
   hints; FEC applies them with its own caps and hysteresis.
6. Add tests for ownership boundaries and FEC hint application.

## Files To Inspect

- `src/brain.rs`
- `src/transport.rs`
- `src/core.rs`
- `src/fec/`
- `src/stealth/mod.rs`
- `src/transport/connection.rs`
- `docs/DOCUMENTATION.md`

## Acceptance Criteria

- Brain cannot change browser/OS persona on an active connection.
- Brain cannot enable domain fronting outside the mode/config policy from TODO-466.
- FEC hint flow remains explicit: Brain writes hints, FEC owns application and caps.
- Tests prove Brain escalation affects timing/padding/cover/FEC hints without identity mutation.
- Documentation states the ownership boundary in one canonical place.

## Implementation Result

- Runtime escalation now sets padding and timing rates while keeping `runtime_rotation_rate` at 0.
- Brain/FEC ownership remains explicit: Brain writes FEC hint atomics; Core/FEC apply interval and redundancy with existing caps.
- Domain fronting is guarded by mode/config policy in `StealthManager::domain_fronting_for_config`.
- Focused tests: `stealth::tests::test_escalate_to_level_2_full_overhead`, `active_persona_does_not_rotate_mid_session`, focused Stealth coverage tests.

## Non-Goals

- Do not remove StealthBrain.
- Do not remove FEC adaptation.
- Do not collapse all policy into one module.
