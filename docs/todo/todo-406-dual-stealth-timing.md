---
id: TODO-406
title: Consolidate dual stealth timing gates
severity: MEDIUM
phase: B
priority: P2
status: DONE
created: 2026-06-05
---

# TODO-406: Consolidate Dual Stealth Timing Gates

## Problem

Stealth timing enforced in both `Connection::send` (~2042-2048) and `core::send` (~930-936, 1016-1020). Independent `next_send_at` / `next_packet_release` can cause double yields (`Ok(0)`).

## Acceptance

- Single owner for outbound timing gate (core OR connection, documented)
- Integration test: no duplicate delay under stealth timing enabled
- Stealth behavior preserved (same average jitter)

## Fix Plan

1. Choose owner: recommend core (orchestrator) delegates to connection OR connection only
2. Remove duplicate gate
3. Update DOCUMENTATION.md data-flow section

## Files

- `src/transport/connection.rs`
- `src/core.rs`
- `src/stealth/mod.rs`

## Note

No UI changes. Stealth policy unchanged.
