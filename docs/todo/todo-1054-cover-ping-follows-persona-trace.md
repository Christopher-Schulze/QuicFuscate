---
id: TODO-1054
title: Cover PING only when the persona trace would send
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1052]
---

# TODO-1054: Cover PING only when the persona trace would send

## Why

A fixed cover-PING interval is a metronome, and its bytes sit outside the padding budget. Browsers are not metronomes. A quiet browser is quiet.

## Current code

- `StealthManager::should_send_cover_ping` (`src/stealth/manager.rs`, `next_cover_ping` mutex).
- `src/core/connection/send.rs` calls it once the handshake is established and then `conn.queue_cover_ping()`.
- Presets set cover intervals (stealth about 30 s, stealth max about 15 s). Those are constants, not a trace.

## Target

- `should_send_cover_ping` asks the TODO-1052 ledger: would the persona trace emit a packet in this gap, and is there remaining budget?
- If no, return false.
- If yes, the PING is a normal QUIC frame. Its UDP length is the trace length, via the same padder. It consumes the budget.
- `off` and `performance` never send cover PINGs.
- Delete the fixed 15 s / 30 s intervals as behavior. Config keys that still parse map to "trace" or "off", not to a number of seconds.

## Non-goals

- No new frame type. PING already exists.
- No frontend visual change.

## Design

The trace row is `(gap_ms, length, direction)`. The scheduler stores `last_tx`. When `now - last_tx` falls inside a trace gap marked "send", and the ledger allows `length`, queue one PING and pad to `length`. Otherwise stay silent. Do not catch up with a burst of missed PINGs.

## Sub-Tasks

- [ ] Replace interval fields in presets with trace-driven or off.
- [ ] Ledger debit from `queue_cover_ping`.
- [ ] Test: a trace with no packet for 60 s produces zero PINGs. A trace with a packet at 30 s produces one, at the trace length.
- [ ] Test: budget exhaustion suppresses the PING.

## Acceptance

- A test clock can advance 60 s on an idle `stealth` connection and observe either silence or exactly the trace's events, never a private 15 s grid.
- Cover-PING bytes are included in the TODO-1052 budget assertion.

## Risks

- `max_idle_timeout` still needs a packet before idle expiry. If the trace is quieter than the idle timeout, send one PING at `idle/2`, count it against the budget, and record it as a timeout keepalive rather than as mimicry. Do not invent a second grid.
