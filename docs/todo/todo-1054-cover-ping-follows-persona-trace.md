---
id: TODO-1054
title: Cover PING only when the persona trace would send
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-21
completed: 2026-09-22
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

- [x] Interval fields removed as behavior — presets carry `enable_cover_ping` only (`cover_ping_interval_ms` still parses but is ignored; `enable` maps to trace-driven emission vs. none). `off`/`performance` never emit; FixedCell has no trace and never emits.
- [x] Ledger debit — `BudgetLedger::cover_ping_due` replays `client_schedule()` deltas against `last_tx` (updated by `note_wire_send` on every wire emission, real data included), `try_spend`s the captured length, and the PING datagram is padded to that exact wire length via `set_short_header_pad_target`. One pending slot; suppressed slots are consumed, never replayed.
- [x] Tests — `cover_ping_replays_trace_deltas_at_trace_lengths` (silent inside the gap, one PING at the trace length, quiet forever after the trace), `cover_ping_suppressed_slot_is_consumed_not_replayed`, `cover_ping_chrome_trace_goes_quiet_after_close` (every captured send fires exactly once on the real fixture), `note_wire_send_restarts_persona_silence`, `cover_ping_fixedcell_and_missing_trace_never_due`, `idle_keepalive_fires_once_per_silent_stretch` (manual clock: past `idle/2` one keepalive, never a second without inbound), `cover_ping_due_requires_a_ledger_and_trace`.
- [x] Idle risk covered — `idle_keepalive_due()` emits one budgeted PING past `max_idle_timeout/2` of peer silence, counted via `COVER_PING_IDLE_KEEPALIVE` as a keepalive, not mimicry.

## Acceptance

- A test clock can advance 60 s on an idle `stealth` connection and observe either silence or exactly the trace's events, never a private 15 s grid.
- Cover-PING bytes are included in the TODO-1052 budget assertion.

## Risks

- `max_idle_timeout` still needs a packet before idle expiry. If the trace is quieter than the idle timeout, send one PING at `idle/2`, count it against the budget, and record it as a timeout keepalive rather than as mimicry. Do not invent a second grid.
