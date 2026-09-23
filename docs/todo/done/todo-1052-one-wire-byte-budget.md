---
id: TODO-1052
title: One wire byte budget for padding, cover, and FEC
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
completed: 2026-09-22
depends_on: [TODO-1046, TODO-1054, TODO-1055]
---

# TODO-1052: One wire byte budget for padding, cover, and FEC

## Why

Padding, cover PINGs, server-push payloads, and FEC repairs each add bytes. The sum matches neither a browser trace nor fixed-size cells. Random padding often builds its own histogram, which is worse than sending nothing. CESNET-QUIC22 and Smith et al. classify the first roughly 30 packets by size, direction, and inter-arrival. One budget can serve one of those goals. It cannot serve both.

## Current code

- `PaddingStrategy::{Random, Fixed, Adaptive, BrowserMimic}` and `max_padding_size` on `StealthConfig`.
- Padding is applied inside the QUIC packet before AEAD (the only size lever that is authenticated).
- Cover PING is an interval, not a draw from a trace (`should_send_cover_ping`).
- Server push has its own intensity and burst interval.
- FEC repair bytes are extra datagrams, today also wrapped (TODO-1046).

## Target

Per connection, one `WireBudget`:

- `cap_bytes_per_sec` and `cap_bytes_per_burst`.
- `shape`: `PersonaTrace` or `FixedCell`.
- Spend order when both want bytes: repairs first if loss is non-zero, then trace-shaped padding, then cover PING. Push does not get a private allowance (TODO-1055).
- `stealth` uses `PersonaTrace` only.
- `Stealth MAX` uses the same cap. A Maybenot machine (TODO-1061) may spend it after the simulator reports a number. Until then `Stealth MAX` uses `PersonaTrace` too.
- `off` and `performance`: budget is zero. No stealth padding.
- `dynamic` picks one shape at connect and does not retarget it (TODO-1059).
- `manual` may select the shape. The four old strategies collapse to these two shapes plus off. Random is removed.

Trace: a checked-in sequence of (direction, length class, gap) for the persona, long enough to cover the first 30 packets and a quiet period. Length classes are the UDP payload sizes the capture actually used, not uniform random up to `max_padding_size`.

## Non-goals

- No claim that PersonaTrace beats a website-fingerprinting model. It only removes the random-padding signature.
- FixedCell is allowed only as an explicit `manual` or future `Stealth MAX` choice after measurement. It will not look like Chrome. Do not enable it in `stealth`.
- No frontend visual change.

## Design

1. A `BudgetLedger` on the connection subtracts repair bytes, padding bytes, and cover bytes from the same counters.
2. The padder asks the ledger for a target length. It does not roll its own RNG range.
3. If the ledger is exhausted, send the real packet at its natural length. Do not borrow from the next second.
4. Repairs that do not fit in the cap are delayed or reduced in count. They are not sent over the cap. Losing mimicry under heavy loss is recorded as a metric, not papered over with a second stream of bytes.

## Sub-Tasks

- [x] Trace fixture for one persona, first 30 packets plus quiet — `crates/qf-stealth/fixtures/persona_trace.toml` carries a real bidirectional Chrome 154 capture (~290 datagrams: 74 client sends incl. handshake, request, and ACK stream, then ~5.2 s of measured quiet before the close). Chromium is wire-captured; Firefox is source-derived (neqo); Safari is honestly marked unverified.
- [x] Ledger and spend order — `qf_stealth::wire_budget::{WireBudget, BudgetLedger, WireShape}`. One `try_spend` gate; repairs debit before `dgram_send_parts`/raw queueing, padding asks `padding_target`, cover PINGs/chaff/keepalives spend last. No second counter, no borrowing (`second_window_refills_without_borrowing`).
- [x] Padder and cover PING call the ledger — `compute_stealth_padding` delegates to `BudgetLedger::padding_target` whenever a ledger is installed; the legacy RNG strategy dispatch is dead on ledgered connections. Cover PING (incl. operator heartbeat keepalive), chaff packets, and repair-image padding all pass `try_spend_wire_*` before emission.
- [x] `PaddingStrategy` removed from the operator enum — `StealthConfig.wire_shape` is the axis; legacy `padding_strategy` spellings (`random`, `fixed`, `adaptive`, `browser_mimic`, `normalize`, `packet_normalize`) parse onto `persona-trace`/`fixed-cell`. `off`/`performance` install no ledger and emit zero stealth bytes; `dynamic` owns a ledger from connect so a later escalation keeps the same image.
- [x] Tests — `zero_loss_padding_lengths_land_on_trace_classes`, `repairs_never_exceed_cap`, `exhausted_ledger_sends_natural_length`, `repair_spend_shrinks_padding_allowance`, `burst_cap_applies_within_the_second`, `fixed_cell_pads_to_cell_or_nothing`, `chromium_trace_is_wire_captured_and_covers_classifier_window`, `oversized_payloads_never_clamp_into_non_class_sizes` plus transport-level `ledger_is_the_only_padding_authority_when_installed`, `ledger_gates_deny_repairs_cover_and_pad_once_spent`, `ledgerless_connection_never_blocks_stealth_spenders`.

## Acceptance

- A zero-loss `stealth` capture's payload lengths are a subset of the fixture's length set, aside from the handshake.
- A lossy run does not exceed `cap_bytes_per_sec` by more than one packet.
- `off` adds zero padding bytes.

## Risks

- A short trace becomes a loop, which is a new period. The fixture needs a non-repeating stretch at least as long as the classifier window (30 packets), then a documented loop only in steady state.
- Cap too small to repair a loss burst. Prefer fewer repairs inside the cap over repairs that break the length set.
