---
id: TODO-1052
title: One wire byte budget for padding, cover, and FEC
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
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

- [ ] Trace fixture for one persona, first 30 packets plus 10 s quiet.
- [ ] Ledger and spend order.
- [ ] Padder and cover PING call the ledger.
- [ ] Delete `PaddingStrategy::Random` from the operator enum. Map old configs `random` to `PersonaTrace` in stealth modes and to off in `off` / `performance`.
- [ ] Test: under zero loss, padding lengths are members of the trace set. Under loss, repair bytes plus padding bytes stay within the cap.

## Acceptance

- A zero-loss `stealth` capture's payload lengths are a subset of the fixture's length set, aside from the handshake.
- A lossy run does not exceed `cap_bytes_per_sec` by more than one packet.
- `off` adds zero padding bytes.

## Risks

- A short trace becomes a loop, which is a new period. The fixture needs a non-repeating stretch at least as long as the classifier window (30 packets), then a documented loop only in steady state.
- Cap too small to repair a loss burst. Prefer fewer repairs inside the cap over repairs that break the length set.
