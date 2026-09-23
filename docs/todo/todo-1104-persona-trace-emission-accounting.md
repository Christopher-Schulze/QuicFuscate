---
id: TODO-1104
title: Match persona cover scheduling and budget to emitted UDP packets
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1052, TODO-1054, TODO-1082, TODO-1095]
---

# TODO-1104: Persona trace emission accounting

## Why and evidence

`crates/qf-stealth/src/wire_budget.rs::persona_trace` includes the captured
Initial/handshake sequence in `client_sends`; `BudgetLedger::new` starts
`cover_cursor=0`. `note_wire_send` only resets `last_tx`. Core calls
`cover_ping_due` only once the connection is established
(`src/core/connection/send.rs`), so the first quiet post-handshake send poll
can replay the capture's first Initial-size client packet as a 1-RTT PING.
That is neither the browser's post-handshake schedule nor a continuation
aligned to the live packets. The current Chrome trace's first client row is
`gap_ms=0, len=1258`.

`cover_ping_due` calls `try_spend(len)` and advances the cursor before a
packet is serialized or emitted. Core then sets `pad_short_header_to(len)`;
`maybe_apply_stealth_padding` calls `try_spend_wire_pad(pad_len)` again. One
cover packet can therefore debit its full captured length plus its padding,
or fail the second allowance check and emit an undersized PING after the
first debit. Congestion, deferral, a short output buffer, failed seal, or a
queued but never emitted packet can also leave the cover slot spent without
a matching UDP datagram. `note_wire_send` is called at transport packet
materialization, including admitted-batch deferral, rather than at the
outer emission boundary.

For ordinary padding, `compute_stealth_padding` passes `off -
(pn_off+pn_len)`, the plaintext frame length, into
`BudgetLedger::padding_target`. `PersonaTrace::length_classes` are captured
UDP payload lengths. Reaching a class of 525 plaintext bytes yields an
actual UDP payload larger by short header, PN and AEAD tag, even before
FEC wrapping or GSO. The existing `class_for` unit tests inspect ledger
numbers, not captured emitted datagrams. TODO-1098 separately owns repair
metadata and admission; this task owns persona padding and cover events.

## Target contract

- A persona schedule has a declared phase and capture provenance. Never
  replay captured Initial/handshake rows as post-handshake cover packets.
  Derive post-handshake behavior from a fresh role/phase-aligned capture;
  if qualifying evidence is unavailable, suppress persona cover PINGs and
  retain only the explicitly labeled, budgeted idle keepalive. Real traffic
  fills eligible schedule slots rather than causing an added duplicate.
- Define the length target at the emitted UDP payload boundary, with
  header, PN, AEAD tag, padding, optional FEC framing and GSO segmentation
  accounted once. A selected trace class either matches the actual emitted
  datagram exactly or is reported as unmet and sends at natural length; no
  successful exact-class claim may be based on plaintext length.
- Use one transactional spend per emitted cover datagram and one spend for
  added padding on ordinary data. Reserve a proven upper bound only when
  required by send architecture; release or reconcile on failed seal,
  congestion, short buffer, deferral cancellation, queue drop and final
  emission. A pending cover slot advances only under the declared skip or
  successful-emission rule, never merely because the ledger was queried.
  `last_tx` reflects actual outer emission for scheduling, not packet
  materialization. Keep TODO-1052's single shared ledger and TODO-1098's
  typed repair origin; do not introduce a second budget.
- Validate `persona_trace.toml` at the same fixture gate as TODO-1082:
  direction strictly `c` or `s`, finite nonnegative gaps, positive lengths
  within supported UDP/path bounds, sensible ascending classes and a
  post-handshake phase marker. A malformed future embedded fixture fails
  CI with a field-specific error before production use. In particular,
  `Duration::from_secs_f64` must never receive NaN/negative time.

## Implementation and proof

- [ ] Trace ledger creation, handshake sends, `cover_ping_due`, every
      `note_wire_send`, target padding, packet admission, queued emission,
      FEC materialization, socket dispatch and GSO segmentation. Record
      where `last_tx` and charge currently precede actual emission.
- [ ] Extend TODO-1082's dated capture manifest with verified
      post-handshake client/peer event phases. Replace the zero-based
      handshake replay with a phase-aligned scheduler; prove real data
      suppresses redundant cover and browser idle remains quiet.
- [ ] Move exact-length selection and one cover debit to the narrow
      existing serialization/emission ownership boundary. Pass actual
      UDP payload size into persona padding; reconcile any reservation
      without duplicate charge. Coordinate repair accounting with
      TODO-1098 and RFC framing with TODO-1095.
- [ ] Add failable tests for first established poll, real-data-filled
      slot, exhausted allowance, exact 39/40/525/1258 classes where path
      MTU permits, packet too large, changed DCID/PN/tag lengths, FEC,
      deferred and dropped output, failed seal, short buffer, GSO, and
      keepalive. Mutate each fixture field into invalid direction, NaN,
      negative/huge gap and impossible length to prove the gate fails.
- [ ] Compare ledger charge, slot disposition, emission timestamp and
      payload length against a real two-direction UDP capture. Correct
      TODO-1052/1054 and product docs to state only measured behavior.

## Acceptance

- Zero post-handshake replay of Initial/handshake rows. Every claimed
  exact-class output matches the captured UDP payload length byte for byte;
  uncovered or MTU-infeasible classes are named, never silently approximated.
- Each emitted cover datagram is charged exactly once for its full added
  UDP payload bytes; each ordinary padded datagram is charged once for its
  added padding. No failed or abandoned emission consumes budget as a
  successful send, and the cap holds in each second and burst window.
- Fixture validation rejects every malformed case without a production
  panic. ACK, PTO, FEC recovery and idle keepalive continue to progress.
