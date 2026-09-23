---
id: TODO-1105
title: Charge H3 and WebTransport cover from emitted wire bytes
severity: MED
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1052, TODO-1055, TODO-1096, TODO-1098, TODO-1104]
---

# TODO-1105: H3 cover wire-budget accounting

## Why and evidence

`src/core/connection/h3_runtime.rs::h3_header_list_bytes` calculates
`sum(name.len + value.len + 8)` for persona headers. Its outer request path
debits that estimate before `h3.send_request`. `emit_due_cover_headers`
repeats the same estimate for full cover requests. Actual QPACK bytes depend
on static/dynamic indexing, table updates and encoding state; the QUIC
STREAM frame, packet header, PN, AEAD tag and padding also reach the UDP
wire. A header-list estimate is neither the encoded delta nor the whole
cover datagram. Error returns and queued-but-abandoned output have no
refund path. The current code can therefore undercharge emitted cover or
charge bytes that never emit. No capture-backed reconciliation is present.

`emit_webtransport_cover_session` debits
`authority.len + path.len + 64` before opening the H3 session. The helper
`StealthManager::webtransport_cover_plan` atomically claims its one-shot
plan before the budget check or `open_webtransport_cover_session` result;
a budget denial or transient open failure can consume the one possible
session without emitting any cover. Subsequent WebTransport streams and
their content need the same attribution as the opening request.

## Target contract

- Keep one `BudgetLedger` and a single outer emission accounting basis from
  TODO-1098/1104. Attach typed cover origin to the existing H3/QUIC send
  work. Count actual added UDP payload bytes after QPACK and packet
  materialization, including table updates, frames, seal overhead, padding
  and GSO segments. When cover and ordinary data share a packet, declare
  a deterministic attribution rule that charges cover once and does not
  charge ordinary application bytes as cover.
- Admission happens before externally visible output. If exact sizing is
  available only after encoding, use an upper-bound reservation and reconcile
  to the actual byte count on successful emission; release on failed
  encoding, stream refusal, congestion, short buffer, reset, abandoned
  queue or connection teardown. No error path leaves a successful spend
  for a nonexistent packet; no cover packet exceeds the declared cap.
- The once-per-connection WebTransport plan is marked consumed only after
  the planned request is admitted and successfully queued for eventual
  emission. A budget denial remains a named skip or retry according to one
  explicit bounded policy; a transient H3 error does not silently masquerade
  as a successful one-shot. Preserve peer interoperability and the
  post-handshake-only H3 lifecycle.
- Coordinate with TODO-1096: cover `:authority` and WebTransport target must
  belong to a validated authenticated outer-hop binding. No unrelated cover
  name may become a proxy authority or appear to reach a third-party host
  merely because the local server accepted an H3 request.

## Implementation and proof

- [ ] Trace header generation, QPACK encoding/table updates,
      `send_request`, WebTransport streams, QUIC STREAM queueing, packet
      sealing, FEC wrapping and socket emission. Record the actual delta
      from an equivalent functional request without persona cover fields.
- [ ] Carry a typed cover-origin marker through the narrow existing
      outbound queue; implement exact charge or a reversible upper-bound
      reservation. Share TODO-1098/1104's accounting basis and ledger; do
      not create an H3-only counter or a second packet pipeline.
- [ ] Make scheduler/WebTransport slot disposition explicit for budget
      denial, QPACK/stream error, short buffer, congestion, reset, and
      success. Preserve bounded retries and no catch-up burst.
- [ ] Add failable tests for static and dynamic QPACK, variable authority
      and header sizes, table update, mixed data/cover packet, failed
      `send_request`, failed WebTransport open, subsequent WebTransport
      streams, FEC, GSO and teardown. A deliberately underestimated
      encoded header must fail the cap proof.
- [ ] Compare ledger totals and per-origin counters with decrypted H3
      frames plus independent UDP capture under the declared browser
      persona. Correct TODO-1052/1055 and canonical docs; report byte,
      CPU and latency costs before enabling a cover policy by default.

## Acceptance

- In the declared capture matrix, 100% of emitted cover-attributed UDP
  bytes are charged exactly once under per-second and per-burst caps; 100%
  of failed or abandoned cover work has zero final spend. Mixed packets
  follow the documented deterministic attribution rule.
- No failed WebTransport attempt is reported as an opened cover session.
  Actual H3 authority and route match TODO-1096's validated entry binding;
  inner tunnel headers remain free of browser cover fields.
- ACK/recovery, H3 flow control, QPACK synchronization, ordinary request
  output and FEC continue to pass the relevant real-behavior tests.
