---
id: TODO-1098
title: Charge FEC repair from actual QUIC wire bytes
severity: MED
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1046, TODO-1052, TODO-1095]
---

# TODO-1098: Exact FEC repair wire-budget accounting

## Why and evidence

`src/core/connection/send.rs` builds an in-QUIC FEC symbol as
`wire::write_symbol` output and calls `try_spend_wire_repair(body.len())`
before `dgram_send_parts(&[QUIC_REPAIR_DISCRIMINATOR], &body)`. The charge
omits that discriminator and the QUIC DATAGRAM frame type/length. If the
repair occupies its own 1-RTT packet, the short header, packet number,
AEAD tag and any packet padding also consume wire bytes. The raw-wrapper
branch separately charges `HEADER_LEN + payload` and does not fix the
in-QUIC discrepancy. `BudgetLedger` enforces exactly the size it receives,
so TODO-1052's "repairs never sent over cap" conclusion is not established
for actual emitted UDP payload bytes. Actual overage and coalescing frequency
require capture; the undercharge itself follows directly from call inputs.

## Target contract

- Define one byte-accounting basis for `cap_bytes_per_sec` and
  `cap_bytes_per_burst`: added emitted UDP payload bytes per connection,
  including FEC frame/discriminator, any standalone packet header, PN,
  AEAD tag, packet padding and GSO segments. State the treatment of a repair
  coalesced with ordinary frames and of baseline header cost so every byte
  is charged once, without treating ordinary application bytes as cover.
- Decide repair admission from the actual serialized packet cost at the
  transport send boundary, before that packet becomes externally visible.
  Carry repair origin as typed metadata through the existing DATAGRAM queue;
  do not infer it from payload bytes or run a second side ledger. If sizing
  must precede seal, reserve a proven upper bound and reconcile unused bytes
  atomically on successful emission or queue removal. A denied repair drops
  only the repair frame and records one reason; it must not discard an
  unrelated ACK/data frame or leave recovery/cwnd bookkeeping for an unsent
  packet.
- Keep the one TODO-1052 ledger and its repair-first ordering. Charge
  persona padding, Maybenot padding, cover PING and FEC at the same defined
  wire boundary, with no duplicate debit. Off/performance retain their
  declared no-ledger policy unless a separate product decision changes it.

## Implementation and proof

- [ ] Trace `dgram_send_parts`, frame materialization, packet sealing,
      padding, GSO dispatch, loss/retransmission and every
      `try_spend_wire_*` call. Record exact packet sizes and whether repairs
      share packets with non-repair frames in production.
- [ ] Add typed repair-origin metadata at the narrow existing queue/send
      boundary and implement exact admission or bounded reservation plus
      reconciliation. Avoid double-charging retransmitted frames; charge
      each emitted repair packet once and only if it is actually emitted.
- [ ] Prove deterministic boundaries with repair-only, repair+ACK/data,
      variable PN/DCID length, padding, failed seal, short caller buffer,
      queue drop, retransmission, and GSO/GRO segmentation.
- [ ] On a real UDP loopback/netns run, compare ledger debit against parsed
      capture bytes for each repair packet and per-second/burst totals under
      loss. Re-run FEC decode/recovery and TODO-1052 ledger tests; measure
      the throughput and repair-ratio cost before accepting any extra
      packet isolation.
- [ ] Correct TODO-1052 and `docs/DOCUMENTATION.md` to distinguish the
      historical body-only check from verified emitted-wire accounting.

## Acceptance

- In the declared capture matrix, 100% of additional emitted repair bytes
  are accounted under the same cap and every emitted packet has exactly one
  consistent charge; no successful cap proof relies solely on `body.len()`.
- No repair is externally emitted after a denied admission. Non-repair
  frames, ACK progress, FEC recovery, congestion accounting and packet
  ordering remain correct across denial and short-buffer paths.
- The before/after benchmark reports added CPU, allocation, and wire-byte
  cost; a more accurate cap is not implemented by silently dropping all
  repairs.
