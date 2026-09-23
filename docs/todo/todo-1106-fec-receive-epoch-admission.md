---
id: TODO-1106
title: Advance FEC receive epoch only after valid symbol admission
severity: MED
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1046]
---

# TODO-1106: Transactional FEC receive-epoch admission

## Why and evidence

`src/core/connection.rs::absorb_quic_fec_datagrams` drains a sealed QUIC
DATAGRAM, rebuilds the FEC wrapper, calls `wire::parse_packet`, then sets
`fec_symbol_epoch_floor = parsed.meta.profile.epoch` before calling
`WireFecReceiver::receive`. Parsing checks framing and metadata, but
`crates/qf-fec/src/receiver.rs::receive_borrowed` can still reject an
`EpochProfileMismatch`, an invalid systematic source payload, or a
resource-exhausted packet. The caller ignores the error and keeps the
advanced floor. A peer-sent high-epoch symbol with an invalid body can
therefore make later otherwise valid lower-epoch symbols fail the floor
check without ever admitting the new epoch. The present test only proves
the floor advances on a syntactically valid epoch-8 symbol.

The receiver also creates/evicts a receive window, advances its shared
horizon and records `last_rx_epoch` before some payload/decoder errors.
Those state changes can contaminate recovery and repair-ACK reporting even
when the core should reject the new symbol. The sender increments its
`fec_tx_epoch` with `wrapping_add(1).max(1)`, while the receiver compares
epochs with a plain numeric `<`; a real wrap from `u32::MAX` to 1 would
make all new symbols look stale. Wrap is a remote edge case, but the
protocol contract should be explicit instead of relying on process age.

## Target contract

- Define one receive-epoch transition rule from the sender's actual
  sequence/profile contract. A syntactically parsed header alone cannot
  fence an older epoch. Advance the floor and receiver's last epoch only
  after full symbol validation and admission succeeds; an invalid or
  resource-rejected symbol leaves the previous floor, windows, horizon,
  dedup and repair-ACK epoch unchanged. Duplicate valid symbols retain the
  declared idempotent outcome.
- Preserve a bounded reordered-symbol window during a legitimate epoch
  transition, or explicitly reject previous-epoch late symbols only after
  the new epoch is committed. No FEC window may mix incompatible profiles
  or silently lose source deliveries. Prefer a receiver admission result
  returned from the existing API to a second independent epoch tracker.
- Define the `u32` wrap rule: either version a nonwrapping epoch/connection
  rollover before exhaustion or use an unambiguous bounded serial-number
  comparison tied to the sender's permitted transition. An arbitrary huge
  forward jump cannot permanently disable FEC without an authenticated,
  accepted transition. Keep per-connection memory bounded.
- Error disposition is observable: invalid format/profile, resource bound,
  stale epoch and duplicate each increment the correct counter or return
  a typed outcome. Do not route invalid FEC bytes to a Reality fallback.

## Implementation and proof

- [ ] Trace sender epoch changes, parser, receiver window creation/eviction,
      `source_datagram_payload`, decoder admission, repair-ACK epoch and
      the core drain. Record which mutations currently precede every
      possible error.
- [ ] Make receive admission transactional at the existing receiver/core
      seam, including window/horizon and last-RX-epoch ownership. Move the
      core floor update after confirmed admission; keep one canonical
      transition decision.
- [ ] Add failable tests for a high-epoch valid header with malformed
      systematic length, same-epoch profile mismatch, resource exhaustion,
      valid next epoch, reordered previous epoch, duplicate, maximum epoch
      and rollover. Assert floor, windows, delivered packets, ACK report
      epoch and counters on every rejection and success.
- [ ] Run focused qf-fec and core FEC recovery tests plus a real loss/
      reordering integration scenario under in-QUIC framing. Measure any
      new admission cost on the receive hot path before accepting it.

## Acceptance

- A rejected symbol causes zero epoch/window/horizon/ACK-epoch state
  change, and a valid transition commits exactly once. No malformed
  high-epoch packet suppresses a later valid lower-epoch symbol.
- Legitimate source and repair recovery, bounded reordering, duplicate
  handling and wrap policy all pass deterministic and impaired-link proof.
