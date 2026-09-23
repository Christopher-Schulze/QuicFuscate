---
id: TODO-1046
title: FEC repairs as normal QUIC packets in stealth modes
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1041]
---

# TODO-1046: FEC repairs as normal QUIC packets in stealth modes

## Why

`auto` FEC leaves Zero under loss and then prepends a cleartext header. A passive observer does not need keys. Every datagram starts with the same two bytes. That is the largest stealth defect in the product. The solver is not the defect. The wrapper is.

## Current code

- `crates/qf-fec/src/wire.rs`: `MAGIC = [0xF1, 0xEC]`, `HEADER_LEN = 32`, `write_packet` copies the magic at bytes 0..2. `ZeroModeMustRemainRaw` keeps Zero unframed.
- `src/core/connection/types.rs`: `write_to` calls `wire::write_packet`.
- `src/core/connection/send.rs`: `prepare_fec_wire_profile` runs when `fec_wire_ready`. The raw path (`send_with_info_raw`) is only taken when `wire_profile` is `None`.
- Repair symbols are combinations of already sealed datagrams. TODO-1041 forbids FEC-then-seal of plaintext, a second custom cipher, and XOR on a sealed datagram.
- A QUIC 1-RTT short header has the header-form bit clear, so the first byte is `0x40`..`0x7F` after header protection. `0xF1` is a long-header-shaped constant.

## Target

Stealth-using modes emit repairs as ordinary QUIC short-header packets.

- Outer bytes: normal header protection plus the mode's payload AEAD (AES-128-GCM in `stealth`, `Stealth MAX`, and `dynamic`).
- Inner payload, after open: one private QUIC frame (unused frame type in the private range, or a DATAGRAM whose first byte is a repair discriminator). The frame body is the current repair symbol, without `MAGIC` and without the 32-byte cleartext header.
- The repair packet is padded to the same UDP length as the data packets in that burst, using QUIC PADDING before seal.
- `congestion_controlled = true`. Repairs count against cwnd.
- Equal-length repairs join the same GSO / `sendmmsg` run as data (`plan_gso_run` already requires uniform length).
- One AEAD epoch per FEC window. A window that crosses the post-auth key change does not mix symbols. That fence stays connection state, as in TODO-1041.
- `off` and `performance` keep `write_packet`. Those modes accept a visible wrapper.
- `manual` uses the in-QUIC frame, not the wrapper. The wrapper is not a manual default.

Receiver:

- Short-header datagrams enter the existing QUIC open path. The repair frame is recognized only after open.
- `0xF1 0xEC` is accepted only when the connection mode is `off` or `performance`.
- `stealth`, `Stealth MAX`, `dynamic`, and `manual` fail closed on `0xF1 0xEC` (drop, count, do not decode as FEC).

## Non-goals

- No new cipher, no tag bits, no trial decrypt.
- No RaptorQ. The GF16 / sliding-window / fountain solver stays.
- No FEC of plaintext before AEAD.
- No frontend visual change.

## Design

1. Add `FecFraming::{Wrapper, QuicFrame}` next to the mode pin in `src/engine/config.rs`, beside `engine_mode_uses_libaegis`. `Wrapper` iff mode is `Off` or `Performance`. Everything else is `QuicFrame`.
2. Split `write_packet` into symbol bytes and optional wrapper. The symbol codec stays. The wrapper call site in `types.rs` checks framing.
3. Sender path in `send.rs`: when framing is `QuicFrame`, do not call `write_packet`. Enqueue a QUIC frame through the normal `conn` send so seal and header protection run once, in the existing order: pad, seal, header protection, timing, then this packet is already a QUIC datagram. Do not wrap it again.
4. Recovery: after AEAD open, if the frame is a repair, feed the symbol to the existing decoder. Recovered source datagrams re-enter the QUIC receive path as they do today after `fec_wire_receiver.drain_recovered`.
5. Size: the repair QUIC packet uses the same padded length as the source datagrams in the window. If the symbol is shorter, QUIC PADDING fills it before seal. If it does not fit in one packet, split across numbered repair frames that still share that length. Do not emit a longer outlier.
6. CC and loss: a repair loss is a normal QUIC loss. Do not send repairs outside cwnd. That would look like a rate anomaly and would create more loss.

## Sub-Tasks

- [x] Mode-to-framing pin with a unit test for all six mode names.
- [x] Symbol codec usable without `MAGIC`.
- [x] Send path emits a QUIC packet for stealth modes and the wrapper for `off` / `performance`.
- [x] Receive path decodes the in-QUIC symbol and still decodes the wrapper in speed modes.
- [x] Stealth modes drop `0xF1 0xEC`.
- [x] Equal-length burst test: repair UDP length equals data UDP length.
- [x] Epoch-mix test: a symbol from the previous AEAD epoch is rejected.
- [x] Existing qf-fec recovery tests stay green on the symbol codec.

## Notes

`FecFraming::Wrapper` is `off` and `performance`. Every other mode is `QuicFrame`.

The UDP datagram in `QuicFrame` mode is a normal QUIC packet. The repair symbol is `write_symbol` (the 30-byte header plus payload, no magic) inside a DATAGRAM that starts with `0xFE`. The receiver prepends `MAGIC` only in memory before the existing decoder. A datagram that itself starts with `0xF1 0xEC` is dropped and counted.

`set_short_header_pad_target` pads the next short header so a repair can match the source sealed length. `fence_fec_symbol_epoch` rejects older in-QUIC symbols.

No live packet capture was taken. The emit and drop tests cover the bytes that would be on the wire.

## Result

`fec_framing_follows_stealth_mode`, `symbol_round_trip_matches_wrapped_packet_without_magic`, `stealth_drops_cleartext_fec_wrapper`, `quic_repair_from_previous_epoch_is_rejected`, and `short_header_pad_target_sets_sealed_length` passed. qf-fec 110/110. Core connection tests 60/60. Repair-ACK wrapper behavior stays on `performance`. Solver unchanged. No new AEAD.

## Acceptance

- A capture of a `stealth` connection under forced loss has zero datagrams starting with `0xF1 0xEC`.
- The same loss still recovers the source plaintext.
- An `off` connection under the same loss still starts framed datagrams with `0xF1 0xEC`.
- cwnd accounting includes repair bytes.
- No new AEAD implementation.

## Tests

- `qf-fec` symbol roundtrip with and without the wrapper.
- Root connection test: stealth framing vs performance framing on the same source packets.
- Negative: stealth peer receiving a wrapper datagram does not recover it and does not panic.

## Risks

- Repair-after-open costs one AES-GCM per repair (about 1 microsecond at 1400 B on Omega). That is the price of removing the prefix.
- A new frame type must not collide with a standard QUIC frame. Use a private type and fail closed on unknown versions.
- Header protection covers the first byte, so the test must compare the post-protection wire image, not the clear header.
