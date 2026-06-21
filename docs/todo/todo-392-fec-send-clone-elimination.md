---
id: TODO-392
title: Eliminate FecPacket clone on send hot path
severity: HIGH
phase: A
priority: P1
status: DONE
created: 2026-06-05
---

# TODO-392: Eliminate `FecPacket::clone()` on FEC Send Hot Path

## Problem

`AdaptiveFec::on_send` (~3275) does `output.push(packet.clone())` then `encoder.take_packet(packet)`. Full datagram copy per packet in active FEC modes. Zero-mode path is already optimal.

## Acceptance

- No full-payload clone on normal FEC send path
- Systematic packet appears once in output; encoder consumes ownership or shares pool block via refcount-safe design
- Cross-fade transition path (`handle_transition_packet`) audited for duplicate clones
- FEC unit + integration tests green

## Fix Plan

1. Change `take_packet` to return systematic output entry or use `split` ownership model
2. `output.push` moves packet; encoder reads from shared pool block without clone
3. Audit `FecPacket::clone` remaining call sites

## Files

- `src/fec/mod.rs`
- `src/core.rs` (send path integration)

## Tradeoff

Active FEC modes still add repair overhead by design. This removes one redundant copy only.
