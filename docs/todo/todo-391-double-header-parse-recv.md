---
id: TODO-391
title: Eliminate double header parse in Connection::recv
severity: MEDIUM
phase: A
priority: P1
status: OPEN
created: 2026-06-05
---

# TODO-391: Eliminate Double QUIC Header Parse on Recv

## Problem

`Connection::recv` pre-parses header at ~987 for PN hint, then `packet::unprotect_and_decrypt` parses again internally. Redundant work on every inbound packet.

## Acceptance

- Single `parse_header` per recv
- Parsed `Header` + offsets passed into decrypt path
- All existing transport packet tests pass
- No semantic change to Retry / 0-RTT / short-header handling

## Fix Plan

1. Add `unprotect_and_decrypt_with_parsed_header` (or extend existing API) accepting pre-parsed header
2. Refactor `recv` to reuse parse result
3. Keep fallback parse only on error recovery paths if needed

## Files

- `src/transport/connection.rs`
- `src/transport/packet.rs`

## Benchmark

Validate with TODO-399 connection bench when available.
