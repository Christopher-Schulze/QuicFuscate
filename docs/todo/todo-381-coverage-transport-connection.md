---
id: TODO-381
title: "Increase test coverage for transport/connection.rs (3399 LOC, ~7 tests/1000 LOC)"
severity: "HIGH (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-381: Increase test coverage for transport/connection.rs (3399 LOC, ~7 tests/1000 LOC)


## Problem
`src/transport/connection.rs` at 3399 LOC has 15 inline + ~10 external tests.

### What IS tested:
- Datagram send/recv
- Path migration
- Path validation
- Cooldown timers
- AEAD rejection

### What is NOT tested:
- Connection state machine (Idle -> Handshake -> Established -> Closing -> Closed)
- Handshake flow (initial, retry, version negotiation)
- Stream management (open, close, flow control, prioritization)
- Recv path (packet processing, decryption, frame dispatch)
- Error recovery (connection-level errors, transport errors)
- 0-RTT early data handling
- Connection migration (full path change, NAT rebinding)
- Congestion controller integration
- Keep-alive and idle timeout

## Fix Plan
Target: +20-25 tests covering:
1. State machine: transitions, invalid transitions, reset (5 tests)
2. Stream management: open/close, flow control limits (5 tests)
3. Error handling: transport errors, application errors, reset (4 tests)
4. 0-RTT: early data acceptance/rejection (3 tests)
5. Idle/keepalive: timeout behavior, ping generation (3 tests)
6. CC integration: window updates, congestion events (3 tests)

## Files to Modify
- src/transport/connection.rs (add/extend #[cfg(test)] module)
- scripts/tests/rust/rt-transport-connection.rs (extend)