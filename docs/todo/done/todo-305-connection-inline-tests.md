---
id: TODO-305
title: src/transport/connection.rs - add inline unit tests (flow control + state machine)
severity: HIGH
status: done
created: 2026-03-25
---

# TODO-305: Connection.rs Inline Tests

## Problem

`src/transport/connection.rs` is 3194 LoC - the transport layer's heart - with **zero inline `#[cfg(test)]` unit tests**. Integration coverage exists (`rt-transport-connection.rs`, `rt-core-connection-basics.rs`) but only tests the public API at a high level. Critical internal invariants are untested:

- Flow control window calculations (MAX_DATA enforcement)
- Stream offset tracking
- Connection state transitions (Active -> Draining -> Closed)
- Key update state machine interactions
- ACK aggregation logic

## What Tests Are Needed

### Priority 1: Flow Control (5 tests)
```rust
fn flow_control_blocks_send_when_window_exhausted()
fn flow_control_window_opens_on_max_data_frame()
fn stream_offset_advances_monotonically()
fn max_data_enforced_per_stream_and_connection()
fn zero_window_allows_single_byte_probe()
```

### Priority 2: State Transitions (4 tests)
```rust
fn connection_enters_draining_on_close_frame()
fn connection_closed_after_drain_timeout()
fn idle_timeout_triggers_close()
fn connection_error_sets_terminal_state()
```

### Priority 3: Key Update (3 tests)
```rust
fn key_update_advances_key_phase()
fn key_update_rejects_replay_with_old_keys()
fn simultaneous_key_update_handled_deterministically()
```

### Priority 4: ACK handling (3 tests)
```rust
fn ack_removes_from_in_flight()
fn ack_triggers_cc_callback()
fn duplicate_ack_not_double_counted()
```

**Total: ~15 tests**

## Note

Many of these can be tested without a real network by constructing a `QuicFuscateConnection` with a loopback config and calling its internal methods directly. See existing integration tests for setup patterns.

## Completion Criteria

- All 15 tests in `#[cfg(test)]` module in connection.rs
- Tests are real (can fail when code is broken)
- Clippy GREEN, `cargo test --lib` passes
