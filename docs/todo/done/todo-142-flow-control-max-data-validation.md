# TODO-142: Flow Control MAX_DATA Lacks Upper Bound Validation

## Status
**DONE** - MAX_DATA clamped to 1 GiB cap with warning log, monotonic increase enforced

## Severity
**MEDIUM**

## Context
In `src/transport/connection.rs:126-131`, `conn_max_data` tracks the peer's advertised connection-level flow control limit. When a `MAX_DATA` frame is received, the value is updated, but there is no validation against an upper bound.

A malicious peer could send `MAX_DATA(u64::MAX)`, which would:
- Allow the local endpoint to buffer up to `u64::MAX` bytes of data
- Effectively disable flow control protection
- Lead to unbounded memory allocation if the application generates data at that rate
- Potential OOM crash

RFC 9000 does not mandate an upper bound on MAX_DATA values, but a practical implementation must protect itself against resource exhaustion from adversarial peers.

## Root Cause
MAX_DATA frame processing updates the limit without sanity checking. Flow control was implemented for correctness (honoring peer's limit) but not for self-protection (capping peer's limit).

## Fix Plan
1. Add a configurable `max_peer_data_limit: u64` to the connection config
   - Default: reasonable value based on expected use case (e.g., 1 GiB = 1_073_741_824)
   - Tunable per deployment
2. When processing MAX_DATA frames:
   ```rust
   let capped = peer_max_data.min(config.max_peer_data_limit);
   conn_max_data = capped;
   ```
3. Log a warning when peer sends MAX_DATA exceeding the configured cap
4. Ensure stream-level MAX_STREAM_DATA has similar validation
5. Add unit tests:
   - MAX_DATA within bounds: accepted
   - MAX_DATA exceeding cap: capped with warning
   - MAX_DATA(u64::MAX): capped, no crash
   - Decreasing MAX_DATA: ignored per RFC (must be monotonically increasing)

## Acceptance Criteria
- MAX_DATA frames validated against a configurable upper bound
- Peer cannot cause unbounded memory allocation via MAX_DATA
- Warning logged when peer exceeds configured limit
- Stream-level MAX_STREAM_DATA similarly validated
- Unit tests cover all edge cases
- Compliant with RFC 9000 (peer's limit is honored up to our cap)

## Dependencies
- `src/engine/config.rs` (new configuration parameter)

## Affected Files
- `src/transport/connection.rs` (MAX_DATA processing)
- `src/engine/config.rs` (configuration)
- `src/transport/frames.rs` (if stream-level validation needed)
