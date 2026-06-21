# TODO-139: ECN Data Read But Discarded in ACK Frame Parsing

## Status
**DONE** - ECN counts now stored in Ack frame when parsing type 0x03

## Severity
**MEDIUM**

## Context
In `src/transport/frames.rs:559-562`, ACK frames with ECN (frame type `0x03`) are parsed: the ECN counts (`ect0`, `ect1`, `ce`) are read from the wire but stored as `None`:

```rust
// ECN counts read from wire
let ect0 = ...;
let ect1 = ...;
let ce = ...;
// But then:
ecn_counts: None  // data discarded
```

This violates RFC 9000 Section 19.3.2, which specifies that ACK frames of type `0x03` carry ECN feedback that MUST be processed by the sender's congestion controller. The `ce` (Congestion Experienced) count is critical for ECN-based congestion response.

Without ECN processing:
- The sender cannot react to ECN congestion signals from the network
- ECN negotiation during handshake is misleading (claims support but ignores feedback)
- Congestion control operates without network-layer signals

## Root Cause
ACK frame parsing was implemented for the basic case (type `0x02`) and the ECN variant (type `0x03`) was added for wire compatibility without integrating the ECN data into the congestion control pipeline.

## Fix Plan
1. Add `ecn_counts: Option<EcnCounts>` field to `AckFrame` struct (if not already present, ensure it is populated)
2. Define `EcnCounts { ect0: u64, ect1: u64, ce: u64 }` struct
3. When parsing frame type `0x03`, store the parsed ECN counts instead of `None`
4. Pass ECN counts to the recovery/congestion control module:
   - `recovery.rs` should process `ce` count increases
   - Trigger congestion response when `ce` increases (similar to packet loss response)
5. Validate ECN counts are monotonically increasing (per RFC 9000 Section 13.4.2.1)
6. Add unit tests for ECN ACK frame parsing and congestion response

## Acceptance Criteria
- ECN counts from ACK frame type `0x03` are preserved and passed to congestion control
- Recovery module processes CE count increases as congestion signal
- ECN count validation (monotonic increase) implemented
- Unit tests cover ECN ACK parsing, storage, and congestion response
- Wire format parsing remains backward-compatible

## Dependencies
- `src/transport/recovery.rs` - congestion control integration
- RFC 9000 Section 19.3.2, Section 13.4.2.1

## Affected Files
- `src/transport/frames.rs` (ACK parsing)
- `src/transport/recovery.rs` (congestion response)
- `src/transport/connection.rs` (ECN count forwarding)
