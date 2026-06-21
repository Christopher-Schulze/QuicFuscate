# TODO-143: Packet Number Overflow and Duplicate Validation Missing

## Status
**DONE** - Duplicate detection and 2^62 overflow check added, on_packet_recv returns bool

## Severity
**MEDIUM**

## Context
In `src/transport/pn.rs:33`, the `on_packet_recv` function processes incoming packet numbers but lacks:

1. **Duplicate detection:** No check whether a packet number has already been received. Duplicate packets should be silently discarded (RFC 9000 Section 12.3).

2. **Overflow validation:** Packet numbers are conceptually unbounded but encoded in 1-4 bytes on the wire. No validation that decoded packet numbers stay within expected bounds or that the largest acknowledged PN doesn't wrap.

3. **Key update validation:** During key rotation, packet numbers must be validated against the key phase to prevent an attacker from replaying packets from a previous key phase. No such validation exists.

Without these checks:
- Duplicate packets could be processed multiple times, causing application-level issues
- Overflowed packet numbers could corrupt the PN decoding window
- Key rotation could be exploited to replay old packets

## Root Cause
Packet number tracking was implemented for the basic case (ordering and ACK generation) without the security-critical validation layers required by QUIC.

## Fix Plan
1. **Duplicate detection:**
   - Maintain a received PN bitmap/window (e.g., sliding window of last N packet numbers)
   - Reject packets with already-seen PNs
   - Window size should cover at least the reordering tolerance (configurable, default 128)
2. **Overflow bounds checking:**
   - Validate decoded PN is within `[largest_pn - window, largest_pn + max_gap]`
   - Reject PNs that are impossibly far from the current window
   - Define `max_gap` based on expected network conditions
3. **Key phase validation:**
   - Track which key phase each PN belongs to
   - During key update, reject packets with old key phase if their PN is within the new phase's range
   - Enforce that key updates happen at most once per round trip
4. Add unit tests:
   - Duplicate PN rejected
   - PN within window accepted
   - PN far outside window rejected
   - Key phase mismatch rejected
5. Add metrics for duplicate/rejected packet counts

## Acceptance Criteria
- Duplicate packet numbers detected and silently discarded
- PN overflow/out-of-window packets rejected
- Key update rotation validates packet numbers against key phase
- Metrics track rejection counts for monitoring
- Unit tests cover all validation paths
- Compliant with RFC 9000 Section 12.3

## Dependencies
- `src/transport/recovery.rs` (largest acknowledged PN tracking)
- `src/crypto.rs` or `src/qftls.rs` (key phase tracking)

## Affected Files
- `src/transport/pn.rs` (core validation logic)
- `src/transport/connection.rs` (integration with packet processing)
- `src/transport/packet.rs` (PN decoding validation)
- `src/crypto.rs` (key phase tracking)
