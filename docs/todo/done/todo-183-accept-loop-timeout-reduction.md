# TODO-183: Accept Loop Timeout and Buffer Allocation

## Status
PARTIAL - Accept timeout reduced from 5s to 500ms (reasonable compromise). Buffer allocation was already pre-allocated outside the loop (line 240). Buffer pool optimization remains open.

## Severity
MEDIUM

## Context
The accept loop uses a 5-second timeout for UDP recv and allocates a 65535-byte buffer on every loop iteration. The 5-second timeout means the server is unresponsive to new connections for up to 5 seconds when idle. The per-iteration buffer allocation wastes memory and CPU cycles on allocation/deallocation in a tight loop.

- `src/implementations/server/accept.rs:235-282`: main accept loop
- 5-second `recv_from` timeout: too long for responsive packet receipt
- `let mut buf = [0u8; 65535]` or equivalent allocation per loop iteration
- At high packet rates, this loop is the entry point for all traffic

## Root Cause
Conservative timeout was chosen to reduce CPU usage when idle, but 5 seconds is excessively long for a networking application. Buffer allocation per iteration was the simplest implementation but unnecessarily wasteful.

## Fix Plan
1. **Reduce timeout to 100ms:**
   - Change `recv_from` timeout from 5s to 100ms
   - This provides responsive packet receipt while still allowing idle-loop housekeeping
   - Consider adaptive timeout: 10ms under load, 100ms when idle
2. **Pre-allocated buffer pool:**
   - Allocate a small pool of 65535-byte buffers at startup (e.g., 16 buffers)
   - Checkout buffer from pool before recv, return after packet processing
   - Eliminates per-iteration allocation overhead
   - Use crossbeam or a simple atomic ring buffer for the pool
3. **Optional: Use recvmmsg on Linux:**
   - Receive multiple packets in a single syscall for higher throughput
   - Already partially implemented in transport layer, wire into accept loop
4. Benchmark before/after: packets-per-second at accept layer

## Acceptance Criteria
- Accept loop timeout <= 100ms
- Buffer reused from pre-allocated pool (no per-iteration allocation)
- No regression in packet processing correctness
- Benchmark shows improved responsiveness and reduced allocation overhead

## Dependencies
- None (standalone improvement)

## Affected Files
- `src/implementations/server/accept.rs`
- `src/implementations/server/mod.rs` (buffer pool initialization)
