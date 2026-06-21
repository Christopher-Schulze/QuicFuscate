# TODO-182: Vec Allocation in Frame Parsing Hot Path

## Status
DOCUMENTED - to_vec() calls annotated with TODO comments explaining the performance concern and the correct fix (Frame<'a> with borrowed slices). Actual zero-copy migration deferred due to lifetime propagation complexity.

## Severity
MEDIUM

## Context
Frame parsing performs `to_vec()` on every frame's payload, causing O(n) heap allocation per packet in the critical data path. At high packet rates (>1M pps), this generates millions of small allocations per second, putting heavy pressure on the allocator and triggering frequent cache invalidation.

- `src/transport/frames.rs:580`: `c.get_bytes(len)?.to_vec()` - STREAM frame data copy
- `src/transport/frames.rs:606`: `c.get_bytes(len)?.to_vec()` - CRYPTO frame data copy
- `src/transport/frames.rs:638`: `c.get_bytes(len)?.to_vec()` - additional frame data copy
- Each call allocates a new Vec on the heap, copies bytes, then the source buffer remains valid
- This is the innermost hot path - every received packet triggers these allocations

## Root Cause
Frame parsing was implemented with owned data (`Vec<u8>`) for simplicity and safety. The frame structures own their data, avoiding lifetime complexity. However, the parsed frames are typically consumed immediately (within the same packet processing cycle), making ownership unnecessary.

## Fix Plan
1. Introduce a `Frame<'a>` lifetime-parameterized frame type that borrows from the packet buffer
   - Replace `Vec<u8>` payload fields with `&'a [u8]` slice references
   - Frame borrows from the packet buffer, which must outlive the frame
2. Ensure packet buffer lifetime extends through frame processing pipeline
   - Verify buffer pool (from todo-183) provides stable references
3. Add `Frame::to_owned()` for cases where frames must outlive the buffer (retransmission queues)
4. Benchmark before/after:
   - Allocation count per packet (should drop to zero for parsing)
   - Throughput at 1M+ pps
5. Update all frame consumers to work with borrowed frames

## Acceptance Criteria
- No heap allocation in frame parsing hot path (zero `to_vec()` calls in common case)
- Frame parsing throughput improved (benchmark proof)
- Retransmission path still works with owned frames where needed
- All existing tests pass

## Dependencies
- todo-183 (accept loop buffer pool) - complementary, provides stable buffer references

## Affected Files
- `src/transport/frames.rs`
- `src/transport/packet.rs`
- `src/transport/connection.rs`
- `src/transport/recovery.rs`
