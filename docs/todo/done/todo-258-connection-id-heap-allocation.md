# TODO-258: Replace ConnectionId Heap Allocation with Fixed-Size Buffer

## Severity: MEDIUM

## Context
`src/transport.rs:335` defines `ConnectionId(Vec<u8>)`, which heap-allocates for every connection ID. QUIC connection IDs are limited to 20 bytes by spec (RFC 9000 Section 17.2). A `SmallVec<[u8; 20]>` or `ArrayVec<u8, 20>` would eliminate the heap allocation entirely, since connection IDs never exceed 20 bytes.

## Desired Outcome
- Replace `ConnectionId(Vec<u8>)` with `ConnectionId([u8; 20], u8)` (buffer + length) or `SmallVec<[u8; 20]>`.
- Eliminate heap allocation for connection ID creation and cloning.
- Maintain all existing `ConnectionId` API surface (comparison, hashing, Display).

## Files
- `src/transport.rs` (~line 335)
- All files that construct or manipulate `ConnectionId`

## Completion Criteria
- `ConnectionId` no longer heap-allocates.
- All existing tests pass.
- `cargo test` passes, clippy clean.
