# TODO 106 - io_uring Runtime Truth Collapse

## Context

After the Linux send-path simplification, `src/transport/uring.rs` still retained two internal worlds:

- a real runtime-owned `IoUringDatagram` path based on the `io_uring` crate
- an older raw-syscall / raw-ring-mapping `IoUringNative` implementation

The productive runtime no longer depended on the raw implementation. Keeping both in the same module made the canonical Linux fast-path story less reviewable and looked like unnecessary duplicate machine room.

## Desired Outcome

Keep exactly one `io_uring` runtime truth in `src/transport/uring.rs`:

- `IoUringDatagram` as the canonical runtime-owned path
- registry and send helpers layered only around that path
- no retained raw syscall / raw mmap ring implementation without a real owner

## Work Items

- [x] Remove the retained raw `IoUringNative` implementation and its syscall/ring-layout support structs.
- [x] Keep the runtime-owned `IoUringDatagram` path unchanged.
- [x] Sync top-level backlog and context to the simplified one-owner truth.

## Final State

- `src/transport/uring.rs` now exposes only the runtime-owned `IoUringDatagram` story.
- The final Linux fast-path contract remains:
  - `io_uring` high-end path
  - UDP/sendmmsg fallback
- The old duplicate raw machine room is gone.
