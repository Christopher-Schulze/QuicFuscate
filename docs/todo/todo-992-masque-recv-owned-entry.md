---
id: TODO-992
title: TODO-992 — MASQUE receive: dispatch directly from the owned queue entry
status: OPEN
created: 2026-09-19
---

# TODO-992 — MASQUE receive: dispatch directly from the owned queue entry

## Context

`try_recv_masque_datagram` popped each inbound DATAGRAM through
`dgram_recv(&mut masque_recv_buffer)` — a full-payload memcpy from the QUIC
receive queue into a permanent scratch buffer (`max_udp_payload + 40` bytes
held per H3 connection for its whole lifetime). The scratch copy existed only
to give the `PacketNormalizer` a writable tail
(`MASQUE_RECV_HEADROOM = 40` for in-place TCP option expansion); the queue
entry's own backing allocation already provides that.

## Implementation

- `src/transport/connection/state.rs`: `DatagramBuffer` raised to
  `pub(crate)`; new `DatagramEntry` alias (`Vec<u8>` default,
  `DatagramBuffer` under `zero_copy_dgram`) describing one owned queue entry.
- `src/transport/connection/api.rs`: `dgram_recv_take()` pops the front
  entry without copying; `dgram_recv_return(entry)` hands it back — freelist
  push on the default path, pool recycle via `Drop` under `zero_copy_dgram`.
- `src/transport/h3/connection.rs`: `masque_recv_buffer` replaced by
  `masque_recv_entry: Option<DatagramEntry>`; the permanently allocated
  scratch is gone (memory footprint win on top of the copy elimination).
- `masque_and_webtransport.rs`: `try_recv_masque_datagram` takes the owned
  entry, decodes the flow-id in place, resizes the entry (default) or relies
  on the pooled block tail (`zero_copy_dgram`) so `payload + 40` stays
  writable, and keeps it live until the next take returns it. Four
  cfg-split `masque_entry_*` helpers hide the `Vec`/`DatagramBuffer`
  difference. Entries larger than `masque_recv_capacity` are now dropped
  instead of silently truncated-dispatched (minor correctness tightening).
- `drain_masque_datagrams` (`src/core/connection/h3_runtime.rs`) and the
  test-only `masque_try_recv_datagram` (`lifecycle.rs`) needed no changes —
  the `(flow_id, offset, len)` + `masque_recv_region(offset)` contract is
  unchanged.

## Verification

- `cargo check`/`clippy`/`fmt` clean on default and `zero_copy_dgram`.
- New tests in `src/transport/connection/tests/flow_and_packet.rs`:
  - `masque_recv_take_dispatches_fifo_payload_with_writable_headroom` —
    FIFO order, payload visibility, writable `+40` tail, freelist/pool
    recycling after drain (both feature variants).
  - `masque_recv_take_drops_malformed_and_oversized_entries` — truncated
    varint and oversized entries are consumed and dropped.
- `cargo test --lib masque`: 49/49 green (default); recv-take tests green
  under `zero_copy_dgram`.
- Omega scenario g: **PASS, 52.3 Mbit/s, 0% loss**, zero EMSGSIZE/panic/
  ERROR in client and server logs — same noise band as post-TODO-991 runs.

## Notes

- One live entry stays held between drains (≈1.5 KB typical); the old code
  held a full `max_udp_payload + 40` scratch permanently — strictly less
  memory now.
- Hot-path copy count for a MASQUE datagram is now 0: queue entry → flow-id
  decode → in-place normalize → dispatch, all in the entry's allocation.
