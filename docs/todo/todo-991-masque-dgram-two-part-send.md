# TODO-991 — MASQUE datagram send without staged concatenation copy

## Context

`send_masque_datagram` prepended the flow-id varint by clearing
`masque_send_scratch`, encoding into it, then `extend_from_slice`ing the
entire packet — and `dgram_send` then copied the assembled buffer into the
send-queue entry a second time. Every uplink/downlink MASQUE datagram paid
~1.5 KB of avoidable memcpy.

## Implementation

- `src/transport/connection/api.rs`: new `dgram_send_parts(prefix, payload)`
  writes both slices into the queue entry directly (freelist `Vec` on the
  default path, pooled block under `zero_copy_dgram`). `dgram_send` is now a
  thin delegate (`dgram_send_parts(&[], buf)`) — one enqueue code path.
- `src/transport/h3/connection/masque_and_webtransport.rs`:
  `send_masque_datagram` encodes the flow-id varint into an 8-byte stack
  array via `qf_transport_pn::varint::write_varint` and calls
  `dgram_send_parts` — no scratch buffer, no payload copy before enqueue.
- `src/transport/h3/connection.rs`: `masque_send_scratch` field removed
  (dead after the change). All callers — client uplink, server downlink,
  relay flows — share this path and benefit uniformly.

## Verification

- `cargo check` (default + `zero_copy_dgram`), `fmt`, `clippy` clean.
- `cargo test --release --lib masque`: 47/47 green, incl.
  `masque_datagram_e2e_roundtrip` and `masque_flow_id_varint_encoding`.
- Omega scenario g: PASS (throughput within single-core noise band).
