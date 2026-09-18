# TODO-974 - Vectored `stream_send_parts` for H3 DATA frames

Status: DONE (local + Omega aarch64 Linux)

## Problem

`H3Connection::send_body` materialized one `Vec` per DATA frame:

```rust
let mut frame = Vec::new();
frame.push(0x00);                       // DATA frame type
Self::encode_varint(len, &mut frame);   // varint length
frame.extend_from_slice(to_send);       // full-body copy
conn.stream_send(stream_id, &frame, fin)
```

and `stream_send` then copied the whole thing a second time into the
stream's `send_buf`/`send_ring`. Per body: one heap alloc + one full-body
intermediate memcpy that existed only because the transport API demanded a
single contiguous slice.

## Fix

New `Connection::stream_send_parts(stream_id, parts: &[&[u8]], fin)`:

- Refactored `stream_send`'s body into a private `stream_send_impl` that
  takes `payload_len` plus an `append: FnOnce(&mut Stream) -> usize`
  closure - connection-level and per-stream flow-control checks, blocked
  signalling, and fin bookkeeping run exactly once, so the vectored path is
  atomic (unlike two sequential `stream_send` calls, which could commit a
  header and then reject the body on flow control).
- Default variant extends `send_buf` per part; `stream_ring_buffer` writes
  per part and keeps the original partial-write -> `InvalidState` contract.
- `send_body` now builds the <=9-byte header in a stack array
  (`0x00` + `write_varint`) and sends `[header, body]` - wire-identical
  bytes (streams are a byte stream; the concatenation is the same), zero
  heap alloc, zero intermediate copy. The body is copied exactly once,
  into the stream send buffer, as before.

Semantics preserved: `FlowControl`/`FinalSize`/`InvalidState` error paths,
`sent_bytes` accounting (payload_len == old frame.len()), empty-body+fin
(header-only parts list still marks fin), `finished_streams` insert.

## Verification

- `cargo test --lib transport::connection` - 142/142 default,
  143/143 `stream_ring_buffer`
- `cargo test --lib transport::h3` - 102/102
- `cargo clippy -p quicfuscate --all-targets` - clean; `cargo fmt` clean
- Omega (aarch64 Linux): native green
