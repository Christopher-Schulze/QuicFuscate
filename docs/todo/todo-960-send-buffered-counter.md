# TODO-960 — `total_send_buffered_bytes`: running counter instead of O(streams) scan

## Status
DONE

## Problem
`stream_send` computed the connection-level pending bytes on every call via

```rust
self.streams.values().map(|s| s.send_buf.len()).sum()
```

— a linear scan over **every** stream in the connection on each application
write. With many concurrent streams (H3 control + request streams,
WebTransport sessions) each `stream_send` paid O(#streams) just to enforce
`peer_max_data`.

## Solution
`send_buffered_bytes: usize` counter on the connection state, maintained at
the only mutation sites:

- `api.rs` `stream_send` push: `+= buf.len()` (Vec path) / `+= written`
  (ring path — counted even on the short-write error return).
- `recv.rs` emit drain: `-= data_len` once after `send_off` update, covering
  both `send_buf` clear/drain and the `send_ring.read` consumption.

`total_send_buffered_bytes` now returns the counter — O(1).

Exactness: `self.streams` has no removal path (stream entries persist for
the connection lifetime), so the counter cannot drift; `saturating_*` ops
guard arithmetic regardless. Both feature variants (`stream_ring_buffer`
on/off) compile and behave identically.

## Verification
- `cargo test -p quicfuscate transport::connection::tests`: 139/139 on
  default and `--features throughput`.
- `cargo check -p quicfuscate --all-targets` both feature sets, clippy,
  `cargo fmt --check`: clean.
- Omega: native check + tests both variants — green on Linux.
