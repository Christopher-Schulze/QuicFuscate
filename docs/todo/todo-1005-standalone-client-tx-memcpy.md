---
id: TODO-1005
title: Standalone client TX staged a second memcpy per packet before GSO coalescing
severity: LOW
phase: S
priority: P3
status: DONE
created: 2026-09-19
depends_on: []
---

# TODO-1005: Standalone client TX double-buffer copy

## Objective
Remove the per-packet memcpy in `flush_connected_outgoing` (`src/main.rs`,
Linux arm): the loop called `conn.send(&mut out)` into a caller scratch buffer
and then `flat.extend_from_slice(&out[..len])` copied the datagram into the
flat staging buffer that GSO coalescing and the per-packet tail read from.
Every outbound datagram paid one ~1.2 KiB memcpy beyond the packet's own
assembly cost.

## Implementation
`conn.send` treats `out` as write-only packet storage (header assembly,
frames, padding, and in-place AEAD only ever read bytes initialized earlier
in the same call), so the loop now writes directly into `flat`'s spare
capacity: `reserve(out.len())`, cast `spare_capacity_mut()[..out.len()]` to
`&mut [u8]`, and `set_len(start + len)` only on success. The staging layout,
span table, GSO run detection, fallback slicing, diagnostics, and telemetry
are byte-identical; on `Done`/error nothing is published.

## Verification
- `cargo check`/`clippy --features io_uring --bin quicfuscate` clean on Omega
  (aarch64, kernel 6.17).
- `tun-e2e-netns.sh` PASS on the rebuilt release binary: real MASQUE/TUN
  traffic through the new path, 0% ping loss before and after restart, clean
  TUN/firewall/forwarding teardown.

## Notes
- The non-Linux arm never had the copy (per-packet async send straight from
  `out`) and is unchanged.
- The standalone `client` runtime deliberately has no io_uring worker (the
  engine/io_driver path owns that) - GSO coalescing is its batching strategy,
  which is why the flat buffer must remain contiguous.
