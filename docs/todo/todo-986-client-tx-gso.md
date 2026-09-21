---
id: TODO-986
title: Standalone client TX: per-packet sendmsg instead of UDP_SEGMENT batching
status: OPEN
created: 2026-09-19
---

# TODO-986 - Standalone client TX: per-packet sendmsg instead of UDP_SEGMENT batching

## Symptom

`flush_connected_outgoing` issued one `sendmsg` per QUIC datagram through
tokio's `async_io(WRITABLE)` wrapper. Under load (~6-7k packets/s in the TUN
scenarios) that is one syscall + one reactor round-trip per datagram. The
server path already coalesced bursts into `UDP_SEGMENT` super-buffers; the
client never did.

## Fix

On Linux the client flush now stages the whole burst into one flat buffer
plus a span table (`conn.send` into the shared `out` scratch, one memcpy per
datagram into `flat`), then emits contiguous same-length runs via
`send_udp_segment` — up to 64 datagrams or 64 KiB per syscall. Single spans
and post-`WouldBlock` tails fall back to the async `send_connected_datagram`
path, which still waits for writability. GSO capability is probed once
process-wide (`linux_udp_gso_capable`, `AtomicU8` cache). Non-Linux keeps the
existing per-packet loop unchanged.

Run planning mirrors the server contract: uniform interior segment size, a
shorter final segment may close the run, runs cap at 64 segments / 65535
bytes.

## Verification

- Omega aarch64 release build clean.
- strace on the live client during scenario g: every `sendmsg` carries
  `SOL_UDP`/`cmsg_type=0x67` (`UDP_SEGMENT`) with `seg_size=1457`,
  `iov_len=4371` — 3 wire datagrams per syscall, no per-packet sends on the
  GSO path.
- Scenario g PASS three consecutive runs: 70.1 / 65.4 / 60.7 Mbit/s — same
  range as the 67.9 Mbit/s pre-change baseline on the single-core testbed
  (syscall reduction does not lift the crypto/contention ceiling, but removes
  ~2/3 of TX syscalls and the per-datagram reactor round-trips).
- Diagnostics counters (`send_polls`, `send_datagrams`, `send_zero_results`,
  `send_done_results`, `send_errors`) preserved with identical semantics.

## Remaining

- Zero-copy staging (conn.send directly into flat windows) needs a >=64 KiB
  window per datagram → 4 MiB persistent staging; deferred — the one small
  memcpy is far cheaper than the syscall it replaces.
- sendmmsg multi-iovec for mixed-length tails is possible but marginal vs the
  GSO runs that dominate under load.
