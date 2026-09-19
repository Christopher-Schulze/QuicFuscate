# TODO-987 — Standalone client RX: per-packet recvmsg + UDP GSO cap off-by-header

## Context

After TODO-986 batched client TX via `UDP_SEGMENT`, the symmetric RX path still
issued one `recvmsg` per datagram through the `ZeroCopyRecvBuffer` wrapper. The
server already enables `UDP_GRO`; the standalone client did not, so kernel-side
coalescing was unavailable exactly where single-core CPU is scarcest.

## Implementation

- `src/main.rs`: new `recv_connected_segments()` — Linux variant wraps
  `qf_transport_udp::recv_msg_gro(fd, buf, false)` in `async_io(READABLE)` and
  returns `(len, gso_size)`; non-Linux delegates to `recv_connected_datagram`
  and reports `gso_size = 1`.
- `src/main/runtime/client.rs`: recv arm consumes `(len, gso_size)` and feeds
  `conn.recv` one `gso_size`-aligned slice at a time; H3/MASQUE drain +
  `flush_connected_outgoing` run once per completed batch instead of per
  datagram. The outer runtime loop is labelled `'runtime` so fatal TLS exits
  still escape from inside the segment loop.
- `UDP_GRO` is enabled via `enable_udp_gro_fd` **after** handshake +
  assignment complete, immediately before the runtime loop — the pre-loop
  paths read with plain `recvmsg` and must keep single-datagram semantics.

## Bugs found during Omega verification (both fixed before merge)

1. **`gso_size = 0` misread as 1-byte segments.** No ancillary data means "one
   plain datagram"; an initial `seg = max(1)` sliced the buffer into `len`
   1-byte `conn.recv` calls — the resulting parse-error flood killed the
   connection ~200 ms after assignment. Fixed: `seg = len` when `gso_size == 0`.
2. **GSO payload cap off by the UDP header.** All three production run
   planners (`main.rs` client flush, `live_auth.rs`, `tun_path.rs`) capped the
   super-buffer at `u16::MAX = 65535`; the kernel encodes `payload + 8` into
   the UDP length field, so buffers in `(65527, 65535]` return `EMSGSIZE`
   (observed live: `UDP GSO send failed: Message too long`). New shared
   constant `qf_transport_udp::UDP_GSO_MAX_PAYLOAD = 65527` is used by all
   planners and the `plan_gso_run` unit tests.

## Verification (Omega, aarch64, kernel 6.17)

- `cargo test --release --lib`: 4/4 `gso_plan_tests` green.
- Scenario g (TUN dataplane, 0% netem): **PASS**, clean client SIGTERM path.
- strace: `sendmsg` carries `cmsg_type=0x67` super-buffers (`iov_len=5824` =
  4×1456), zero `EMSGSIZE` after the cap fix; `recvmsg` issued at 64 KiB
  iov and no `UDP_GRO` cmsgs appeared — the kernel did not coalesce at this
  rate (the client keeps up, so the receive queue rarely exceeds one
  datagram). The path is armed and correct regardless; coalescing engages
  automatically under deeper queueing.
- The earlier handshake-time TLS decrypt failure is explained by GRO enabled
  at socket setup: coalesced buffers reached the assignment path which parses
  no ancillary data. Post-handshake enablement removes that interaction.

## Follow-ups

- Under heavier downlink (multi-core host), confirm `UDP_GRO` cmsgs actually
  arrive and count segments-per-syscall in telemetry.
- Consider the same `recv_msg_gro` conversion for `runtime.rs`'s post-handshake
  assignment reader if it ever becomes hot.
