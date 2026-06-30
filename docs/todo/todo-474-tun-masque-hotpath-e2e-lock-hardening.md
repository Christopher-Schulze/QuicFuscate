---
id: TODO-474
title: TUN/MASQUE hotpath and E2E lock hardening
severity: HIGH
phase: "R"
priority: P0
status: DONE
created: 2026-06-30
depends_on: [TODO-422, TODO-423, TODO-473]
---

# TODO-474: TUN/MASQUE hotpath and E2E lock hardening

## Goal
Remove unnecessary production hotpath work from the authenticated H3/MASQUE/TUN path and make the Linux TUN/netns proof scripts stable under accidental parallel invocation. The target is lower runtime overhead, less log amplification, and reproducible Broderick evidence even when DNS and FEC gates are triggered at the same time.

## Implemented State

- `src/core.rs` now logs per-packet MASQUE uplink/downlink TX lines at `debug` level instead of `info`. Connection lifecycle events, including CONNECT-UDP open and peer flow registration, remain `info`.
- `src/implementations/server/mod.rs` no longer sweeps every connected client after one TUN downlink packet is queued. The TUN reader records the target client address only when `send_masque_downlink(&pkt)` succeeds, then flushes only that client's connection.
- `scripts/tests/tun-e2e-netns.sh`, `tun-e2e-dns-leak-netns.sh`, `tun-e2e-fec-netns.sh`, `tun-e2e-fec-burst-netns.sh`, `tun-e2e-fec-transition-netns.sh`, and `tun-e2e-fec-netem-adversity.sh` now acquire a shared `flock` guard before touching fixed netns/process/log/cert state.
- The lock defaults to `/tmp/quicfuscate-tun-e2e.lock` and `300` seconds. Operators can override it with `QF_E2E_LOCK_FILE` and `QF_E2E_LOCK_TIMEOUT`.
- The E2E lock deliberately serializes these suites instead of randomizing only namespace names, because the scripts also share cleanup behavior, log paths, admin sockets, generated config/certs, and process names.

## Broderick Evidence

All commands were run on `broderick` from `/root/QuicFuscate-git` after the current local changes were synchronized for validation.

| Gate | Result | Evidence |
|---|---:|---|
| Release build | PASS | `cargo build --release --bin quicfuscate` completed successfully |
| Base TUN/MASQUE netns | PASS | `5 packets transmitted, 5 received, 0% packet loss` |
| Per-packet log trim | PASS | Base TUN run keeps CONNECT-UDP lifecycle `info` lines while packet-level `MASQUE TX` / `MASQUE downlink TX` lines no longer spam `info` logs |
| DNS+FEC parallel collision proof | PASS | Concurrent DNS and FEC invocations serialized through the shared lock instead of corrupting `ns-srv` / `ns-cli` state |
| DNS leak netns | PASS | `dig_exit=0`, DNS response present, `raw_port_53_packets=0` |
| FEC smoke netns | PASS | `3 passed, 0 failed, 2 skipped`; 0%, 5%, and 10% loss gates passed |
| Criterion ci_regression | PASS | `connection_1rtt_send_recv/payload_1400B` about `25.63 us`; stealth-on vs stealth-off overhead about `0.6%`; `ack_sent_byte_accounting/10240_inflight_ack_sparse` about `1.73 ms` |

## Notes

- The target-client flush keeps existing non-async `try_send_to` semantics and avoids introducing a borrow-across-await refactor into the TUN reader loop.
- The observed ACK sparse-accounting cost is real and remains the next measured optimization candidate, but it is separate from this TUN/MASQUE hotpath fix.
- The lock is intentionally coarse. It protects correctness over parallel throughput because these scripts validate root-level shared Linux namespace state, not isolated unit tests.

## Acceptance

- [x] Per-packet MASQUE TX/downlink logs do not run at `info` level in production hot paths.
- [x] Server TUN downlink flushes only the client that owns the queued MASQUE downlink packet.
- [x] TUN/netns E2E scripts serialize through a shared lock when invoked concurrently.
- [x] Broderick release build, base tunnel, DNS leak, and FEC smoke gates remain green.
- [x] Documentation records the hotpath change, lock behavior, and measured follow-up candidate.
