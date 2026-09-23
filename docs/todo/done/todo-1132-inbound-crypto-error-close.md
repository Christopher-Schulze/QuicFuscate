---
id: TODO-1132
title: Close on inbound CRYPTO capacity and overlap failures
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1127]
---

# TODO-1132: Convert inbound CRYPTO admission failures into QUIC closes

## Why and evidence

`Connection::process_crypto_frame` passed `CryptoStream::recv` errors through
`?` in both provider-backed and local receive paths. The 65,536-byte window
from TODO-1127 can reject a peer CRYPTO frame with `CryptoBufferExceeded`,
but the connection remained open and Core treated the error as possible probe
traffic. RFC 9000 Section 7.5 requires a handshake overflow to close with
`CRYPTO_BUFFER_EXCEEDED` (`0x0d`) if the buffer is not enlarged. After the
handshake, closing with the same code is explicitly permitted. Conflicting
overlap bytes likewise cannot be passed to TLS or silently accepted.

## Target contract

- For Initial, Handshake and application CRYPTO, in both real-TLS and local
  transport receive paths, a `CryptoBufferExceeded` admission error records
  the original typed cause, marks the connection closed/draining and queues
  exactly one transport `CONNECTION_CLOSE` with error code `0x0d`.
- Conflicting retained bytes (`InvalidFrame`) close with
  `PROTOCOL_VIOLATION` (`0x0a`); an invalid CRYPTO range (`InvalidPacket`)
  closes with `FRAME_ENCODING_ERROR` (`0x07`). Unexpected internal failures
  close with `INTERNAL_ERROR` (`0x01`). No TLS data or CRYPTO buffer state is
  advanced by the rejected frame.
- The close frame is protected under an available encryption level and opens
  at the peer with the exact code. Preserve the first local root cause and
  the first queued close on repeated errors. Packet-number timing and Core
  probe-fallback classification remain TODO-1129 and TODO-1133 respectively.

## Implementation and proof

- [x] Reproduce non-closing capacity and overlap errors in both receive
      owners before the fix; verify the RFC policy against the standard.
- [x] Route leaf admission errors through one typed close boundary after
      releasing the CRYPTO lock; keep contiguous TLS drain only on success.
- [x] Add failable tests for all three levels and both receive owners,
      conflicting overlap, exact close code and peer-opened protected close.
- [x] Run focused/default/feature library tests, strict Clippy and formatting;
      update the owning architecture and task docs with exact evidence.

## Acceptance

- Every tested CRYPTO admission failure enters one terminal close with the
  correct code, without feeding rejected bytes to TLS or retaining them.
- A peer decrypts the protected `0x0d` close; required gates pass.

## Verification and limits

- The capacity and conflict tests failed before the fix because the
  connection remained open. After the fix, all three CRYPTO levels and both
  provider-backed/local receive paths close with `0x0d`, the conflicting
  overlap closes with `0x0a`, an overflowing offset closes with `0x07`, and
  a repeated error retains the first cause and one close. A paired 1-RTT
  peer decrypts the protected `0x0d` close.
- Local macOS default root library: `1,869 passed, 1 ignored`; feature root
  library (`rust-tests`, `stream_ring_buffer`, `zero_copy_dgram`): `1,874
  passed, 1 ignored`. Strict root library Clippy, workspace formatting and
  diff hygiene pass. `CARGO_INCREMENTAL=0` avoided the previously observed
  target-cache race. No external peer or independent wire capture was run.
- This task does not claim whole-packet ACK atomicity or correct Core Reality
  fallback routing after a terminal transport error. TODO-1129/1133 own
  those boundaries. RFC 9000 Section 11.1 permits effect-free discard of
  invalid Initials to resist spoofing; TODO-1129 must evaluate that policy
  before any change to this standards-permitted close behavior.
