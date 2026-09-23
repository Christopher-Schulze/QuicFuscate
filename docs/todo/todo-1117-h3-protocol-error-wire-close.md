---
id: TODO-1117
title: Complete H3 protocol-error wire closure
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1110]
---

# TODO-1117: H3 protocol-error wire closure

## Why and evidence

`src/transport/h3/connection.rs::poll` returns errors from control-stream
initialization, peer reset handling, QPACK flushing, `process_stream`, and
unblocked-stream processing. Before TODO-1110, even peer `IdError` and
`StreamCreationError` only escaped as Rust values; no H3 application close was
queued. TODO-1110 owns those two classes when `process_stream` rejects peer
input. The other peer-triggered errors escape without a mapped
application close. `src/core/connection/h3_runtime.rs` converts the returned
H3 error into a textual `ConnectionError::Transport`; that conversion is not
an on-wire H3 close. A peer can therefore see a silent stop or later timeout
instead of the required protocol code. The exact effect of each production
caller on close flushing remains to be traced.

## Target contract

- One typed boundary distinguishes peer-caused connection errors, local fatal
  errors, stream-scoped errors, and retryable/incomplete conditions. The
  mapping follows RFC 9114 Section 8.1 and RFC 9204 Section 4.4. A peer
  FRAME_UNEXPECTED, FRAME_ERROR, SETTINGS_ERROR, CLOSED_CRITICAL_STREAM,
  EXCESSIVE_LOAD, or QPACK failure queues exactly one matching QUIC
  application close. Internal fatal failures use H3_INTERNAL_ERROR only when
  the H3 session cannot continue.
- `Done`, incomplete varints/frames awaiting more STREAM data, backpressure,
  unknown unidirectional types and transport-owned failures never masquerade
  as peer H3 violations. Preserve TODO-1110's `H3_ID_ERROR` and
  `H3_STREAM_CREATION_ERROR` behavior without a second close path or duplicate
  code table.
- The runtime owns a bounded flush of the queued close before teardown where
  the transport is still usable. The original local cause remains observable
  even if close emission itself fails. No repeated poll may replace the first
  close code.

## Implementation and proof

- [ ] Trace every H3 `Error` producer, `Connection::poll` exit, core call site,
      transport `close`/`send` behavior, and QPACK error conversion. Classify
      each by peer/local/retryable provenance before choosing a wire code.
- [ ] Centralize the RFC H3/QPACK code mapping at the H3 boundary and make
      fatal peer input close once. Remove TODO-1110's narrow mapping only when
      the replacement has identical tested behavior for both push cases.
- [ ] Prove paired-connection wire close for one fixture per mapped class,
      including fragmented input that remains incomplete until its final
      invalid byte, duplicate/critical stream errors, invalid SETTINGS,
      malformed QPACK instructions, and both push errors. Assert decoded
      peer application error codes, not only local enum variants.
- [ ] Prove core client/server dispatch transmits the queued close under
      normal egress and preserves a stable local error when send fails. Check
      unknown stream, ordinary `Done`, QPACK flow-control deferral and
      transport failure remain free of false application closes.
- [ ] Run H3/transport and core integration tests, Clippy and formatting;
      update `docs/DOCUMENTATION.md`, `docs/MAP.md`, and this board with only
      evidence-backed runtime claims.

## Acceptance

- Every supported fatal peer H3/QPACK violation emits exactly one RFC-coded
  application close observable by the paired peer; zero retryable, partial,
  unknown-stream, or transport-owned outcomes emit an H3 close.
- Both core runtimes either transmit the close or report a named terminal
  send failure without silently claiming successful protocol closure.
