# TODO-979 - TLS cover jitter: deferred emission instead of thread::sleep

Status: DONE (local tests; deadline plumbing shared with the startup fix)

## Problem

`TlsCoverProvider::generate_fake_crypto_frame` ended with
`std::thread::sleep(plan.jitter)` for timing-channel mitigation when
`QUICFUSCATE_STEALTH_JITTER_US` is set. The comment claimed the path ran
"on a dedicated sync path, NOT inside an async task" - wrong:
`next_crypto_frame` is invoked inside `conn.send()`, which the standalone
and io_driver runtimes call from `tokio::select!` branches and flush
loops. A blocking sleep there stalls the entire runtime worker: socket
reads, housekeeping, timers and pacing deadlines all freeze for the
jitter window (and per cover frame, not per datagram).

## Fix

`src/qftls/tls_cover_provider.rs`:

- The provider now owns the shared `ProtocolClock`, a
  `cover_ready_at: Option<Instant>` deadline, and a
  `pending_cover_frame: Option<Vec<u8>>` holding the already-encrypted
  record.
- A jittered plan stores the finished frame and arms
  `cover_ready_at = clock.now() + jitter` instead of sleeping; the call
  returns no frame (the established `Ok(0)` "nothing ready" contract).
- `next_crypto_frame` releases the held frame once the window elapses.
  Post-handshake completion drops a held frame and disarms the deadline.
- New `handshake_send_ready_at()` accessor mirrors the rustls provider's
  readiness contract (elapsed windows report `None`).
- `CombinedProvider::handshake_send_ready_at` merges rustls and cover
  deadlines (earliest unblock), so `next_send_deadline()` wakes the
  runtime exactly when the deferred frame becomes emittable.

Semantics improve on the original intent: the wire now sees the cover
record emitted at the jittered instant in its own datagram flow instead
of stalling every other scheduled send - better timing decorrelation
with zero worker blocking.

## Proof

- `cargo test --lib qftls`: 35/35, incl. new regression
  `tls_cover_jitter_defers_frame_and_surfaces_deadline` (manual clock:
  frame held, deadline surfaced, emitted after `advance`).
- `cargo clippy --all-targets`: clean, fmt clean.
- Commit: pending.
