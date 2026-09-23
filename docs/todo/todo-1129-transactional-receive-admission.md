---
id: TODO-1129
title: Commit QUIC receive state only after stateful frame admission
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1127]
---

# TODO-1129: Commit receive effects only for fully processed packets

## Why and evidence

`src/transport/connection/recv.rs` performs stateless frame syntax preflight
around line 305 and calls `pkt_spaces[space_idx].on_packet_recv` around line
371 before dispatching frames. A CRYPTO frame reaches the stateful
`Connection::process_crypto_frame` around line 685; its bounded reassembly can
reject an authenticated but out-of-window or conflicting range after the
packet number was recorded. TLS-provider rejection after CRYPTO drain and
other fallible frame handlers after the same boundary require an inventory.
A rejected packet can therefore change duplicate-detection, ACK, key,
recovery or earlier-frame state despite the receive call returning an error.
TODO-1127 fixes the CRYPTO buffer itself; TODO-1132 closes capacity and
overlap failures but does not fix premature packet-number admission.
Pre-open AEAD/HP failures also call `record_local_error` in `recv.rs` even
though Core treats their datagrams as possible probes and keeps the connection
live. This can leave a transient forged-packet error in the first-wins local
root-cause slot. Remove that terminal-state pollution without losing typed
diagnostics or the authenticated close path.

RFC 9000 Sections 7.5 and 13.1 require a handshake CRYPTO buffer overflow
to close with `CRYPTO_BUFFER_EXCEEDED` and forbid acknowledging a packet until
all its frames are processed. Section 11.1 permits discarding an invalid
Initial only if no frame effects are applied or those effects are reverted.
After the handshake, a discarded CRYPTO frame requires an ACK; this project
chooses the simpler permitted connection close for buffer exhaustion. A
terminal TLS or transport error does not require a whole-connection clone and
rollback before close, but cannot be treated as a recoverable probe failure.
Because Initial secrets are publicly derivable, Section 11.1 also permits an
invalid Initial to be discarded to reduce spoofed-close denial of service.
TODO-1132 uses the standards-permitted close for the immediate capacity bug;
this task must evaluate a strictly effect-free Initial discard before changing
that policy, including packet-number, TLS, path and stealth state.

## Target contract

- For every packet the implementation continues to process, validate all
  recoverable stateful admission before irreversible frame effects. A packet
  deliberately discarded after decryption changes no packet-number, ACK,
  recovery, TLS, stream, control, replay or connection state beyond bounded
  rejection telemetry. An invalid Initial can be discarded only under this
  rule; otherwise it takes a correctly coded terminal close path.
- Fatal TLS, CRYPTO or transport violations close once with the applicable
  QUIC error code. They need no speculative clone of TLS or the entire
  connection, but must not publish partial application delivery or be routed
  through the stealth probe fallback. TODO-1132/1133 own the immediate CRYPTO
  close and Core fallback seams.
- Preserve QUIC duplicate/replay semantics and private-key epoch commits.
  Packet number becomes ACK-eligible once only after every frame is processed
  or an RFC-permitted frame-discard policy explicitly requires an ACK; this
  project closes rather than discards exhausted CRYPTO. Accepted multi-frame
  packets apply effects exactly once in wire order.
- Pre-open probe rejection must not occupy the terminal local-error slot or
  alter packet keys, packet-number history, TLS state, or application delivery;
  bounded diagnostic telemetry may record it.
- Keep preflight bounded by packet size and encryption level. Do not clone
  whole connections, invoke TLS twice, or create a second frame parser with
  divergent semantics. Share parsed frame metadata or stage irreversible
  effects behind one commit boundary.

## Implementation and proof

- [ ] Inventory every `?`, early return and state mutation between frame
      preflight and final receive accounting in `recv.rs`, including CRYPTO,
      TLS-provider, STREAM, ACK, RESET_STREAM, CID, PATH and close frames.
      Identify which checks are pure and which effects require staging.
- [ ] Classify each post-preflight failure as discardable, terminal, or
      locally recoverable under RFC 9000/9001. Define one bounded per-packet
      admission/commit boundary for continuing packets, including CRYPTO
      window/overlap validation before `on_packet_recv`; stage or preflight
      other fallible handlers without duplicating parser rules or TLS work.
      Compare close versus effect-free discard for spoofable Initials under
      active-probe and denial-of-service tests.
- [ ] Add failable tests for a valid leading frame followed by recoverably
      discarded or terminal CRYPTO, conflicting overlap, stream limit,
      malformed control and mixed packet-space frames. Assert exact
      PN/ACK/recovery/TLS/queue snapshots for continuing packets, correct
      close state for terminal packets, and one peer-visible effect after a
      valid retry only when retry is permitted.
- [ ] Run default/feature library tests, targeted integration, strict Clippy,
      formatting and relevant native wire gates; document exact evidence.

## Acceptance

- A packet that remains on a live connection is not ACK-eligible before all
  frames are processed. Discarded packets have no frame effects; terminal
  packets close with the correct code and expose no partial application data.
- Duplicate detection and recovery are unchanged for accepted packets; tests
  prove exact failure atomicity and successful single application.
- Required gates pass with counts and native limits recorded.
