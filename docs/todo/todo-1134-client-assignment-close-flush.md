---
id: TODO-1134
title: Flush a terminal QUIC close before client assignment teardown
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1133]
---

# TODO-1134: Preserve the client assignment close send opportunity

## Why and evidence

`src/implementations/client/io_driver/runtime.rs::negotiate_assignment`
flushes outbound traffic at the start of each iteration, then calls
`ClientDataPlane::recv_mut`. If that receive queues a terminal QUIC close,
the `is_closed()` branch around line 529 marks the connection failed and
returns before the next iteration's flush. Core can seal the correct close
(TODO-1133), but this live client phase may discard it without a socket send.
The standby loop flushes after receive before checking `is_closed()`; the
server's live receive handler also flushes before reconciliation. The
assignment path therefore needs its own exact runtime gate.

## Target contract

- After an inbound terminal transport/TLS failure during assignment, attempt
  the one pending protected QUIC close on the same socket and selected path
  before marking the circuit failed. Do not emit queued application or cover
  data after close, retry indefinitely, or hide a socket-send failure.
- Preserve the original typed terminal cause in the connection. Report a
  bounded close-send failure separately while still terminating assignment;
  no failure response should claim that a close reached the peer without a
  successful socket send.
- Keep valid assignment, benign no-progress receive and timeout behavior
  unchanged. Do not move the ordinary pre-receive flush or add a second
  packet-production pipeline.

## Implementation and proof

- [ ] Trace `negotiate_assignment`, `ClientDataPlane::send_physical`,
      `CircuitRuntime::drive`, `flush_outbound` and all assignment exit paths;
      determine whether `drive()` permits terminal close emission and whether
      a direct transport-close drain is needed.
- [ ] Add one bounded close-drain step at the post-receive terminal branch,
      using the existing socket/path send primitive and respecting the
      `Connection::send` one-close contract. Keep the original terminal
      failure as the assignment outcome.
- [ ] Add a real client/server UDP loopback test where an inbound protected
      protocol or TLS failure queues a close during assignment. Assert one
      peer-opened close with the exact code before local teardown, no cached
      cover reply, no extra send after terminal drain, and unchanged success
      and benign-probe paths.
- [ ] Run focused client/runtime, default and feature root tests, strict
      Clippy and formatting; record platform limits and any socket failure
      evidence in this file.

## Acceptance

- The live assignment loop gives every locally queued terminal close exactly
  one bounded send opportunity before failure teardown, and the loopback
  peer opens the expected protected frame.
- A failed socket send remains a reported failure, and all gates pass.
