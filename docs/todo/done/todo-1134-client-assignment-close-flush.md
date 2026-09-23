---
id: TODO-1134
title: Flush the physical QUIC close before client assignment teardown
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1133]
---

# TODO-1134: Send the physical-hop close before assignment teardown

## Why and evidence

`src/implementations/client/io_driver/runtime.rs::negotiate_assignment`
flushes outbound traffic at the start of each iteration, then calls
`ClientDataPlane::recv_mut`. If that receive queues a terminal QUIC close,
the post-receive `is_closed()` branch formerly marked the connection failed
and returned before the next iteration's flush. Core can seal the correct close
(TODO-1133), but this live client phase may discard it without a socket send.
The standby loop flushes after receive before checking `is_closed()`; the
server's live receive handler also flushes before reconciliation. The
assignment path therefore needs its own exact runtime gate.

`ClientDataPlane::send_physical` calls `CircuitRuntime::drive()` before
`hops[0].send()`, so a physical-hop close can be blocked by unrelated circuit
work even if the assignment loop adds another ordinary flush. A nested-hop
close has different MASQUE queue and link-order obligations; TODO-1135 owns
that circuit-wide terminal path.

## Target contract

- When receive observes a terminal transport/TLS failure on the physical hop
  during assignment, attempt its pending protected QUIC close on the connected
  socket before marking the circuit failed. The terminal drain bypasses
  `CircuitRuntime::drive()` and emits no application or cover data after
  close. It is bounded to one actual close frame, one socket send, and no
  indefinite retry.
- Preserve the original typed terminal cause in the connection. Report a
  bounded close-send failure separately while still terminating assignment;
  no failure response should claim that a close reached the peer without a
  successful socket send.
- Keep valid assignment, benign no-progress receive and timeout behavior
  unchanged. Do not move the ordinary pre-receive flush or add a second
  packet-production pipeline.

## Implementation and proof

- [x] Trace `negotiate_assignment`, `ClientDataPlane::recv_physical_mut`,
      `send_physical`, `CircuitRuntime::drive`, `flush_outbound`, and the
      post-receive physical-hop terminal exit. Handle a receive `Err` that already
      closed the transport as well as an `Ok` with closed state.
- [x] Add one bounded close-drain step at the post-receive terminal branch,
      using the existing Core close serializer and connected socket send.
      Bypass circuit `drive()` only for this physical terminal branch;
      preserve the original failure as the assignment outcome.
- [x] Add a real client/server UDP loopback test where a Core CRYPTO admission
      error queues a physical close while assignment waits for inbound data.
      Assert one peer-opened protected close with the exact code before local
      teardown and no extra send after terminal drain. Prove an actual socket
      send failure is typed and retains the original local cause. TODO-1136
      owns a protected inbound CRYPTO packet that closes inside `recv_mut`,
      including its `Err` outcome and cover suppression.
- [x] Run focused client/runtime, default and feature root tests, strict
      Clippy and formatting; record platform limits and any socket failure
      evidence in this file.

## Acceptance

- The live assignment loop gives each physical-hop terminal close observed
  after receive one bounded send opportunity before failure teardown; the loopback peer
  opens the expected protected frame. Nested-hop failure remains TODO-1135.
- A failed socket send remains a reported failure, and all gates pass.

## Verification and limits

- The assignment loop now checks physical terminal state after `recv_mut`
  whether it returned `Ok` or `Err`, serializes at most one Core close through
  the physical connection without `CircuitRuntime::drive`, attempts one UDP
  send with a 500 ms timeout, and only then marks the data plane failed.
- A real localhost UDP peer decrypted the `0x0d` close queued by genuine
  `process_crypto_frame` capacity rejection while assignment waited at
  `recv_mut`; no additional socket output arrived within 30 ms after the task returned.
  A separate unconnected-socket test proved `TransportSend` on the UDP stage
  and retained `CryptoBufferExceeded` as the Core local cause.
- Focused `physical_close_`: 2 passed. Default root library: 1,874 passed,
  1 ignored. Feature root library (`rust-tests,stream_ring_buffer,zero_copy_dgram`):
  1,879 passed, 1 ignored. Strict root library Clippy, formatting and diff
  checks passed on macOS. Linux/Windows live-socket behavior is not claimed.
- The loopback failure is queued by direct CRYPTO admission rather than a
  protected inbound peer packet; the actual protected-input wire gate and
  cover suppression remain TODO-1136. Nested-hop terminal relay
  remains TODO-1135. Other early assignment exits that may acquire a queued
  close remain TODO-1137. These limits do not change the post-receive physical
  close contract.
