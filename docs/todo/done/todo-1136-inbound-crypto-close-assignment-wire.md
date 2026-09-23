---
id: TODO-1136
title: Prove assignment close on protected inbound CRYPTO failure
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1134]
---

# TODO-1136: Prove the inbound CRYPTO failure to assignment-close wire path

## Why and evidence

TODO-1134 proves that a physical Core close queued while the assignment loop
waits reaches a real UDP peer exactly once, and that a failed socket send is
reported. Its loopback test invokes the genuine CRYPTO receive-window admission
function directly and wakes `recv_mut` with a probe. It does not prove that a
peer's protected CRYPTO frame closes the physical connection during
`recv_mut`, nor that a queued Reality cover reply stays behind the close on
this live path. `Core::deliver_wire_payload` intentionally converts a
transport `Err` with an already-closed connection into `Ok`, retaining the
typed cause in `conn.local_error()`. The assignment loop must inspect closed
state after either receive result; an `Err` is not expected for this specific
frame. TODO-1129 separately owns packet
number and ACK admission after a fallible frame handler.

## Target contract

- Establish a real client/server QUIC/TLS pair with connected UDP sockets and
  keep the client inside `IoDriver::negotiate_assignment` before receiving an
  authenticated assignment. Send an AEAD-protected application CRYPTO frame
  with offset 65,536 and a nonempty payload to the client. The bounded CRYPTO
  receive window must reject it with `CryptoBufferExceeded` and queue exactly
  one transport close with code `0x0d`.
- The assignment loop must recognize terminal state regardless of
  `ClientDataPlane::recv_mut`'s result, use the physical close serializer
  without circuit drive, send the close on the same UDP socket, preserve the
  original typed Core cause, and fail assignment. The server must decrypt the
  close. A queued cover response must not replace or follow it.
- Keep benign unopenable probes nonterminal and keep a valid assignment path
  unchanged. Do not add production test hooks, parallel packet builders, or
  synthetic success signals merely to satisfy this gate.

## Implementation and proof

- [x] Reuse the existing paired TLS test setup and live assignment loop;
      identify the smallest fixture seam that keeps actual Core packet
      protection and socket I/O. Confirm frame construction signatures and
      QUIC encryption level before using them.
- [x] Send the protected out-of-window CRYPTO frame through the peer socket,
      observe the actual Core receive result and closed-state branch, and assert the local cause,
      one peer-opened `0x0d` close, no cover reply, and no later UDP output.
- [x] Run the existing Core benign-probe distinction and control-plane
      successful-assignment reception regressions. The full live successful
      assignment path lacks its own E2E fixture and is tracked by TODO-1138.
- [x] Run focused assignment/Core tests, default and feature root tests,
      strict library Clippy, formatting, and diff hygiene.

## Acceptance

- An actual peer-protected CRYPTO failure reaches assignment's terminal
  branch and produces exactly one peer-opened close without cover leak.
- The existing assignment-reception and benign-probe regressions pass, and all
  required gates pass. Full live successful-assignment proof is TODO-1138.

## Verified finding and implementation

- The constructor-based real UDP/TLS fixture completed both handshakes and
  kept assignment waiting. An AEAD-protected 1-RTT CRYPTO packet then left
  the client open until assignment timeout. A fresh protected packet delivered
  directly to Core also returned without a local cause, isolating the failure
  from UDP scheduling.
- `crates/qf-transport-frames/src/lib.rs::frame_type_allowed` wrongly excluded
  frame type `0x06` from 1-RTT. The adjacent packet-space test encoded this
  incorrect expectation, and `docs/DOCUMENTATION.md` repeated it. RFC 9000
  Table 3 permits CRYPTO in Initial, Handshake, and 1-RTT, but not 0-RTT.
  The parser now admits `0x06` in 1-RTT; the packet-space test and canonical
  documentation match the standard.
- The loopback test now observes the local `CryptoBufferExceeded` cause and
  the server opening one protected `0x0d` close. The Reality cached response
  remains queued, no fallback is invoked, and no later UDP output appears in
  the bounded observation window. Core intentionally returns `Ok` after a
  closed transport receive; the assignment loop checks physical closed state.
- Focused frame-leaf suite: 21 passed. Focused Core probe distinction: 1
  passed. Physical assignment close tests: 2 passed. New inbound wire test:
  1 passed. Control-plane successful reception: 1 passed. Default root library:
  1,875 passed, 1 ignored. Feature root library (`rust-tests`,
  `stream_ring_buffer`, `zero_copy_dgram`): 1,880 passed, 1 ignored. Strict root
  library Clippy, formatting, and diff hygiene pass on macOS. Linux and
  Windows live-socket behavior remains unclaimed.

## Deviations

- The original checklist asked for a real successful-assignment runtime gate
  alongside this terminal-path proof. No such reusable live fixture exists;
  the control-plane reception test only proves its own boundary. TODO-1138
  owns the distinct full-path fixture so this terminal bug fix remains bounded.
