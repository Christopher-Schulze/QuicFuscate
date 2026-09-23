---
id: TODO-1136
title: Prove assignment close on protected inbound CRYPTO failure
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1134]
---

# TODO-1136: Prove the inbound CRYPTO failure to assignment-close wire path

## Why and evidence

TODO-1134 proves that a physical Core close queued while the assignment loop
waits reaches a real UDP peer exactly once, and that a failed socket send is
reported. Its loopback test invokes the genuine CRYPTO receive-window admission
function directly and wakes `recv_mut` with a probe. It does not prove that a
peer's protected CRYPTO frame causes `recv_mut` to return `Err` with the
physical connection already terminal, nor that a queued Reality cover reply
stays behind the close on this live path. The code handles that branch, but
the end-to-end evidence is still missing. TODO-1129 separately owns packet
number and ACK admission after a fallible frame handler.

## Target contract

- Establish a real client/server QUIC/TLS pair with connected UDP sockets and
  keep the client inside `IoDriver::negotiate_assignment` before receiving an
  authenticated assignment. Send an AEAD-protected application CRYPTO frame
  with offset 65,536 and a nonempty payload to the client. The bounded CRYPTO
  receive window must reject it with `CryptoBufferExceeded` and queue exactly
  one transport close with code `0x0d`.
- The assignment loop must recognize terminal state even when
  `ClientDataPlane::recv_mut` returns `Err`, use the physical close serializer
  without circuit drive, send the close on the same UDP socket, preserve the
  original typed Core cause, and fail assignment. The server must decrypt the
  close. A queued cover response must not replace or follow it.
- Keep benign unopenable probes nonterminal and keep a valid assignment path
  unchanged. Do not add production test hooks, parallel packet builders, or
  synthetic success signals merely to satisfy this gate.

## Implementation and proof

- [ ] Reuse the existing paired TLS test setup and live assignment loop;
      identify the smallest fixture seam that keeps actual Core packet
      protection and socket I/O. Confirm frame construction signatures and
      QUIC encryption level before using them.
- [ ] Send the protected out-of-window CRYPTO frame through the peer socket,
      observe the `Err` plus closed-state branch, and assert the local cause,
      one peer-opened `0x0d` close, no cover reply, and no later UDP output.
- [ ] Run a benign-probe and successful-assignment regression gate with the
      same real path or point to existing focused tests that exercise those
      exact behaviors. Record any native-platform limit explicitly.
- [ ] Run focused assignment/Core tests, default and feature root tests,
      strict library Clippy, formatting, and diff hygiene.

## Acceptance

- An actual peer-protected CRYPTO failure reaches assignment's terminal
  `Err` branch and produces exactly one peer-opened close without cover leak.
- No real assignment or benign-probe regression, and all required gates pass.
