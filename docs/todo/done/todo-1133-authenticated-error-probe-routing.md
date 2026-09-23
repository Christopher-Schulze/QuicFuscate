---
id: TODO-1133
title: Keep authenticated QUIC failures out of Reality probe fallback
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1132]
---

# TODO-1133: Classify transport failures before stealth fallback

## Why and evidence

`src/core/connection.rs::deliver_wire_payload` forwards every non-TLS
`Connection::recv` error to `StealthManager::handle_fallback`, which can send
cached cover TLS material or invoke the Reality proxy. An authenticated QUIC
packet with a CRYPTO capacity, frame or protocol violation can already have
caused a local transport close. Routing that packet as an unauthenticated
probe mixes a real connection error with the probe persona and can produce
an unrelated cover response while a QUIC close is queued. This is directly
reachable after TODO-1132; the general packet-admission classification is
also tracked by TODO-1129.

## Target contract

- Forward only packets that failed before QUIC AEAD opening or explicitly
  discardable probes to the Reality fallback. Successful opening of an
  Initial packet is not peer-identity authentication because its keys are
  public. A transport error after packet opening or a local close does not
  emit cached cover material or relay traffic.
- Preserve the protected QUIC close send opportunity and original typed
  terminal cause. Avoid turning every malformed unauthenticated datagram
  into a connection teardown, which would weaken active-probe resistance.
- Use the smallest reliable classification boundary backed by the transport
  receive result and close state. If close state alone cannot distinguish all
  live authenticated errors, add one typed receive disposition at the owner;
  do not infer authentication from error enum names or duplicate packet
  parsing in Core.

## Implementation and proof

- [x] Trace Core raw/FEC receive callers, Reality cached/relay effects and
      transport error/close ownership; identify which errors are pre- and
      post-opening.
- [x] Apply one classification and routing rule across raw, recovered and
      batched receive paths without adding a second stealth policy engine.
- [x] Add real-code tests for an unauthenticated probe, an AEAD-opened
      protocol-invalid frame, a TLS terminal failure, a direct CRYPTO close
      and an accepted packet; assert fallback counts, peer-opened close and
      cached-response priority. CRYPTO is not wire-admissible in 1-RTT, so a
      protected 1-RTT CRYPTO test would only exercise frame preflight.
- [x] Run relevant transport/Core/stealth tests, default and feature library
      gates, strict Clippy and formatting; document native wire limits.

## Acceptance

- Terminal failures after packet opening never enter Reality fallback; probe
  traffic still receives only the configured cover behavior.
- The peer can receive the one correct protected QUIC close, and all
  required gates pass.

## Verification and limits

- Real paired TLS/QUIC tests show an AEAD-opened invalid `HANDSHAKE_DONE`
  frame causes zero Reality fallback calls, an unopenable 32-byte probe causes
  one, and a later protected PING causes no additional call. A real rustls
  failure closes the transport and later probe input cannot trigger fallback.
- The direct CRYPTO capacity path queues `0x0d`; Core sends that protected
  close before a prequeued cached Reality response, and the paired peer opens
  it with the exact code. The `StealthManager` call counter is test-only and
  observes the actual fallback method; no proxy network request is needed.
- Default root library: `1,872 passed, 1 ignored`; feature root library
  (`rust-tests`, `stream_ring_buffer`, `zero_copy_dgram`): `1,877 passed,
  1 ignored`. Focused Core connection tests: `82 passed` before the added
  TLS-terminal regression; that regression passed separately. Strict root
  library Clippy and workspace formatting pass. No external peer or native
  capture was run.
- A 1-RTT CRYPTO frame fails frame-space preflight before CRYPTO reassembly;
  direct application-level CRYPTO tests are defensive API coverage, not
  1-RTT wire evidence. TODO-1129 owns nonterminal post-open failures and
  pre-open error-slot pollution. TODO-1134 owns the client assignment loop's
  missed close flush before teardown; this task proves Core output, not that
  live assignment delivery.
