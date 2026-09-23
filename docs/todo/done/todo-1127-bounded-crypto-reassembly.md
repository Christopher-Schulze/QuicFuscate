---
id: TODO-1127
title: Bound and normalize inbound QUIC CRYPTO reassembly
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1126]
---

# TODO-1127: Enforce a receive-offset-based CRYPTO reassembly window

## Why and evidence

`crates/qf-transport-crypto-stream/src/lib.rs::CryptoStream::recv` checks an
incoming range against `recv_max + 65,536`, then raises `recv_max` to the new
highest offset. A peer can leave an early gap open and send successively
higher ranges within 65,536 bytes of each prior maximum, so `recv_buf` grows
without a fixed bound. `read` drains only an entry whose start equals
`recv_off`, and `recv` does not trim bytes below `recv_off` or merge overlapping
ranges. Reordered retransmissions can leave stale or overlapping entries
retained indefinitely. `Connection::process_crypto_frame` uses this same leaf
receive buffer before passing contiguous bytes to the real TLS provider, so
the memory exposure is product-reachable before handshake authentication.

## Target contract

- Anchor a finite receive window to the next unread offset, not the highest
  observed offset. The initial target is 64 KiB of future CRYPTO sequence
  space per encryption level, matching the existing nominal window. Reject
  ranges extending beyond `recv_off + 65,536` with a typed transport error
  before allocation or state change. Advance the window only as contiguous
  bytes are delivered to TLS.
- Bound retained unique bytes and interval count independently. Normalize
  duplicates and partial overlaps: trim bytes already delivered, merge
  identical overlaps, and reject conflicting bytes without changing existing
  state. Maintain deterministic contiguous drain and exact offsets across
  reordered frames, duplicate retransmissions and partial reads.
- Apply the same validated contract to Initial, Handshake and application
  CRYPTO levels in both provider-backed and transport-local paths. Reassembly
  admission rejection must not advance TLS or CRYPTO buffer state; valid
  large handshake flights proceed through repeated bounded drains.
  Packet-number, multi-frame and TLS-provider failure atomicity are owned by
  TODO-1129.

## Implementation and proof

- [x] Inventory `Connection::process_crypto_frame`, `CryptoStream::recv/read`,
      provider `provide_quic_data`, all reset paths, and existing receive
      limits; validate 64 KiB window and interval cap against actual profile
      and certificate-chain handshakes.
- [x] Replace `recv_max`-relative admission with checked `recv_off`-relative
      range validation and explicit retained-byte/interval accounting. Use a
      single canonical interval store with overlap normalization; no parallel
      receive implementation.
- [x] Add failable tests for stepped-gap memory amplification, edge/exceeded
      window, exact duplicates, equal/conflicting partial overlaps, stale
      retransmissions, fragmented contiguous release, reset, and all levels.
      Include a real TLS-provider handshake with reordered CRYPTO frames and
      assert exact completion without unbounded memory.
- [x] Run leaf, transport, default/feature library, strict Clippy and
      formatting gates; record the TODO-1129 packet-admission limit explicitly
      and update owning docs with exact evidence.

## Acceptance

- For every accepted frame, unread future sequence space is at most 65,536
  bytes from `recv_off`; retained bytes and interval count have enforced
  finite caps independent of the total handshake length or packet count.
- Duplicate/reordered bytes are byte-exact and do not accumulate stale
  entries; conflicting overlap and out-of-window input fail atomically.
- Real Initial/Handshake TLS completion, loss/reorder tests, and required
  gates pass with counts and native limits recorded.

## Investigation record

- The product provider-backed `Connection::process_crypto_frame` inserts every
  CRYPTO frame into the same `CryptoStream` and drains contiguous chunks into
  rustls. The transport-local fallback also uses this leaf type. The current
  `recv_max` admission permits stepped-gap growth; `read` only matches an
  exact start offset, so stale or overlapping entries can remain indefinitely.
- The bounded design uses `recv_off + 65,536` as the inclusive end limit,
  at most 65,536 unique retained bytes, and at most 1,024 disjoint intervals
  per encryption level. Admission validates identical overlapping bytes
  before mutating the map; already-delivered prefixes are discarded. Adjacent
  ranges merge into the same canonical interval. Duplicate frames wholly
  covered by one retained interval return without reallocation.
- `recv.rs` records the packet number before stateful CRYPTO processing.
  TODO-1129 owns whole-packet preflight and commit so this leaf change can
  keep its own rejection atomic without claiming packet-level atomicity.
- Local macOS proof: qf-transport-crypto-stream `10/10`; default root library
  `1,865 passed, 1 ignored`; feature root library (`rust-tests`,
  `stream_ring_buffer`, `zero_copy_dgram`) `1,870 passed, 1 ignored`.
  A real rustls ClientHello and server Handshake flight were independently
  fragmented and reordered through the bounded CRYPTO store; the completed
  client/server handshake test passed in default and feature configurations.
  Strict leaf/root library Clippy, formatting and diff hygiene pass. No
  independent native peer/wire capture was run for this memory-safety change.
- The additional strict `--tests` Clippy probe fails at two unchanged test
  expressions in `src/brain.rs:868` (`manual_is_multiple_of`) and
  `src/stealth/manager/coverage_tests.rs:183` (`identity_op`). Both, plus a
  third all-target lint, are already owned by TODO-1079. This probe does not
  invalidate the passing library Clippy gate or the executed tests.
