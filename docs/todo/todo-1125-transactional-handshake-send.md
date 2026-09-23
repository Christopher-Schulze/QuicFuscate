---
id: TODO-1125
title: Commit Initial and Handshake send obligations only after packet protection
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1124, TODO-1126]
---

# TODO-1125: Make Initial and Handshake sends transactional

## Why and evidence

`src/transport/connection/send.rs` removes an Initial or Handshake CRYPTO range
through `next_crypto_frame`, removes the matching PTO probe from
`pending_probe_spaces`, and commits its ACK before `encrypt_and_protect` returns.
The adjacent TODO-1124 key preflight prevents these mutations when an AEAD or
HP key is absent, but cannot prevent an AEAD error, HP `new_mask` error,
insufficient final packet capacity, or a serialization failure after those
mutations. `CryptoStream::next_crypto_frame` also advances fresh offsets and
retains data as if sent, or consumes a retransmit queue entry. A failed send
must not silently turn these obligations into sent work. Existing TODO-694
only protects ACKs from frame capacity and serialization errors; TODO-1112
covers application-space obligations, not Initial/Handshake.

## Target contract

- Stage Initial/Handshake fresh and retransmitted CRYPTO byte ranges without
  advancing the stream offset, changing `send_buf`, splitting retained ranges,
  consuming `retx`, or evicting retained bytes. Preserve byte-for-byte FIFO and
  the bounded retention policy from TODO-1126. Commit the exact selected range
  once only after AEAD and HP succeed.
- Stage ACK and PTO probe decisions without clearing either before the packet
  is sealed. An ACK-only send remains eligible after any failure; a failed
  probe still produces an ack-eliciting packet on retry. Move sent/recovery
  accounting and PN advancement after the same seal boundary.
- Validate packet size and expected frame lengths before source mutation.
  Treat a post-seal accounting failure as impossible by checked preflight or
  preserve a recoverable sealed-packet owner. The TLS provider and the local
  `CryptoStream` must obey the same ownership contract; no test-only fallback.
- A retry after a failed seal emits exactly one valid Initial/Handshake packet
  carrying the original CRYPTO range, ACK and/or probe. A peer decrypts it and
  the recovery map has exactly one corresponding sent record.

## Implementation and proof

- [ ] Trace `Connection::next_crypto_frame`, TLS provider
      `next_crypto_frame`/`requeue_all_crypto`, and `CryptoStream` fresh/retx
      branches; identify a common non-consuming selection and commit contract.
- [ ] Rework Initial/Handshake assembly in `send_with_datagram_overhead` so
      CRYPTO, ACK and probe ownership transfers after `encrypt_and_protect`.
      Keep Initial 1200-byte padding, ACK-only congestion treatment, and
      recovery metadata intact.
- [ ] Add failable tests for missing capacity, AEAD failure, HP mask failure,
      fresh and retransmitted CRYPTO, ACK-only packet and PTO probe, for both
      packet spaces and both TLS-provider/local-stream sources where reachable.
      Assert unchanged queues/offsets/counters after error, exact peer-opened
      retry bytes, and one recovery entry.
- [ ] Run focused transport tests, default and relevant feature-mode library
      tests, strict library Clippy and formatting; update owning architecture
      and task documentation with exact results.

## Acceptance

- No Initial/Handshake send obligation is committed before a fully protected
  packet exists, including every error branch after frame selection.
- Failed attempts do not create phantom CRYPTO retention, ACK/probe loss, PN
  advancement, or sent/recovery accounting; a successful retry is peer-opened
  once with the original obligations.
- Default and relevant feature-mode tests and required gates pass with counts
  and remaining platform limits recorded.
