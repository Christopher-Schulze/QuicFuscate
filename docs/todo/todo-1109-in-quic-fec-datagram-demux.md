---
id: TODO-1109
title: Demultiplex in-QUIC FEC without stealing application DATAGRAMs
severity: MED
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1046, TODO-1106]
---

# TODO-1109: Collision-free QUIC DATAGRAM ownership

## Why and evidence

`crates/qf-fec/src/wire.rs` declares the private in-QUIC repair
discriminator `0xFE`. In QuicFrame mode,
`src/core/connection.rs::absorb_quic_fec_datagrams` calls
`Connection::drain_prefixed_datagrams(0xFE)` before any FEC parsing. The
transport method removes every matching entry from the general DATAGRAM
receive queue, regardless of whether it is a valid repair, repair ACK or
another application payload. A malformed match is then silently skipped.
The H3/MASQUE consumer drains that same queue later. A generic raw QUIC
DATAGRAM beginning with `0xFE` is valid application data and is lost; an
eight-byte H3 flow-ID varint may also start with `0xFE`, though no current
normal-sized MASQUE flow has been shown to collide. The current first-byte
convention is not a negotiated, disjoint payload namespace.

`drain_prefixed_datagrams` also scans and rebuilds the entire queue on each
FEC poll; the zero-copy configuration copies every matched repair payload
into a new vector. These costs are unnecessary if the owner is identified
at admission. This is a source-level compatibility/performance finding;
the affected raw DATAGRAM product path and frequency require tests.

## Target contract

- Define one negotiated wire owner for in-QUIC FEC that is disjoint from
  generic QUIC DATAGRAM and H3 DATAGRAM/MASQUE contexts. A peer without
  that capability must not emit or accept the FEC encoding as a silent raw
  application packet. Version any encoding change with a bounded migration
  rule; no permanent parallel FEC implementation.
- At receive admission, route each authenticated DATAGRAM exactly once to
  FEC, H3/MASQUE or the generic application queue using a validated context
  and connection capability. An invalid FEC frame is counted and rejected
  as FEC only after it has been unambiguously assigned to FEC; it never
  consumes a legitimate application payload by prefix coincidence.
- Preserve RFC QUIC DATAGRAM semantics, negotiated H3 flow identifiers,
  repair ACK handling, queue/memory bounds and the TODO-1106 epoch fence.
  Avoid rebuilding the complete receive queue on each poll; retain pooled
  buffer ownership where the existing transport supports it.

## Implementation and proof

- [ ] Inventory every DATAGRAM producer/consumer and negotiated ALPN/H3
      context: raw transport API, MASQUE CONNECT flow-ID encoding, FEC
      repair/ACK, zero-copy queue, recovery tests and external integrations.
      Determine the smallest existing demux boundary and a versioned
      capability signal before changing wire bytes.
- [ ] Implement one disjoint owner/context contract and route on validated
      admission. Remove first-byte queue draining and its repeated full scan;
      preserve the existing decoder and exact recovery behavior. Propagate
      the encoding/capability change to both sender and receiver atomically.
- [ ] Add failable tests with FEC enabled for raw DATAGRAMs starting
      `0xFE`, truncated/invalid FEC, valid repair, repair ACK, coalesced
      receive, MASQUE flow-ID boundary values and mixed queue order. Assert
      exactly-once delivery, no unexpected drop, counters and zero-copy
      ownership. Test capability mismatch and rolling-upgrade disposition.
- [ ] Run a real impaired-link FEC/MASQUE exchange and profile queue scan,
      copy and allocation counts against the prior path. Update TODO-1046
      and protocol documentation with the negotiated wire format and limits.

## Acceptance

- FEC, H3/MASQUE and generic DATAGRAM payloads coexist without prefix
  collision; every authenticated payload reaches exactly one declared
  owner or a named invalid-frame counter. A raw `0xFE` application payload
  is delivered intact under active FEC.
- No full receive-queue rebuild per FEC poll and no new payload copy in the
  pooled receive path without a measured, documented necessity. Loss/
  reordering recovery and repair ACK tests remain green.
