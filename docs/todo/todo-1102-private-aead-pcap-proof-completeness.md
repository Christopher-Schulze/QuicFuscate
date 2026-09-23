---
id: TODO-1102
title: Make private-AEAD pcap proof complete and fail closed
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1029, TODO-1095, TODO-1099]
---

# TODO-1102: Private-AEAD capture proof completeness

## Why and evidence

`src/bin/qf-aead-wire-proof.rs` is the claimed TODO-1029 packet-capture
verifier. `read_pcap` stops on a truncated record without an error;
`parse_frame` returns `None` for unsupported link types/non-UDP frames and
can index `ip[0]` or IPv4 `ip[9]` before checking their length.
`analyze_datagram` returns without accounting for malformed long headers,
Version Negotiation, Retry, unsupported versions and all 0-RTT packets.
`Report::finish` needs only a positive combined Initial/Handshake count and
some 1-RTT packets, so an incomplete or selectively skipped capture can
report PASS. Its keylog map uses the TLS label alone, ignoring client random,
and direction is guessed solely from source port. That is insufficient when
the capture or keylog contains multiple connections or unrelated UDP.

The standard key-update branch re-parses `pnl` under an updated HP key and
constructs AAD with that length, but calls AEAD open on `body` sliced using
the earlier `pn_len`. A legitimate key update whose PN length differs can
be reported unopenable. The code describes trial sweeps as "exhaustive"
while bounding them to selected epochs/PN candidates; this is a diagnostic
search, not exhaustive proof. TODO-1095 separately owns the absent RFC QUIC
Length field which the analyzer currently accommodates as a private format.

## Target contract

- Define an exact capture scope: one named connection/tuple, peer roles,
  client random, QUIC version, packet-number spaces and expected lifecycle.
  Parse keylog secrets by `(label, client_random)` and bind them to the
  captured handshake; bind TODO-1099's role-separated private material to
  the same connection. Ambiguous or missing identity fails.
- Every in-scope UDP record is either counted as a successfully classified
  QUIC packet or produces a named failure. Track and report captured
  datagrams, individual QUIC packets, opened Initial, Handshake, 0-RTT,
  standard 1-RTT, private 1-RTT, VN, Retry, malformed, truncated, unsupported
  and unrelated records separately. Out-of-scope traffic is excluded only
  by a declared capture filter or an explicit counted rule, never by an
  unreported `None`/`return`.
- Distinguish traffic that is intentionally outside the AEAD-owner claim
  (VN, Retry) from unexpected missing coverage; validate its RFC shape and
  count it. If 0-RTT is enabled, authenticate it with the standard early-data
  key or fail the proof as unsupported; if disabled, observed 0-RTT fails.
  Require both directions and the expected Initial, Handshake, pre-boundary
  and post-boundary classes for a private run; require both directions and
  zero private packets for the control. Do not claim a class absent from
  the capture.
- Use TODO-1095's RFC packet boundaries, and compare framing with an
  independent standards parser. Validate pcap record lengths, IP header
  lengths and UDP length against actual bytes before indexing or slicing;
  reject unsupported link types with an actionable error. Handle or reject
  IP fragments/IPv6 extension chains explicitly. Do not silently truncate.
- Recompute the payload offset when a candidate HP key changes PN length.
  Bound diagnostic trial work, label it as a search, and leave normal owner
  classification based on authenticated packet opens and negotiated boundary.

## Implementation and proof

- [ ] Inventory capture command/filter, pcap format, keylog concatenation,
      private dump, packet constructors and expected counts in both TODO-1029
      runs. Check multi-connection and GSO/GRO behavior in the same path.
- [ ] Make pcap, IP/UDP and RFC QUIC parsing return typed outcomes with
      packet/record counters. Eliminate silent skips and panicable short-frame
      indices. Bind secrets and private records to the selected handshake.
- [ ] Correct updated-HP PN/body parsing and state progression; prove with
      a real packet capture crossing a key update and a changed PN length.
- [ ] Add failable fixtures for truncated pcap record, short IPv4/IPv6,
      unsupported link type, unrelated UDP, VN, Retry, 0-RTT, absent
      Handshake, absent direction, missing post-boundary traffic, mixed
      keylogs, duplicate role records, and valid private/control runs.
- [ ] Rerun TODO-1029's two capture cases after TODO-1095 and TODO-1099,
      report observed/analyzed/skipped counts, and correct its detail and
      product docs. Do not preserve a previous PASS label without reproof.

## Acceptance

- 100% of in-scope captured datagrams and their packets have explicit,
  counted dispositions; zero silent parser skips or panics on malformed
  input. A missing required packet class, role or matched keylog fails.
- Both private and standard control proofs pass using RFC-framed packets,
  role-bound secrets and independently checked capture counts. A key update
  with a changed PN length is classified correctly.
