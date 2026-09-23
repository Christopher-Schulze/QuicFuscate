---
id: TODO-1124
title: Reject missing QUIC packet sealers instead of reporting header-only success
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1121]
---

# TODO-1124: Fail closed at the packet-encryption key boundary

## Why and evidence

`src/transport/packet.rs::encrypt_and_protect` returns `Ok(hdr_len)` when the
selected Initial, Handshake, 0-RTT or 1-RTT AEAD sealer is absent. It also
returns `Ok(hdr_len)` for unsupported packet types. The same file's
`protect_header` returns `Ok(())` when the selected HP key is absent or the
packet type is unsupported. The three current connection callers in
`src/transport/connection/send.rs` treat every `Ok` as
a successfully protected packet and can advance packet numbers, counters and
send ownership. TODO-1121 guards provider-less product 1-RTT admission, but
does not change this public packet primitive or prove the other levels cannot
reach the no-key branch. This is a source-level fail-open finding, not proof
that a current deployment emits a header-only datagram.

## Target contract

- A request to protect an Initial, Handshake, 0-RTT or 1-RTT packet without
  the selected AEAD sealer returns a typed error before reporting packet
  length or committing caller-owned packet-number and send state. Missing
  header-protection keys also fail closed; no `Ok` denotes a header-only or
  plaintext substitute for an authenticated QUIC packet.
- Unsupported packet types return a typed invalid-packet error. Keep valid
  version-negotiation and Retry serialization on their separate explicit
  unencrypted paths; never route them through this protection function.
- The product send paths preserve queued CRYPTO, close, ACK, and replay-safe
  STREAM obligations across a no-key error. Key restoration allows exactly
  one valid peer-opened retry without packet-number reuse or phantom sent
  counters. Existing private 1-RTT selection and key-update boundaries stay
  unchanged except where a missing selected sealer must fail closed.

## Implementation and proof

- [x] Inventory the three direct callers, all packet-type branches, TLS key
      installation/removal windows, and any tests or helpers relying on
      `Ok(hdr_len)` as a no-op. Classify which missing-key states are normally
      unreachable and which can occur after teardown or failed setup.
- [x] Replace every no-sealer and unsupported-type success branch in
      `encrypt_and_protect` with a typed error. Preserve the existing AEAD,
      header-protection and short-header private-owner contracts.
- [x] Add failable primitive tests for each packet type with absent sealer and
      absent HP key. Add real connection send/retry tests for reachable
      Initial, Handshake and replay-safe 0-RTT ownership boundaries; assert
      byte-for-byte queued payload, packet-number and sent-counter invariants
      before retry and exactly one peer-opened packet afterward.
- [x] Run focused transport tests, the root library gate, strict library
      Clippy and formatting; update `docs/DOCUMENTATION.md`, `docs/MAP.md`
      and this task record with actual proof and remaining limits.

## Acceptance

- `encrypt_and_protect` has no successful missing-key or unsupported-type
  branch. An `Ok` always reports a fully protected packet length.
- No current caller commits send state or exposes header-only output after a
  missing-key failure; valid retries decrypt at the peer exactly once.
- Default and relevant feature-mode tests plus the required library gates
  pass with exact counts recorded.

## Investigation record

- `encrypt_and_protect` has four missing-sealer `Ok(hdr_len)` branches and
  an unsupported-type success branch. `protect_header` has missing-HP and
  unsupported-type success branches. The batch AEAD helper already returns
  `TlsError` when no sealer exists, so the direct packet helper is inconsistent.
- The three direct product callers are pre-validation close, Initial/
  Handshake flight, and replay-safe 0-RTT send. Each advances send state on
  `Ok`. Short-header product send uses a separate fail-closed sealer; its
  public packet-primitive entry still needs a correct contract.
- The implementation must validate both the selected AEAD and HP key before
  sealing. Detecting absent HP only after AEAD would mutate a caller buffer
  and could retry the same packet number after a failed seal.
- Initial AEAD and HP are installed through separate transport calls, so an
  incomplete pair is possible if setup fails between them. The rustls
  Handshake bundle installs both under one `CryptoContext` write lock;
  `clear_handshake_and_one_rtt_keys` clears both together. 0-RTT remains
  disabled until enabled and is cleared as one group. The primitive also
  serves direct callers and inconsistent or torn-down contexts, so all levels
  require the same fail-closed contract.
- `outgoing_packet_sealer` and `outgoing_header_protector` select the exact
  owners before AEAD mutation; unsupported types return `InvalidPacket` and
  absent owners return `TlsError`. The Initial/Handshake send path preflights
  keys before taking CRYPTO, probe or ACK work. Close and replay-safe 0-RTT
  ownership already commits only after packet protection succeeds.
- Primitive regressions covered all four encrypted levels, missing AEAD,
  missing HP, buffer immutability, Retry and Version Negotiation rejection.
  Connection regressions covered Initial/Handshake missing HP followed by a
  peer-opened retry, 0-RTT missing AEAD followed by its existing peer-opened
  retry, and pre-validation close missing AEAD followed by successful retry.
  The first missing-AEAD primitive regression was red before the fix
  (`Ok(4)`), so the test detects the original defect.
- Gates: default root library `1,861 passed, 1 ignored`; feature-mode
  (`rust-tests,stream_ring_buffer,zero_copy_dgram`) connection tests `179/179`;
  strict library Clippy and workspace format check passed. These are local
  source/build proofs, not native wire or deployment evidence.
- Follow-up TODO-1125 owns Initial/Handshake obligations across errors after
  key selection. TODO-1126 owns the independent `CryptoStream` behavior that
  evicts unacknowledged ranges above 4 MiB and admits unbounded unsent data.
