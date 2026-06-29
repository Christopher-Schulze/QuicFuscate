---
id: TODO-453
title: QUIC version negotiation (v1 + v2)
severity: HIGH
phase: "J"
priority: P2
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-453: QUIC Version Negotiation (v1 + v2)

## Problem

The transport supports **only QUIC v1** (`0x00000001`). Version negotiation
packets are parsed but never acted upon, and the config actively rejects any
non-v1 version. This prevents interoperability with QUIC v2
(`0x6b3343cf`, RFC 9369) deployments and eliminates version fallback as a
censorship-resistance vector.

Evidence:

- `src/transport.rs:199` — `pub const PROTOCOL_VERSION: u32 = 0x00000001;`
  Only v1 is defined as a constant.
- `src/transport/config.rs:105-107` — `new_with_version` rejects any version
  ≠ `PROTOCOL_VERSION` with `ConnectionError::VersionMismatch`:
  ```rust
  if version != PROTOCOL_VERSION {
      return Err(crate::error::ConnectionError::VersionMismatch);
  }
  ```
- `src/transport/packet.rs:274` — `PacketType::VersionNegotiation` is
  recognized in the packet type match:
  ```rust
  (0, _) => PacketType::VersionNegotiation,
  ```
  But the parsed VN packet is never used to select a version or trigger
  fallback. The parse path recognizes it; the connection logic ignores it.
- No `supported_versions` list exists in `Config`. No VN packet generation on
  the server side. No client-side VN response processing.

## Goal

Implement multi-version QUIC support with full version negotiation per RFC 9000
§17 and RFC 9369 (QUIC v2):

1. **Multi-version support** — both v1 (`0x00000001`) and v2
   (`0x6b3343cf`) as first-class supported versions.
2. **Server version negotiation** — server that doesn't support the client's
   version sends a Version Negotiation packet listing supported versions.
3. **Client version fallback** — client that receives a VN packet selects the
   highest mutually supported version and retries.
4. **Version config** — `supported_versions = [1, 2]` (or raw version numbers).

## Implementation Plan

### Step 1: Define version constants

In `src/transport.rs`:

- Keep `PROTOCOL_VERSION: u32 = 0x00000001` (v1, backward compat).
- Add `QUIC_VERSION_2: u32 = 0x6b3343cf` (v2, RFC 9369).
- Add `SUPPORTED_VERSIONS: &[u32] = &[PROTOCOL_VERSION, QUIC_VERSION_2]`.
- Add a helper `is_supported_version(v: u32) -> bool`.

### Step 2: Configuration

In `src/transport/config.rs`:

- Add field `supported_versions: Vec<u32>` (default `[PROTOCOL_VERSION]` for
  backward compat; servers that want v2 add it explicitly).
- Add setter `set_supported_versions(&mut self, versions: Vec<u32>)`.
- Modify `new_with_version` (line 104-107): instead of rejecting non-v1
  outright, check if `version` is in `supported_versions`. If not, return
  `VersionMismatch`. If the caller wants multi-version, they set
  `supported_versions` after construction.
- Add `new_multi_version(versions: Vec<u32>) -> Result<Self>` constructor that
  sets `supported_versions` and picks the preferred (first) version as the
  active `version`.

### Step 3: Server-side Version Negotiation packet generation

In `src/transport/packet.rs` (or a new `src/transport/version_negotiation.rs`):

- Add `build_version_negotiation_packet(dcid: &[u8], scid: &[u8], supported: &[u32]) -> Vec<u8>`:
  - First byte: `0x80` (long header bit set, fixed bit 1, form bit 1 — the rest
    is unused/random per RFC 9000 §17.1; the 4 reserved bits SHOULD be random).
  - Version field: `0x00000000` (signals VN packet).
  - DCID length + DCID (echo client's DCID).
  - SCID length + SCID (server's SCID).
  - Supported versions: each as 4-byte big-endian.

In the server's Initial packet processing (`connection.rs` or server accept
logic):

- When a client Initial arrives with a version not in `supported_versions`:
  - Generate and send a VN packet with `supported_versions`.
  - Drop the client Initial (do not create a connection).

### Step 4: Client-side Version Negotiation response processing

In the client's packet receive path:

- When a VN packet is received (already parsed as `PacketType::VersionNegotiation`
  at `packet.rs:274`):
  - Parse the supported versions list from the VN packet body.
  - Intersect with the client's `supported_versions`.
  - If intersection is non-empty: pick the highest-priority (first in client's
    `supported_versions` that is also in the server's list) version, restart
    the handshake with that version.
  - If intersection is empty: fail with `VersionMismatch`.
  - Guard: if the VN packet's DCID doesn't match the client's SCID, discard it
    (RFC 9000 §17.2.1.1 — a client MUST discard VN packets that don't match).

Add a `VersionNegotiationResponse` handler to `Connection` or the client
connection manager:

```rust
fn handle_version_negotiation(&mut self, vn_packet: &[u8]) -> Result<VersionSelection> {
    let server_versions = parse_vn_versions(vn_packet)?;
    let chosen = self.config.supported_versions.iter()
        .find(|v| server_versions.contains(v))
        .ok_or(ConnectionError::VersionMismatch)?;
    // Restart handshake with chosen version
    self.restart_with_version(*chosen)?;
    Ok(VersionSelection::Negotiated(*chosen))
}
```

### Step 5: Version fallback state machine

Add connection state for version negotiation:

```rust
pub enum VersionState {
    Initial,          // Haven't sent Initial yet
    AwaitingVn,       // Sent Initial, waiting for either SH or VN
    Negotiated(u32),  // Version selected (either no VN needed, or after VN)
    Failed,           // No mutually supported version
}
```

Client flow:
1. `Initial` → send Initial with preferred version → `AwaitingVn`.
2. `AwaitingVn` + receive Handshake → `Negotiated(version)` (no VN needed).
3. `AwaitingVn` + receive VN → select version → restart → `AwaitingVn`.
4. `AwaitingVn` + receive VN with no overlap → `Failed`.

### Step 6: v2 salt and initial keys

QUIC v2 (RFC 9369) uses a **different initial salt** than v1:

- v1 salt: `38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
- v2 salt: `0cdba4ba26dfb6b6e4b9d49e8b8b6b0c5a0a3a8a`

The initial key derivation in the TLS/HKDF layer must select the salt based on
the negotiated version. Audit `src/transport/` and the TLS integration for
hardcoded v1 salt and parameterize it.

### Step 7: Wire into packet parsing

In `src/transport/packet.rs`, the version field is already parsed. Ensure:

- The parsed version is passed to the connection layer for VN handling.
- v2 long-header packet type bits are handled (v2 uses the same long-header
  format but different type bit assignments per RFC 9369 §3, though the wire
  format is identical — only the version field and salt differ).

## Files to Modify/Create

- `src/transport.rs` — `QUIC_VERSION_2`, `SUPPORTED_VERSIONS`,
  `is_supported_version`.
- `src/transport/config.rs` — `supported_versions` field + setters;
  `new_multi_version` constructor; relax `new_with_version` check.
- `src/transport/version_negotiation.rs` — **new**: VN packet build/parse,
  `VersionState`, `VersionSelection`, `handle_version_negotiation`.
- `src/transport/packet.rs` — VN packet body parsing (extract supported
  versions list); pass version to connection layer.
- `src/transport/connection.rs` — server-side VN generation on version
  mismatch; client-side VN response handling; version fallback state machine.
- TLS/HKDF integration — parameterize initial salt by version.
- `src/transport.rs` — re-export `VersionState`, `VersionSelection`.
- Tests: VN packet build/parse, client v1→server v1+v2, client v2-only→server
  v1+v2, no overlap failure.

## Acceptance Criteria

- [ ] Client (v1 only) connects to server (v1 + v2): connection uses v1, no VN
      packet needed.
- [ ] Client (v2 only) connects to server (v1 + v2): connection uses v2.
- [ ] Client (v1 + v2, prefers v2) connects to server (v1 + v2): connection
      uses v2 (highest-priority mutual).
- [ ] Client (v1 + v2, prefers v1) connects to server (v2 only): client
      receives VN, falls back to v2, connection succeeds.
- [ ] Client (v1 only) connects to server (v2 only): client receives VN, no
      overlap, connection fails with `VersionMismatch`.
- [ ] Server sends VN packet with correct wire format (version=0, DCID echoed,
      SCID present, supported versions list).
- [ ] Client discards VN packet if DCID doesn't match its SCID (RFC 9000
      §17.2.1.1).
- [ ] v2 connections use the v2 initial salt for key derivation.
- [ ] `supported_versions` config is respected — server only offers configured
      versions in VN packets.
- [ ] Unit tests for VN packet build + parse round-trip.
- [ ] Unit test for version selection logic (priority ordering).

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| VN packet build + parse round-trip | < 1ms | Unit test |
| Client v1 → server v1+v2 (no VN) | < 5s | Normal handshake |
| Client v2-only → server v1+v2 | < 5s | v2 handshake |
| Client fallback (VN → retry) | < 10s | 1 RTT for VN + 1 RTT for handshake |
| No-overlap failure | < 5s | Immediate VersionMismatch |
| Version selection unit test | < 1s | All priority permutations |
