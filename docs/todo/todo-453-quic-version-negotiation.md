---
id: TODO-453
title: QUIC version negotiation
severity: HIGH
phase: "J"
priority: P2
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-453: QUIC Version Negotiation

## Goal
Implement multi-version QUIC support (v1 RFC 9000 + v2 RFC 9369) with full
version negotiation, version-aware packet parsing, and version greasing for
obfuscation. This enables interoperability with QUIC v2 deployments, provides
version fallback as a censorship-resistance vector, and allows custom version
IDs that look like random/unknown QUIC versions to DPI for enhanced stealth.

## Current State (verified against code)

The transport supports only QUIC v1 and actively rejects all other versions:

- `src/transport.rs:199` — `pub const PROTOCOL_VERSION: u32 = 0x00000001;`
  Only v1 is defined as a constant. No v2 constant.
- `src/transport/config.rs:9` — `version: u32` field stores a single version.
- `src/transport/config.rs:104-107` — `new_with_version` rejects any version
  ≠ `PROTOCOL_VERSION` with `ConnectionError::VersionMismatch`:
  ```rust
  if version != PROTOCOL_VERSION {
      return Err(crate::error::ConnectionError::VersionMismatch);
  }
  ```
  This is a hard gate — no version negotiation is possible.
- `src/transport/packet.rs:273-274` — `PacketType::VersionNegotiation` is
  recognized in the packet type match:
  ```rust
  (0, _) => PacketType::VersionNegotiation,
  ```
  The VN packet is parsed (version field = 0 triggers this), but the parsed VN
  packet is never used to select a version or trigger fallback. The parse path
  recognizes it; the connection logic ignores it.
- `src/transport/packet.rs:305-308` — the parsed header includes `version:
  u32`, but this version is not passed to any version negotiation logic.
- No `supported_versions` list exists in `Config`. No VN packet generation on
  the server side. No client-side VN response processing.
- No `version_information` transport parameter (RFC 9368) is implemented.
- No version greasing support (RFC 9287 grease_quic_bit is separate but
  related).
- `src/transport/connection.rs:4` — `PROTOCOL_VERSION` is imported and used
  as a constant. No version-aware logic.

## Problem Analysis

### Single-version lock-in
The transport is locked to QUIC v1. This has several consequences:
1. **No v2 interoperability**: QUIC v2 (RFC 9369) deployments cannot
   communicate with QuicFuscate. As v2 adoption grows, this becomes a
   compatibility issue.
2. **No version fallback**: if a network blocks QUIC v1 (e.g., a censor
   detects v1's version field `0x00000001`), there is no fallback to v2 or
   a custom version.
3. **No version greasing**: the version field is always `0x00000001`, making
   QuicFuscate traffic trivially identifiable by DPI that checks the version
   field.

### QUIC v2 (RFC 9369)
QUIC v2 is identical to v1 except for:
1. **Version number**: `0x6b3343cf` (randomly chosen, not "2").
2. **Initial salt**: different HKDF salt for initial key derivation.
3. **Long header type bits**: different type bit assignments for Initial,
   0-RTT, Handshake, Retry (v2 swaps the type bits to combat ossification).
4. **Header protection mask**: different initial HP mask derivation.

The wire format is otherwise identical. A v2 implementation reuses all v1
logic with different constants (salt, type bits, version number).

### Version negotiation (RFC 9000 §17 + RFC 9368)
RFC 9000 defines the Version Negotiation (VN) packet:
- Server sends VN when it doesn't support the client's version.
- VN packet: version=0, DCID=client's SCID, SCID=server's SCID, followed by
  a list of 4-byte supported version numbers.
- Client receives VN, selects a mutually supported version, restarts.

RFC 9368 (Compatible Version Negotiation) extends this:
- Allows negotiation without an extra round trip when versions share a
  compatible first-flight format (v1 and v2 are compatible).
- Uses `version_information` transport parameter to prevent downgrade attacks.
- Both endpoints MUST parse and validate the peer's version_information.

### Version greasing for stealth
The version field in QUIC long headers is a clear fingerprint. DPI can:
1. Check if version == `0x00000001` (QUIC v1) — trivial detection.
2. Check if version == `0x6b3343cf` (QUIC v2) — trivial detection.
3. Flag unknown version numbers as "suspicious QUIC" or "QUIC-like."

For stealth, QuicFuscate should support:
1. **Custom version IDs**: use a random or configured version ID that looks
   like an unknown QUIC version to DPI. The peer must support the same custom
   version (configured out-of-band).
2. **Version greasing in VN**: when sending VN packets, include fake version
   IDs alongside real ones to confuse fingerprinters. RFC 9000 §17.2 allows
   this: "The list of versions MAY include grease values."
3. **Version field randomization**: for short headers (1-RTT), the version
   field is not present, so this is only relevant for long headers (Initial,
   Handshake). The Initial packet's version field is always the negotiated
   version.

### Downgrade attack prevention
RFC 9368 requires the `version_information` transport parameter to prevent
downgrade attacks:
- Client sends its supported versions in `version_information`.
- Server echoes back the chosen version and its supported versions.
- Both endpoints verify that the chosen version is in the peer's supported
  list. If not, the connection is closed with a transport error.

Without this, an on-path attacker could inject a VN packet with a lower
version, forcing the client to downgrade to a less secure version.

## Proposed Architecture

### Version constants and registry
```
src/transport/version.rs
├── QUIC_V1: u32 = 0x00000001           // RFC 9000
├── QUIC_V2: u32 = 0x6b3343cf           // RFC 9369
├── SUPPORTED_VERSIONS: &[u32]          // configurable list
├── VersionSalt enum                    // V1Salt | V2Salt | Custom([u8; 20])
├── VersionConfig struct                // version list, greasing, custom salts
└── is_supported_version(v) -> bool
```

### Version negotiation state machine
```
Client:
  Initial ──(send Initial with preferred version)──► AwaitingVn
  AwaitingVn ──(receive Handshake)──► Negotiated(version)
  AwaitingVn ──(receive VN)──► select version ──► restart ──► AwaitingVn
  AwaitingVn ──(receive VN, no overlap)──► Failed

Server:
  Listening ──(receive Initial, version supported)──► Negotiated(version)
  Listening ──(receive Initial, version not supported)──► send VN ──► Listening
```

### Version-aware packet parsing
The packet parser (`packet.rs`) must handle different long-header type bit
assignments per version:
- v1: Initial=0x00, 0-RTT=0x10, Handshake=0x20, Retry=0x30
- v2: Initial=0x10, 0-RTT=0x20, Handshake=0x30, Retry=0x00 (swapped)

The parser must select the type bit mapping based on the version field.

### Version-specific crypto parameters
Each version has its own:
- Initial salt (for HKDF key derivation).
- Header protection mask derivation.
- PN offset in long headers (may differ for v2).

The crypto context (`CryptoContext`) must be parameterized by version.

### Version greasing
- In VN packets: include random "grease" version IDs (e.g., `0x0a0a0a0a`,
  `0x1a2b3c4d`) alongside real versions. These are valid 4-byte values that
  are not real QUIC versions. DPI that tries to fingerprint based on version
  lists will see noise.
- In Initial packets: the version field is the negotiated version (real or
  custom). For custom version mode, the version field is a configured random
  value that both client and server know.

## Implementation Plan

### Step 1: Define version constants and registry
Create `src/transport/version.rs`:
- `QUIC_V1: u32 = 0x00000001` (RFC 9000).
- `QUIC_V2: u32 = 0x6b3343cf` (RFC 9369).
- `SUPPORTED_VERSIONS: &[u32] = &[QUIC_V1, QUIC_V2]`.
- `is_supported_version(v: u32) -> bool`.
- `VersionSalt` enum: `V1Salt` (`38762cf7f55934b34d179ae6a4c80cadccbb7f0a`),
  `V2Salt` (`0cdba4ba26dfb6b6e4b9d49e8b8b6b0c5a0a3a8a`),
  `Custom([u8; 20])`.
- `version_salt(v: u32) -> VersionSalt`.
- `VersionConfig` struct: `supported_versions: Vec<u32>`,
  `grease_versions: Vec<u32>`, `custom_salts: HashMap<u32, [u8; 20]>`.

### Step 2: Configuration
In `src/transport/config.rs`:
- Add field `supported_versions: Vec<u32>` (default `[PROTOCOL_VERSION]` for
  backward compat; servers that want v2 add it explicitly).
- Add field `version_greasing: bool` (default `false`).
- Add field `custom_version: Option<u32>` (for stealth custom version mode).
- Add field `custom_version_salt: Option<[u8; 20]>` (for custom version HKDF).
- Add setter `set_supported_versions(&mut self, versions: Vec<u32>)`.
- Add setter `set_version_greasing(&mut self, enabled: bool)`.
- Add setter `set_custom_version(&mut self, version: u32, salt: [u8; 20])`.
- Modify `new_with_version` (line 104-107): instead of rejecting non-v1
  outright, check if `version` is in `SUPPORTED_VERSIONS` or is a configured
  custom version. If not, return `VersionMismatch`.
- Add `new_multi_version(versions: Vec<u32>) -> Result<Self>` constructor.

### Step 3: Server-side Version Negotiation packet generation
Create `src/transport/version_negotiation.rs` (or add to `packet.rs`):
- `build_version_negotiation_packet(dcid: &[u8], scid: &[u8], supported:
  &[u32], grease: bool) -> Vec<u8>`:
  - First byte: `0xc0 | random_4_bits` (long header, fixed bit=1, form bit=1,
    4 random bits per RFC 9000 §17.1).
  - Version field: `0x00000000` (signals VN packet).
  - DCID length + DCID (echo client's DCID).
  - SCID length + SCID (server's SCID).
  - Supported versions: each as 4-byte big-endian.
  - If `grease`: insert random grease version IDs between real versions.
- In the server's Initial packet processing:
  - When a client Initial arrives with a version not in `supported_versions`:
    generate and send a VN packet. Drop the client Initial.

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
  - Guard: if the VN packet's DCID doesn't match the client's SCID, discard
    it (RFC 9000 §17.2.1.1).

### Step 5: Version fallback state machine
Add `VersionState` enum to `connection.rs` or `version_negotiation.rs`:
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
QUIC v2 (RFC 9369) uses a different initial salt:
- v1 salt: `38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
- v2 salt: `0cdba4ba26dfb6b6e4b9d49e8b8b6b0c5a0a3a8a`

The initial key derivation in the TLS/HKDF layer must select the salt based
on the negotiated version. Audit `src/transport/` and the TLS integration for
hardcoded v1 salt and parameterize it:
- `derive_initial_keys(version: u32, connection_id: &[u8]) -> (Key, IV, HP)`.
- Select salt based on `version_salt(version)`.

### Step 7: Version-aware packet parsing
In `src/transport/packet.rs`, the version field is already parsed. Add:
- Version-aware type bit mapping:
  ```rust
  fn packet_type_from_bits(version: u32, ty_bits: u8) -> PacketType {
      match version {
          QUIC_V1 => match ty_bits {
              0x00 => Initial, 0x10 => ZeroRTT, 0x20 => Handshake, 0x30 => Retry,
              _ => Initial,
          },
          QUIC_V2 => match ty_bits {
              0x10 => Initial, 0x20 => ZeroRTT, 0x30 => Handshake, 0x00 => Retry,
              _ => Initial,
          },
          _ => // custom version: use v1 mapping as default
      }
  }
  ```
- Replace the current match at line 273-279 with this version-aware function.
- Pass the parsed version to the connection layer for VN handling.

### Step 8: version_information transport parameter (RFC 9368)
Add the `version_information` (formerly `version_negotiation`) transport
parameter:
- Format: chosen_version (4 bytes) + available_versions (list of 4 bytes).
- Client sends its supported versions.
- Server echoes back the chosen version and its supported versions.
- Both endpoints verify: chosen version must be in both endpoints' supported
  lists. If not, close with `TRANSPORT_PARAMETER_ERROR`.
- This prevents downgrade attacks.

### Step 9: Version greasing
- In VN packets: insert random grease version IDs. RFC 9000 §17.2:
  > "A client MAY discard a Version Negotiation packet if the values in the
  > Supported Versions list are not acceptable."
  Grease versions are ignored by the client (not in its supported list) but
  visible to DPI, adding noise.
- Generate grease versions: random 4-byte values with the fixed bit (0x40)
  set and the form bit (0x80) set (to look like valid QUIC version numbers).
  Avoid real version numbers.
- Configurable: `version_greasing: bool` (default false for interop, true for
  stealth).

### Step 10: Custom version mode (stealth)
For maximum stealth, support a custom version ID:
- `custom_version: Option<u32>` — a random or configured version ID.
- `custom_version_salt: Option<[u8; 20]>` — the HKDF salt for this version.
- Both client and server must be configured with the same custom version and
  salt (out-of-band).
- The custom version uses v1 type bit mapping and v1 wire format.
- To DPI, the version field looks like an unknown QUIC version — not v1, not
  v2. DPI that blocks v1 (`0x00000001`) will not match.
- The custom version is not advertised in VN packets (it's a private version).

## Technology Choices

### RFC 9369 (QUIC Version 2)
The IETF standard for QUIC v2, published 2023. Key design decisions:
- Version number `0x6b3343cf` is randomly chosen (not "2") to combat
  ossification — middleboxes that hardcode version checks for "2" won't match.
- Type bits are swapped from v1 to combat ossification of type bit patterns.
- v2 is a "compatible version" with v1 (RFC 9368) — they share the same
  first-flight format, enabling zero-RTT version negotiation.

### RFC 9368 (Compatible Version Negotiation)
Published 2023. Enables version negotiation without an extra round trip for
compatible versions. Key requirement: `version_information` transport
parameter for downgrade attack prevention. Both v1 and v2 endpoints MUST
send and validate this parameter.

### RFC 9287 (Greasing the QUIC Bit)
Separate but related: allows randomizing the "QUIC Bit" (0x40, the fixed bit)
in all packets after negotiation. This combats ossification of the fixed bit.
Should be implemented alongside version greasing for comprehensive
ossification defense.

### Reference implementations
- **quiche**: supports v1 and v2 with version negotiation. Good reference for
  version-aware packet parsing and salt selection.
- **quinn**: supports v1 only but has a clean version abstraction. Good
  reference for version config structure.
- **picoquic**: supports v1, v2, and custom versions. Good reference for
  version greasing and custom version mode.

## Stealth/Efficiency Considerations

### Stealth: version field as fingerprint
The QUIC version field in long headers is a clear fingerprint:
- `0x00000001` = QUIC v1 — trivially detected by DPI.
- `0x6b3343cf` = QUIC v2 — trivially detected by DPI.
- Unknown version = "suspicious QUIC-like traffic" — may be blocked or
  flagged.

**Custom version mode** is the strongest stealth option:
- Use a random 4-byte version ID that both client and server know.
- To DPI, the traffic looks like an unknown QUIC variant — not v1, not v2.
- DPI that blocks v1 specifically will not match.
- The version field appears random, blending with other unknown-protocol
  traffic.

**Version greasing in VN** adds noise to VN packets:
- Real versions are interspersed with random grease versions.
- DPI that tries to fingerprint based on version lists sees noise.
- Does not affect negotiation (client ignores grease versions).

### Stealth: v2 type bit swapping
QUIC v2 swaps the long-header type bits (Initial=0x10 instead of 0x00, etc.).
This means DPI that checks for the v1 Initial type bit pattern (0x00 in bits
5-6) will not match v2 traffic. Using v2 provides some ossification defense
even without custom version mode.

### Efficiency: zero-RTT version negotiation
RFC 9368 compatible version negotiation avoids an extra round trip for v1↔v2
negotiation. The client sends an Initial with its preferred version; if the
server supports a compatible version, it can switch without a VN packet. This
saves 1 RTT compared to traditional VN.

### Efficiency: version negotiation cost
Traditional VN adds 1 RTT (client Initial → server VN → client retry with
selected version). This is acceptable for initial connection setup but should
be avoided for reconnects (use 0-RTT + compatible VN instead).

## Testing Plan

### Unit tests
- VN packet build + parse round-trip: build a VN packet, parse it, verify
  supported versions list matches.
- VN packet with grease: verify grease versions are included and parseable.
- Version selection logic: all priority permutations (client prefers v1,
  server has v1+v2; client prefers v2, server has v1+v2; etc.).
- Version-aware type bit mapping: v1 and v2 type bits map to correct
  `PacketType`.
- `version_salt()`: v1 returns v1 salt, v2 returns v2 salt, custom returns
  custom salt.
- `is_supported_version()`: returns true for v1 and v2, false for unknown.
- VN packet DCID matching: client discards VN if DCID doesn't match its SCID.
- `version_information` transport parameter encode/decode.
- Downgrade attack detection: chosen version not in peer's supported list →
  `TRANSPORT_PARAMETER_ERROR`.

### Integration tests
- **Client (v1 only) → server (v1 + v2)**: connection uses v1, no VN needed.
- **Client (v2 only) → server (v1 + v2)**: connection uses v2.
- **Client (v1 + v2, prefers v2) → server (v1 + v2)**: connection uses v2
  (highest-priority mutual).
- **Client (v1 + v2, prefers v1) → server (v2 only)**: client receives VN,
  falls back to v2, connection succeeds.
- **Client (v1 only) → server (v2 only)**: client receives VN, no overlap,
  connection fails with `VersionMismatch`.
- **Server sends VN with correct wire format**: version=0, DCID echoed, SCID
  present, supported versions list.
- **v2 connections use v2 initial salt**: verify key derivation uses v2 salt.
- **Custom version mode**: client and server with same custom version +
  salt → connection succeeds. DPI sees unknown version field.
- **Version greasing**: VN packet includes grease versions; client ignores
  them; negotiation still works.
- **`version_information` transport parameter**: both endpoints send and
  validate; downgrade attack is detected.
- **No regression**: v1-only connections work exactly as before.

### Performance tests
- VN packet build + parse: < 1μs.
- Client v1 → server v1+v2 (no VN): < 5s (normal handshake).
- Client v2-only → server v1+v2: < 5s (v2 handshake).
- Client fallback (VN → retry): < 10s (1 RTT for VN + 1 RTT for handshake).
- No-overlap failure: < 5s (immediate VersionMismatch).
- Custom version handshake: < 5s (same as v1 but with custom version field).

## Files to Create/Modify

- `src/transport/version.rs` — **new**: version constants, `VersionSalt`,
  `VersionConfig`, `is_supported_version`, `version_salt`, grease version
  generation.
- `src/transport/version_negotiation.rs` — **new**: VN packet build/parse,
  `VersionState`, `VersionSelection`, `handle_version_negotiation`,
  `version_information` transport parameter encode/decode.
- `src/transport.rs` — add `QUIC_V2`, `SUPPORTED_VERSIONS`, re-export
  `VersionState`, `VersionSelection`, `VersionConfig`.
- `src/transport/config.rs` — `supported_versions`, `version_greasing`,
  `custom_version`, `custom_version_salt` fields + setters; relax
  `new_with_version` check; add `new_multi_version` constructor.
- `src/transport/packet.rs` — version-aware type bit mapping (replace line
  273-279); VN packet body parsing (extract supported versions list); pass
  version to connection layer.
- `src/transport/connection.rs` — server-side VN generation on version
  mismatch; client-side VN response handling; version fallback state machine;
  version-aware crypto context initialization.
- TLS/HKDF integration — parameterize initial salt by version; audit for
  hardcoded v1 salt.
- `src/transport/frames.rs` or transport params — `version_information`
  transport parameter.
- Tests: VN packet build/parse, version selection, v1/v2/custom handshakes,
  greasing, downgrade detection.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| v2 type bit swap breaks existing packet parsing | High — correctness | Version-aware type bit mapping function; test both v1 and v2 type bits |
| v2 salt not applied → key derivation failure | High — security | Parameterize salt by version; test v2 handshake end-to-end |
| Custom version mode breaks interop with standard QUIC | Expected — by design | Custom version is opt-in; default is v1; document that custom version requires both endpoints configured |
| VN packet spoofing by on-path attacker | High — security | `version_information` transport parameter (RFC 9368) prevents downgrade; client discards VN with mismatched DCID |
| Version greasing confuses non-greasing peers | Low — interop | Grease versions are only in VN packets; client ignores unknown versions; standard peers ignore them too |
| `version_information` transport parameter not understood by v1-only peers | Medium — interop | Only send when both endpoints advertise v2 support; v1-only peers don't send it |
| Custom version field flagged by DPI as "unknown QUIC" | Medium — stealth | This is expected and acceptable; "unknown QUIC" is less detectable than "known QUIC v1"; custom version can be changed periodically |

## Completion Criteria

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
- [ ] v2 long-header type bits are correctly mapped (swapped from v1).
- [ ] `supported_versions` config is respected — server only offers configured
      versions in VN packets.
- [ ] Custom version mode: client and server with same custom version + salt
      connect successfully; version field is the custom value.
- [ ] Version greasing: VN packet includes grease versions; client ignores
      them; negotiation still works.
- [ ] `version_information` transport parameter is sent and validated by both
      endpoints.
- [ ] Downgrade attack: chosen version not in peer's supported list →
      `TRANSPORT_PARAMETER_ERROR`.
- [ ] `set_cc_algorithm_name` and other config methods still work with v2.
- [ ] Unit tests for VN packet build + parse round-trip.
- [ ] Unit test for version selection logic (all priority permutations).
- [ ] Unit test for version-aware type bit mapping (v1 and v2).
- [ ] Unit test for `version_salt()` (v1, v2, custom).
- [ ] No regression in v1-only connections.
