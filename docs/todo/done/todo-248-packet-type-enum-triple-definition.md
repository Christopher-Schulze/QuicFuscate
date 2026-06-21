# TODO-248: Consolidate Triple PacketType Enum Definition

## Severity: MEDIUM

## Context
`PacketType` is defined three separate times:
1. `src/transport.rs:464` - 6 variants (Initial, Retry, Handshake, ZeroRTT, Short, VersionNegotiation)
2. `src/transport/packet.rs:60` - identical 6 variants (exact duplicate)
3. `src/stealth.rs:3141` - 4 different variants (used for stealth classification)

The first two are true duplicates. The third serves a different purpose (stealth packet classification) and may justify a separate type with a clearer name.

## Desired Outcome
- Remove the duplicate definition in `transport/packet.rs` and use the canonical one from `transport.rs`.
- Rename the stealth-specific type to something like `StealthPacketClass` to avoid confusion.
- Update all imports and references.

## Files
- `src/transport.rs` (~line 464)
- `src/transport/packet.rs` (~line 60)
- `src/stealth.rs` (~line 3141)

## Completion Criteria
- Only one `PacketType` definition for QUIC packet types.
- Stealth classification uses a distinctly named type.
- `cargo test` passes, clippy clean.
