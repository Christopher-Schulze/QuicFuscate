---
id: TODO-300
title: TLS Cover generates no cover traffic after handshake completion
severity: LOW
status: done
created: 2026-03-24
---

# TODO-300: TLS Cover Post-Handshake Cover Traffic Gap

## Mandatory Gate

**Before marking this TODO complete, ALL of the following must be checked and updated:**
- `src/stealth/mod.rs` - `TlsCoverState`, `next_crypto_frame()`, `generate_fake_crypto_frame()`
- `src/core.rs` - where `next_crypto_frame()` is called / cover frame injection point
- `src/qftls.rs` - TLS cover provider wiring
- `scripts/tests/rust/rt-tls-cover-cipher.rs` - existing TLS cover test
- `scripts/tests/suites/test-stealth.sh` - stealth suite runner
- `scripts/tests/suites/test-transport.sh` - transport suite (if core.rs changes)
- `docs/DOCUMENTATION.md` - TLS Cover section (lines ~2800-2940)
- `docs/MAP.md` - stealth module wiring if changed
- `docs/context.md` - session state
- `docs/changelog.md` - grouped entry

No fix is complete without verifying all relevant scripts run clean and docs reflect the new behavior.

---

## Current State (Bug)

In `src/stealth/mod.rs`, the `next_crypto_frame()` method:

```rust
pub(crate) fn next_crypto_frame(
    &mut self,
    _level: crate::qftls::Level,
    max_len: usize,
) -> Option<(u64, Vec<u8>)> {
    // Generate sophisticated TLS Cover frames for cover traffic
    if !self.handshake_complete {             // <-- gate
        let frame = self.generate_fake_crypto_frame(max_len);
        if !frame.is_empty() {
            return Some((0, frame));
        }
    }
    None                                     // <-- post-handshake: always None
}
```

Once `handshake_complete = true`, the function returns `None` unconditionally. **No cover traffic is generated after the handshake completes.**

### Why This Is a Security Issue

TLS Cover is designed to make the connection look like a real TLS session to passive observers and DPI engines. A real TLS session generates crypto frames during handshake AND emits application data records throughout the session lifetime. A QuicFuscate connection that suddenly stops producing TLS-like frame patterns after handshake is trivially distinguishable from real TLS:

- Real TLS: sporadic APPLICATION_DATA records visible throughout session lifetime
- QuicFuscate (current): TLS-like frames only during handshake, then silent

This is especially visible in:
1. Long-lived connections (VPN sessions can be hours)
2. Low-traffic periods where the absence of cover frames is visible
3. Traffic analysis tools correlating handshake pattern vs. subsequent silence

---

## Technical Background

### What QUIC CRYPTO frames are

QUIC carries TLS handshake data in `CRYPTO` frames. After the handshake, real QUIC-over-TLS sessions do not have CRYPTO frames (the TLS record layer is encapsulated inside QUIC 1-RTT encryption). So injecting fake CRYPTO frames post-handshake would actually be anomalous from a QUIC perspective.

### The real solution: APPLICATION_DATA-level cover

Post-handshake cover traffic should NOT use CRYPTO frames (they only appear during handshake in real QUIC). Instead, post-handshake cover should be:

1. **HTTP/3 PUSH_PROMISE or PUSH data** - the `Server Push Cover Traffic` system (`CoverTrafficScheduler`) already does this at the HTTP/3 level. This is the correct long-term cover mechanism.
2. **Fake QUIC STREAM frames** - injecting small zero-padded stream frames on a dedicated cover stream ID.
3. **PADDING frames** - QUIC has a native PADDING frame type (0x00) which is valid at any point during a connection. These are invisible to DPI but pad packet sizes.

### Current Cover Traffic Inventory (post-handshake)

What IS working post-handshake:
- `CoverTrafficScheduler` / Server Push Cover: HTTP/3-level, fires on interval when `enable_server_push_cover` is true (Stealth/AntiDpi/Intelligent-escalated modes)
- `TrafficPadding` via `process_outgoing_packet()`: pads individual outgoing packets
- `FlowShaper`: rate-smoothing with dummy retransmits (Anti-DPI only)

What is MISSING:
- Realistic TLS APPLICATION_DATA record appearance in the encrypted payload stream
- Post-handshake CRYPTO-frame-like patterns (not valid in real QUIC, but see alternative below)

---

## Implementation Plan

### Phase 1: Document the gap accurately (immediate)

The `docs/DOCUMENTATION.md` TLS Cover section currently does not mention that cover is handshake-only. This is a documentation accuracy gap. Add a note clarifying:

> TLS Cover generates synthetic crypto frames during the handshake phase only. Post-handshake cover is provided by the Server Push Cover Traffic system (HTTP/3 PUSH frames) and traffic padding, not by CRYPTO-frame injection (which is anomalous post-handshake in real QUIC).

**Status:** DOCUMENTATION.md update required - TLS Cover section.

### Phase 2: Evaluate QUIC PADDING injection (medium-term)

QUIC PADDING frames (type 0x00) are valid at any point during a connection and cost 1 byte each. They can be used to:
- Normalize packet sizes (already done partially by TrafficPadding)
- Add low-frequency spurious transmissions to maintain "activity pattern" realism

Implementation location: `src/transport/packet.rs` or `src/transport/frames.rs` - extend the outgoing packet building to optionally append PADDING frames.

Config surface: `StealthConfig.padding_strategy` already governs padding; PADDING-frame injection can be a new sub-strategy option.

### Phase 3: Fake APPLICATION_DATA record injection (long-term)

A more sophisticated cover would inject fake HTTP/3 DATA frames on a dedicated cover stream. This requires:

1. A dedicated cover stream ID (use an even-numbered server-initiated stream, e.g. stream ID 6)
2. Periodic injection of small `DATA` frames (16-64 bytes) containing random-length payloads
3. The stream must be opened during handshake so it exists naturally
4. Timing: inject on the same cadence as `CoverTrafficScheduler`

This is the correct architectural extension of the current Server Push Cover system.

**Key constraint:** Cover stream DATA frames must be encrypted (they go into 1-RTT QUIC packets), so they are not visible to passive DPI anyway - the cover value is in packet timing and size distribution, not in content.

---

## Files to Modify

### Phase 1 (doc only)
- `docs/DOCUMENTATION.md`: TLS Cover section (~line 2800) - clarify handshake-only scope
- `docs/DOCUMENTATION.md`: Stealth mode matrix notes - add clarifying footnote for TLS Cover column

### Phase 2 (PADDING frames)
- `src/transport/frames.rs`: Add `FrameType::Padding` variant with bulk-write support
- `src/transport/packet.rs`: In outgoing packet builder, optionally append PADDING bytes to reach target size
- `src/stealth/mod.rs`: `StealthConfig` - extend `PaddingStrategy` enum with `PaddingStrategy::PacketNormalize`
- `scripts/tests/rust/rt-tls-cover-cipher.rs`: Add test asserting post-handshake PADDING injection fires

### Phase 3 (APPLICATION_DATA cover stream)
- `src/stealth/mod.rs`: `TlsCoverState` - add `cover_stream_id: u64`, `next_cover_seq: u64`
- `src/core.rs`: In outgoing packet build path, call `stealth_manager.next_cover_stream_frame()`
- `scripts/tests/rust/rt-tls-cover-cipher.rs`: Test cover stream frame injection

---

## Completion Criteria

**Phase 1:**
- `docs/DOCUMENTATION.md` TLS Cover section accurately states handshake-only scope
- All scripts/docs gate items checked

**Phase 2 (PADDING):**
- PADDING frames injected in Stealth/AntiDpi/Intelligent post-handshake packets
- `cargo test --lib` 450+ passed, 0 failed
- `cargo clippy --workspace --all-targets -- -D warnings` GREEN
- All mandatory gate items checked and updated

**Phase 3 (cover stream):**
- Cover stream frames visible in `cargo test` integration
- Post-handshake cover pattern is statistically indistinguishable from idle HTTP/3 session
- All mandatory gate items checked and updated
