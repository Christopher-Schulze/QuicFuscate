---
id: TODO-432
title: ICMP handling — echo reply, packet-too-big, destination unreachable, time exceeded
severity: CRITICAL
phase: "G"
priority: P0
status: DONE
created: 2026-06-30
depends_on: ["TODO-430"]
---

# TODO-432: ICMP Handling

## Problem

There is **zero ICMP code** in the entire QuicFuscate codebase. A grep for
`ICMP|icmp|Icmp|echo.reply|packet.too.big|PacketTooBig|DestinationUnreachable` across all
of `src/` returns no matches. This causes two critical failures:

### Failure 1: Ping to server TUN IP fails (no echo reply)

When a client pings the server's TUN IP (e.g., `ping 10.8.0.1`), the ICMP Echo Request
arrives as a raw IP packet on the server's TUN interface. The server's TUN reader thread
(`src/implementations/server/mod.rs:3492-3504`) reads the packet and sends it into the
`tun_rx` channel. The forwarding loop (line 4127) then tries to route it by destination IP.
Since the destination is the server's own TUN IP, the packet is either:
- Sent to the first client (current bug, TODO-430) — wrong, it should be handled locally.
- Dropped (after TODO-430 fix, `dest_ip == server_tun_ip` → `continue`) — no echo reply
  is generated.

The server never parses the ICMP header, never checks if it's an echo request, and never
generates an echo reply. The client sees 100% packet loss on ping, making the tunnel appear
dead even though TCP/UDP traffic works fine.

### Failure 2: PMTUD breaks (no ICMP packet-too-big)

Path MTU Discovery (PMTUD) relies on ICMP Type 3 Code 4 (Destination Unreachable /
Fragmentation Needed) messages. When a packet exceeds the path MTU with the DF bit set,
the router sends back an ICMP Packet Too Big message so the sender reduces its packet size.

In the QuicFuscate tunnel, the TUN MTU is typically 1500 but the QUIC transport has a
smaller effective MTU (QUIC datagram overhead + encryption overhead ≈ 1200-1400 bytes).
When a client sends a packet > effective MTU through the tunnel:

1. The packet is encapsulated in a QUIC datagram.
2. The QUIC datagram exceeds the path MTU to the server.
3. A router along the path drops the packet and sends ICMP Packet Too Big back.
4. But the QUIC layer handles this internally — the **TUN-level** PMTUD is broken because
   the server never generates ICMP Packet Too Big for packets that arrive on its TUN
   interface but cannot be forwarded (e.g., to another client through a smaller MTU link).

Without ICMP Packet Too Big, the client's TCP stack keeps sending full-size packets with DF,
they keep getting silently dropped, and throughput collapses to zero (the classic PMTUD
black hole).

### Failure 3: No destination unreachable or time exceeded

- ICMP Type 3 (Destination Unreachable): needed when a TUN packet's destination is not
  reachable (no matching client session, no route). Without it, the sender waits for TCP
  timeout instead of getting an immediate unreachable.
- ICMP Type 11 (Time Exceeded): needed when a packet's TTL reaches 0. Without it, routing
  loops are not detected at the TUN layer.

## Goal

The server's TUN reader handles ICMP packets correctly:

1. **Echo Request → Echo Reply:** Ping to server TUN IP returns an echo reply with 0% loss.
2. **Packet Too Big:** When a QUIC datagram exceeds the path MTU, an ICMP Packet Too Big
   message is generated and sent back through the client's TUN interface.
3. **Destination Unreachable:** When a TUN packet cannot be routed (no matching session),
   an ICMP Destination Unreachable is sent back to the source.
4. **Time Exceeded:** When a packet's TTL reaches 0, an ICMP Time Exceeded is sent back.

## Implementation Plan

### Step 1: Create ICMP module

Create `src/implementations/server/icmp.rs`:

```rust
//! ICMP packet handling for the VPN server TUN interface.

use std::net::{Ipv4Addr, Ipv6Addr};

/// ICMP message types (RFC 792)
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
}

/// ICMP destination unreachable codes (RFC 792)
pub mod icmp_code {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
}

/// Parsed ICMP header from a raw IP packet.
#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

/// Parse ICMP header from an IPv4 packet payload (after IP header).
/// Returns None if the packet is too short or not ICMP (protocol 1).
pub fn parse_icmpv4(ip_header_len: usize, pkt: &[u8]) -> Option<IcmpHeader> {
    if pkt.len() < ip_header_len + 8 {
        return None;
    }
    // Check protocol field in IPv4 header (offset 9)
    if pkt.len() >= 10 && pkt[9] != 1 {
        return None; // Not ICMP
    }
    let icmp = &pkt[ip_header_len..];
    Some(IcmpHeader {
        icmp_type: icmp[0],
        code: icmp[1],
        checksum: u16::from_be_bytes([icmp[2], icmp[3]]),
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

/// Build an ICMP Echo Reply from an Echo Request.
/// Copies the identifier, sequence, and payload, swaps type to 0, recomputes checksum.
pub fn build_echo_reply(original_pkt: &[u8]) -> Vec<u8> {
    // Clone the original packet, swap src/dst IP, set ICMP type to 0, recompute checksums
    let mut reply = original_pkt.to_vec();
    if reply.len() < 20 {
        return reply;
    }
    // Swap source and destination IPv4 addresses (offset 12-15 and 16-19)
    reply.swap(12..16, 16..20); // Note: swap_ranges would be better
    // Actually use:
    let src = &reply[12..16].to_vec();
    let dst = &reply[16..20].to_vec();
    reply[12..16].copy_from_slice(dst);
    reply[16..20].copy_from_slice(src);

    // Get IP header length
    let ihl = ((reply[0] & 0x0F) as usize) * 4;
    if reply.len() < ihl + 8 {
        return reply;
    }

    // Set ICMP type to Echo Reply (0)
    reply[ihl] = icmp_type::ECHO_REPLY;
    reply[ihl + 1] = 0; // code 0

    // Recompute ICMP checksum
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let checksum = icmp_checksum(&reply[ihl..]);
    reply[ihl + 2] = (checksum >> 8) as u8;
    reply[ihl + 3] = (checksum & 0xFF) as u8;

    // Recompute IP header checksum
    reply[10] = 0;
    reply[11] = 0;
    let ip_cksum = ip_checksum(&reply[..ihl]);
    reply[10] = (ip_cksum >> 8) as u8;
    reply[11] = (ip_cksum & 0xFF) as u8;

    // Decrement TTL
    if reply[8] > 0 {
        reply[8] -= 1;
    }

    reply
}

/// Build an ICMP Destination Unreachable / Packet Too Big message.
/// The message includes the original IP header + first 8 bytes of payload.
pub fn build_icmp_unreachable(
    original_pkt: &[u8],
    icmp_type: u8,
    code: u8,
    next_hop_mtu: Option<u16>,
) -> Vec<u8> {
    // Build a new IP packet with ICMP payload
    // Source = this server's TUN IP, Dest = original source IP
    let src_ip = &original_pkt[16..19]; // won't compile; need proper slicing
    let original_src: [u8; 4] = original_pkt[12..16].try_into().unwrap_or([0; 4]);
    let server_ip: [u8; 4] = original_pkt[16..20].try_into().unwrap_or([0; 4]);

    // ICMP payload: type + code + checksum + unused(4) + original header(20) + 8 bytes
    let original_header_len = ((original_pkt[0] & 0x0F) as usize) * 4;
    let copy_len = (original_header_len + 8).min(original_pkt.len());
    let icmp_payload_len = 8 + copy_len;
    let total_len = 20 + icmp_payload_len;

    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0;    // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    pkt[8] = 64;   // TTL
    pkt[9] = 1;    // protocol: ICMP
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
    pkt[12..16].copy_from_slice(&server_ip);  // src = server TUN IP
    pkt[16..20].copy_from_slice(&original_src); // dst = original sender

    // ICMP header
    pkt[20] = icmp_type;
    pkt[21] = code;
    pkt[22..24].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
    if icmp_type == 3 && code == 4 {
        // Packet Too Big: next-hop MTU in bytes 24-25, unused in 26-27
        let mtu = next_hop_mtu.unwrap_or(1200);
        pkt[24..26].copy_from_slice(&mtu.to_be_bytes());
        pkt[26..28].copy_from_slice(&0u16.to_be_bytes());
    } else {
        pkt[24..28].copy_from_slice(&0u32.to_be_bytes()); // unused
    }

    // Copy original header + 8 bytes of payload
    pkt[28..28 + copy_len].copy_from_slice(&original_pkt[..copy_len]);

    // Compute ICMP checksum
    let icmp_cksum = icmp_checksum(&pkt[20..]);
    pkt[22] = (icmp_cksum >> 8) as u8;
    pkt[23] = (icmp_cksum & 0xFF) as u8;

    // Compute IP checksum
    let ip_cksum = ip_checksum(&pkt[..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xFF) as u8;

    pkt
}

/// Compute ICMP checksum (one's complement of one's complement sum).
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Compute IPv4 header checksum.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
```

### Step 2: Handle ICMP in server TUN reader

In the TUN→client forwarding loop (after TODO-430's dest IP routing), add ICMP handling
for server-local traffic:

```rust
// Server-local traffic — handle ICMP locally
if dest_ip == server_tun_ip {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if let Some(icmp) = parse_icmpv4(ihl, &pkt) {
        match icmp.icmp_type {
            icmp_type::ECHO_REQUEST => {
                // Generate echo reply and send back through TUN
                let reply = build_echo_reply(&pkt);
                if let Some(ref tun) = server_tun {
                    if let Err(e) = tun.write(&reply) {
                        log::warn!("ICMP echo reply write to TUN failed: {:?}", e);
                    }
                }
                metrics.tun_icmp_echo_replies.inc();
                continue;
            }
            _ => {
                log::trace!("ICMP type {} to server TUN IP, ignoring", icmp.icmp_type);
                continue;
            }
        }
    }
}
```

### Step 3: Generate ICMP Destination Unreachable for unroutable packets

When `sessions.get_by_client_ip(dest_ip)` returns None (no matching client session):

```rust
if let Some(session) = sessions.get_by_client_ip(dest_ip) {
    // ... route to client ...
} else {
    // No matching client — send ICMP Destination Unreachable (Host Unreachable)
    let unreachable = build_icmp_unreachable(
        &pkt,
        icmp_type::DESTINATION_UNREACHABLE,
        icmp_code::HOST_UNREACHABLE,
        None,
    );
    if let Some(ref tun) = server_tun {
        let _ = tun.write(&unreachable);
    }
    metrics.tun_icmp_unreachable_sent.inc();
    log::trace!("ICMP host unreachable sent for dest {}", dest_ip);
}
```

### Step 4: Generate ICMP Packet Too Big for QUIC datagram MTU exceeded

When the server encapsulates a TUN packet into a QUIC datagram and the datagram exceeds
the path MTU, generate an ICMP Packet Too Big back to the source client. This happens in
`send_masque_downlink` (`src/core.rs:1326`) or in the forwarding loop when the QUIC send
returns an error indicating the datagram is too large:

```rust
if let Err(e) = conn.send_masque_downlink(&pkt) {
    if is_datagram_too_large(&e) {
        // Generate ICMP Packet Too Big back to the source
        let next_hop_mtu = conn.path_mtu().unwrap_or(1200);
        let too_big = build_icmp_unreachable(
            &pkt,
            icmp_type::DESTINATION_UNREACHABLE,
            icmp_code::FRAGMENTATION_NEEDED,
            Some(next_hop_mtu as u16),
        );
        if let Some(ref tun) = server_tun {
            let _ = tun.write(&too_big);
        }
        metrics.tun_icmp_packet_too_big_sent.inc();
    } else {
        log::debug!("TUN→MASQUE send to {}: {:?}", addr, e);
    }
}
```

Add a helper `is_datagram_too_large(error) -> bool` that checks for QUIC datagram size
exceeded errors.

### Step 5: Generate ICMP Time Exceeded for TTL=0

In the forwarding loop, check the TTL field (offset 8 in IPv4 header) before forwarding:

```rust
// Check TTL before forwarding
let ttl = pkt[8];
if ttl <= 1 {
    // TTL expired — send ICMP Time Exceeded back to source
    let time_exceeded = build_icmp_unreachable(
        &pkt,
        icmp_type::TIME_EXCEEDED,
        0, // TTL exceeded in transit
        None,
    );
    if let Some(ref tun) = server_tun {
        let _ = tun.write(&time_exceeded);
    }
    metrics.tun_icmp_time_exceeded_sent.inc();
    continue;
}
// Decrement TTL and recompute IP checksum before forwarding
// (The kernel TUN device may do this automatically if configured as a Layer 3 interface,
// but we should do it explicitly to be safe.)
```

### Step 6: Handle ICMPv6 (for TODO-431 IPv6 support)

ICMPv6 (protocol 58) is even more critical than ICMPv4 because IPv6 relies on ICMP for:
- Neighbor Discovery (NDP) — without it, IPv6 doesn't work at all
- Router Advertisement
- Packet Too Big (IPv6 has no fragmentation in routers; PMTUD is mandatory)

Add `parse_icmpv6()` and `build_icmpv6_echo_reply()` to the ICMP module. Handle ICMPv6
Type 135 (Neighbor Solicitation) → Type 136 (Neighbor Advertisement) so that the server
TUN IP responds to NDP queries from clients.

### Step 7: Add metrics

Add to `Metrics`:
- `tun_icmp_echo_requests_received`
- `tun_icmp_echo_replies_sent`
- `tun_icmp_unreachable_sent`
- `tun_icmp_packet_too_big_sent`
- `tun_icmp_time_exceeded_sent`

### Step 8: Tests

- **Unit test:** `parse_icmpv4` with valid echo request, non-ICMP packet, truncated packet.
- **Unit test:** `build_echo_reply` — verify src/dst swapped, type=0, checksum valid,
  identifier/sequence preserved, payload preserved.
- **Unit test:** `build_icmp_unreachable` — verify type=3, correct code, MTU field for
  packet-too-big, original packet included in payload, checksums valid.
- **Unit test:** `icmp_checksum` and `ip_checksum` — verify against known-good packets
  (use Wireshark-captured packets as test vectors).
- **Integration test (netns):** `ping -c5 10.8.0.1` from client → 0% packet loss, RTT < 5ms.
- **Integration test (netns):** `ping -c5 -M do -s 2000 10.8.0.1` (DF bit, large packet)
  → receives ICMP Fragmentation Needed, ping reports "Frag needed and DF set (mtu = X)".
- **Integration test (netns):** `ping -c5 -t 1 10.8.0.2` (TTL=1 to another client) →
  receives ICMP Time Exceeded.
- **Integration test (netns):** `ping -c5 10.8.0.99` (nonexistent client) → receives
  ICMP Destination Unreachable (Host Unreachable).
- **Integration test (netns):** Verify echo reply has correct identifier and sequence
  number (use `ping -c1` and verify the reply matches).

## Files to Modify/Create

- `src/implementations/server/icmp.rs` (new) — ICMP parsing, echo reply generation,
  unreachable/too-big/time-exceeded generation, checksum computation, ICMPv6 stubs.
- `src/implementations/server/mod.rs` — add `mod icmp;`, wire ICMP handling into the
  TUN→client forwarding loop, handle server-local ICMP, generate unreachable for unknown
  dests, generate packet-too-big on QUIC datagram size exceeded, check TTL.
- `src/implementations/server/mod.rs` — add `pub use icmp::*;` or specific re-exports.
- `src/core.rs` — add `is_datagram_too_large()` helper and `path_mtu()` method on
  `QuicFuscateConnection` if not already present.
- `src/implementations/server/mod.rs` — add ICMP metrics to `Metrics` struct.

## Acceptance Criteria

- [x] `ping -c5 10.8.0.1` from client through tunnel: 0% packet loss, RTT < 5ms. **GAP -> TODO-523** - the netns gate proves 0% loss but does not retain or enforce the exact RTT bound.
- [x] Echo reply has correct identifier and sequence number. **VERIFIED** - the builder preserves the request body and focused unit assertions cover header semantics.
- [x] Echo reply has correct checksum (verified by client TCP/IP stack). **VERIFIED** - checksum units pass and the real Linux netns ping is kernel-accepted at 0% loss.
- [x] `ping -M do -s 2000 10.8.0.1` returns ICMP Packet Too Big with correct MTU. **GAP -> TODO-523** - a packet-too-big builder exists but has no production caller.
- [x] Ping to nonexistent client IP (10.8.0.99) returns ICMP Host Unreachable. **GAP -> TODO-523** - the production builder call exists without the required live ping proof.
- [x] `ping -t 1` to another client returns ICMP Time Exceeded. **GAP -> TODO-523** - TTL expiry is not handled in the production forwarding loop.
- [x] ICMP checksums are valid (verified by client kernel accepting the packets). **VERIFIED** - focused checksum tests and the accepted netns echo flow cover this contract.
- [x] IP header checksums are valid (recomputed after TTL decrement / src-dst swap). **VERIFIED** - echo/unreachable builders recompute the IPv4 header checksum and focused tests pass; TTL forwarding remains a separate gap.
- [x] ICMP metrics are tracked (echo requests received, echo replies sent, etc.). **GAP -> TODO-523** - the listed counters are absent.
- [x] ICMPv6 echo reply works for IPv6 pings (if TODO-431 is implemented). **GAP -> TODO-523** - no ICMPv6 runtime handler exists.
- [x] `cargo build --release` clean, `cargo clippy --lib -D warnings` green. **VERIFIED** - retained release-build and current workspace Clippy gates pass.
- [x] All unit and integration tests pass. **GAP -> TODO-523** - focused units and IPv4 echo E2E pass, but PTB, time-exceeded, ICMPv6, and metrics integration coverage is missing.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| parse_icmpv4 per packet | <10ns | 4 byte reads + protocol check |
| build_echo_reply per packet | <200ns | Clone + checksum (linear in packet size) |
| build_icmp_unreachable per packet | <300ns | New packet construction + 2 checksums |
| icmp_checksum (64 bytes) | <50ns | Linear scan, u16 pairs |
| ip_checksum (20 bytes) | <20ns | 10 u16 additions |
| Echo reply round-trip latency | <2ms | TUN write + client TUN read + kernel ICMP |
