---
id: TODO-430
title: Multi-client TUN forwarding — per-client routing by destination IP
severity: CRITICAL
phase: "G"
priority: P0
status: OPEN
created: 2026-06-30
depends_on: ["TODO-422"]
---

# TODO-430: Multi-Client TUN Forwarding

## Problem

The server's TUN→client forwarding loop sends **all** TUN packets to the **first** connected
client, ignoring the packet's destination IP and ignoring all other connected clients. This
makes multi-client VPN impossible — only one client can receive traffic at a time.

### Code Evidence

**`src/implementations/server/mod.rs:4127-4163`** — the TUN→client forwarding loop in the
housekeeping tick of `run_loop`:

```rust
// Forward TUN→client: drain any packets from the TUN reader thread
// and send them to the first connected client via QUIC datagrams.
if let Some(ref rx) = tun_rx {
    for _ in 0..32 {
        match rx.try_recv() {
            Ok(pkt) => {
                let live = self.live_mut();
                // Send to the first active client (simple VPN model: 1 TUN ↔ 1 client).
                if let Some((addr, conn)) = live.live_state.clients.iter_mut().next() {
                    let addr = *addr;
                    if let Err(e) = conn.send_masque_downlink(&pkt) {
                        log::debug!("TUN→MASQUE send to {}: {:?}", addr, e);
                    }
                }
                // Flush outgoing for all clients after queuing dgrams
                ...
            }
        }
    }
}
```

The comment explicitly says "simple VPN model: 1 TUN ↔ 1 client." The `clients.iter_mut().next()`
call (line 4133) returns an arbitrary first entry from the HashMap — not even a deterministic
one (HashMap iteration order is randomized). If 3 clients are connected (10.8.0.2, 10.8.0.3,
10.8.0.4), a TUN packet destined for 10.8.0.3 might be sent to 10.8.0.2's QUIC connection.

### What Already Works

- **IpPool** (`src/implementations/server/ip_pool.rs`): allocates IPs from a range
  (default 10.8.0.2–10.8.0.254). Each client gets a unique IP via `ip_pool.allocate()` in
  `accept_session_in_domain()` (line 2242).
- **SessionManager** (`src/implementations/server/session.rs`): maintains three indexes:
  - `sessions: HashMap<SessionId, Session>` (line 125)
  - `by_client_ip: HashMap<Ipv4Addr, SessionId>` (line 126)
  - `by_remote_addr: HashMap<SocketAddr, SessionId>` (line 127)
  - `get_by_client_ip(ip)` (line 192) — lookup session by TUN IP. **This already exists but
    is never used in the forwarding loop.**
- **Session** stores `client_ip: Ipv4Addr` (line 44) and exposes `client_ip()` (line 99).
- The TUN reader thread (`src/implementations/server/mod.rs:3492-3504`) reads raw IP packets
  from the TUN device and sends them into the `tun_rx` channel as `Vec<u8>`.

### What Is Missing

1. **Destination IP parsing:** The forwarding loop never parses the destination IP from the
   raw IP packet (`pkt`). It needs to extract the IPv4 destination address from the IP header
   (offset 16-19 for IPv4) to route correctly.
2. **Session lookup by TUN IP:** The loop never calls `sessions.get_by_client_ip(dest_ip)` to
   find which client session owns the destination IP.
3. **Per-client connection routing:** The loop never maps the session to the corresponding
   QUIC connection in `live.live_state.clients` (which is keyed by `SocketAddr`, not by TUN IP).
4. **Broadcast/multicast handling:** Packets destined to the subnet broadcast address
   (e.g., 10.8.0.255) or multicast ranges should be sent to all clients.
5. **Server-local traffic:** Packets destined to the server's own TUN IP (10.8.0.1) should
   be handled locally (ICMP echo reply — see TODO-431) not forwarded.

## Goal

Each TUN packet read from the server's TUN interface is routed to the correct client based on
the destination IP in the IP header. Multiple clients connected simultaneously each receive
only the traffic destined for their assigned TUN IP.

## Implementation Plan

### Step 1: Add IP packet parsing utility

Create a lightweight IP header parser (no external dependency — we only need the destination
address). Add to `src/implementations/server/mod.rs` or a new `src/implementations/server/ip_parse.rs`:

```rust
/// Parse the destination IPv4 address from a raw IP packet.
/// Returns None if the packet is too short or not IPv4.
#[inline]
fn parse_ipv4_dest(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl {
        return None;
    }
    // IPv4 destination address is at offset 16-19
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}
```

Also add `parse_ipv6_dest` for future IPv6 support (TODO-431).

### Step 2: Add SessionManager → clients connection lookup

The `live.live_state.clients` is a `HashMap<SocketAddr, QuicFuscateConnection>` (or similar).
The `SessionManager` indexes by `client_ip` → `SessionId` and `SessionId` → `remote_addr`.
We need a chain: `dest_ip` → `session_id` → `remote_addr` → `connection`.

Add a helper method to `LiveServerState` or the run loop:

```rust
/// Find the QUIC connection for a client with the given TUN IP.
fn connection_by_tun_ip(
    &mut self,
    dest_ip: Ipv4Addr,
) -> Option<(&SocketAddr, &mut QuicFuscateConnection)> {
    let live = self.live_mut();
    let session = live.live_state.sessions.read().unwrap();
    let session = session.get_by_client_ip(dest_ip)?;
    let remote_addr = session.remote_addr();
    drop(session); // release RwLock before borrowing clients
    live.live_state.clients.get_mut(&remote_addr).map(|conn| (&remote_addr, conn))
}
```

Note: `sessions` is `Arc<RwLock<SessionManager>>` (line 826). The read lock is needed to
look up by client IP. The `clients` map is directly in `LiveServerState`.

### Step 3: Rewrite the TUN→client forwarding loop

Replace the `clients.iter_mut().next()` logic at line 4133 with destination-IP-based routing:

```rust
if let Some(ref rx) = tun_rx {
    for _ in 0..64 {  // increase batch to 64 for multi-client throughput
        match rx.try_recv() {
            Ok(pkt) => {
                let dest_ip = match parse_ipv4_dest(&pkt) {
                    Some(ip) => ip,
                    None => {
                        log::trace!("TUN packet with unparseable dest, dropping");
                        continue;
                    }
                };

                // Server-local traffic (server TUN IP) — handle locally
                if dest_ip == server_tun_ip {
                    // TODO-432: ICMP echo reply, etc.
                    continue;
                }

                // Broadcast to all clients if broadcast address
                if dest_ip.is_broadcast() {
                    let live = self.live_mut();
                    for (addr, conn) in live.live_state.clients.iter_mut() {
                        let _ = conn.send_masque_downlink(&pkt);
                    }
                    continue;
                }

                // Unicast: route to the specific client
                let live = self.live_mut();
                let sessions = live.live_state.sessions.read().unwrap();
                if let Some(session) = sessions.get_by_client_ip(dest_ip) {
                    let remote_addr = session.remote_addr();
                    drop(sessions);
                    if let Some(conn) = live.live_state.clients.get_mut(&remote_addr) {
                        if let Err(e) = conn.send_masque_downlink(&pkt) {
                            log::debug!("TUN→MASQUE send to {} (tun_ip={}): {:?}", remote_addr, dest_ip, e);
                        }
                    } else {
                        log::trace!("TUN packet for {} (tun_ip={}) but no active QUIC connection", remote_addr, dest_ip);
                    }
                } else {
                    log::trace!("TUN packet for unknown client IP {}, dropping", dest_ip);
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                tun_rx = None;
                break;
            }
        }
    }
}
```

### Step 4: Store server TUN IP for local-traffic check

The server's TUN IP is `server_config.server_ip` (default `10.8.0.1`, line 118). Store it
in `ServerLiveRuntime` or pass it into the run loop scope so the forwarding loop can compare
against it.

Add to `ServerLiveRuntime` struct:
```rust
server_tun_ip: Ipv4Addr,
```

Initialize from `server_config.server_ip` in the runtime construction (around line 3517).

### Step 5: Verify per-client TUN IP assignment in session setup

The session setup in `accept_session_in_domain()` (line 2228) already allocates a TUN IP
from the pool and stores it in the `Session`. Verify that the TUN IP is communicated to the
client during the connection handshake so the client configures its TUN interface with the
correct IP.

Check the MASQUE/HTTP3 handshake flow: the server should send the assigned TUN IP, netmask,
DNS servers, and server TUN IP to the client as part of the tunnel setup metadata. If this
is not already done, add a configuration capsule/datagram that carries:

```rust
struct TunnelConfig {
    client_tun_ip: Ipv4Addr,
    server_tun_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
    mtu: u16,
}
```

### Step 6: Add metrics for routing decisions

Add counters to `Metrics`:
- `tun_packets_routed_unicast` — packets routed to a specific client
- `tun_packets_routed_broadcast` — packets broadcast to all clients
- `tun_packets_local` — packets destined for server TUN IP
- `tun_packets_unknown_dest` — packets with no matching client session
- `tun_packets_unparseable` — packets with invalid IP headers

### Step 7: Tests

- **Unit test:** `parse_ipv4_dest` with valid IPv4 packet, truncated packet, IPv6 packet,
  zero-length packet.
- **Unit test:** 3 sessions in SessionManager with IPs 10.8.0.2, 10.8.0.3, 10.8.0.4.
  `get_by_client_ip(10.8.0.3)` returns the correct session.
- **Integration test (netns):** 3 clients connected simultaneously in separate network
  namespaces. Each client pings the server TUN IP (10.8.0.1). Each client receives only
  its own echo replies. Client A's ping does not appear in Client B's TUN.
- **Integration test (netns):** Client A pings Client B's TUN IP (10.8.0.3 from 10.8.0.2).
  Packet traverses: Client A TUN → server TUN → server routes to Client B → Client B TUN.
  Verify Client B receives the packet.
- **Integration test:** Broadcast packet (dest 10.8.0.255) is sent to all 3 clients.
- **Stress test:** 10 clients, each running iperf3 through the tunnel simultaneously.
  Verify no cross-talk and aggregate throughput > 80% of single-client throughput.

## Files to Modify/Create

- `src/implementations/server/mod.rs` — rewrite TUN→client forwarding loop (line 4127-4163),
  add `parse_ipv4_dest()`, add `server_tun_ip` to `ServerLiveRuntime`, add routing metrics.
- `src/implementations/server/ip_parse.rs` (new) — IP header parsing utilities
  (`parse_ipv4_dest`, `parse_ipv6_dest`, `parse_src_ip`, `is_broadcast`).
- `src/implementations/server/session.rs` — verify `get_by_client_ip` is sufficient;
  add `get_remote_addr_by_client_ip` convenience method if needed.
- `src/implementations/server/mod.rs` — ensure TUN IP is sent to client during handshake
  (TunnelConfig capsule).
- `src/core.rs` — if TunnelConfig capsule needs a new MASQUE/H3 message type.

## Acceptance Criteria

- [ ] `parse_ipv4_dest` correctly extracts destination IP from valid IPv4 packets.
- [ ] TUN packets are routed to the client whose assigned TUN IP matches the dest IP.
- [ ] 3 clients connected simultaneously each receive only their own traffic.
- [ ] Client-to-client traffic (A pings B's TUN IP) routes through the server correctly.
- [ ] Broadcast packets are sent to all connected clients.
- [ ] Packets to server TUN IP (10.8.0.1) are handled locally, not forwarded.
- [ ] Packets to unknown TUN IPs are dropped with a trace log and metric increment.
- [ ] No cross-talk between clients (verified with tcpdump in netns).
- [ ] `cargo build --release` clean, `cargo clippy --lib -D warnings` green.
- [ ] All unit and integration tests pass.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| parse_ipv4_dest per packet | <10ns | Inline, 4 byte reads + version check |
| SessionManager lookup per packet | <100ns | HashMap lookup by Ipv4Addr (u32 key) |
| Forwarding loop throughput (10 clients) | >500 Mbps | Bounded by QUIC datagram send, not routing |
| Memory overhead per client | <1KB | Session + indexes already exist |
| Broadcast fan-out (10 clients) | <1ms | Sequential send_masque_downlink per client |
