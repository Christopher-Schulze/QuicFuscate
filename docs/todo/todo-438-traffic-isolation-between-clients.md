---
id: TODO-438
title: Traffic isolation between clients
severity: HIGH
phase: "G"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-438: Traffic isolation between clients

## Goal
Implement per-client traffic isolation on the VPN server so that client A cannot see, intercept, or influence client B's traffic. This includes preventing ARP spoofing, direct TUN IP access, lateral movement between clients, and broadcast traffic leakage. The solution must work with the existing multi-client TUN forwarding architecture and be lightweight enough for production deployment.

## Current State (verified against code)

### TUN forwarding (shared, no isolation)
- `src/implementations/server/mod.rs:2045-2057` — Server reads data from QUIC streams and writes to the TUN interface: `tun.write(data)`. All clients share the same TUN device. There is no per-client filtering — any client can send packets addressed to any other client's TUN IP, and the server will write them to the TUN interface.
- `src/implementations/server/mod.rs:2008-2017` — MASQUE datagram callback writes directly to TUN: `tun_sink.write(payload)`. Same issue — no source validation.
- `src/implementations/server/mod.rs:2801-2803` — `tun_rx` channel receives packets from the TUN interface reader thread. These are forwarded to the appropriate client via QUIC datagrams. The forwarding logic uses the destination IP to look up the client — but there's no filtering of what a client can send.

### Routing (NAT, no inter-client firewall)
- `src/implementations/server/routing.rs:87-112` — `RoutingManager::setup()` on Linux: enables IP forwarding, sets up MASQUERADE NAT, adds FORWARD rules for TUN→WAN and WAN→TUN (established). There are NO rules preventing TUN→TUN (client-to-client) forwarding.
- `src/implementations/server/routing.rs:389-456` — `setup_iptables()` adds:
  1. `POSTROUTING -s <subnet> -o <wan> -j MASQUERADE` (NAT outbound)
  2. `FORWARD -i <tun> -o <wan> -j ACCEPT` (allow TUN to WAN)
  3. `FORWARD -i <wan> -o <tun> -m state --state ESTABLISHED,RELATED -j ACCEPT` (allow return traffic)
  Missing: `FORWARD -i <tun> -o <tun> -j DROP` (block client-to-client).
- `src/implementations/server/routing.rs:593-608` — TUN interface address assignment via `ip addr add`. No per-client interface or routing table.

### IP pool allocation
- `src/implementations/server/ip_pool.rs` — `IpPool` allocates IPs from a range (default `10.8.0.2` – `10.8.0.254`). Each client gets a unique IP. But the IPs are all on the same subnet (`10.8.0.0/24`), on the same TUN interface, with no L2/L3 isolation between them.

### Session management
- `src/implementations/server/session.rs` — `SessionManager` tracks sessions by remote address. Each session has an assigned TUN IP. But there's no enforcement that a client can only send traffic from its assigned IP — a client could spoof another client's source IP.

## Problem Analysis

### Attack vectors without isolation

**1. Client-to-client direct access**
Client A (10.8.0.2) can send a packet to Client B (10.8.0.3). The server writes it to the TUN interface. The Linux kernel routes it back out the TUN interface (since 10.8.0.3 is on the TUN subnet). The TUN reader thread picks it up and forwards it to Client B via QUIC. Client A can now port-scan, attack, or sniff Client B.

**2. Source IP spoofing**
Client A sends packets with source IP 10.8.0.3 (Client B's IP). The server writes them to TUN without validating the source IP. Return traffic for 10.8.0.3 goes to Client B, but Client A's spoofed packets may reach external services appearing to come from Client B.

**3. ARP spoofing (L2)**
On the TUN interface, if clients can send ARP requests/replies, they can poison the ARP cache of other clients. However, TUN interfaces are L3 (no ARP) — this is primarily a concern with TAP interfaces. Still, ICMP redirect attacks are possible at L3.

**4. Broadcast traffic**
A client sending to the broadcast address (10.8.0.255) reaches all clients. This enables amplification attacks and information leakage (discovering all other clients' IPs).

**5. Lateral movement**
A compromised client can use the VPN tunnel as a pivot point to attack other clients' services (SSH, RDP, internal web apps accessible via TUN IP).

### Why current state is insufficient
- The iptables FORWARD chain allows TUN→WAN but does not explicitly DROP TUN→TUN. The Linux kernel's default FORWARD policy may be ACCEPT (depending on distribution), allowing client-to-client traffic.
- There is no source IP validation — the server trusts whatever source IP the client puts in the IP packet.
- There is no per-client firewall ruleset — all clients share the same FORWARD rules.
- There is no per-client routing table — all clients share the same routing table, so a client can route to any other client's subnet.

## Proposed Architecture

### Approach: Policy-based routing + iptables owner/conntrack match (lightweight)

Three isolation approaches were evaluated (see Technology Choices). The chosen approach is **policy-based routing + iptables with per-client rules**, which provides L3 isolation without the overhead of network namespaces or the complexity of VRF for a VPN use case.

```
┌─────────────────────────────────────────────────────────────────────┐
│ SERVER                                                              │
│                                                                     │
│  TUN interface (tun0, 10.8.0.1/24)                                 │
│  ┌──────────────────────────────────────────────────────┐          │
│  │  Client A (10.8.0.2)   Client B (10.8.0.3)   ...     │          │
│  │       │                     │                         │          │
│  │  ┌────▼─────┐          ┌────▼─────┐                   │          │
│  │  │ src IP   │          │ src IP   │                   │          │
│  │  │ validate │          │ validate │                   │          │
│  │  │ (10.8.0.2│          │ (10.8.0.3│                   │          │
│  │  │  only)   │          │  only)   │                   │          │
│  │  └────┬─────┘          └────┬─────┘                   │          │
│  │       │                     │                         │          │
│  │  ┌────▼─────────────────────▼────────────────────┐    │          │
│  │  │           FORWARD chain (iptables)             │    │          │
│  │  │                                                │    │          │
│  │  │  Rule 1: -i tun0 -o tun0 -j DROP               │    │          │
│  │  │           (block all client-to-client)          │    │          │
│  │  │  Rule 2: -i tun0 -o <wan> -s <client_ip>        │    │          │
│  │  │           -j ACCEPT (allow to internet)         │    │          │
│  │  │  Rule 3: -i <wan> -o tun0 -d <client_ip>        │    │          │
│  │  │           -m conntrack --state ESTABLISHED      │    │          │
│  │  │           -j ACCEPT (allow return traffic)      │    │          │
│  │  └────────────────────────────────────────────────┘    │          │
│  └──────────────────────────────────────────────────────┘          │
│         │                                                           │
│  ┌──────▼──────────────────────────────────────────────┐           │
│  │  Source IP Validation (in Rust, before TUN write)    │           │
│  │  • Parse IP packet header                            │           │
│  │  • Extract source IP                                 │           │
│  │  • Compare to session's assigned TUN IP              │           │
│  │  • Drop packet if mismatch (log + metric)            │           │
│  └──────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

### Components

1. **Source IP Validator (Rust, in-process)**: Before writing a client's packet to the TUN interface, parse the IP header and verify the source IP matches the client's assigned TUN IP. Drop and log if mismatched. This prevents source IP spoofing at the application level.

2. **Inter-client FORWARD DROP (iptables/nftables)**: Add a FORWARD rule that drops all TUN→TUN traffic: `iptables -A FORWARD -i tun0 -o tun0 -j DROP`. This is the primary isolation mechanism — it prevents any client-to-client routing at the kernel level.

3. **Per-client FORWARD rules (iptables)**: For each client, add:
   - `iptables -A FORWARD -i tun0 -o <wan> -s <client_ip> -j ACCEPT` (allow outbound)
   - `iptables -A FORWARD -i <wan> -o tun0 -d <client_ip> -m conntrack --state ESTABLISHED,RELATED -j ACCEPT` (allow return)
   These replace the current blanket TUN→WAN ACCEPT rule with per-client rules, ensuring only assigned IPs can send outbound traffic.

4. **Broadcast/multicast DROP**: `iptables -A FORWARD -i tun0 -d 10.8.0.255 -j DROP` (broadcast) and `iptables -A FORWARD -i tun0 -d 224.0.0.0/4 -j DROP` (multicast).

5. **ClientIsolationManager**: Rust struct that manages the lifecycle of per-client firewall rules. On client connect: install rules. On client disconnect: remove rules. On server shutdown: cleanup all rules.

## Implementation Plan

### Phase 1: Source IP validation (in-process)
1. Create `src/implementations/server/isolation.rs` with `SourceIpValidator`:
   ```rust
   pub struct SourceIpValidator {
       // Session-assigned IPs by remote address
       assignments: HashMap<SocketAddr, Ipv4Addr>,
   }
   
   impl SourceIpValidator {
       pub fn validate(&self, remote: &SocketAddr, packet: &[u8]) -> bool {
           // Parse IPv4/IPv6 header, extract source IP
           // Compare to assigned IP for this remote
           // Return true if valid, false if spoofed
       }
   }
   ```
2. Integrate into the TUN write path in `src/implementations/server/mod.rs:2045-2057`:
   ```rust
   if !source_validator.validate(&addr, data) {
       metrics.packets_dropped_spoofed_source.inc();
       log::warn!("Dropped packet with spoofed source IP from {}", addr);
       return;
   }
   tun.write(data);
   ```
3. Handle both IPv4 and IPv6 packets (check first nibble: 4 or 6).
4. Handle ICMP, TCP, UDP — all IP protocols carry the source IP in the IP header.

### Phase 2: Inter-client FORWARD DROP
1. In `RoutingManager::setup_iptables()`, add as the FIRST FORWARD rule (before any ACCEPT rules):
   ```rust
   // Block all client-to-client traffic
   Command::new("iptables")
       .args(["-A", "FORWARD", "-i", &self.tun_name, "-o", &self.tun_name, "-j", "DROP"])
   ```
2. Add broadcast/multicast drops:
   ```rust
   // Block broadcast
   Command::new("iptables")
       .args(["-A", "FORWARD", "-i", &self.tun_name, "-d", &broadcast_addr, "-j", "DROP"])
   // Block multicast
   Command::new("iptables")
       .args(["-A", "FORWARD", "-i", &self.tun_name, "-d", "224.0.0.0/4", "-j", "DROP"])
   ```
3. In `teardown()`, remove these rules in reverse order.
4. Add IPv6 equivalents using `ip6tables` (block `ff00::/8` multicast, TUN→TUN DROP).

### Phase 3: Per-client firewall rules
1. Create `ClientIsolationManager` in `src/implementations/server/isolation.rs`:
   ```rust
   pub struct ClientIsolationManager {
       tun_name: String,
       wan_interface: String,
       subnet: String,
       active_rules: HashMap<Ipv4Addr, Vec<String>>,  // client_ip → rule identifiers
   }
   ```
2. `install_client_rules(client_ip: Ipv4Addr)`:
   - Add per-client outbound ACCEPT: `-s <client_ip> -i <tun> -o <wan> -j ACCEPT`
   - Add per-client inbound ESTABLISHED: `-d <client_ip> -i <wan> -o <tun> -m conntrack --state ESTABLISHED,RELATED -j ACCEPT`
   - Store rule identifiers for later removal.
3. `remove_client_rules(client_ip: Ipv4Addr)`: Remove rules by identifier.
4. `cleanup_all()`: Remove all per-client rules (server shutdown).
5. Integrate with session lifecycle: call `install_client_rules` on session create, `remove_client_rules` on session expire/disconnect.

### Phase 4: Replace blanket FORWARD ACCEPT with per-client rules
1. Remove the current blanket rules in `setup_iptables()`:
   - `FORWARD -i <tun> -o <wan> -j ACCEPT` (too permissive — allows any source IP)
   - `FORWARD -i <wan> -o <tun> -m state --state ESTABLISHED,RELATED -j ACCEPT` (too permissive — allows any dest IP)
2. Replace with per-client rules installed by `ClientIsolationManager`.
3. Keep the TUN→TUN DROP and broadcast/multicast DROP as global rules (always present).

### Phase 5: nftables support (future-proofing)
1. Detect whether the system uses iptables-legacy or nftables.
2. If nftables is available, use `nft` commands instead of `iptables` for better performance (nftables has O(1) set lookups vs iptables' O(n) rule traversal).
3. Use an nftables named set for client IPs: `nft add set inet quicfuscate clients { type ipv4_addr; }` and rules that reference the set.
4. This is optional — iptables works everywhere, nftables is an optimization.

### Phase 6: Metrics and audit
1. Add metrics: `packets_dropped_spoofed_source`, `packets_dropped_client_to_client`, `isolation_rules_installed`, `isolation_rules_active`.
2. Log when a client's packet is dropped due to source IP mismatch (rate-limited to prevent log flooding).
3. Audit event on isolation rule installation/removal (TODO-439).

## Technology Choices

### Chosen: Policy-based routing + iptables per-client rules (lightweight)
- **Pros**: No kernel module changes, works on all Linux distributions, minimal overhead (iptables rules are fast for <1000 clients), integrates with existing `RoutingManager`.
- **Cons**: iptables rule traversal is O(n) — with 1000 clients and 2 rules each, that's 2000 rules. For >10,000 clients, consider nftables sets.
- **Why not VRF**: VRF (Virtual Routing and Forwarding) creates separate L3 routing domains. It's elegant but requires creating a VRF device per client, moving the TUN interface into it, and managing per-VRF routing tables. This is heavyweight for a VPN server where all clients share the same TUN interface. VRF is better suited for network routers with multiple physical interfaces.

### Evaluated: Linux network namespaces (heavy)
- **Pros**: Complete isolation — each client gets its own network stack (interfaces, routing tables, iptables, sockets). No possibility of client-to-client traffic.
- **Cons**: Requires creating a TUN interface per client inside each namespace, moving packets between namespaces via veth pairs. Massive overhead: each namespace consumes ~1MB of kernel memory, and packet crossing involves context switches. Not practical for >100 clients.
- **Rejected**: Too heavy for a VPN server. Network namespaces are designed for container isolation, not VPN multi-tenancy.

### Evaluated: Linux VRF (lighter than namespaces, heavier than iptables)
- **Pros**: L3 isolation with separate routing tables. No L2 impact. Can be nested in namespaces. VRF devices are lightweight (~100 bytes each).
- **Cons**: Requires `ip link add type vrf` per client, assigning the TUN interface to a VRF (but TUN is shared — can't be in multiple VRFs). Would need per-client TUN interfaces or veth pairs into VRFs. Complex setup. Requires kernel ≥4.8 (most modern distros have this).
- **Rejected**: The shared TUN interface is the fundamental problem — VRF requires interfaces to be in a single VRF domain. Would need architectural changes to create per-client TUN interfaces, which conflicts with the current single-TUN design.

### Evaluated: eBPF/XDP for source validation
- **Pros**: Kernel-level source IP validation at wire speed (before packets enter the networking stack). Zero-copy, sub-microsecond overhead.
- **Cons**: Requires CAP_BPF, kernel ≥5.0, complex to debug, platform-specific. Overkill for source IP validation which can be done in Rust userspace.
- **Rejected for now**: Userspace validation (Phase 1) is sufficient. eBPF could be a future optimization if validation becomes a bottleneck.

## Stealth/Efficiency Considerations

### Stealth
- **No impact on stealth**: Traffic isolation is server-internal. It does not change the TLS handshake, packet structure, or traffic patterns visible to DPI.
- **Audit logging**: Isolation rule changes are logged for audit (TODO-439) but do not leak to network observers.

### Performance
- **Source IP validation in Rust**: Parsing an IP header is ~20ns (reading 20 bytes). Negligible compared to QUIC decryption (~1μs per packet).
- **iptables rule count**: With 100 clients, 200 per-client rules + 3 global rules = 203 rules. iptables processes ~10M rules/second on modern hardware. 203 rules = ~20μs per packet. Acceptable.
- **For >1000 clients**: Switch to nftables with named sets. A set lookup is O(1) regardless of set size. `nft add rule inet quicfuscate forward ip saddr @clients accept` is O(1).
- **Rule installation/removal**: `iptables -A` and `iptables -D` are each a fork+exec (~5ms). For 100 clients connecting/disconnecting, this is 500ms total. Acceptable for a VPN server (clients connect infrequently). Could be optimized with `iptables-restore` for batch operations.

## Testing Plan

### Unit tests
- `SourceIpValidator::validate`: correct source IP → pass, wrong source IP → drop, malformed packet → drop, IPv4 and IPv6.
- `ClientIsolationManager::install_client_rules`: verify iptables commands are correct (mock `Command::new`).
- Broadcast/multicast address detection.

### Integration tests (require root or CAP_NET_ADMIN)
- Two clients connected to server. Client A sends ping to Client B's TUN IP. Verify packet is dropped (no response from Client B).
- Client A sends packet with Client B's source IP. Verify packet is dropped by source IP validator.
- Client A sends to broadcast address. Verify packet is dropped.
- Client A sends to external IP. Verify packet is forwarded (NAT).
- External service sends to Client A. Verify return traffic is forwarded (ESTABLISHED).
- Client disconnects. Verify per-client rules are removed.
- Server restarts. Verify stale rules are cleaned up (cleanup_stale).

### E2E tests
- 10 clients connected. Each client tries to port-scan every other client's TUN IP. Verify zero responses.
- Each client tries to send with every other client's source IP. Verify all spoofed packets are dropped.
- Each client browses the internet normally. Verify no impact on legitimate traffic.

## Files to Create/Modify

### New files
- `src/implementations/server/isolation.rs` — `SourceIpValidator`, `ClientIsolationManager`
- `tests/isolation_tests.rs` — Integration tests for traffic isolation

### Modified files
- `src/implementations/server/routing.rs` — Add TUN→TUN DROP, broadcast/multicast DROP in `setup_iptables()`; add cleanup in `teardown()` and `cleanup_stale()`
- `src/implementations/server/mod.rs` — Integrate `SourceIpValidator` into TUN write path; integrate `ClientIsolationManager` into session lifecycle
- `src/implementations/server/session.rs` — Call `ClientIsolationManager::install_client_rules` on session create, `remove_client_rules` on session expire
- `src/optimize/telemetry.rs` — Add `PACKETS_DROPPED_SPOOFED_SOURCE`, `PACKETS_DROPPED_CLIENT_TO_CLIENT` counters

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| iptables rule accumulation if clients disconnect uncleanly | `cleanup_stale()` on startup removes all QuicFuscate-tagged rules. Use comment match: `-m comment --comment "quicfuscate-client-<ip>"` for identification. |
| Source IP validation adds latency to hot path | IP header parse is ~20ns. Negligible. If it becomes a bottleneck, move to eBPF/XDP. |
| iptables not available (container without CAP_NET_ADMIN) | Detect at startup. If iptables unavailable, log warning and rely on source IP validation only (weaker isolation). Document the trade-off. |
| nftables/iptables-legacy conflict | Detect which is in use (`iptables --version` or `nft list ruleset`). Use the appropriate tool. Some distros have iptables-nft (iptables syntax, nftables backend) — this works transparently. |
| Per-client rules for 10,000+ clients | Switch to nftables named sets: `nft add element inet quicfuscate clients { <ip> }`. O(1) lookup regardless of client count. |
| IPv6 isolation | Mirror all rules with `ip6tables`. Block `ff00::/8` (multicast). Block TUN→TUN for IPv6. |
| macOS/Windows support | macOS: pf rules with per-client tables. Windows: Windows Firewall with per-client rules. Implement platform-specific modules. Lower priority — Linux is the primary server platform. |

## Completion Criteria

- [ ] Source IP validation drops packets with mismatched source IP before TUN write
- [ ] iptables FORWARD rule drops all TUN→TUN (client-to-client) traffic
- [ ] iptables FORWARD rules drop broadcast and multicast from TUN
- [ ] Per-client FORWARD rules allow only assigned IP to send outbound traffic
- [ ] Per-client FORWARD rules allow only ESTABLISHED return traffic to assigned IP
- [ ] Client A cannot ping, port-scan, or connect to Client B's TUN IP
- [ ] Client A cannot send packets with Client B's source IP
- [ ] Client A cannot send broadcast traffic to all clients
- [ ] Per-client rules are installed on session create and removed on session expire
- [ ] Stale rules are cleaned up on server restart (cleanup_stale)
- [ ] IPv6 isolation mirrors IPv4 (ip6tables)
- [ ] Metrics: spoofed source drops, client-to-client drops, active isolation rules
- [ ] All unit, integration, and E2E tests pass
- [ ] No impact on legitimate client-to-internet traffic
