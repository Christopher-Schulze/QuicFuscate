---
id: TODO-454
title: NAT traversal (STUN/TURN/ICE) for restrictive firewalls
severity: HIGH
phase: "J"
priority: P2
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-454: NAT Traversal (STUN/TURN/ICE) for Restrictive Firewalls

## Problem

The transport's NAT handling works only for **cone NAT** (where the public
IP:port mapping is stable). For **symmetric NAT** and restrictive firewalls,
there is no fallback mechanism. The connection simply fails.

Standard QUIC path validation (PATH_CHALLENGE / PATH_RESPONSE) can handle
address changes when the public mapping is predictable, but:

- **Symmetric NAT**: each destination gets a different public IP:port mapping.
  The client doesn't know its public address for a given server, and
  peer-reflexive candidates can't be predicted.
- **Restrictive firewalls**: block incoming UDP entirely. No amount of path
  validation can punch through a firewall that drops all inbound UDP.
- **No relay fallback**: without TURN, if direct connectivity is impossible,
  the connection cannot be established.

There is no STUN, TURN, or ICE implementation anywhere in `src/transport/`.

Evidence:

- `src/transport/` directory listing: `anti_replay.rs`, `batch.rs`, `cc/`,
  `config.rs`, `connection.rs`, `frames.rs`, `h3.rs`, `packet.rs`, `pn.rs`,
  `recovery.rs`, `udpfast.rs`, `xdp.rs`. No `stun.rs`, `turn.rs`, `ice.rs`, or
  `nat.rs`.
- `src/transport/config.rs` — no `stun_servers`, `turn_servers`, `ice_enabled`
  fields.
- `src/transport/connection.rs` — path validation (`initiate_path_validation`,
  `commit_path_validation`) assumes the peer address is directly reachable. No
  candidate gathering, no connectivity checks, no relay.

## Goal

Implement STUN/TURN/ICE for NAT traversal so that QuicFuscate can establish
connections through symmetric NAT and restrictive firewalls:

1. **STUN binding** (RFC 8489) — discover public IP:port (server-reflexive
   candidate).
2. **ICE candidate gathering** — host, server-reflexive (srflx), relay
   candidates.
3. **ICE connectivity checks** — test candidate pairs, select best working
   pair.
4. **TURN relay fallback** (RFC 8656) — relay traffic through TURN server when
   direct connectivity fails (symmetric NAT / restrictive firewall).
5. **NAT keepalive** — STUN binding indications every 15s to maintain NAT
   bindings.
6. **Config**: `stun_servers`, `turn_servers`, `ice_enabled`.

## Implementation Plan

### Step 1: STUN protocol implementation

Create `src/transport/stun.rs`:

```rust
// RFC 8489 STUN message types
pub enum StunMessageType {
    BindingRequest,
    BindingResponse,
    BindingIndication,
    Allocate,         // TURN
    SendIndication,   // TURN
    DataIndication,   // TURN
    CreatePermission, // TURN
    // ...
}

pub struct StunMessage {
    msg_type: StunMessageType,
    magic_cookie: u32,        // 0x2112A442
    transaction_id: [u8; 12],
    attributes: Vec<StunAttribute>,
}

pub enum StunAttribute {
    MappedAddress { family: u8, port: u16, ip: IpAddr },
    XorMappedAddress { family: u8, port: u16, ip: IpAddr },
    Username(String),
    MessageIntegrity([u8; 20]),   // HMAC-SHA1
    Fingerprint(u32),
    Software(String),
    // TURN-specific
    RequestedTransport(u8),
    Lifetime(u32),
    RelayAddress { family: u8, port: u16, ip: IpAddr },
    XorRelayAddress { family: u8, port: u16, ip: IpAddr },
    Data(Vec<u8>),
    XorPeerAddress { family: u8, port: u16, ip: IpAddr },
}
```

Functions:

- `stun_binding_request(server: SocketAddr) -> StunMessage`
- `parse_stun_response(buf: &[u8]) -> Result<StunMessage>`
- `extract_xor_mapped_address(msg: &StunMessage) -> Option<SocketAddr>`
- `stun_binding_indication()` — for keepalive (no response expected)
- `compute_message_integrity(msg: &StunMessage, key: &[u8]) -> [u8; 20]`
  (HMAC-SHA1 per RFC 8489 §15.4)

### Step 2: STUN binding for server-reflexive candidate discovery

```rust
pub async fn stun_discover_public_addr(
    stun_server: SocketAddr,
    local_socket: &UdpSocket,
) -> Result<SocketAddr> {
    let req = StunMessage::binding_request();
    let mut buf = vec![0u8; 1500];
    local_socket.send_to(&req.encode(), stun_server).await?;
    let (n, _) = local_socket.recv_from(&mut buf).await?;
    let resp = parse_stun_response(&buf[..n])?;
    extract_xor_mapped_address(&resp)
        .ok_or(NatError::NoMappedAddress)
}
```

Send a STUN Binding Request to the STUN server. The response contains
`XOR-MAPPED-ADDRESS` — the client's public IP:port as seen by the STUN server.
This is the server-reflexive (srflx) candidate.

### Step 3: ICE candidate gathering

Create `src/transport/ice.rs`:

```rust
pub enum CandidateType {
    Host,       // Local interface address
    Srflx,      // Server-reflexive (from STUN)
    Relay,      // TURN relay
}

pub struct Candidate {
    candidate_type: CandidateType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,  // public addr for srflx/relay
    priority: u32,             // ICE priority formula (RFC 8445 §5.1.2)
    foundation: String,
    component_id: u16,
}
```

Candidate gathering:

1. **Host candidates**: enumerate local interfaces (`std::net::IpAddr` via
   `if_addrs` crate or platform APIs). Each local IP:port is a host candidate.
2. **Server-reflexive candidates**: send STUN binding requests to each
   configured STUN server. Each response yields a srflx candidate.
3. **Relay candidates**: send TURN Allocate requests to each TURN server. Each
   successful allocation yields a relay candidate (the relayed address on the
   TURN server).

Priority computation per RFC 8445 §5.1.2:
```
priority = (2^24) * type_preference + (2^8) * local_preference + (2^0) * component_id
```
Type preferences: host=126, srflx=100, relay=10.

### Step 4: ICE connectivity checks

```rust
pub struct IceAgent {
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    candidate_pairs: Vec<CandidatePair>,
    check_list: VecDeque<CandidatePair>,  // ordered by priority
    nominated_pair: Option<CandidatePair>,
}

pub struct CandidatePair {
    local: Candidate,
    remote: Candidate,
    priority: u64,        // pair priority (RFC 8445 §5.3.2)
    state: PairState,     // Waiting, InProgress, Succeeded, Failed
}
```

Connectivity check flow (RFC 8445 §7):

1. Form candidate pairs (local × remote), sort by pair priority.
2. For each pair (highest priority first): send a STUN Binding Request from the
   local candidate to the remote candidate. A successful response → pair
   `Succeeded`.
3. Use triggered checks: when a STUN request is received from a remote
   candidate, immediately check the matching pair.
4. Once a pair succeeds, nominate it (regular or aggressive nomination).
5. The nominated pair becomes the connection's transport address.

### Step 5: TURN relay (RFC 8656)

Create `src/transport/turn.rs`:

- `TurnClient` struct managing a TURN allocation:
  - `allocate(server, username, credential) -> Result<TurnAllocation>`
  - `create_permission(peer_addr) -> Result<()>` — install a permission for the
    peer's IP.
  - `send_data(peer_addr, data: &[u8]) -> Result<()>` — send via
    `SEND-INDICATION`.
  - `recv_data() -> Result<(SocketAddr, Vec<u8>)>` — receive via
    `DATA-INDICATION`.
  - `refresh() -> Result<()>` — refresh allocation before lifetime expires.
  - `destroy() -> Result<()>` — deallocate.

TURN authentication: RFC 8489 long-term credential mechanism (username, realm,
nonce, HMAC-SHA1 of `MD5(username:realm:password)`).

When ICE determines that only relay candidates work (symmetric NAT), the
connection's UDP socket sends to the TURN relay address, and `TurnClient`
forwards via `SEND-INDICATION`. Incoming data arrives as `DATA-INDICATION` and
is demuxed to the connection.

### Step 6: NAT keepalive

- Send a STUN Binding Indication every 15s on each active path/candidate pair.
- Binding Indications are NOT retransmitted and do not expect a response (RFC
  8489 §7.3.2).
- This prevents NAT bindings from expiring (typical NAT binding timeout is
  30-120s; 15s keepalive is safe).
- For TURN allocations: send `REFRESH` requests before the allocation lifetime
  expires (default refresh at 50% of lifetime).

Integrate into the connection's event loop / timeout processing in
`connection.rs`:

```rust
// In the periodic timeout processing:
if now.duration_since(last_keepalive) > Duration::from_secs(15) {
    self.send_stun_keepalive();
    last_keepalive = now;
}
```

### Step 7: Configuration

In `src/transport/config.rs`:

- Add fields:
  - `ice_enabled: bool` (default `false`).
  - `stun_servers: Vec<String>` (e.g. `["stun:stun.l.google.com:19302"]`).
  - `turn_servers: Vec<TurnServerConfig>`:
    ```rust
    pub struct TurnServerConfig {
        pub uri: String,        // "turn:turn.example.com:3478"
        pub username: String,
        pub credential: String, // password
        pub credential_type: TurnCredentialType, // Password / OAuth
    }
    ```
  - `nat_keepalive_interval_secs: u64` (default `15`).
- Add setters: `set_ice_enabled`, `set_stun_servers`, `set_turn_servers`,
  `set_nat_keepalive_interval`.
- Parse `stun:` and `turn:` URIs into `SocketAddr` + credentials.

### Step 8: Integration with connection establishment

When `ice_enabled == true`:

1. Before sending the QUIC Initial, run ICE candidate gathering + connectivity
   checks.
2. Once a candidate pair is nominated, use that local→remote address pair for
   the QUIC connection.
3. If using a relay candidate, wrap the socket in a `TurnRelaySocket` that
   translates `send_to` / `recv_from` into TURN `SEND-INDICATION` /
   `DATA-INDICATION`.
4. The QUIC connection (`Connection`) is unaware of the relay — it just sees a
   `UdpSocket`-like interface.

When `ice_enabled == false`: current behavior (direct connect, no ICE).

## Files to Modify/Create

- `src/transport/stun.rs` — **new**: STUN protocol (encode/parse, binding
  request/response/indication, XOR-MAPPED-ADDRESS, message integrity).
- `src/transport/ice.rs` — **new**: `IceAgent`, `Candidate`, `CandidatePair`,
  candidate gathering, connectivity checks, nomination.
- `src/transport/turn.rs` — **new**: `TurnClient`, `TurnAllocation`,
  Allocate/CreatePermission/SendIndication/DataIndication/Refresh.
- `src/transport/nat.rs` — **new**: NAT traversal orchestration (STUN discover,
  ICE agent setup, keepalive timer, relay socket wrapper).
- `src/transport/config.rs` — `ice_enabled`, `stun_servers`, `turn_servers`,
  `nat_keepalive_interval_secs` fields + setters + `TurnServerConfig`.
- `src/transport/connection.rs` — integrate ICE candidate gathering before
  handshake; keepalive timer in event loop; relay socket support.
- `src/transport.rs` — re-export `IceAgent`, `Candidate`, `TurnClient`; add
  module declarations.
- `Cargo.toml` — add `if-addrs` (or equivalent) for interface enumeration, if
  not already a dependency.
- Tests: STUN encode/parse, ICE candidate gathering (mock STUN server), TURN
  relay (mock TURN server), symmetric NAT integration test.

## Acceptance Criteria

- [ ] STUN binding request to a real STUN server returns the correct
      server-reflexive address (XOR-MAPPED-ADDRESS).
- [ ] ICE gathers host, srflx, and relay candidates when configured.
- [ ] ICE connectivity checks select a working candidate pair for cone NAT
      (host or srflx candidate succeeds).
- [ ] Client behind symmetric NAT connects via TURN relay — connection
      established and data flows through the relay.
- [ ] NAT keepalive (STUN Binding Indication) is sent every 15s on active
      candidate pairs.
- [ ] TURN allocation is refreshed before lifetime expires (no allocation
      timeout during long-lived connections).
- [ ] `ice_enabled = false` preserves current direct-connect behavior (no
      regression).
- [ ] STUN messages include correct `MESSAGE-INTEGRITY` (HMAC-SHA1) and
      `FINGERPRINT` attributes.
- [ ] TURN long-term credential authentication works (username/realm/nonce/
      credential exchange).
- [ ] Unit tests for STUN message encode/parse round-trip.
- [ ] Unit tests for ICE priority computation (RFC 8445 §5.1.2).
- [ ] Integration test: two peers behind symmetric NAT connect via TURN relay.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| STUN binding (real server) | < 1s | 1 RTT to STUN server |
| ICE candidate gathering (3 servers) | < 3s | Parallel STUN + TURN |
| ICE connectivity checks (10 pairs) | < 5s | Parallel checks |
| TURN relay connection | < 10s | Allocate + permission + ICE |
| Symmetric NAT integration test | < 30s | Full handshake via relay |
| Keepalive interval | 15s | Binding indication, no response |
| TURN refresh | 50% of allocation lifetime | Proactive refresh |
| STUN encode/parse unit tests | < 2s | Round-trip all message types |
| Memory per ICE agent | < 16 KiB | Candidates + pairs + check list |
