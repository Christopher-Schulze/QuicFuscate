---
id: TODO-438
title: "Per-client traffic isolation on the server"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-438: Per-client traffic isolation on the server

## Problem

All VPN clients share a single TUN interface (`qfserver0`) on the
server, and there are no firewall rules preventing client-to-client
traffic. A compromised or curious client can reach another client's
TUN IP address and potentially intercept or probe their traffic.

### 1. Single shared TUN interface

The server creates one TUN interface named `qfserver0`
(`src/implementations/server/mod.rs:847-848`):
```rust
let tun_config = TunConfig {
    name: Some("qfserver0".to_string()),
    ip: engine_config.interface.tun_ip.or(Some(server_config.server_ip.into())),
    ...
};
```

All clients are assigned IPs from a shared `IpPool`
(`src/implementations/server/ip_pool.rs`) with a default range of
`10.8.0.2` – `10.8.0.254` (`src/implementations/server/mod.rs:116-117`).
Every client's TUN IP is in the same `/24` subnet, and all traffic
from all clients enters and exits through the same `qfserver0`
interface.

### 2. No client-to-client FORWARD drop rule

The server's `RoutingManager::setup_iptables`
(`src/implementations/server/routing.rs:221-285`) adds three FORWARD
rules:

1. `MASQUERADE` in `POSTROUTING` (NAT for outbound) — line 223-246
2. `FORWARD -i qfserver0 -o <wan> -j ACCEPT` (TUN→WAN) — line 248-262
3. `FORWARD -i <wan> -o qfserver0 -m state --state RELATED,ESTABLISHED -j ACCEPT` (WAN→TUN return) — line 264-285

There is **no rule that drops client-to-client traffic**. Since all
clients are on the same subnet (`10.8.0.0/24`) and the same interface,
the kernel's default FORWARD behavior (which is `ACCEPT` after
`enable_ip_forwarding` at line 212) allows `10.8.0.2` to send packets
to `10.8.0.3` through the server's routing table. The packets are
forwarded from `qfserver0` back to `qfserver0` — the server acts as a
router between clients.

### 3. No policy routing or VRF isolation

There is no `ip rule` configuration, no VRF (Virtual Routing and
Forwarding) device per client, and no network namespace per client.
The `RoutingManager` (`src/implementations/server/routing.rs:17-46`)
only manages:
- `tun_name: String`
- `server_ip: Ipv4Addr`
- `server_netmask: Ipv4Addr`
- `wan_interface: String`

There is no per-client routing table or isolation boundary.

### 4. No per-client firewall rules

The `Session` struct (`src/implementations/server/session.rs:41-51`)
tracks `client_ip: Ipv4Addr` but this is used only for IP pool
management and session accounting, not for firewall rules. When a
client connects (`accept_session_in_domain` at
`src/implementations/server/mod.rs:2230`), no iptables rules are
added for that client's IP. When a client disconnects, no rules are
removed.

## Goal

- Client A cannot send packets to client B's TUN IP address.
- Client A cannot see client B's traffic (no promiscuous access, no
  ARP spoofing within the VPN subnet).
- The server does not forward traffic between client subnets.
- Isolation is enforced via firewall rules (FORWARD chain drop for
  client-to-client) as the primary mechanism, with optional VRF /
  policy routing as an advanced mode.
- Tests verify that client A cannot ping client B's TUN IP and that
  client A cannot see client B's traffic in a packet capture.

## Implementation Plan

### Step 1: Add client-to-client FORWARD drop rule

**File:** `src/implementations/server/routing.rs`

- In `setup_iptables` (line 221), add a FORWARD drop rule for
  intra-TUN traffic **before** the TUN→WAN accept rule:
  ```rust
  // Drop client-to-client traffic (same subnet, same interface)
  let status = Command::new("iptables")
      .args([
          "-A", "FORWARD",
          "-i", &self.tun_name,
          "-o", &self.tun_name,
          "-j", "DROP",
      ])
      .status()
      .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;
  if !status.success() {
      return Err(RoutingError::CommandFailed(
          "iptables FORWARD client-to-client DROP rule failed".to_string(),
      ));
  }
  ```
- In `teardown` (line 82), add the corresponding delete rule:
  ```rust
  Command::new("iptables")
      .args(["-D", "FORWARD", "-i", &self.tun_name, "-o", &self.tun_name, "-j", "DROP"])
      .status()
  ```

### Step 2: Add per-client firewall rules on connect/disconnect

**File:** `src/implementations/server/mod.rs`

- Create a new function `apply_client_firewall_rules`:
  ```rust
  fn apply_client_firewall_rules(
      client_ip: Ipv4Addr,
      tun_name: &str,
      action: FirewallAction, // Add or Remove
  ) -> Result<(), std::io::Error>
  ```
  - **Add** (on connect): Insert a rule that drops FORWARD traffic
    from this client IP to the TUN subnet (except to the server IP):
    ```
    iptables -A FORWARD -s <client_ip> -d 10.8.0.0/24 ! -d <server_ip> -j DROP
    ```
    And a reverse rule:
    ```
    iptables -A FORWARD -d <client_ip> -s 10.8.0.0/24 ! -s <server_ip> -j DROP
    ```
  - **Remove** (on disconnect): Delete both rules.
- Call `apply_client_firewall_rules` in `accept_session_in_domain`
  (line 2230) after allocating the client IP, and in
  `remove_session_from_domain` (where sessions are removed) before
  releasing the IP.

### Step 3: Add FORWARD chain default policy hardening

**File:** `src/implementations/server/routing.rs`

- In `setup_iptables`, after enabling IP forwarding, set the FORWARD
  chain default policy to `DROP` and explicitly allow only the
  required paths:
  ```
  iptables -P FORWARD DROP
  iptables -A FORWARD -i qfserver0 -o <wan> -j ACCEPT
  iptables -A FORWARD -i <wan> -o qfserver0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -i qfserver0 -o qfserver0 -j DROP  (explicit, redundant with default)
  ```
- In `teardown`, reset the FORWARD policy to `ACCEPT` (to restore the
  system to its pre-VPN state).

### Step 4: Optional VRF isolation mode (advanced)

**File:** `src/implementations/server/vrf.rs` (new)

- Create a `VrfManager` that, when `isolation_mode = "vrf"` is
  configured, creates a VRF device per client:
  ```rust
  pub struct VrfManager {
      vrfs: HashMap<Ipv4Addr, VrfDevice>,
  }
  pub struct VrfDevice {
      name: String,
      table_id: u32,
      master_interface: String,
  }
  ```
  - On client connect: create a VRF device (`ip link add vrf-<id>
    type vrf table <table_id>`), move the client's TUN interface into
    the VRF (`ip link set qfserver0 master vrf-<id>`), and add a
    per-table default route.
  - On client disconnect: destroy the VRF device.
- This is an advanced mode; the default is firewall-based isolation
  (Step 1-3). VRF mode requires Linux kernel ≥ 4.8 and the
  `CONFIG_NET_VRF` option.
- Add `isolation_mode: IsolationMode` to `ServerConfig`
  (`src/implementations/server/mod.rs:104`):
  ```rust
  pub enum IsolationMode {
      Firewall,  // default: iptables FORWARD drop
      Vrf,       // advanced: per-client VRF
  }
  ```

### Step 5: Add macOS and Windows isolation

**File:** `src/implementations/server/routing.rs`

- **macOS**: In `pf_rules` (line 332), add a rule that blocks traffic
  between clients on the TUN subnet:
  ```
  block in quick on <tun_name> inet from <subnet> to <subnet> ! to <server_ip>
  ```
- **Windows**: In `setup_windows_nat` (line 87), add a netsh firewall
  rule that blocks traffic between client IPs. Since Windows uses
  NetNat, client-to-client traffic is less likely (no shared TUN in
  the same way), but if the TUN interface bridges clients, add an
  explicit block rule.

### Step 6: Tests

**File:** `tests/traffic_isolation_test.rs` (new)

- Unit test: `setup_iptables` generates a FORWARD DROP rule for
  `qfserver0` → `qfserver0`. Verify by capturing the iptables
  commands.
- Unit test: `apply_client_firewall_rules` with `Add` action creates
  rules for the client IP. Verify the iptables arguments.
- Integration test (Linux, requires root): Start the server with two
  clients connected (client A at `10.8.0.2`, client B at
  `10.8.0.3`). From client A, attempt to ping `10.8.0.3`. Verify
  the ping fails (100% packet loss).
- Integration test (Linux, requires root): From client A, run
  `tcpdump -i qfserver0` while client B generates traffic. Verify
  client A cannot see client B's packets (the FORWARD DROP rule
  prevents the packets from being forwarded to client A's TUN IP).
- Integration test: Disconnect a client. Verify their per-client
  firewall rules are removed (check `iptables -L FORWARD`).

## Files to Modify/Create

- `src/implementations/server/routing.rs` — add FORWARD DROP for
  client-to-client, set FORWARD default policy to DROP, add
  macOS/Windows isolation rules
- `src/implementations/server/mod.rs` — add
  `apply_client_firewall_rules`, call on connect/disconnect, add
  `IsolationMode` to `ServerConfig`
- `src/implementations/server/vrf.rs` — **new**: VRF isolation mode
  (advanced, Linux only)
- `src/engine/config.rs` — add `isolation_mode` config field
- `tests/traffic_isolation_test.rs` — **new**: integration tests

## Acceptance Criteria

- [ ] `RoutingManager::setup_iptables` adds a `FORWARD -i qfserver0
      -o qfserver0 -j DROP` rule.
- [ ] `RoutingManager::teardown` removes the client-to-client DROP
      rule.
- [ ] FORWARD chain default policy is set to `DROP` during server
      operation and restored to `ACCEPT` on teardown.
- [ ] `apply_client_firewall_rules` adds per-client DROP rules on
      connect and removes them on disconnect.
- [ ] Client A cannot ping client B's TUN IP (integration test).
- [ ] Client A cannot see client B's traffic in tcpdump (integration
      test).
- [ ] macOS pf rules include a client-to-client block.
- [ ] VRF isolation mode is available as an advanced option
      (`isolation_mode = "vrf"`).
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| iptables rule add/remove per client | < 10 ms | Two `iptables -A/-D` commands per connect/disconnect |
| FORWARD DROP rule overhead | 0 | Kernel-level rule, no userspace cost |
| VRF device creation per client | < 50 ms | `ip link add` + `ip link set master` |
| Max clients with per-client rules | 253 | Limited by IpPool range (10.8.0.2–10.8.0.254); iptables handles thousands of rules efficiently |
| Memory per client firewall rule | < 100 bytes | Kernel iptables rule entry |
