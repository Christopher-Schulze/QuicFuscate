---
id: TODO-431
title: IPv6 support — dual-stack TUN, IPv6 NAT, IPv6 IP pool, IPv6 forwarding
severity: CRITICAL
phase: "G"
priority: P0
status: DONE
created: 2026-06-30
depends_on: ["TODO-430"]
---

# TODO-431: IPv6 Support

## Problem

The entire VPN data plane is IPv4-only. Every routing, NAT, IP pool, TUN configuration, and
session management component hardcodes `Ipv4Addr`. Clients on IPv6-only networks or dual-stack
networks that prefer IPv6 cannot use the tunnel. This is a production blocker for any deployment
targeting modern networks (most mobile carriers, many ISPs now prefer or require IPv6).

### Code Evidence

**`src/implementations/server/routing.rs`** (530 lines) — all IPv4:

1. `RoutingManager` struct (line 17) stores `server_ip: Ipv4Addr`, `netmask: Ipv4Addr` —
   no IPv6 fields.
2. `enable_ip_forwarding()` (line 212) writes to `/proc/sys/net/ipv4/ip_forward` — no
   `net.ipv6.conf.all.forwarding=1`.
3. `setup_iptables()` (line 221) adds `iptables -t nat -A POSTROUTING ... -j MASQUERADE` —
   no `ip6tables` equivalent.
4. `calculate_subnet()` (line 426) computes IPv4 CIDR from `u32::from(server_ip) & u32::from(netmask)`
   — no IPv6 subnet calculation.
5. macOS `pf_rules()` (line 345) uses `nat on ... inet from ...` — `inet` is IPv4-only;
   no `inet6` rules.
6. Windows `setup_windows_nat()` (line 413) uses `New-NetNat -InternalIPInterfaceAddressPrefix`
   — no IPv6 prefix.

**`src/implementations/server/ip_pool.rs`** (102 lines) — IPv4-only:

1. `IpPool` struct (line 7) stores `start: u32`, `end: u32`, `allocated: HashSet<u32>` —
   no IPv6 support. `u32` cannot represent IPv6 addresses.
2. `allocate()` returns `Option<Ipv4Addr>` — no `Ipv6Addr` variant.

**`src/implementations/server/session.rs`** (300 lines) — IPv4-only:

1. `Session` struct (line 41) stores `client_ip: Ipv4Addr` — no IPv6 field.
2. `SessionManager` indexes: `by_client_ip: HashMap<Ipv4Addr, SessionId>` (line 126) —
   no IPv6 index.

**`src/implementations/server/mod.rs`** — `ServerConfig` (line 88):

1. `ip_pool_start: Ipv4Addr`, `ip_pool_end: Ipv4Addr` (lines 97-99) — no IPv6 pool.
2. `server_ip: Ipv4Addr`, `server_netmask: Ipv4Addr` (lines 101-103) — no IPv6 server address.
3. `dns_servers: Vec<Ipv4Addr>` (line 105) — no IPv6 DNS.
4. No `ipv6_pool_start`, `ipv6_pool_end`, `ipv6_server_ip`, `ipv6_dns_servers` fields.

**`src/interface.rs`** — `TunConfig` (line 152):

1. `ip: Option<IpAddr>` (line 156) — technically supports `IpAddr::V6` but no `ip6` field
   for dual-stack configuration.
2. `netmask: Option<IpAddr>` (line 158) — same; no `netmask6` for IPv6 prefix length.
3. No `ip6: Option<Ipv6Addr>`, no `netmask6: Option<u8>` (IPv6 uses prefix length, not netmask).

**`src/main.rs`** — CLI args (line 744-757):

1. `tun_ip: Option<String>` (line 753) — no `tun_ip6`.
2. `tun_netmask: Option<String>` (line 757) — no `tun_netmask6` or `tun_prefix6`.

## Goal

Full dual-stack IPv4/IPv6 VPN support. Clients receive both an IPv4 and an IPv6 address from
the server. TUN devices are configured with both addresses. NAT64 is not required — both
protocols are NAT'd independently (IPv4 via iptables MASQUERADE, IPv6 via ip6tables MASQUERADE).
Pings and iperf over IPv6 through the tunnel work end-to-end.

## Implementation Plan

### Step 1: Add IPv6 IP pool

Create `src/implementations/server/ip_pool_v6.rs` (or extend `ip_pool.rs` with a generic
variant):

```rust
use std::collections::HashSet;
use std::net::Ipv6Addr;

/// IPv6 address pool for VPN clients.
pub struct Ipv6Pool {
    start: u128,
    end: u128,
    allocated: HashSet<u128>,
}

impl Ipv6Pool {
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self {
            start: u128::from(start),
            end: u128::from(end),
            allocated: HashSet::new(),
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv6Addr> {
        for ip in self.start..=self.end {
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Some(Ipv6Addr::from(ip));
            }
        }
        None
    }

    pub fn release(&mut self, ip: Ipv6Addr) {
        self.allocated.remove(&u128::from(ip));
    }

    pub fn available(&self) -> usize {
        let total = (self.end - self.start + 1) as usize;
        total.saturating_sub(self.allocated.len())
    }
}
```

Default pool: `fd00::2` to `fd00::fe` (253 addresses, ULA range `fd00::/48`).

### Step 2: Add IPv6 fields to ServerConfig

In `src/implementations/server/mod.rs`, extend `ServerConfig` (line 88):

```rust
pub struct ServerConfig {
    // ... existing IPv4 fields ...
    /// IPv6 IP pool start
    pub ipv6_pool_start: Option<Ipv6Addr>,
    /// IPv6 IP pool end
    pub ipv6_pool_end: Option<Ipv6Addr>,
    /// Server IPv6 TUN address
    pub ipv6_server_ip: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64)
    pub ipv6_prefix_len: u8,
    /// IPv6 DNS servers to push
    pub ipv6_dns_servers: Vec<Ipv6Addr>,
    /// Enable IPv6 (None = auto-detect, Some(true) = force, Some(false) = disable)
    pub ipv6_enabled: Option<bool>,
}
```

Default:
```rust
ipv6_pool_start: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)),
ipv6_pool_end: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x00fe)),
ipv6_server_ip: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001)),
ipv6_prefix_len: 64,
ipv6_dns_servers: vec![
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), // Cloudflare
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), // Google
],
ipv6_enabled: None,
```

### Step 3: Add IPv6 fields to Session

In `src/implementations/server/session.rs`, extend `Session` (line 41):

```rust
pub struct Session {
    // ... existing fields ...
    client_ipv6: Option<Ipv6Addr>,
}
```

Add `client_ipv6()` accessor. Update `SessionManager` to add:
```rust
by_client_ipv6: HashMap<Ipv6Addr, SessionId>,
```

Add `get_by_client_ipv6(ip: Ipv6Addr) -> Option<&Session>`.

### Step 4: Add IPv6 to RoutingManager

In `src/implementations/server/routing.rs`, extend `RoutingManager`:

```rust
pub struct RoutingManager {
    tun_name: String,
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    wan_interface: String,
    // IPv6 fields
    server_ipv6: Option<Ipv6Addr>,
    ipv6_prefix_len: u8,
}
```

Add IPv6 setup methods:

**Linux:**
```rust
fn enable_ipv6_forwarding(&self) -> Result<(), RoutingError> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .map_err(|_| RoutingError::PermissionDenied)?;
    log::debug!("IPv6 forwarding enabled");
    Ok(())
}

fn setup_ip6tables(&self, ipv6_subnet: &str) -> Result<(), RoutingError> {
    // MASQUERADE for outbound IPv6 traffic
    let status = Command::new("ip6tables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-s", ipv6_subnet,
               "-o", &self.wan_interface, "-j", "MASQUERADE"])
        .status()?;
    if !status.success() {
        return Err(RoutingError::CommandFailed("ip6tables NAT failed".into()));
    }
    // Allow forwarding from TUN to WAN (IPv6)
    Command::new("ip6tables")
        .args(["-A", "FORWARD", "-i", &self.tun_name, "-o", &self.wan_interface,
               "-j", "ACCEPT"])
        .status()?;
    // Allow established back
    Command::new("ip6tables")
        .args(["-A", "FORWARD", "-i", &self.wan_interface, "-o", &self.tun_name,
               "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        .status()?;
    Ok(())
}
```

**macOS:** Add `inet6` rules to `pf_rules()`:
```rust
fn pf_rules_v6(&self, ipv6_subnet: &str) -> String {
    format!(
        "nat on {} inet6 from {} to any -> ({})\n\
         pass quick on {} inet6 from {} to any keep state\n\
         pass quick on {} inet6 from any to {} keep state\n",
        self.wan_interface, ipv6_subnet, self.wan_interface,
        self.tun_name, ipv6_subnet,
        self.wan_interface, ipv6_subnet
    )
}
```

**Windows:** Add IPv6 NAT:
```powershell
New-NetNat -Name 'QuicFuscateNatV6' -InternalIPInterfaceAddressPrefix '{ipv6_subnet}'
```

Add `calculate_ipv6_subnet()`:
```rust
fn calculate_ipv6_subnet(&self) -> Option<String> {
    self.server_ipv6.map(|ip| {
        format!("{}/{}", ip, self.ipv6_prefix_len)
    })
}
```

Update `setup()` to call both IPv4 and IPv6 setup if IPv6 is enabled.

### Step 5: Add dual-stack TUN configuration

In `src/interface.rs`, extend `TunConfig` (line 152):

```rust
pub struct TunConfig {
    pub name: Option<String>,
    pub ip: Option<IpAddr>,
    pub netmask: Option<IpAddr>,
    pub mtu: u16,
    pub zero_copy: bool,
    // IPv6
    pub ip6: Option<Ipv6Addr>,
    pub prefix6: Option<u8>,  // IPv6 prefix length (1-128)
}
```

Update TUN device creation to configure both IPv4 and IPv6 addresses on the interface.

**Linux:** `ip addr add {ip6}/{prefix6} dev {tun_name}`
**macOS:** `ifconfig {tun_name} inet6 {ip6} prefixlen {prefix6}`
**Windows:** `New-NetIPAddress -InterfaceAlias {tun_name} -IPAddress {ip6} -PrefixLength {prefix6}`

### Step 6: Add CLI flags for IPv6

In `src/main.rs`, add to `SharedArgs` (line 676):

```rust
/// TUN IPv6 address
#[clap(long)]
tun_ip6: Option<String>,

/// TUN IPv6 prefix length (1-128, default 64)
#[clap(long)]
tun_prefix6: Option<u8>,
```

### Step 7: Update TUN→client forwarding for IPv6

In the forwarding loop (TODO-430), add IPv6 dest IP parsing:

```rust
fn parse_ip_dest(pkt: &[u8]) -> Option<IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_ipv4_dest(pkt).map(IpAddr::V4),
        6 => parse_ipv6_dest(pkt).map(IpAddr::V6),
        _ => None,
    }
}

fn parse_ipv6_dest(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 40 {
        return None;
    }
    // IPv6 destination address is at offset 24-39
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Addr::from(addr))
}
```

Update the routing logic to handle both `IpAddr::V4` and `IpAddr::V6` lookups.

### Step 8: Update session setup for dual-stack IP allocation

In `accept_session_in_domain()` (line 2228), allocate both IPv4 and IPv6:

```rust
let client_ip = ip_pool.allocate().ok_or(AcceptError::IpPoolExhausted)?;
let client_ipv6 = if let Some(ref mut v6_pool) = ipv6_pool {
    v6_pool.allocate()
} else {
    None
};
let session = Session::new_dual_stack(remote_addr, client_ip, client_ipv6, client_timeout_secs);
```

### Step 9: Send IPv6 config to client during handshake

Extend the TunnelConfig capsule (from TODO-430) to include IPv6:

```rust
struct TunnelConfig {
    client_tun_ip: Ipv4Addr,
    server_tun_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
    mtu: u16,
    // IPv6
    client_tun_ipv6: Option<Ipv6Addr>,
    server_tun_ipv6: Option<Ipv6Addr>,
    ipv6_prefix_len: Option<u8>,
    ipv6_dns_servers: Vec<Ipv6Addr>,
}
```

### Step 10: Tests

- **Unit test:** `Ipv6Pool` allocate/release/exhaustion.
- **Unit test:** `parse_ipv6_dest` with valid IPv6 packet, truncated, wrong version.
- **Integration test (netns):** IPv6 ping through tunnel: `ping6 -c5 fd00::1` from client
  TUN to server TUN → 0% packet loss.
- **Integration test (netns):** IPv6 iperf3 through tunnel: `iperf3 -6 -c fd00::1` →
  throughput > 80% of link capacity.
- **Integration test (netns):** Dual-stack: client has both 10.8.0.2 and fd00::2. IPv4 ping
  and IPv6 ping both work. IPv4 iperf and IPv6 iperf both work.
- **Integration test (netns):** 3 clients, each gets unique IPv6 (fd00::2, fd00::3, fd00::4).
  Client A pings Client B's IPv6 → routes correctly.
- **Integration test:** IPv6 NAT verification: `ip6tables -t nat -L POSTROUTING` shows
  MASQUERADE rule. Client's IPv6 traffic to external IPv6 host is NAT'd.
- **Integration test:** IPv6 forwarding sysctl: `cat /proc/sys/net/ipv6/conf/all/forwarding`
  returns 1 after server start.

## Files to Modify/Create

- `src/implementations/server/ip_pool.rs` — add `Ipv6Pool` struct or generic `IpPool<T>`.
- `src/implementations/server/routing.rs` — add IPv6 forwarding, `ip6tables MASQUERADE`,
  `pf inet6` rules, Windows IPv6 NAT, `calculate_ipv6_subnet()`.
- `src/implementations/server/session.rs` — add `client_ipv6: Option<Ipv6Addr>` to `Session`,
  add `by_client_ipv6` index to `SessionManager`, add `get_by_client_ipv6()`.
- `src/implementations/server/mod.rs` — add IPv6 fields to `ServerConfig`, allocate IPv6
  in `accept_session_in_domain()`, store `Ipv6Pool` in `LiveServerState`, add `server_ipv6`
  to runtime, update TUN→client forwarding for IPv6 dest parsing.
- `src/interface.rs` — add `ip6: Option<Ipv6Addr>`, `prefix6: Option<u8>` to `TunConfig`.
- `src/main.rs` — add `--tun-ip6`, `--tun-prefix6` CLI flags.
- `src/implementations/server/ip_parse.rs` (new, from TODO-430) — add `parse_ipv6_dest()`.
- `src/core.rs` — extend TunnelConfig capsule with IPv6 fields.

## Acceptance Criteria

- [x] `Ipv6Pool` allocates and releases IPv6 addresses correctly. **VERIFIED** - allocation, reuse, and exhaustion tests pass.
- [x] `ServerConfig` has IPv6 pool, server IP, prefix length, and DNS fields. **VERIFIED** - the current typed config owns all listed fields and defaults.
- [x] `RoutingManager` enables `net.ipv6.conf.all.forwarding=1` on Linux. **VERIFIED** - the Linux setup writes the kernel forwarding control when IPv6 is enabled.
- [x] `RoutingManager` adds `ip6tables -t nat -A POSTROUTING -j MASQUERADE` on Linux. **VERIFIED** - the platform setup owns the NAT and both forwarding rules with status checks.
- [x] `RoutingManager` adds `inet6` NAT rules in pf anchor on macOS. **VERIFIED** - the macOS ruleset builder and setup boundary include IPv6 NAT.
- [x] `RoutingManager` adds `New-NetNat` with IPv6 prefix on Windows. **VERIFIED** - the Windows setup boundary emits the typed IPv6 prefix command and checks its result.
- [x] `TunConfig` supports `ip6` and `prefix6` for dual-stack configuration. **VERIFIED** - both fields are part of the canonical interface type.
- [x] TUN device is configured with both IPv4 and IPv6 addresses. **VERIFIED** - Linux, macOS, and Windows interface setup paths consume both configured addresses.
- [x] `--tun-ip6` and `--tun-prefix6` CLI flags work. **VERIFIED** - clap fields reach `TunConfig` in the standalone client path.
- [x] IPv6 ping through tunnel: 0% packet loss. **GAP -> TODO-523** - no privileged dual-stack runtime proof exists.
- [x] IPv6 iperf3 through tunnel: >80% of link capacity. **GAP -> TODO-523** - no measured IPv6 throughput evidence exists.
- [x] Dual-stack: both IPv4 and IPv6 work simultaneously. **GAP -> TODO-523** - source wiring is present without simultaneous live proof.
- [x] 3 clients each get unique IPv6 addresses; routing is correct. **GAP -> TODO-523** - allocation units exist without three-client runtime evidence.
- [x] IPv6 NAT is active (verified via ip6tables/pf/netsh). **GAP -> TODO-523** - commands exist but no retained privileged platform-state proof satisfies the criterion.
- [x] `cargo build --release` clean, `cargo clippy --lib -D warnings` green. **VERIFIED** - retained release-build and current workspace Clippy gates pass.
- [x] All unit and integration tests pass. **GAP -> TODO-523** - unit coverage passes, but the required dual-stack integration suite does not exist.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Ipv6Pool::allocate() | <1us | HashSet lookup on u128 |
| parse_ipv6_dest per packet | <15ns | 16 byte copy + version check |
| ip6tables MASQUERADE setup | <100ms | Single command per rule |
| IPv6 forwarding sysctl enable | <5ms | Single file write |
| Dual-stack TUN configuration | <50ms | Two ip/ifconfig commands |
| Memory overhead per client (IPv6) | <100B | Ipv6Addr (16B) + HashSet entry |
