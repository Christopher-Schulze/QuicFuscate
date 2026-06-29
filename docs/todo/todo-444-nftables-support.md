---
id: TODO-444
title: nftables backend for kill switch and routing (auto-detection with iptables fallback)
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-444: nftables Backend for Kill Switch and Routing

## Problem

### Kill switch uses legacy iptables only

The Linux kill switch (`src/implementations/client/killswitch.rs:125-240`) uses
`iptables-restore` and `iptables` exclusively:

- `block_traffic()` (line 136): spawns `iptables-restore --noflush` with a
  `*filter` ruleset that drops all OUTPUT except loopback
- `allow_vpn_traffic()` (line 175): spawns `iptables-restore --noflush` with a
  ruleset that allows VPN server + TUN + loopback, drops the rest
- `cleanup()` (line 218): spawns `iptables -F OUTPUT`

### Routing uses legacy iptables only

The server routing manager (`src/implementations/server/routing.rs:58-288`) uses
`iptables` for all Linux firewall/NAT operations:

- `setup()` (line 59): calls `setup_iptables()` which adds NAT MASQUERADE,
  FORWARD ACCEPT, and ESTABLISHED/RELATED rules via `iptables -A`
- `teardown()` (line 100): removes rules via `iptables -D`
- `setup_iptables()` (line 221): three separate `iptables` invocations for
  MASQUERADE, FORWARD, and ESTABLISHED rules

### Why this is a problem

nftables is the standard firewall framework on modern Linux:
- **Debian 10+** (Buster, 2019): nftables is the default backend; `iptables` is
  a compatibility wrapper (`iptables-nft`) that translates to nftables internally
- **Ubuntu 20.04+** (Focal, 2020): same — `iptables-nft` is default
- **RHEL 8+** / CentOS 8+ / Rocky 8+ / AlmaLinux 8+ (2019): nftables is the
  default and recommended firewall; `firewalld` uses nftables backend
- **Fedora 32+** (2020): nftables is default

Using raw `iptables` commands on these systems hits the `iptables-nft`
compatibility layer, which:
1. Is slower (translation overhead per rule)
2. Can produce inconsistent state (compat layer doesn't always map cleanly)
3. Misses nftables features (sets, maps, stateful objects, atomic transactions)
4. Will eventually be removed when `iptables-legacy` is dropped from distros

There is no nftables backend, no auto-detection, and no configuration option to
select the firewall backend.

## Goal

A nftables backend for both kill switch and routing, with automatic detection of
the available backend (`nft` binary + kernel module) and graceful fallback to
iptables when nftables is unavailable. The backend is configurable via
`firewall_backend = "auto" | "nftables" | "iptables"`.

## Implementation Plan

### Step 1: Backend abstraction trait

Create a `FirewallBackend` trait that both iptables and nftables implement:

```rust
// src/implementations/client/killswitch.rs (or new src/firewall/mod.rs)

pub enum FirewallBackendKind {
    Nftables,
    Iptables,
}

pub trait FirewallBackend {
    fn block_all_traffic(&self) -> Result<(), KillSwitchError>;
    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError>;
    fn cleanup(&self) -> Result<(), KillSwitchError>;
}

/// Auto-detect the best available firewall backend.
pub fn detect_backend() -> FirewallBackendKind {
    // 1. Check if `nft` binary exists in PATH
    // 2. Check if nftables kernel module is loaded (or built-in):
    //    `cat /proc/net/netfilter/nf_tables` or check /sys/module/nf_tables
    // 3. If both → Nftables, else → Iptables
    if nft_available() {
        FirewallBackendKind::Nftables
    } else {
        FirewallBackendKind::Iptables
    }
}

fn nft_available() -> bool {
    // Check for `nft` binary
    if std::process::Command::new("nft").arg("--version").output().is_ok() {
        // Check kernel module
        std::path::Path::new("/sys/module/nf_tables").exists()
            || std::path::Path::new("/proc/net/netfilter/nf_tables").exists()
    } else {
        false
    }
}
```

### Step 2: nftables kill switch backend

Implement `NftablesKillSwitch`:

```rust
struct NftablesKillSwitch {
    rules_active: AtomicBool,
    table_name: String,  // "quicfuscate_ks"
}

impl NftablesKillSwitch {
    fn block_all_traffic(&self) -> Result<(), KillSwitchError> {
        // Atomic transaction via `nft -f -` (stdin)
        let rules = r#"
table inet quicfuscate_ks
delete table inet quicfuscate_ks

table inet quicfuscate_ks {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        counter drop
    }
}
"#;
        self.apply_rules(rules)
    }

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        let rules = format!(r#"
table inet quicfuscate_ks
delete table inet quicfuscate_ks

table inet quicfuscate_ks {{
    chain killswitch {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ip daddr {server_ip} accept
        oifname "{tun_name}" accept
        counter drop
    }}
}}
"#);
        self.apply_rules(&rules)
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        // Delete the entire table atomically
        let rules = "delete table inet quicfuscate_ks\n";
        self.apply_rules(rules)
    }

    fn apply_rules(&self, rules: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(rules.as_bytes())
                .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        }

        let status = child.wait()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        if !status.success() {
            return Err(KillSwitchError::CommandFailed(
                "nft -f - failed to apply rules".to_string()
            ));
        }
        Ok(())
    }
}
```

Key design decisions:
- Use `table inet quicfuscate_ks` (inet family = IPv4 + IPv6 in one table)
- Use `delete table` before `table` definition for idempotent atomic application
- Use `nft -f -` (stdin) for atomic transaction — all rules apply or none do
- Chain hooks `output` at priority 0 with `policy drop`
- Rules: accept loopback, accept VPN server IP, accept TUN interface, drop rest

### Step 3: nftables routing/NAT backend

Implement nftables NAT in `routing.rs`:

```rust
#[cfg(target_os = "linux")]
fn setup_nftables(&self, subnet: &str) -> Result<(), RoutingError> {
    let rules = format!(r#"
table ip quicfuscate_nat
delete table ip quicfuscate_nat

table ip quicfuscate_nat {{
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        ip saddr {subnet} oifname != "{tun}" masquerade
    }}
}}

table inet quicfuscate_fwd
delete table inet quicfuscate_fwd

table inet quicfuscate_fwd {{
    chain forward {{
        type filter hook forward priority 0; policy accept;
        iifname "{tun}" oifname "{wan}" accept
        iifname "{wan}" oifname "{tun}" ct state established,related accept
    }}
}}
"#, tun = self.tun_name, wan = self.wan_interface, subnet = subnet);

    apply_nft_rules(&rules)
}

#[cfg(target_os = "linux")]
fn teardown_nftables(&self) -> Result<(), RoutingError> {
    let rules = "delete table ip quicfuscate_nat\ndelete table inet quicfuscate_fwd\n";
    apply_nft_rules(rules)
}
```

Key design decisions:
- NAT uses `table ip quicfuscate_nat` (ip family for NAT, IPv4 only)
- `masquerade` on postrouting for traffic from VPN subnet going out WAN
- `oifname != "tun0"` prevents masquerading traffic that stays on the tunnel
- Forward chain in `table inet quicfuscate_fwd` for IPv4+IPv6
- `ct state established,related` for return traffic (conntrack)

### Step 4: Refactor kill switch to use backend abstraction

Modify `KillSwitch` struct to hold a `Box<dyn FirewallBackend>`:

```rust
pub struct KillSwitch {
    enabled: AtomicBool,
    vpn_connected: AtomicBool,
    #[cfg(target_os = "linux")]
    backend: Box<dyn FirewallBackend>,
    // ...
}

impl KillSwitch {
    pub fn new() -> Self {
        let backend = match Self::select_backend() {
            FirewallBackendKind::Nftables => Box::new(NftablesKillSwitch::new()),
            FirewallBackendKind::Iptables => Box::new(LinuxKillSwitch::new()),
        };
        Self {
            enabled: AtomicBool::new(false),
            vpn_connected: AtomicBool::new(false),
            backend,
        }
    }

    pub fn with_backend(backend: FirewallBackendKind) -> Self {
        // For explicit config override
        // ...
    }
}
```

### Step 5: Refactor routing to use backend abstraction

Modify `RoutingManager::setup()` and `teardown()` to detect and dispatch:

```rust
#[cfg(target_os = "linux")]
pub fn setup(&self) -> Result<(), RoutingError> {
    self.enable_ip_forwarding()?;
    let subnet = self.calculate_subnet();

    match detect_backend() {
        FirewallBackendKind::Nftables => self.setup_nftables(&subnet),
        FirewallBackendKind::Iptables => self.setup_iptables(&subnet),
    }
}

#[cfg(target_os = "linux")]
pub fn teardown(&self) -> Result<(), RoutingError> {
    match detect_backend() {
        FirewallBackendKind::Nftables => self.teardown_nftables(),
        FirewallBackendKind::Iptables => self.teardown_iptables(),
    }
}
```

### Step 6: Configuration

Add `firewall_backend` to the client and server config:

```toml
# config/quicfuscate.toml (client)
firewall_backend = "auto"  # "auto" | "nftables" | "iptables"

# config/server-linux.default.toml (server)
firewall_backend = "auto"
```

Add to `LoggingConfig` or a new `FirewallConfig` in `src/engine/config.rs`:

```rust
pub struct FirewallConfig {
    pub backend: FirewallBackendMode,  // Auto, Nftables, Iptables
}

pub enum FirewallBackendMode {
    Auto,
    Nftables,
    Iptables,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self { backend: FirewallBackendMode::Auto }
    }
}
```

When `backend = "nftables"` but nft is not available, return an error at startup
(fail fast). When `backend = "auto"`, detect and log which backend was selected.

### Step 7: Fallback testing

When `backend = "auto"` and nftables is not available (e.g., old kernel, no `nft`
binary), the code must fall back to iptables silently. Log a warning:

```
WARN killswitch: nftables not available (nft binary not found), falling back to iptables
```

## Files to Modify/Create

- `src/implementations/client/killswitch.rs:125-240` — refactor `LinuxKillSwitch`
  into `IptablesKillSwitch`, add `NftablesKillSwitch`, add `FirewallBackend` trait
  and `detect_backend()`
- `src/implementations/server/routing.rs:58-288` — add `setup_nftables()`,
  `teardown_nftables()`, refactor `setup()`/`teardown()` to dispatch by backend
- `src/engine/config.rs` — add `FirewallConfig` with `backend` field
- `config/quicfuscate.toml` — add `firewall_backend = "auto"`
- `config/server-linux.default.toml` — add `firewall_backend = "auto"`
- `docs/DOCUMENTATION.md` — document nftables backend, auto-detection, config

## Acceptance Criteria

- On a system with nftables: `detect_backend()` returns `Nftables`
- On a system without nftables: `detect_backend()` returns `Iptables`
- Kill switch with nftables: `nft list table inet quicfuscate_ks` shows the
  correct rules after `enable()` / `on_vpn_connected()`
- Kill switch with nftables: `nft list table inet quicfuscate_ks` shows no table
  (or empty) after `disable()` / `cleanup()`
- Routing with nftables: `nft list table ip quicfuscate_nat` shows the MASQUERADE
  rule after `setup()`
- Routing with nftables: `nft list table inet quicfuscate_fwd` shows FORWARD rules
  after `setup()`
- Routing with nftables: tables are deleted after `teardown()`
- Fallback: on a system without `nft`, kill switch and routing use iptables
  (verified by checking `iptables -L` / `iptables -t nat -L`)
- `firewall_backend = "nftables"` on a system without nft → startup error
- `firewall_backend = "auto"` logs which backend was selected
- VPN traffic flows correctly through the tunnel with nftables backend
- Kill switch blocks all non-VPN traffic with nftables backend
- `cargo clippy --lib -D warnings` is clean
- All existing kill switch and routing tests still pass

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Backend detection | < 5ms | Two path existence checks + one process spawn |
| nft rules apply (kill switch) | < 10ms | Single `nft -f -` transaction |
| nft rules apply (routing) | < 10ms | Single `nft -f -` transaction |
| nft rules cleanup | < 5ms | `delete table` transaction |
| iptables fallback apply | < 15ms | `iptables-restore` (existing path) |
| Memory per backend | < 1KB | Struct + AtomicBool + table name string |
