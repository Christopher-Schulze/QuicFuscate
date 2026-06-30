---
id: TODO-444
title: "nftables backend for kill switch and routing (auto-detection with iptables fallback)"
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: []
---

# TODO-444: nftables Backend for Kill Switch and Routing

## Goal
Add a nftables backend for both the client kill switch and server routing/NAT, with automatic detection of the available backend (`nft` binary + kernel module) and graceful fallback to iptables when nftables is unavailable. The backend must be configurable via `firewall_backend = "auto" | "nftables" | "iptables"` and use atomic transaction-based rule application via `nft -f` batch files or the `nftables` crate's JSON API.

## Current State (verified against code)

### Kill switch uses iptables exclusively
`src/implementations/client/killswitch.rs:148-590` — `LinuxKillSwitch` uses `iptables` / `iptables-restore` / `ip6tables` / `ip6tables-restore`:
- `ensure_chain()` (line 173): creates `QUICFUSCATE_KS` chain in both iptables and ip6tables, adds jump from OUTPUT
- `block_traffic()` (line 204): flushes chain, applies block rules via `iptables-restore --noflush`
- `allow_vpn_traffic()` (line 262): allows VPN server IP + TUN interface, drops rest
- `cleanup()` (line 342): flushes chain and removes jump rule
- Uses dedicated chain `QUICFUSCATE_KS` (line 161) to avoid touching user's OUTPUT chain

### Routing uses iptables exclusively
`src/implementations/server/routing.rs:388-455` — `setup_iptables()` on Linux:
- MASQUERADE: `iptables -t nat -A POSTROUTING -s <subnet> -o <wan> -j MASQUERADE` (line 391)
- FORWARD TUN→WAN: `iptables -A FORWARD -i <tun> -o <wan> -j ACCEPT` (line 412)
- FORWARD WAN→TUN: `iptables -A FORWARD -i <wan> -o <tun> -m state --state RELATED,ESTABLISHED -j ACCEPT` (line 431)
- `teardown()` (line 268): removes rules via `iptables -D`
- IPv6 variants via `ip6tables` (line 217-236)

### No nftables code anywhere
No `nft` binary invocation, no `nftables` crate dependency, no `FirewallBackend` trait, no auto-detection logic exists anywhere in the codebase.

### Config has no firewall_backend field
`config/server-linux.default.toml` and `config/quicfuscate.toml` have no firewall backend configuration. `src/engine/config.rs` has no `FirewallConfig` struct.

## Problem Analysis

nftables is the standard firewall framework on modern Linux:
- **Debian 10+** (2019): nftables is default; `iptables` is a compatibility wrapper (`iptables-nft`)
- **Ubuntu 20.04+** (2020): same — `iptables-nft` is default
- **RHEL 8+** / Rocky 8+ / AlmaLinux 8+ (2019): nftables is default and recommended
- **Fedora 32+** (2020): nftables is default

Using raw `iptables` commands on these systems hits the `iptables-nft` compatibility layer, which:
1. Is slower (translation overhead per rule)
2. Can produce inconsistent state (compat layer doesn't always map cleanly)
3. Misses nftables features (sets, maps, stateful objects, atomic transactions)
4. Will eventually be removed when `iptables-legacy` is dropped from distros

The current approach also lacks atomicity — each `iptables -A` is a separate process invocation. If the server crashes mid-setup, rules are left in a partial state. nftables' `nft -f` applies an entire ruleset atomically (all or nothing).

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Firewall Backend Abstraction                   │
│                                                                   │
│  ┌─────────────────┐     ┌──────────────────────────────────┐    │
│  │ detect_backend()│────▶│ FirewallBackendKind             │    │
│  │ (auto/nft/ipt)  │     │   Nftables | Iptables           │    │
│  └─────────────────┘     └──────────────────────────────────┘    │
│          │                                                        │
│          ▼                                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              FirewallBackend trait                        │   │
│  │  fn block_all_traffic()                                   │   │
│  │  fn allow_vpn_traffic(tun_name, server_ip)                │   │
│  │  fn cleanup()                                             │   │
│  │  fn setup_nat(subnet, tun, wan)                           │   │
│  │  fn teardown_nat()                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│          │                        │                              │
│          ▼                        ▼                              │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │ NftablesKS   │         │ IptablesKS   │                      │
│  │ (nft -f -)   │         │ (existing)   │                      │
│  │ Atomic txn   │         │ iptables -A  │                      │
│  │ table inet   │         │ per-rule     │                      │
│  └──────────────┘         └──────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
```

Both backends implement the same trait. The kill switch and routing manager dispatch to the selected backend. nftables uses `table inet quicfuscate_ks` (inet family = IPv4 + IPv6 in one table) for the kill switch and `table ip quicfuscate_nat` + `table inet quicfuscate_fwd` for routing. All rules are applied atomically via `nft -f -` (stdin batch file).

## Implementation Plan

### Step 1: Backend abstraction trait
Create a `FirewallBackend` trait in a new `src/firewall/mod.rs` (or inline in `killswitch.rs`):

```rust
pub enum FirewallBackendKind {
    Nftables,
    Iptables,
}

pub trait FirewallBackend: Send + Sync {
    fn block_all_traffic(&self) -> Result<(), KillSwitchError>;
    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError>;
    fn cleanup(&self) -> Result<(), KillSwitchError>;
}

pub trait NatBackend: Send + Sync {
    fn setup_nat(&self, subnet: &str, tun_name: &str, wan_iface: &str) -> Result<(), RoutingError>;
    fn teardown_nat(&self) -> Result<(), RoutingError>;
}

/// Auto-detect the best available firewall backend.
pub fn detect_backend(config: &FirewallBackendMode) -> FirewallBackendKind {
    match config {
        FirewallBackendMode::Nftables => FirewallBackendKind::Nftables,
        FirewallBackendMode::Iptables => FirewallBackendKind::Iptables,
        FirewallBackendMode::Auto => {
            if nft_available() { FirewallBackendKind::Nftables }
            else { FirewallBackendKind::Iptables }
        }
    }
}

fn nft_available() -> bool {
    if std::process::Command::new("nft").arg("--version").output().is_ok() {
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
        ip6 daddr {server_ip} accept
        oifname "{tun_name}" accept
        counter drop
    }}
}}
"#);
        self.apply_rules(&rules)
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        self.apply_rules("delete table inet quicfuscate_ks\n")
    }

    fn apply_rules(&self, rules: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("nft")
            .arg("-f").arg("-")
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
            return Err(KillSwitchError::CommandFailed("nft -f - failed".to_string()));
        }
        Ok(())
    }
}
```

Key design decisions:
- `table inet quicfuscate_ks` (inet family = IPv4 + IPv6 in one table — replaces separate iptables/ip6tables)
- `delete table` before `table` definition for idempotent atomic application
- `nft -f -` (stdin) for atomic transaction — all rules apply or none do
- Chain hooks `output` at priority 0 with `policy drop`

### Step 3: nftables routing/NAT backend
Implement nftables NAT in `routing.rs`:

```rust
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
```

- NAT uses `table ip quicfuscate_nat` (ip family for IPv4 NAT)
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
}
```

`KillSwitch::new()` calls `detect_backend()` and instantiates the appropriate backend. Add `with_backend(kind)` for explicit config override.

### Step 5: Refactor routing to use backend abstraction
Modify `RoutingManager::setup()` and `teardown()` to detect and dispatch:

```rust
pub fn setup(&self) -> Result<(), RoutingError> {
    self.enable_ip_forwarding()?;
    let subnet = self.calculate_subnet();
    match detect_backend() {
        FirewallBackendKind::Nftables => self.setup_nftables(&subnet),
        FirewallBackendKind::Iptables => self.setup_iptables(&subnet),
    }
}
```

### Step 6: Configuration
Add `firewall_backend` to config:

```rust
pub struct FirewallConfig {
    pub backend: FirewallBackendMode,  // Auto, Nftables, Iptables
}
pub enum FirewallBackendMode { Auto, Nftables, Iptables }
```

```toml
# config/server-linux.default.toml
firewall_backend = "auto"  # "auto" | "nftables" | "iptables"
```

When `backend = "nftables"` but nft is not available, return an error at startup (fail fast). When `backend = "auto"`, detect and log which backend was selected.

### Step 7: Fallback testing
When `backend = "auto"` and nftables is not available, fall back to iptables silently with a warning:
```
WARN killswitch: nftables not available (nft binary not found), falling back to iptables
```

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| nftables interaction | `nft -f -` (CLI batch file via stdin) | Simplest approach; atomic transactions; no additional crate dependency; works on all nftables versions ≥ 0.9.3 |
| Alternative: `nftables` crate v0.6.3 | Considered | Provides typed JSON API via libnftables; 2.1M downloads; but adds dependency and requires libnftables at runtime. Use for Phase II if typed rule construction is needed |
| Table family | `inet` for kill switch, `ip` for NAT | inet = IPv4+IPv6 in one table (replaces separate iptables/ip6tables); NAT is IPv4-only (ip family) |
| Atomic application | `delete table` + `table` definition in one `nft -f -` | Idempotent: all rules apply or none; no partial state on crash |
| Auto-detection | Check `nft --version` + `/sys/module/nf_tables` | Two checks: binary existence + kernel module loaded/built-in |
| Backward compatibility | Keep iptables backend fully functional | iptables still works on older systems; auto-detection picks the right one |

## Stealth/Efficiency Considerations

- **Atomic rule application**: nftables' `nft -f -` applies an entire ruleset in one transaction. If the process crashes mid-application, no partial rules are left — unlike iptables where each `-A` is a separate process.
- **Performance**: nftables rules are compiled into BPF programs in the kernel. Rule lookup is O(1) via sets/maps, vs iptables' O(n) linear chain traversal. For a VPN server with many clients, this reduces per-packet firewall overhead.
- **IPv6 leak prevention**: The `inet` family table handles both IPv4 and IPv6 in one ruleset — no risk of forgetting ip6tables rules (a common IPv6 leak vector).
- **Stealth**: nftables tables are visible via `nft list ruleset`. The table name `quicfuscate_ks` is identifiable. For stealth, consider a generic name like `qf_ks` or allow configuration of the table name.
- **No hot-path impact**: Firewall rules are applied once at startup/connection. The per-packet path is in-kernel BPF — zero userspace overhead.

## Testing Plan

### Unit tests
- `test_nft_available_detection` — mock `nft --version` output; verify detection logic
- `test_nftables_ruleset_generation` — verify generated nftables ruleset text is correct for block/allow/cleanup
- `test_detect_backend_auto_nftables` — when nft is available, auto selects Nftables
- `test_detect_backend_auto_iptables` — when nft is not available, auto selects Iptables
- `test_detect_backend_explicit_nftables` — explicit `Nftables` mode returns Nftables regardless of availability

### Integration tests (require Linux with nftables)
- `test_nftables_killswitch_block` — `nft list table inet quicfuscate_ks` shows correct rules after `block_traffic()`
- `test_nftables_killswitch_allow_vpn` — `nft list table inet quicfuscate_ks` shows allow rules after `allow_vpn_traffic()`
- `test_nftables_killswitch_cleanup` — table is deleted after `cleanup()`
- `test_nftables_routing_setup` — `nft list table ip quicfuscate_nat` shows MASQUERADE rule after `setup()`
- `test_nftables_routing_teardown` — tables are deleted after `teardown()`
- `test_iptables_fallback` — on system without `nft`, kill switch and routing use iptables
- `test_firewall_backend_nftables_unavailable` — `firewall_backend = "nftables"` on system without nft → startup error
- `test_vpn_traffic_flows_nftables` — VPN traffic flows correctly through tunnel with nftables backend
- `test_killswitch_blocks_non_vpn_nftables` — kill switch blocks all non-VPN traffic with nftables backend

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `src/firewall/mod.rs` | Create | `FirewallBackend` trait, `NatBackend` trait, `FirewallBackendKind`, `detect_backend()`, `nft_available()` |
| `src/implementations/client/killswitch.rs:148-590` | Modify | Refactor `LinuxKillSwitch` into `IptablesKillSwitch`, add `NftablesKillSwitch`, add trait dispatch |
| `src/implementations/server/routing.rs:87-98, 268-350, 388-455` | Modify | Add `setup_nftables()`, `teardown_nftables()`, refactor `setup()`/`teardown()` to dispatch by backend |
| `src/engine/config.rs` | Modify | Add `FirewallConfig` with `backend: FirewallBackendMode` field |
| `config/quicfuscate.toml` | Modify | Add `firewall_backend = "auto"` |
| `config/server-linux.default.toml` | Modify | Add `firewall_backend = "auto"` |
| `docs/DOCUMENTATION.md` | Modify | Document nftables backend, auto-detection, config |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| nftables not available on older kernels | Medium | Auto-detection falls back to iptables; explicit `nftables` mode fails fast with clear error |
| `nft -f -` syntax errors silently fail | Medium | Check exit status; log stderr on failure; test ruleset generation |
| nftables rules conflict with existing firewall (firewalld, ufw) | Medium | Use dedicated table name `quicfuscate_ks` / `quicfuscate_nat`; document potential conflicts |
| iptables-nft compatibility layer confusion | Low | Auto-detection checks for `nft` binary + kernel module, not iptables-nft wrapper |
| IPv6 rules missing in nftables | Low | `inet` family handles both IPv4 and IPv6; test with IPv6 traffic |
| Container environments without nftables | Low | Auto-detection falls back; document that containers may need `--cap-add NET_ADMIN` |

## Completion Criteria

- [ ] `detect_backend()` returns `Nftables` on systems with nftables, `Iptables` on systems without
- [ ] Kill switch with nftables: `nft list table inet quicfuscate_ks` shows correct rules after `enable()` / `on_vpn_connected()`
- [ ] Kill switch with nftables: table is deleted after `disable()` / `cleanup()`
- [ ] Routing with nftables: `nft list table ip quicfuscate_nat` shows MASQUERADE rule after `setup()`
- [ ] Routing with nftables: `nft list table inet quicfuscate_fwd` shows FORWARD rules after `setup()`
- [ ] Routing with nftables: tables are deleted after `teardown()`
- [ ] Fallback: on system without `nft`, kill switch and routing use iptables (verified via `iptables -L`)
- [ ] `firewall_backend = "nftables"` on system without nft → startup error
- [ ] `firewall_backend = "auto"` logs which backend was selected
- [ ] VPN traffic flows correctly through tunnel with nftables backend
- [ ] Kill switch blocks all non-VPN traffic with nftables backend
- [ ] `cargo clippy --lib -D warnings` is clean
- [ ] All existing kill switch and routing tests still pass
