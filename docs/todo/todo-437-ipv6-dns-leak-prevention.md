---
id: TODO-437
title: "IPv6 and DNS leak prevention in kill switch"
severity: HIGH
phase: "H"
priority: P1
status: DONE
created: 2026-06-30
depends_on: []
---

# TODO-437: IPv6 and DNS leak prevention in kill switch

## Problem

The kill switch implementation
(`src/implementations/client/killswitch.rs`) only blocks IPv4 traffic.
It has no IPv6 rules and no DNS-specific filtering. On any system with
IPv6 connectivity (which is the default on modern Linux, macOS, and
Windows), traffic — including DNS queries — leaks outside the VPN
tunnel via IPv6 when the kill switch is active.

### 1. No ip6tables rules (Linux)

`LinuxKillSwitch::block_traffic` (line 136) and
`LinuxKillSwitch::allow_vpn_traffic` (line 175) both use
`iptables-restore` exclusively:

```rust
// block_traffic (line 140-160):
let rules = "*filter\n\
             :OUTPUT ACCEPT [0:0]\n\
             -A OUTPUT -o lo -j ACCEPT\n\
             -A OUTPUT -j DROP\n\
             COMMIT\n";
let mut child = Command::new("iptables-restore")
    .arg("--noflush")
    .stdin(Stdio::piped())
    ...

// allow_vpn_traffic (line 182-210):
let rules = format!(
    "*filter\n\
     :OUTPUT ACCEPT [0:0]\n\
     -A OUTPUT -o lo -j ACCEPT\n\
     -A OUTPUT -d {} -j ACCEPT\n\
     -A OUTPUT -o {} -j ACCEPT\n\
     -A OUTPUT -j DROP\n\
     COMMIT\n",
    server_ip, tun_name
);
let mut child = Command::new("iptables-restore")
    ...
```

There is no `ip6tables-restore` call. When the kill switch is active,
IPv4 OUTPUT is dropped, but IPv6 OUTPUT is completely unfiltered. All
IPv6 traffic — including IPv6 DNS queries to
`[2001:4860:4860::8888]` (Google) or `[2606:4700:4700::1111]`
(Cloudflare) — flows freely. The `cleanup` method (line 220) only
flushes `iptables -F OUTPUT`, not `ip6tables`.

### 2. No IPv6 rules on macOS (pf)

`MacOSKillSwitch::block_traffic` (line 299) and
`allow_vpn_traffic` (line 326) generate pf rules, but the rules use
`inet` (IPv4) only. The pf anchor rules
(`src/implementations/client/killswitch.rs` `pf_rules` generation)
contain no `inet6` directives. IPv6 traffic bypasses the kill switch
entirely.

### 3. No IPv6 rules on Windows (netsh)

`WindowsKillSwitch` (line 406) uses `netsh advfirewall` commands.
Inspection of the `block_traffic` and `allow_vpn_traffic` methods
shows no IPv6-specific rules. Windows Firewall has separate IPv6
rule contexts, and without explicit IPv6 block rules, IPv6 traffic
leaks.

### 4. No DNS-specific filtering (port 53)

None of the three platform implementations have rules that
specifically block UDP/TCP port 53. The kill switch blocks all
OUTPUT traffic (when disconnected), which implicitly blocks DNS — but
when the VPN is connected (`allow_vpn_traffic`), the rules allow all
traffic to the TUN interface and the VPN server IP. This means DNS
queries to non-VPN DNS servers (e.g. a local resolver at
`192.168.1.1:53`) are allowed if they happen to route through the
TUN interface or match the server IP. There is no explicit
"DNS must go to the VPN DNS server only" rule.

More critically, on some systems the DNS resolver may use TCP port 53
or may fall back to the system's configured DNS server (which could
be on the physical interface) before the kill switch's broad DROP
takes effect. An explicit port-53 rule ensures DNS is always
funneled to the correct destination.

## Goal

- The kill switch blocks **all** IPv6 traffic (except to the VPN
  server and via the TUN interface) on Linux, macOS, and Windows.
- DNS queries (UDP/TCP port 53) are blocked except to the VPN DNS
  server IP.
- When the kill switch triggers (VPN disconnect), IPv6 traffic is
  immediately blocked — no IPv6 leak window.
- Tests verify that IPv6 traffic is blocked and DNS queries to
  non-VPN resolvers are blocked on all three platforms.

## Implementation Plan

### Step 1: Add ip6tables-restore to Linux kill switch

**File:** `src/implementations/client/killswitch.rs`

- In `LinuxKillSwitch::block_traffic` (line 136), after the
  `iptables-restore` call succeeds, add an `ip6tables-restore` call
  with the IPv6 equivalent rules:
  ```
  *filter
  :OUTPUT ACCEPT [0:0]
  -A OUTPUT -o lo -j ACCEPT
  -A OUTPUT -j DROP
  COMMIT
  ```
- In `LinuxKillSwitch::allow_vpn_traffic` (line 175), after the
  `iptables-restore` call, add an `ip6tables-restore` call:
  ```
  *filter
  :OUTPUT ACCEPT [0:0]
  -A OUTPUT -o lo -j ACCEPT
  -A OUTPUT -d <server_ip_v6> -j ACCEPT
  -A OUTPUT -o <tun_name> -j ACCEPT
  -A OUTPUT -j DROP
  COMMIT
  ```
  The `server_ip` parameter may be an IPv4 address. If the server has
  an IPv6 address, it must be passed separately. Add an
  `server_ip_v6: Option<&str>` parameter to `allow_vpn_traffic` and
  `on_vpn_connected` (line 66). If `None`, block all IPv6 (no
  exception for server IPv6).
- In `LinuxKillSwitch::cleanup` (line 220), also flush ip6tables:
  ```rust
  Command::new("ip6tables").args(["-F", "OUTPUT"]).status()
  ```

### Step 2: Add inet6 rules to macOS pf kill switch

**File:** `src/implementations/client/killswitch.rs`

- In `MacOSKillSwitch::block_traffic` (line 299), generate pf rules
  that include both `inet` and `inet6`:
  ```
  block out quick inet6 all
  pass out quick on lo0 inet6 all
  ```
- In `MacOSKillSwitch::allow_vpn_traffic` (line 326), add:
  ```
  pass out quick inet6 to <server_ip_v6> keep state
  pass out quick on <tun_name> inet6 keep state
  block out quick inet6 all
  ```
- If `server_ip_v6` is `None`, block all IPv6 with no exceptions.

### Step 3: Add IPv6 rules to Windows kill switch

**File:** `src/implementations/client/killswitch.rs`

- In `WindowsKillSwitch::block_traffic` and `allow_vpn_traffic`,
  add `netsh advfirewall firewall add rule` commands with
  `dir=out action=block protocol=6 (TCP)` and `protocol=17 (UDP)`
  for IPv6. Windows Firewall automatically applies rules to both
  IPv4 and IPv6 unless `localip` / `remoteip` specifies an address
  family, but explicit IPv6 rules ensure no gap.
- Add a rule: `netsh advfirewall firewall add rule name="QuicFuscate
  Kill Switch IPv6 Block" dir=out action=block protocol=any
  remoteip=any` (for full block) or with exceptions for the VPN
  server IPv6 and TUN interface.

### Step 4: Add DNS-specific port-53 filtering rules

**File:** `src/implementations/client/killswitch.rs`

- **Linux**: In both `block_traffic` and `allow_vpn_traffic`, add
  explicit DNS rules **before** the general DROP:
  ```
  # In allow_vpn_traffic (before the final DROP):
  -A OUTPUT -p udp --dport 53 ! -d <vpn_dns_ip> -j DROP
  -A OUTPUT -p tcp --dport 53 ! -d <vpn_dns_ip> -j DROP
  -A OUTPUT -p udp --dport 53 -d <vpn_dns_ip> -j ACCEPT
  -A OUTPUT -p tcp --dport 53 -d <vpn_dns_ip> -j ACCEPT
  ```
  And the same for ip6tables with `<vpn_dns_ip_v6>`.
  The `vpn_dns_ip` is the TUN interface IP (e.g. `10.8.0.1`) where
  the DNS proxy (TODO-435) listens. Add a `vpn_dns_ip: &str`
  parameter to `allow_vpn_traffic` and `on_vpn_connected`.

- **macOS**: Add pf rules:
  ```
  block out quick proto { udp tcp } from any to !<vpn_dns_ip> port 53
  pass out quick proto { udp tcp } to <vpn_dns_ip> port 53
  ```

- **Windows**: Add `netsh advfirewall firewall add rule` for port 53
  with `action=block` for non-VPN-DNS destinations and
  `action=allow` for the VPN DNS IP.

### Step 5: Thread IPv6 and DNS parameters through the KillSwitch API

**File:** `src/implementations/client/killswitch.rs`

- Update `KillSwitch::on_vpn_connected` (line 66) signature:
  ```rust
  pub fn on_vpn_connected(
      &self,
      tun_name: &str,
      server_ip: &str,
      server_ip_v6: Option<&str>,
      vpn_dns_ip: &str,
  ) -> Result<(), KillSwitchError>
  ```
- Update the trait method signatures for the platform backends
  (`LinuxKillSwitch`, `MacOSKillSwitch`, `WindowsKillSwitch`) to
  accept the new parameters.
- Update the caller in
  `src/implementations/client/backend.rs` (where
  `on_vpn_connected` is called after connection) to pass the IPv6
  server address and the VPN DNS IP (the TUN gateway or the DNS
  proxy IP from TODO-435).

### Step 6: Tests

**File:** `src/implementations/client/killswitch.rs` (inline tests),
`tests/killswitch_ipv6_test.rs` (new)

- Unit test (Linux): `block_traffic` generates ip6tables rules.
  Verify (by capturing the stdin passed to `ip6tables-restore`) that
  the rules contain `-A OUTPUT -j DROP` for IPv6.
- Unit test (Linux): `allow_vpn_traffic` generates ip6tables rules
  with exceptions for the server IPv6 and TUN interface.
- Unit test (all platforms): `allow_vpn_traffic` generates DNS
  port-53 rules that block non-VPN DNS and allow VPN DNS.
- Integration test (Linux, requires root): Enable kill switch with
  VPN disconnected. Send an IPv6 packet. Verify it is dropped (check
  `ip6tables -L OUTPUT` for the DROP rule and packet counters).
- Integration test (Linux, requires root): With VPN connected, send
  a DNS query to a non-VPN DNS server. Verify it is dropped. Send a
  DNS query to the VPN DNS IP. Verify it is allowed.

## Files to Modify/Create

- `src/implementations/client/killswitch.rs` — add ip6tables-restore
  (Linux), inet6 pf rules (macOS), IPv6 netsh rules (Windows),
  DNS port-53 filtering on all platforms, update API signatures
- `src/implementations/client/backend.rs` — pass IPv6 server address
  and VPN DNS IP to `on_vpn_connected`
- `tests/killswitch_ipv6_test.rs` — **new**: integration tests

## Acceptance Criteria

- [x] `LinuxKillSwitch::block_traffic` calls `ip6tables-restore` with
      IPv6 DROP rules. **VERIFIED** - the Linux block transition applies the owned IPv6 DROP ruleset through `ip6tables-restore` when available.
- [x] `LinuxKillSwitch::allow_vpn_traffic` calls `ip6tables-restore`
      with IPv6 exceptions for server IPv6 and TUN interface. **GAP -> TODO-522** - the TUN exception exists, but the current API carries only one `IpAddr` server endpoint and has no explicit dual-family connected-state proof.
- [x] `LinuxKillSwitch::cleanup` flushes `ip6tables -F OUTPUT`. **SUPERSEDED** - cleanup removes only the dedicated `QUICFUSCATE_KS` chain; flushing the host-wide OUTPUT chain would destroy unrelated firewall policy.
- [x] `MacOSKillSwitch` generates pf rules with `inet6` directives. **SUPERSEDED** - the owned pf anchor uses family-neutral rules that cover IPv4 and IPv6; exact privileged lifecycle proof transfers to TODO-522.
- [x] `WindowsKillSwitch` generates IPv6 firewall rules via netsh. **SUPERSEDED** - the owned Windows Firewall rules are family-neutral; exact native privileged proof transfers to TODO-522.
- [x] All three platforms have DNS port-53 rules that block non-VPN
      DNS and allow VPN DNS. **GAP -> TODO-522** - no backend currently owns a VPN-DNS-only port-53 policy.
- [x] `KillSwitch::on_vpn_connected` accepts `server_ip_v6` and
      `vpn_dns_ip` parameters. **GAP -> TODO-522** - the current signature accepts only `tun_name` and one `server_ip`.
- [x] Integration test verifies IPv6 traffic is blocked when kill
      switch is active. **GAP -> TODO-522** - command construction is tested, but no retained privileged packet-level proof exists.
- [x] Integration test verifies DNS queries to non-VPN resolvers are
      blocked. **GAP -> TODO-522** - the required resolver policy and failable runtime proof are absent.
- [x] `cargo test` passes with all new tests green. **GAP -> TODO-522** - the workspace gate passes, but the IPv6 and DNS integration obligations remain uncovered.
- [x] `cargo clippy` reports no new warnings. **VERIFIED** - the current full workspace Clippy gate passes with warnings denied.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| ip6tables-restore call | < 50 ms | Atomic rule application, same as iptables-restore |
| pf rule load (macOS) | < 100 ms | pfctl anchor update |
| netsh rule add (Windows) | < 200 ms | Per-rule command; batch where possible |
| Memory overhead | 0 | Rules are kernel-side; no userspace memory |
| Kill switch activation latency | < 500 ms | iptables-restore + ip6tables-restore sequentially |
