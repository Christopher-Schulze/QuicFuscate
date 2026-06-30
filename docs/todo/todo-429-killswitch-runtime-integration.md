---
id: TODO-429
title: Kill switch runtime integration — wire KillSwitch into ClientRuntime and engine lifecycle
severity: CRITICAL
phase: "G"
priority: P0
status: DONE
created: 2026-06-30
depends_on: ["TODO-422"]
---

# TODO-429: Kill Switch Runtime Integration

## Problem

A fully-implemented, cross-platform kill switch module exists at
`src/implementations/client/killswitch.rs` (566 lines) with complete Linux (iptables-restore),
macOS (pf anchor), and Windows (netsh) backends. The `KillSwitch` struct exposes a clean API:

- `enable()` — blocks all non-loopback traffic via iptables-restore / pf / netsh (line 38)
- `disable()` — removes all firewall rules (line 51)
- `on_vpn_connected(tun_name, server_ip)` — switches to VPN-allow ruleset that permits
  traffic to the server IP and via the TUN interface only (line 64)
- `on_vpn_disconnected()` — re-blocks all traffic (line 75)
- `Drop` impl calls `cleanup()` to guarantee rule removal on process exit (line 92)

**The kill switch is never instantiated.** Evidence:

1. `src/implementations/client/mod.rs:32` re-exports `KillSwitch` (`pub use killswitch::KillSwitch`)
   but no consumer imports it.
2. `src/implementations/client/runtime.rs` (79 lines) defines `RuntimeConfig` and
   `create_runtime()` — it manages the Tokio runtime only and holds **no `KillSwitch` reference**.
   The `ClientRuntime` struct (defined in `src/implementations/client/mod.rs:47`) has no
   kill switch field.
3. `src/engine/engine.rs` (1414 lines) — the `QuicFuscateEngine` struct (line 233) has fields for
   `config`, `state`, `stats`, `callbacks`, `event_sinks`, `client_runtime`, `server_loop_handle`,
   `server_loop_shutdown_tx`, `server_metrics`, `start_time` — **no `KillSwitch` field**.
   A grep for `KillSwitch|kill_switch` in engine.rs returns zero matches.
4. `Engine::connect()` (line 861) transitions to `EngineState::Connected` and calls
   `notify_connected(remote)` but never calls `kill_switch.on_vpn_connected()`.
5. `Engine::disconnect()` (line 926) calls `notify_disconnected(DisconnectReason::Requested)`
   but never calls `kill_switch.on_vpn_disconnected()`.
6. There is no connection-loss detection: `DisconnectReason` (line 512) has variants
   `Requested`, `RemoteClosed`, `Timeout`, `Error`, `IdleTimeout` — but no heartbeat-based
   connection-loss watchdog triggers `on_vpn_disconnected()` automatically.
7. No CLI flag `--kill-switch` exists in `src/main.rs` (the `SharedArgs` struct at line 676
   has no kill-switch field).
8. No config option `kill_switch = true` exists in any TOML config schema.

**Consequence:** If the VPN tunnel drops unexpectedly (server crash, network change, packet
loss exceeding idle timeout), the client's default route remains open. All traffic flows
unencrypted through the user's real IP — a critical privacy leak that defeats the entire
purpose of a VPN. This is a P0 production blocker.

## Goal

Wire the existing `KillSwitch` into the client lifecycle so that:

1. `--kill-switch` CLI flag and `kill_switch = true` config option enable it.
2. On `Engine::connect()` success → `kill_switch.on_vpn_connected(tun_name, server_ip)`.
3. On `Engine::disconnect()` → `kill_switch.on_vpn_disconnected()`.
4. On unexpected connection loss (heartbeat timeout) → `kill_switch.on_vpn_disconnected()`
   fires automatically, blocking all traffic within 100ms.
5. On process exit (clean or crash) → `Drop` impl removes all firewall rules.
6. iptables/pf/netsh rules are verified applied on connect and removed on disconnect.

## Implementation Plan

### Step 1: Add KillSwitch to QuicFuscateEngine struct

In `src/engine/engine.rs`, add a field to `QuicFuscateEngine` (line 233):

```rust
/// Kill switch (client mode, optional)
kill_switch: Option<Arc<KillSwitch>>,
```

Add `use crate::implementations::client::KillSwitch;` to imports.

### Step 2: Add kill_switch to EngineConfig

In the `EngineConfig` struct (wherever it is defined, likely `src/engine/config.rs` or
inline in engine.rs), add:

```rust
/// Enable kill switch (blocks all non-VPN traffic)
pub kill_switch: bool,
```

Default: `false`. Parse from TOML config `kill_switch = true` and from CLI `--kill-switch`.

### Step 3: Instantiate KillSwitch in Engine::start()

In `Engine::start()` (around line 670-784), after creating the client runtime, if
`self.config.kill_switch` is true and mode is Client:

```rust
if self.config.engine.mode == EngineMode::Client && self.config.kill_switch {
    let ks = Arc::new(KillSwitch::new());
    ks.enable().map_err(|e| EngineError::Internal(
        format!("Kill switch enable failed: {}", e)
    ))?;
    self.kill_switch = Some(ks);
    log::info!("Kill switch enabled (firewall blocking until VPN connects)");
}
```

### Step 4: Wire on_vpn_connected into Engine::connect()

In `Engine::connect()` (line 861), after the successful handshake and before
`self.set_state(EngineState::Connected)` (line 914):

```rust
if let Some(ref ks) = self.kill_switch {
    let tun_name = self.config.interface.tun_name.as_deref().unwrap_or("tun0");
    let server_ip = remote.ip().to_string();
    ks.on_vpn_connected(tun_name, &server_ip).map_err(|e| {
        EngineError::Internal(format!("Kill switch VPN-connected failed: {}", e))
    })?;
    log::info!("Kill switch: VPN traffic allowed, non-VPN traffic blocked");
}
```

### Step 5: Wire on_vpn_disconnected into Engine::disconnect()

In `Engine::disconnect()` (line 926), before `self.set_state(EngineState::Running)` (line 940):

```rust
if let Some(ref ks) = self.kill_switch {
    if let Err(e) = ks.on_vpn_disconnected() {
        log::error!("Kill switch on_vpn_disconnected failed: {}", e);
    }
    log::warn!("Kill switch: all traffic blocked (VPN disconnected)");
}
```

### Step 6: Add connection-loss detection (heartbeat watchdog)

Add a heartbeat mechanism to detect unexpected connection loss. In `ClientRuntime`
(`src/implementations/client/mod.rs`), add:

```rust
/// Last time we received any data from the server
last_heartbeat: Arc<AtomicU64>,  // stores Instant::now().as_millis() as u64
/// Heartbeat timeout (ms) — if no data received for this long, trigger connection loss
heartbeat_timeout_ms: u64,
```

In the IO driver's receive path (`src/implementations/client/io_driver.rs`), update
`last_heartbeat` on every received QUIC packet (any frame type — ACK, STREAM, DATAGRAM).

Spawn a watchdog task in the client runtime that checks every 500ms:

```rust
async fn heartbeat_watchdog(
    last_heartbeat: Arc<AtomicU64>,
    timeout_ms: u64,
    disconnect_tx: tokio::sync::mpsc::UnboundedSender<()>,
) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let last = Instant::from_millis(last_heartbeat.load(Ordering::Relaxed) as u128);
        if last.elapsed() > Duration::from_millis(timeout_ms) {
            let _ = disconnect_tx.send(());
            break;
        }
    }
}
```

Default `heartbeat_timeout_ms`: derive from `EngineConfig.connection.idle_timeout_ms` (already
exists, line 72: `transport.set_max_idle_timeout(config.connection.idle_timeout_ms)`). Use
`idle_timeout_ms` as the heartbeat timeout, or a fraction thereof (e.g., 75% to fire before
QUIC's own idle timeout).

### Step 7: Wire connection-loss into Engine

In the engine's event loop (or the client run loop in `src/main.rs`), when the watchdog fires:

```rust
// Connection loss detected
engine.handle_connection_loss(DisconnectReason::Timeout);
```

Add to `QuicFuscateEngine`:

```rust
pub fn handle_connection_loss(&mut self, reason: DisconnectReason) {
    if self.state == EngineState::Connected {
        log::warn!("Connection loss detected: {:?}, activating kill switch", reason);
        if let Some(ref ks) = self.kill_switch {
            if let Err(e) = ks.on_vpn_disconnected() {
                log::error!("Kill switch activation on connection loss failed: {}", e);
            }
        }
        self.set_state(EngineState::Running);
        self.notify_state_change(EngineState::Connected, EngineState::Running);
        self.notify_disconnected(reason);
    }
}
```

### Step 8: Add CLI flag --kill-switch

In `src/main.rs`, add to `SharedArgs` (line 676):

```rust
/// Enable kill switch (blocks all non-VPN traffic when disconnected)
#[clap(long)]
kill_switch: bool,
```

Pass `shared.kill_switch` through to `EngineConfig` in the client command handler
(around line 1076 where `shared.tun` etc. are passed).

### Step 9: Add config option kill_switch = true

In the TOML config parsing (wherever `EngineConfig` is deserialized), ensure `kill_switch`
is a serde field with `#[serde(default)]` so existing configs are unaffected.

### Step 10: Ensure Drop cleanup on crash

The existing `Drop` impl for `KillSwitch` (line 92) calls `cleanup()`. However, on a hard
crash (SIGKILL, segfault), `Drop` does not run. Add a signal handler for SIGTERM/SIGINT
in the client main loop that calls `kill_switch.disable()` before exit. For SIGKILL, the
firewall rules persist — document this and add a `--cleanup-firewall` recovery flag that
removes stale rules on next launch.

### Step 11: Tests

Write integration tests in `src/implementations/client/killswitch.rs` (extend the existing
test module) and in `src/engine/engine.rs` test module:

- **Unit test:** `KillSwitch::new()` + `enable()` → verify `is_enabled() == true`.
- **Unit test:** `enable()` + `disable()` → verify rules removed.
- **Integration test (Linux, requires root):** Start engine with `kill_switch = true`,
  connect → verify `iptables -L OUTPUT` shows DROP rule with VPN exception. Disconnect →
  verify DROP rule persists (traffic still blocked). Clean shutdown → verify rules removed.
- **Integration test (connection loss):** Connect, then kill server → verify
  `on_vpn_disconnected()` fires within `heartbeat_timeout_ms` and iptables shows full DROP.
- **Integration test (macOS):** Same as above but verify `pfctl -a com.quicfuscate.killswitch -s rules`
  shows the anchor rules.
- **Integration test (Windows):** Same but verify `netsh advfirewall` shows the block rules.

## Files to Modify/Create

- `src/engine/engine.rs` — add `kill_switch` field to `QuicFuscateEngine`, wire into
  `connect()`, `disconnect()`, `start()`, `stop()`, add `handle_connection_loss()`.
- `src/engine/config.rs` (or wherever `EngineConfig` is defined) — add `kill_switch: bool` field.
- `src/implementations/client/mod.rs` — add `last_heartbeat` and `heartbeat_timeout_ms` to
  `ClientRuntime`, wire heartbeat updates in IO driver receive path.
- `src/implementations/client/io_driver.rs` — update `last_heartbeat` on every received packet.
- `src/implementations/client/runtime.rs` — spawn heartbeat watchdog task.
- `src/main.rs` — add `--kill-switch` to `SharedArgs`, pass to `EngineConfig`, add
  `--cleanup-firewall` recovery flag, add SIGTERM/SIGINT handler.
- `src/implementations/client/killswitch.rs` — add `cleanup_stale_rules()` static method
  for `--cleanup-firewall` recovery, extend tests.
- Config TOML schema docs — document `kill_switch = true` option.

## Acceptance Criteria

- [ ] `--kill-switch` CLI flag enables kill switch in client mode.
- [ ] `kill_switch = true` in TOML config enables kill switch in client mode.
- [ ] On `Engine::connect()` success, `on_vpn_connected(tun_name, server_ip)` is called.
- [ ] On `Engine::disconnect()`, `on_vpn_disconnected()` is called.
- [ ] On heartbeat timeout (connection loss), `on_vpn_disconnected()` fires automatically
      within 100ms of timeout.
- [ ] Linux: `iptables -L OUTPUT` shows DROP rule with VPN exception after connect.
- [ ] Linux: `iptables -L OUTPUT` shows full DROP (no VPN exception) after disconnect.
- [ ] Linux: iptables rules are removed on clean process exit (Drop impl).
- [ ] macOS: `pfctl -a com.quicfuscate.killswitch -s rules` shows rules after connect.
- [ ] macOS: anchor rules are flushed on disconnect.
- [ ] Windows: `netsh advfirewall firewall show rule` shows block rules after connect.
- [ ] Windows: block rules are removed on disconnect.
- [ ] SIGTERM/SIGINT handler calls `disable()` before exit.
- [ ] `--cleanup-firewall` removes stale rules from a crashed previous session.
- [ ] `cargo build --release` clean, `cargo clippy --lib -D warnings` green.
- [ ] All new unit and integration tests pass.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| KillSwitch::enable() latency | <50ms | iptables-restore is a single atomic call |
| on_vpn_connected() latency | <50ms | iptables-restore with VPN-allow ruleset |
| on_vpn_disconnected() latency | <50ms | iptables-restore with full-block ruleset |
| Heartbeat watchdog CPU | <0.1% | 500ms poll interval, single comparison |
| Connection-loss detection latency | <100ms after timeout | Watchdog poll interval + rule application |
| Drop cleanup latency | <100ms | Single iptables flush or pfctl flush |
| Memory overhead | <1KB | AtomicBool + AtomicU64 + platform struct |
