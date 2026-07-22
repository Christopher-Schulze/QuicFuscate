---
id: TODO-448
title: Graceful shutdown (SIGTERM, SIGHUP reload, drain mode, systemd notify)
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: ["TODO-446"]
---

# TODO-448: Graceful Shutdown

## Problem

### Only SIGINT (ctrl_c) is handled

The server run-loop (`src/implementations/server/mod.rs:4014-4018`) handles
only `tokio::signal::ctrl_c()`:

```rust
_ = tokio::signal::ctrl_c() => {
    log::info!("Shutdown signal received");
    self.shutdown_live(b"ctrl_c");
    break;
}
```

The client (`src/main.rs:1634-1640`) similarly handles only ctrl_c:

```rust
_ = tokio::signal::ctrl_c() => {
    info!("Shutdown signal received");
    if let Err(e) = conn.conn.close(true, 0x0, b"ctrl_c") {
        warn!("Client close on ctrl_c failed: {:?}", e);
    }
    break;
}
```

**SIGTERM is not handled.** This is critical because:
- `systemctl stop` sends SIGTERM (not SIGINT)
- Docker `docker stop` sends SIGTERM (with a 10s grace period, then SIGKILL)
- Orchestrated container termination sends SIGTERM (with a configurable grace period)
- Container orchestrators universally use SIGTERM for graceful shutdown

When SIGTERM is received, the default action is to terminate the process
immediately — the `tokio::select!` arm never fires, no cleanup runs, and:
- Active QUIC connections are not closed gracefully (no CONNECTION_CLOSE frame)
- TUN devices are not cleaned up
- iptables/nftables rules are not removed
- Sessions are not properly terminated
- The `Drop` impl for `ServerRuntime` (`src/implementations/server/mod.rs:4265-4272`)
  may run but under signal-delivery conditions, destructors may not complete

### No SIGHUP for config reload

There is no SIGHUP handler. Config reload is only available via the Admin API
(`AdminAction::Reload`, `src/implementations/server/mod.rs:1085-1086`). The
standard Unix convention is to reload config on SIGHUP — operators expect this.

### No drain mode

`shutdown_live()` (`src/implementations/server/mod.rs:4257-4262`) immediately
shuts down everything:

```rust
pub fn shutdown_live(&mut self, reason: &'static [u8]) {
    let live = self.live_mut();
    live.service_signals.shutdown_all();
    live.accept_loop.shutdown();
    live.live_state.shutdown_all(reason);
}
```

This kills all active connections instantly. There is no:
- "Stop accepting new connections" phase
- "Notify existing connections to close" phase
- "Wait for grace period" phase
- "Force close remaining" phase

For a production VPN, this means:
- In-flight file downloads are interrupted
- Active SSH sessions through the VPN are dropped
- No client-side reconnect logic is triggered gracefully (CONNECTION_CLOSE
  with reason "server_shutdown" vs. an abrupt timeout)

### No configurable grace period

There is no `shutdown_grace_secs` config option. The shutdown is instantaneous.

### No systemd notify support

There is no `sd_notify("READY=1")` or `sd_notify("STOPPING=1")` integration.
With `Type=notify` in a systemd unit, systemd:
- Waits for `READY=1` before considering the service started
- Waits for `STOPPING=1` before starting the `TimeoutStopSec` countdown
- Without these, systemd uses `Type=simple` semantics (no startup confirmation,
  no graceful stop signaling)

## Goal

### 2026-07-21 Reality Check

TODO-448 was previously marked DONE after SIGTERM/SIGINT handling was added, but its broader acceptance contract was never implemented. Native ARM64 Omega proof on commit `7e335d3` showed that a listener recreated inside the busy runtime loop could miss both signals and require SIGKILL. Commit `da36a44` fixes that cancellation gap by preserving one pinned listener for the runtime lifetime; the repeated Omega proof stopped an authenticated, loaded server in 108 ms and logged `SIGTERM received` plus `Server stopped`.

The current runtime still closes all clients immediately through `shutdown_live()`. It has no `Running -> Draining -> Stopped` lifecycle, configurable grace period, SIGHUP reload, admin drain/status API, or live wiring for the existing systemd notifier. This TODO is reopened for those original unmet acceptance criteria. The verified signal-delivery fix remains complete and must not regress.

### 2026-07-21 Implementation Checkpoint

The active implementation uses the existing canonical `[engine] shutdown_timeout_ms` setting instead of introducing a duplicate `shutdown_grace_secs` field. Shutdown now enters a shared `Running -> Draining -> Stopped` lifecycle, rejects new clients through the existing accept gate, lets established sessions close until the configured deadline, then queues and flushes QUIC CONNECTION_CLOSE before resource teardown. Authenticated `POST /api/drain` and `GET /api/drain/status` use the same state owner as SIGINT, SIGTERM, and admin shutdown. SIGHUP reuses the validated runtime reload path and refreshes the grace timeout. The existing systemd notifier is wired for READY, RELOADING, STOPPING, STATUS, and watchdog messages; Linux abstract notification sockets use `SocketAddrExt` rather than a pathname containing a NUL byte. The client shutdown branch now flushes its queued CONNECTION_CLOSE datagram before disabling the kill switch and exiting.

Client SIGHUP hot-reload is intentionally excluded from the final contract. Established client connections freeze TLS, QUIC transport parameters, FEC ownership, and fingerprint identity for session coherence, so mutating the original config in place would produce a split-brain session. Client SIGINT/SIGTERM graceful close remains required and live-proven. A future client reload must be a separately specified make-before-break reconnection workflow, not a false in-place reload claim.

### 2026-07-22 Local Verification Checkpoint

The live-process regression harness `scripts/tests/suites/test-graceful-shutdown.sh` now proves two QKey-authenticated TLS clients, SIGHUP reload without restart, immediate rejection of a new connection while draining, active-client reconciliation from two to one after client SIGTERM, deadline force-close, peer close-frame handling by the remaining client, auxiliary-service shutdown, and clean server exit. The configured 5000 ms grace completed in 5118 ms. The proof also exposed and fixed a final-association self-deadlock in `QKeyConnectionTracker::dissociate()`; the tracker now holds one `by_key` write guard through mutation and removal.

Local gates are green: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; and `cargo test --features rust-tests` with 1677 library tests plus all integration and documentation targets passing. CI artifact validation and native Omega lifecycle proof remain before closure.

1. **SIGTERM handler** — graceful shutdown on SIGTERM, identical to ctrl_c but
   with proper drain semantics.

2. **SIGHUP handler** — reload configuration without restarting the process.

3. **Drain mode** — state machine: `Running → Draining → Stopped`.
   - `Running`: normal operation, accepting new connections
   - `Draining`: stop accepting new connections, notify existing connections to
     close, wait for grace period
   - `Stopped`: all connections closed, cleanup complete

4. **Configurable grace period** — `shutdown_grace_secs = 30` in config.

5. **Admin API drain command** — `POST /api/drain` to initiate drain without
   signals.

6. **systemd notify** — `sd_notify("READY=1")` on startup,
   `sd_notify("STOPPING=1")` on shutdown, `sd_notify("RELOADING=1")` on config
   reload.

## Implementation Plan

### Step 1: SIGTERM handler

Add Unix signal handling for SIGTERM alongside ctrl_c:

```rust
// src/implementations/server/mod.rs — in the run-loop tokio::select!

#[cfg(unix)]
{
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())
        .expect("install SIGTERM handler");
    let mut sighup = signal(SignalKind::hangup())
        .expect("install SIGHUP handler");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("SIGINT received, initiating graceful shutdown");
                self.initiate_drain(b"sigint");
                // Don't break immediately — wait for drain
            }
            _ = sigterm.recv() => {
                log::info!("SIGTERM received, initiating graceful shutdown");
                self.initiate_drain(b"sigterm");
            }
            _ = sighup.recv() => {
                log::info!("SIGHUP received, reloading configuration");
                self.reload_config();
                // Continue running
            }
            // ... other select arms (admin actions, recv, etc.) ...

            // Check drain completion
            _ = self.drain_timer.tick(), if self.is_draining() => {
                if self.all_connections_closed() || self.drain_elapsed() {
                    log::info!("Drain complete, shutting down");
                    self.shutdown_live(b"drain_complete");
                    break;
                }
            }
        }
    }
}
```

For Windows (no Unix signals), keep ctrl_c as the only signal:

```rust
#[cfg(not(unix))]
{
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("Ctrl+C received, initiating graceful shutdown");
                self.initiate_drain(b"ctrl_c");
            }
            // ... other arms + drain timer ...
        }
    }
}
```

### Step 2: Shutdown state machine

Add a `ShutdownState` enum and drain logic to `ServerRuntime`:

```rust
// src/implementations/server/mod.rs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownState {
    Running,
    Draining,
    Stopped,
}

pub struct ServerRuntime {
    // ... existing fields ...
    shutdown_state: ShutdownState,
    drain_started: Option<Instant>,
    grace_period: Duration,
}

impl ServerRuntime {
    /// Initiate graceful drain: stop accepting new connections,
    /// notify existing connections to close.
    pub fn initiate_drain(&mut self, reason: &'static [u8]) {
        if self.shutdown_state != ShutdownState::Running {
            return;  // Already draining or stopped
        }
        log::info!("Initiating drain mode (reason: {:?}, grace: {:?})",
            reason, self.grace_period);
        self.shutdown_state = ShutdownState::Draining;
        self.drain_started = Some(Instant::now());

        // 1. Stop accepting new connections
        self.live_mut().accept_loop.stop_accepting();

        // 2. Send CONNECTION_CLOSE to all active connections with reason
        //    "server_shutdown" — this tells clients to reconnect elsewhere
        self.live_mut().live_state.notify_all_shutdown(reason);

        // 3. systemd notify
        #[cfg(feature = "systemd")]
        sd_notify("STOPPING=1");

        // 4. Flush logs
        log::info!("Drain initiated, waiting up to {:?} for connections to close",
            self.grace_period);
    }

    /// Check if all connections have closed.
    pub fn all_connections_closed(&self) -> bool {
        self.live().live_state.session_count() == 0
    }

    /// Check if the grace period has elapsed.
    pub fn drain_elapsed(&self) -> bool {
        self.drain_started
            .map(|start| start.elapsed() >= self.grace_period)
            .unwrap_or(true)
    }

    pub fn is_draining(&self) -> bool {
        self.shutdown_state == ShutdownState::Draining
    }
}
```

### Step 3: Stop accepting new connections

Add a method to the accept loop to stop accepting (but keep processing existing
connections):

```rust
// In the accept loop / live state
pub fn stop_accepting(&self) {
    self.accepting.store(false, Ordering::SeqCst);
    log::info!("Stopped accepting new connections");
}

// In the recv path, check before creating a new session:
if !self.accepting.load(Ordering::SeqCst) {
    // Send CONNECTION_CLOSE with reason "server_draining"
    // Don't create a new session
    continue;
}
```

### Step 4: Notify existing connections

Send a QUIC CONNECTION_CLOSE frame to all active sessions:

```rust
// src/implementations/server/mod.rs — in LiveState or equivalent

pub fn notify_all_shutdown(&self, reason: &[u8]) {
    for (id, session) in self.sessions.iter() {
        log::debug!("Notifying session {} of shutdown", id);
        // Send CONNECTION_CLOSE frame on this connection
        // The transport layer (src/transport/connection.rs:3156) sets
        // is_draining = true on close()
        if let Some(conn) = self.connection_for_session(*id) {
            conn.close(true, 0x0, reason);
        }
    }
}
```

The QUIC CONNECTION_CLOSE frame triggers the client's reconnect logic (if any)
and allows in-flight streams to complete their current RTT before the connection
is fully torn down.

### Step 5: Configurable grace period

Add `shutdown_grace_secs` to config:

```rust
// src/engine/config.rs

pub struct ServerConfig {
    // ... existing fields ...
    /// Grace period in seconds for graceful shutdown.
    /// During this period, new connections are rejected and existing
    /// connections are given time to close cleanly.
    pub shutdown_grace_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            // ...
            shutdown_grace_secs: 30,
        }
    }
}
```

Config file:
```toml
# config/server-linux.default.toml
shutdown_grace_secs = 30
```

### Step 6: SIGHUP config reload

Wire SIGHUP to the existing `AdminAction::Reload` path:

```rust
_ = sighup.recv() => {
    log::info!("SIGHUP received, reloading configuration");
    #[cfg(feature = "systemd")]
    sd_notify("RELOADING=1");

    if let Err(e) = self.reload_config_from_file() {
        log::error!("Config reload failed: {}", e);
    } else {
        log::info!("Configuration reloaded successfully");
    }

    #[cfg(feature = "systemd")]
    sd_notify("READY=1");
}
```

The `reload_config_from_file()` method re-reads the config file and applies
non-disruptive changes (log levels, bandwidth limits, stealth config) without
dropping active connections.

### Step 7: Admin API drain command

Add a drain endpoint to the admin API:

```rust
// src/implementations/server/admin_http.rs

("POST", "/api/drain") => {
    if !admin_shutdown_enabled() {
        return text_response(404, "Not Found");
    }
    let resp = handler.handle_drain();
    log_action(peer, "drain", "-", resp.success);
    admin_json_response(&resp)
}

("GET", "/api/drain/status") => {
    admin_json_response(&handler.handle_drain_status())
}
```

```rust
// In the handler
pub fn handle_drain(&self) -> AdminResponse {
    self.actions.send(AdminAction::Drain).map(|_| {
        AdminResponse::ok_with_message("Drain initiated".to_string())
    }).unwrap_or(AdminResponse::error("Failed to initiate drain"))
}

pub fn handle_drain_status(&self) -> AdminResponse {
    AdminResponse::ok_with_data(serde_json::json!({
        "state": format!("{:?}", self.shutdown_state),
        "active_connections": self.session_count(),
        "grace_period_secs": self.grace_period.as_secs(),
        "drain_elapsed_secs": self.drain_started
            .map(|s| s.elapsed().as_secs()).unwrap_or(0),
    }))
}
```

Add `AdminAction::Drain` to the action enum and handle it in the run-loop:

```rust
AdminAction::Drain => {
    log::info!("Admin API drain requested");
    self.initiate_drain(b"admin_drain");
}
```

### Step 8: systemd notify integration

Add optional systemd support via the `systemd` feature:

```toml
# Cargo.toml
[dependencies]
sd-notify = { version = "0.4", optional = true }

[features]
systemd = ["dep:sd-notify"]
```

```rust
// src/systemd.rs (new file)
#[cfg(feature = "systemd")]
pub fn notify(state: &str) {
    if let Err(e) = sd_notify::notify(true, &[state]) {
        log::debug!("sd_notify failed: {}", e);
    }
}

#[cfg(not(feature = "systemd"))]
pub fn notify(_state: &str) {}
```

Call at appropriate points:
- After server startup (socket bound, ready to accept): `notify("READY=1")`
- On drain/shutdown: `notify("STOPPING=1")`
- On config reload: `notify("RELOADING=1")` then `notify("READY=1")`
- Periodic watchdog: `notify("WATCHDOG=1")` (if `WatchdogSec` is set in unit)

Example systemd unit file (document in docs):

```ini
# /etc/systemd/system/quicfuscate.service
[Unit]
Description=QuicFuscate VPN Server
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/quicfuscate server --config /etc/quicfuscate/quicfuscate.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=45
Restart=on-failure
RestartSec=5
WatchdogSec=30
CapabilityBoundingSet=NET_ADMIN
AmbientCapabilities=NET_ADMIN
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
```

### Step 9: Client-side graceful shutdown

Update the client (`src/main.rs:1634-1640`) to handle SIGTERM:

```rust
#[cfg(unix)]
{
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())
        .expect("install SIGTERM handler");
    let mut sighup = signal(SignalKind::hangup())
        .expect("install SIGHUP handler");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received, shutting down");
                self.close_connection(b"sigint");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down");
                self.close_connection(b"sigterm");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading client config");
                self.reload_config();
            }
            // ... other arms ...
        }
    }
}
```

## Files to Modify/Create

- `src/implementations/server/mod.rs:4014-4018` — add SIGTERM/SIGHUP handlers,
  drain state machine, drain timer
- `src/implementations/server/mod.rs:4257-4262` — refactor `shutdown_live()`
  into `initiate_drain()` + `force_shutdown()`
- `src/implementations/server/mod.rs` — add `ShutdownState` enum, drain fields
  to `ServerRuntime`
- `src/implementations/server/admin_http.rs:~2740` — add `/api/drain` and
  `/api/drain/status` endpoints, `AdminAction::Drain`
- `src/main.rs:1634-1640` — add SIGTERM/SIGHUP handlers for client
- `src/engine/config.rs` — add `shutdown_grace_secs` to `ServerConfig`
- `src/systemd.rs` (new) — `sd_notify` wrapper
- `Cargo.toml` — add `sd-notify` optional dependency, `systemd` feature
- `config/server-linux.default.toml` — add `shutdown_grace_secs = 30`
- `docs/DOCUMENTATION.md` — document graceful shutdown, drain mode, systemd unit

## Acceptance Criteria

- `kill -TERM <pid>` triggers graceful shutdown (not instant termination)
- `kill -INT <pid>` (ctrl_c) triggers graceful shutdown (existing behavior preserved)
- `kill -HUP <pid>` triggers config reload (no shutdown)
- On SIGTERM: server stops accepting new connections immediately
- On SIGTERM: existing connections receive CONNECTION_CLOSE frame with reason
  "sigterm" (or "server_shutdown")
- On SIGTERM: server waits up to `shutdown_grace_secs` for connections to close
- On SIGTERM: after grace period, remaining connections are force-closed
- On SIGTERM: cleanup runs (TUN destroyed, iptables/nftables rules removed,
  sessions cleaned up)
- `POST /api/drain` initiates drain mode without a signal
- `GET /api/drain/status` returns current state, active connection count,
  elapsed drain time
- With `[engine] shutdown_timeout_ms = 5000`: drain completes within 5-6 seconds
- With all connections closed before grace period: drain completes immediately
  (doesn't wait full grace period)
- With `systemd` feature: `sd_notify("READY=1")` is sent after startup
- With `systemd` feature: `sd_notify("STOPPING=1")` is sent on drain initiation
- With `systemd` feature: `sd_notify("RELOADING=1")` is sent on SIGHUP reload
- Client handles SIGTERM: sends CONNECTION_CLOSE, exits cleanly
- Client SIGHUP in-place reload is explicitly excluded; a future implementation must use make-before-break reconnection
- Docker `docker stop` (sends SIGTERM): server drains gracefully within
  Docker's grace period
- Orchestrated container termination: server drains within the configured grace period
- `cargo clippy --lib -- -D warnings` is clean (with and without `systemd` feature)
- No panics during shutdown sequence

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Signal handler install | < 1ms | tokio::signal::unix::signal() |
| Drain initiation | < 5ms | Stop accept + notify all connections |
| CONNECTION_CLOSE send (per connection) | < 1ms | QUIC close frame encode + send |
| Grace period wait | configurable | shutdown_grace_secs (default 30s) |
| Force shutdown | < 5ms | Cleanup TUN, firewall, sessions |
| Config reload (SIGHUP) | < 100ms | Re-read file + apply non-disruptive changes |
| sd_notify call | < 1ms | Unix socket write to systemd |
| Memory overhead | ~64 bytes | ShutdownState + Instant + Duration |
