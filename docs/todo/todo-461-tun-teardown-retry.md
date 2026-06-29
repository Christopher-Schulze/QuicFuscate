---
id: TODO-461
title: "TUN teardown retry, cleanup verification, and stale-rule cleanup on startup"
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-461: TUN Teardown Retry, Cleanup Verification, and Stale-Rule Cleanup on Startup

## Problem

TUN/routing teardown is a single-shot, best-effort operation with no retry,
no verification, and no startup cleanup of stale state from crashed sessions.
When teardown fails (iptables rule deletion fails, TUN interface is busy,
`/dev/net/tun` is held by another process), the failure is silently logged
at `warn` and stale rules/interfaces persist across restarts.

### 1. Server teardown is single-shot, no retry

`src/implementations/server/mod.rs:889-897`:

```rust
fn teardown(self) {
    if let Some(routing) = self.routing {
        if let Err(e) = routing.teardown() {
            log::warn!("Failed to teardown routing: {:?}", e);
        }
    }
    log::info!("Closing server TUN: {}", self.tun.name());
    drop(self.tun);
}
```

`routing.teardown()` is called once. If it returns `Err`, the error is
logged and nothing else happens. There is no retry, no fallback, no
verification that the iptables rules were actually removed.

### 2. Routing teardown is best-effort, no verification

`src/implementations/server/routing.rs:100-185` — the Linux
`RoutingManager::teardown` issues three separate `iptables -D ...` commands
(MASQUERADE, FORWARD TUN->WAN, FORWARD WAN->TUN established) and logs each
result at `debug` level:

```rust
match Command::new("iptables")
    .args(["-t", "nat", "-D", "POSTROUTING", "-s", &subnet, "-o", &wan, "-j", "MASQUERADE"])
    .status()
{
    Ok(status) => log::debug!("iptables teardown MASQUERADE delete returned status {}", status),
    Err(e) => log::debug!("iptables teardown MASQUERADE delete failed: {}", e),
}
```

Failures are logged at `debug` (not even `warn`), so they are invisible in
default log configurations. No check confirms the rules are gone afterward.

### 3. No cleanup of stale state on startup

There is no `cleanup_on_startup()` path. If the server crashes (OOM, panic,
`kill -9`, power loss), the iptables MASQUERADE/FORWARD rules and the TUN
interface persist. On next start, `routing.setup()` adds **duplicate** rules
(`iptables -A` appends), and `open_server_tun` may fail because the TUN
interface name is already in use. This is a common cause of "server won't
start after crash" bugs.

### 4. Client teardown path has the same gaps

The client teardown path (TUN close + routing/iptables teardown on the
client side) shares the same single-shot, no-retry, no-verify pattern.

## Goal

- Teardown retries up to 3 times with 100ms backoff between attempts.
- After teardown, verify cleanup succeeded: check `iptables -L OUTPUT -n`
  and `iptables -t nat -L POSTROUTING -n` for stale QuicFuscate rules;
  check `ip link show` for a stale TUN interface.
- On the final failed attempt, force cleanup: `iptables -F OUTPUT`,
  `ip link delete <tun>`.
- All teardown failures are logged at `warn` (not `debug`).
- A `cleanup_on_startup()` function runs on server **and** client start to
  remove any stale rules/interfaces from a previous crashed session before
  normal setup proceeds.

## Implementation Plan

### Step 1: Add a retry-with-verification helper

**File:** `src/implementations/server/routing.rs`

Add a generic retry wrapper for teardown operations:

```rust
const TEARDOWN_MAX_ATTEMPTS: u32 = 3;
const TEARDOWN_BACKOFF: Duration = Duration::from_millis(100);

fn teardown_with_retry<F>(label: &str, mut op: F) -> Result<(), RoutingError>
where
    F: FnMut() -> Result<(), RoutingError>,
{
    for attempt in 1..=TEARDOWN_MAX_ATTEMPTS {
        match op() {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::warn!(
                    "teardown '{}' attempt {}/{} failed: {:?}",
                    label, attempt, TEARDOWN_MAX_ATTEMPTS, e
                );
                if attempt < TEARDOWN_MAX_ATTEMPTS {
                    std::thread::sleep(TEARDOWN_BACKOFF);
                }
            }
        }
    }
    Err(RoutingError::TeardownFailed(label.to_string()))
}
```

### Step 2: Verify cleanup after teardown

**File:** `src/implementations/server/routing.rs`

Add verification functions that inspect the live iptables/ip-link state:

```rust
fn stale_masquerade_exists(subnet: &str, wan: &str) -> bool {
    let out = Command::new("iptables")
        .args(["-t", "nat", "-L", "POSTROUTING", "-n", "--line-numbers"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("MASQUERADE") && text.contains(subnet) && text.contains(wan)
        }
        _ => false,
    }
}

fn stale_tun_exists(tun_name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", tun_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
```

### Step 3: Force cleanup on final attempt

**File:** `src/implementations/server/routing.rs`

In `RoutingManager::teardown`, after the retry loop exhausts attempts for
a given rule, force-remove it:

```rust
if stale_masquerade_exists(&subnet, &wan) {
    log::warn!("force-flushing stale MASQUERADE rules for subnet {}", subnet);
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", &subnet, "-o", &wan, "-j", "MASQUERADE"])
        .status();
    // If still present, flush the chain (nuclear option, documented).
    if stale_masquerade_exists(&subnet, &wan) {
        log::warn!("MASQUERADE still present after explicit delete; flushing nat POSTROUTING");
        let _ = Command::new("iptables").args(["-t", "nat", "-F", "POSTROUTING"]).status();
    }
}
```

For the TUN interface, on final failure:

```rust
if stale_tun_exists(tun_name) {
    log::warn!("force-deleting stale TUN interface {}", tun_name);
    let _ = Command::new("ip").args(["link", "delete", tun_name]).status();
}
```

### Step 4: Wrap the existing teardown calls with retry + verify

**File:** `src/implementations/server/routing.rs`

Refactor `RoutingManager::teardown` (lines 100-185) so each of the three
iptables deletions goes through `teardown_with_retry`, and after all three,
run the verification + force-cleanup block. Promote all `log::debug!`
failure lines to `log::warn!`.

### Step 5: Server-side teardown with TUN retry

**File:** `src/implementations/server/mod.rs:889-897`

Update `ServerHostResources::teardown` to retry routing teardown and verify
the TUN is gone:

```rust
fn teardown(self) {
    if let Some(routing) = self.routing {
        let tun_name = self.tun.name().to_string();
        if let Err(e) = teardown_with_retry("routing", || routing.teardown()) {
            log::warn!("Routing teardown exhausted retries: {:?}", e);
        }
        log::info!("Closing server TUN: {}", tun_name);
        drop(self.tun);
        // Verify TUN is gone; force-delete if stale.
        if stale_tun_exists(&tun_name) {
            log::warn!("Stale TUN {} still present after drop; force-deleting", tun_name);
            let _ = Command::new("ip").args(["link", "delete", &tun_name]).status();
        }
    } else {
        log::info!("Closing server TUN: {}", self.tun.name());
        drop(self.tun);
    }
}
```

### Step 6: `cleanup_on_startup()` for stale state from crashed sessions

**File:** `src/implementations/server/routing.rs` (new method),
`src/implementations/server/mod.rs` (call site), and the client startup path.

Add:

```rust
impl RoutingManager {
    /// Remove any stale iptables rules / TUN interfaces left by a
    /// previous crashed session. Called at startup, before `setup()`.
    pub fn cleanup_on_startup(&self) -> Result<(), RoutingError> {
        // Remove stale MASQUERADE/FORWARD rules matching our subnet/tun.
        if stale_masquerade_exists(&self.subnet, &self.wan_interface) {
            log::warn!("stale MASQUERADE rule detected on startup; removing");
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "POSTROUTING", "-s", &self.subnet, "-o", &self.wan_interface, "-j", "MASQUERADE"])
                .status();
        }
        // Remove stale FORWARD rules (both directions).
        // ... analogous -D calls for the FORWARD rules ...
        // Remove stale TUN interface.
        if stale_tun_exists(&self.tun_name) {
            log::warn!("stale TUN {} detected on startup; deleting", self.tun_name);
            let _ = Command::new("ip").args(["link", "delete", &self.tun_name]).status();
        }
        Ok(())
    }
}
```

Call `cleanup_on_startup()` at the top of `ServerHostResources::start`
(before `routing.setup()`), and in the client startup path before TUN
creation. This makes restart-after-crash reliable.

### Step 7: Client teardown path

Apply the same retry + verify + force-cleanup pattern to the client-side
TUN/routing teardown (locate the client `teardown`/`Drop` impl and wrap
analogously).

### Step 8: Tests

**File:** `tests/teardown_retry_test.rs` (new) or extend existing integration
tests.

- **Simulate teardown failure**: mock/stub `iptables` to fail on the first
  attempt and succeed on the second; verify the retry loop calls it 2 times
  and the final result is `Ok`.
- **Simulate persistent failure**: stub `iptables` to always fail; verify 3
  attempts, `warn`-level logs, and the force-cleanup path runs.
- **Stale-rule cleanup on startup**: pre-seed iptables with a MASQUERADE
  rule + a TUN interface, then call `cleanup_on_startup()`; verify both are
  removed.
- **Verification**: after a successful teardown, assert
  `stale_masquerade_exists()` returns `false` and `stale_tun_exists()`
  returns `false`.

## Files to Modify/Create

- `src/implementations/server/routing.rs` — `teardown_with_retry`,
  `stale_masquerade_exists`, `stale_tun_exists`, force-cleanup block,
  `cleanup_on_startup`; refactor `teardown` to use retry + verify; promote
  `debug` logs to `warn`.
- `src/implementations/server/mod.rs` — update
  `ServerHostResources::teardown` (lines 889-897) with retry + TUN verify;
  call `cleanup_on_startup()` at the top of `start`.
- Client teardown/startup path (locate and apply the same pattern).
- `tests/teardown_retry_test.rs` — **new**: retry, persistent-failure,
  stale-cleanup, and verification tests.

## Acceptance Criteria

- [ ] Teardown retries up to 3 times with 100ms backoff between attempts.
- [ ] After teardown, `stale_masquerade_exists()` and `stale_tun_exists()`
      are checked; stale state triggers force-cleanup.
- [ ] On the final failed attempt, `iptables -F` / `ip link delete` is
      invoked as a last resort.
- [ ] All teardown failures are logged at `warn` level (not `debug`).
- [ ] `cleanup_on_startup()` removes stale iptables rules and TUN
      interfaces before normal setup on both server and client.
- [ ] A server that crashed with active rules/TUN starts successfully on
      the next launch (no duplicate rules, no "TUN already exists" error).
- [ ] Test: simulated first-attempt failure → retry succeeds on attempt 2.
- [ ] Test: persistent failure → 3 attempts + force-cleanup invoked.
- [ ] Test: pre-seeded stale state → `cleanup_on_startup()` removes it.
- [ ] `cargo test` passes; `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Normal teardown (succeeds attempt 1) | < 5 ms | Single iptables -D pass |
| Teardown with 1 retry | ~105 ms | 100ms backoff + 2nd attempt |
| Teardown with full retry + force | ~305 ms | 3 attempts + force flush |
| `cleanup_on_startup` (no stale state) | < 5 ms | Two `iptables -L` + one `ip link show` |
| `cleanup_on_startup` (stale state) | < 50 ms | Above + 2-3 delete commands |
| Verification (`stale_*_exists`) | < 5 ms each | Single `iptables -L` / `ip link show` |
