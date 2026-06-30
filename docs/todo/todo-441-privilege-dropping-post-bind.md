---
id: TODO-441
title: Privilege dropping (post-bind setuid/setgid)
severity: HIGH
phase: "G"
priority: P0
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-441: Privilege dropping (post-bind setuid/setgid)

## Goal
Drop root privileges after all privileged operations (socket bind, TUN setup, iptables/routing setup) are complete. Use Linux capabilities (CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE) instead of full root where possible. setuid/setgid to a dedicated `quicfuscate` user after initialization. Add capability detection at startup, chroot jail option, and macOS sandbox support. Ensure all firewall/routing setup happens BEFORE dropping privileges.

## Current State (verified against code)

### Server startup (runs as root, never drops)
- `src/main.rs:2066-2264` — `run_server()` is the main server entry point. It:
  1. Loads config (line 2102-2158).
  2. Creates transport config (line 2160-2168).
  3. Loads server identity / certs (line 2170).
  4. Creates `ServerRuntime` (line 2219-2228) — this initializes TUN interface, IP pool, routing.
  5. Creates `PreparedStandaloneLaunch` (line 2230-2256) — this sets up admin HTTP, metrics, stealth.
  6. Calls `runtime.run_standalone(launch).await` (line 2261) — enters the main accept loop.
- **At no point does the server drop privileges.** It runs as whatever user started it (typically root, because TUN setup and iptables require root).
- There is no `setuid`, `setgid`, `prctl`, or capability manipulation anywhere in the codebase.

### Privileged operations requiring root
- `src/implementations/server/routing.rs:380-386` — `enable_ip_forwarding()` writes to `/proc/sys/net/ipv4/ip_forward` (requires root or `CAP_SYS_ADMIN`).
- `src/implementations/server/routing.rs:389-456` — `setup_iptables()` runs `iptables` commands (requires `CAP_NET_ADMIN`).
- `src/implementations/server/routing.rs:598-608` — `assign_tun_address_linux()` runs `ip addr add` (requires `CAP_NET_ADMIN`).
- TUN interface creation — `TunInterface::new()` creates a `/dev/net/tun` device (requires `CAP_NET_ADMIN` or root).
- `src/main.rs:2259` — UDP socket bind to port 4433 (or configured port). If port < 1024, requires `CAP_NET_BIND_SERVICE` or root.

### Client-side privileged operations
- `src/implementations/client/killswitch.rs:38-48` — `KillSwitch::enable()` calls `block_traffic()` which runs iptables commands (requires `CAP_NET_ADMIN`).
- `src/implementations/client/killswitch.rs:64-72` — `on_vpn_connected()` calls `allow_vpn_traffic()` which modifies iptables rules.
- TUN interface creation on client side (same as server).

### Existing capability probe (minimal)
- `src/main.rs:986-992` — `Commands::Capabilities` subcommand exists but only checks compile-time feature flags (`benches`, etc.). It does NOT check runtime Linux capabilities.
- `src/main.rs:1209-1217` — The handler outputs JSON with feature flag booleans. No `CAP_NET_ADMIN` check, no UID check, no privilege information.

## Problem Analysis

### Security implications of running as root
1. **Full root access for entire process lifetime**: The server runs as root from start to shutdown. If a vulnerability is exploited (buffer overflow, logic error in packet parsing), the attacker gets full root access to the server.
2. **No principle of least privilege**: The server only needs root for ~5 seconds during startup (bind socket, create TUN, set up iptables). After that, it only needs to read/write to the TUN file descriptor and the UDP socket — both of which remain valid after dropping privileges.
3. **Container escape risk**: In containerized deployments, a root process has higher container escape risk. Dropping to a non-root user significantly reduces the attack surface.
4. **Compliance requirements**: Security standards (PCI-DSS, CIS Benchmarks, NIST 800-53) require least-privilege operation. Running a network service as root violates these standards.

### Why current state is insufficient
- The server runs as root for its entire lifetime, even though privileged operations are only needed during initialization.
- There is no mechanism to drop to a non-root user after setup.
- There is no capability detection — the server doesn't know if it has `CAP_NET_ADMIN` or if it needs full root.
- The `Capabilities` subcommand is a compile-time feature check, not a runtime capability check.
- No chroot or sandbox option exists for defense in depth.

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Server Startup Sequence                         │
│                                                                     │
│  1. Parse CLI args, load config                                     │
│  2. Check capabilities (am I root? Do I have CAP_NET_ADMIN?)       │
│  3. ┌─ PRIVILEGED PHASE ──────────────────────────────────────┐    │
│     │                                                          │    │
│     │  a. Bind UDP socket (CAP_NET_BIND_SERVICE if port <1024) │    │
│     │  b. Create TUN interface (CAP_NET_ADMIN)                 │    │
│     │  c. Assign TUN IP address (CAP_NET_ADMIN)                │    │
│     │  d. Enable IP forwarding (CAP_SYS_ADMIN or root)         │    │
│     │  e. Set up iptables/routing rules (CAP_NET_ADMIN)        │    │
│     │  f. Set up kill switch (CAP_NET_ADMIN) [client only]     │    │
│     │  g. Install DNS redirect rules (CAP_NET_ADMIN)           │    │
│     │  h. Open audit log file (if needs root for chattr +a)    │    │
│     │  i. Set up chroot (if configured)                        │    │
│     │  j. Set up sandbox (macOS: Sandbox framework)            │    │
│     │                                                          │    │
│     └──────────────────────────────────────────────────────────┘    │
│  4. ┌─ PRIVILEGE DROP ─────────────────────────────────────────┐   │
│     │                                                          │    │
│     │  a. Clear supplementary groups                           │    │
│     │  b. setgid(quicfuscate)                                  │    │
│     │  c. setuid(quicfuscate)                                  │    │
│     │  d. Drop all Linux capabilities (prctl PR_SET_NO_NEW_PRIVS│   │
│     │     + capset to empty effective/permitted/inheritable)    │    │
│     │  e. Verify: getuid() != 0, geteuid() != 0                │    │
///     │  f. Log: "Dropped privileges to UID=X GID=Y"             │    │
│     │  g. Audit event: PrivilegeDropped                         │    │
│     │                                                          │    │
│     └──────────────────────────────────────────────────────────┘    │
│  5. ┌─ UNPRIVILEGED PHASE (rest of process lifetime) ──────────┐   │
│     │                                                          │    │
│     │  • Accept loop (UDP socket already bound)                │    │
│     │  • QUIC handshake / crypto                               │    │
│     │  • TUN read/write (fd already open)                      │    │
│     │  • Admin HTTP server (if on port >1024)                  │    │
│     │  • DNS proxy (port 5353, >1024)                          │    │
│     │  • Metrics endpoint                                      │    │
│     │  • Audit logging                                         │    │
│     │                                                          │    │
│     └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Key insight: file descriptors survive privilege drop
Once a socket is bound and a TUN file descriptor is opened, the kernel keeps them valid even after the process drops privileges. The process can continue to `read()`/`write()`/`accept()` on these descriptors as an unprivileged user. This is the fundamental mechanism that makes privilege dropping possible.

## Implementation Plan

### Phase 1: Capability detection at startup
1. Create `src/privilege/mod.rs` with `CapabilityChecker`:
   ```rust
   pub struct CapabilityReport {
       pub is_root: bool,
       pub uid: u32,
       pub euid: u32,
       pub gid: u32,
       pub has_cap_net_admin: bool,
       pub has_cap_net_raw: bool,
       pub has_cap_net_bind_service: bool,
       pub has_cap_sys_admin: bool,
       pub can_drop_privileges: bool,
       pub target_user_exists: bool,
   }
   ```
2. On Linux: use `caps` crate (or direct syscall via `nix`) to read effective capabilities.
3. On macOS: check `getuid() == 0` and use `authd` for authorization status.
4. On Windows: check for administrator privileges via `OpenProcessToken` + `GetTokenInformation`.
5. Log a clear startup report: "Running as root: YES, CAP_NET_ADMIN: YES, will drop to UID 1000 after init".
6. If running as root but no `--drop-privileges` flag: log a WARNING.
7. If not root and missing required capabilities: log an ERROR with instructions (`setcap cap_net_admin,cap_net_bind_service+ep quicfuscate`).

### Phase 2: Privilege dropping (Linux)
1. Create `src/privilege/drop.rs`:
   ```rust
   pub fn drop_privileges(target_uid: u32, target_gid: u32) -> Result<(), PrivilegeError> {
       // 1. Clear supplementary groups
       nix::unistd::setgroups(&[])?;
       
       // 2. Set GID first (must be done while still root)
       nix::unistd::setgid(Gid::from_raw(target_gid))?;
       
       // 3. Set UID
       nix::unistd::setuid(Uid::from_raw(target_uid))?;
       
       // 4. Drop all capabilities via prctl + capset
       //    PR_SET_NO_NEW_PRIVS prevents gaining new capabilities via execve
       drop_all_capabilities()?;
       
       // 5. Verify
       let uid = nix::unistd::getuid();
       let euid = nix::unistd::geteuid();
       if uid.is_root() || euid.is_root() {
           return Err(PrivilegeError::DropFailed("Still running as root after setuid"));
       }
       
       Ok(())
   }
   ```
2. `drop_all_capabilities()`:
   - Use `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` — prevents the process from gaining new privileges via execve.
   - Use `capset` to clear all capabilities from effective, permitted, and inheritable sets.
   - On kernels ≥5.15: use `prctl(PR_SET_SECUREBITS, SECBIT_NOROOT)` — prevents regaining root capabilities even if UID is changed back to 0.
3. Resolve `quicfuscate` user by name: `getpwnam("quicfuscate")` → UID/GID. If user doesn't exist, create it during installation (documented in setup guide) or use `--drop-uid` / `--drop-gid` CLI flags for explicit numeric IDs.

### Phase 3: Integration into server startup
1. In `src/main.rs:run_server()`, restructure the startup sequence:
   ```rust
   async fn run_server(...) -> std::io::Result<()> {
       // 1. Check capabilities
       let cap_report = CapabilityChecker::check();
       cap_report.log_summary();
       
       // 2. PRIVILEGED PHASE
       //    All operations that need root/CAP_NET_ADMIN happen here
       let socket = UdpSocket::bind(listen_addr).await?;  // bind
       let tun = create_tun_interface(...)?;               // TUN
       routing_manager.setup()?;                            // iptables
       // DNS redirect rules (TODO-435)
       // Audit log file with chattr +a (TODO-439)
       
       // 3. PRIVILEGE DROP
       if cap_report.is_root && drop_privileges_enabled {
           let target = resolve_target_user("quicfuscate")?;
           drop_privileges(target.uid, target.gid)?;
           log::info!("Privileges dropped to UID={} GID={}", target.uid, target.gid);
           audit_log.log(AuditEvent::PrivilegeDropped { ... });
       }
       
       // 4. UNPRIVILEGED PHASE
       //    Server runs with minimal privileges for the rest of its lifetime
       let mut runtime = ServerRuntime::from_prepared(socket, tun, routing_manager, ...);
       runtime.run_standalone(launch).await?;
   }
   ```
2. This requires refactoring `ServerRuntime::new_initialized_standalone_default()` to accept pre-created socket and TUN, or to split initialization into "privileged init" and "unprivileged run" phases.

### Phase 4: Capability-based operation (no root needed)
1. If the binary has capabilities set via `setcap`:
   ```
   setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep /usr/bin/quicfuscate
   ```
   Then the server can create TUN, bind to port 443, and set up iptables WITHOUT being root.
2. In this mode, privilege dropping means dropping from the capability-endowed user to a non-capability user.
3. The `CapabilityChecker` detects this mode and adjusts the startup report.
4. Document both modes:
   - **Root mode**: start as root, drop to `quicfuscate` user after init.
   - **Capability mode**: start as `quicfuscate` user with `setcap`-endowed binary, drop capabilities after init (no setuid needed).

### Phase 5: chroot jail option
1. Add `--chroot <path>` CLI flag.
2. After privilege drop, before entering the main loop:
   ```rust
   if let Some(chroot_path) = chroot_path {
       // Must be done after dropping privileges but requires
       // the chroot path to be accessible by the target user
       nix::unistd::chroot(chroot_path)?;
       nix::unistd::chdir("/")?;
   }
   ```
3. The chroot directory must contain:
   - `/dev/net/tun` (or a bind mount of the real device)
   - The TUN file descriptor (already open, survives chroot)
   - The UDP socket (already bound, survives chroot)
   - Config files (copied or bind-mounted into chroot)
   - Audit log directory
   - `/dev/urandom` (for crypto — bind mount or the RNG is already seeded)
4. Note: chroot is defense-in-depth, not a security boundary. It prevents accidental file access, not determined attackers. Combine with seccomp for stronger isolation.

### Phase 6: macOS sandbox support
1. On macOS, use the Sandbox framework (`sandbox_init_with_parameters`) instead of setuid.
2. Create a sandbox profile file that allows:
   - Network access (UDP/TCP on the bound socket)
   - File access to the TUN device, config, and audit log
   - No access to other system files
3. The sandbox is applied after privileged initialization (TUN creation, pf rules).
4. On macOS, TUN creation requires root (no capability system). The process starts as root, creates TUN, sets up pf, then drops to sandbox.
5. Add `--sandbox-profile <path>` CLI flag for custom sandbox profiles.

### Phase 7: Enhanced `quicfuscate capabilities` subcommand
1. Replace the current compile-time feature check with a comprehensive runtime report:
   ```json
   {
     "uid": 0,
     "euid": 0,
     "gid": 0,
     "is_root": true,
     "capabilities": {
       "cap_net_admin": true,
       "cap_net_raw": true,
       "cap_net_bind_service": true,
       "cap_sys_admin": true
     },
     "can_create_tun": true,
     "can_bind_low_ports": true,
     "can_modify_firewall": true,
     "can_drop_privileges": true,
     "target_user": {
       "name": "quicfuscate",
       "uid": 1000,
       "gid": 1000,
       "exists": true
     },
     "features": {
       "fec_bench": false,
       "pool_bench": false
     }
   }
   ```
2. This helps operators diagnose permission issues before starting the server.

## Technology Choices

### Chosen: `nix` crate for Unix syscalls
- `nix` provides safe Rust wrappers for `setuid`, `setgid`, `setgroups`, `chroot`, `prctl`.
- Already a common dependency in Rust system projects. Pure Rust, no C dependency.
- Alternative: raw `libc` calls. Rejected — `nix` provides error handling and type safety.

### Chosen: `caps` crate for Linux capability management
- `caps` provides `Capability`, `CapSet`, `read`, `drop` functions for Linux capabilities.
- Used by `drop-root-caps` crate and other privilege-dropping projects.
- Alternative: raw `capget`/`capset` syscalls via `libc`. Rejected — `caps` is safer and more ergonomic.

### Chosen: `prctl(PR_SET_NO_NEW_PRIVS)` for hardening
- Prevents the process from gaining new privileges via `execve()`.
- Supported since Linux 3.5 (2012). Universally available.
- Combined with `SECBIT_NOROOT` (kernel 5.15+), provides strong protection against privilege escalation.

### Chosen: Order: filesystem → capabilities → privileges
Following the established best practice from the Rust sandboxing community (2025):
1. Set up filesystem restrictions (chroot) — while still root.
2. Drop capabilities (capset) — while still root.
3. Drop privileges (setgid, setuid) — last step.
This order ensures that each step has the permissions needed for the next.

### Evaluated and rejected
- **seccomp-bpf**: Considered for syscall filtering. Rejected for now — adds complexity and platform-specific code. Could be added as a future hardening layer on top of privilege dropping. The `seccompiler` crate would be the choice if added.
- **Landlock (Linux LSM)**: Considered for filesystem sandboxing. Rejected — kernel 6.4+ required for network restrictions, not universally available yet. chroot is more portable.
- **systemd sandboxing (ProtectSystem, ProtectHome, etc.)**: Complementary, not a replacement. Document as recommended systemd unit file options. The application should still drop privileges internally for non-systemd deployments.
- **Docker/Podman user namespace remapping**: Complementary. The container should still drop privileges internally for defense in depth.

## Stealth/Efficiency Considerations

### Stealth
- **No impact on stealth**: Privilege dropping is a server-internal security measure. It does not affect the TLS handshake, packet structure, or traffic patterns visible to DPI.
- **Audit logging**: The privilege drop event is logged (TODO-439) for audit purposes but does not leak to network observers.

### Performance
- **Zero runtime overhead**: Privilege dropping happens once at startup. After that, the process runs as an unprivileged user with no additional checks.
- **File descriptors survive**: The TUN fd and UDP socket remain valid after privilege drop. No performance impact on packet processing.
- **No capability checks in hot path**: Capabilities are checked once at startup. The hot path (packet processing) does not check capabilities.

## Testing Plan

### Unit tests
- `CapabilityChecker::check()`: correct detection of root/non-root, capabilities present/absent.
- `drop_privileges()`: UID/GID are changed correctly, supplementary groups cleared.
- `drop_all_capabilities()`: effective/permitted/inheritable sets are empty after drop.
- Verification: `getuid() != 0` after drop, `geteuid() != 0` after drop.
- Error cases: dropping when not root (should fail or no-op), dropping to non-existent user (should fail).

### Integration tests (require root to run)
- Start server as root → verify TUN created, iptables set up → verify privileges dropped → verify `getuid()` returns non-zero → verify server still accepts connections and processes traffic.
- Start server with `setcap` binary as non-root → verify TUN created, iptables set up → verify capabilities dropped → verify server still works.
- Start server with `--chroot` → verify process is in chroot → verify server still works.
- Start server as non-root without capabilities → verify clear error message.

### E2E tests
- Full VPN session after privilege drop: client connects, transfers data, disconnects. Verify no privilege-related failures.
- Kill switch after privilege drop: client kill switch activates, blocks traffic, deactivates. Verify iptables rules are managed correctly (they were set up before privilege drop, so the fds are valid but new iptables commands would fail — verify this is handled).
- Hot-reload after privilege drop: cert reload (TODO-434) triggers file read. Verify the unprivileged user can read the cert file (permissions set correctly).

## Files to Create/Modify

### New files
- `src/privilege/mod.rs` — Module root: `CapabilityReport`, `CapabilityChecker`, `PrivilegeError`
- `src/privilege/drop.rs` — `drop_privileges()`, `drop_all_capabilities()`, `resolve_target_user()`
- `src/privilege/chroot.rs` — chroot jail setup and verification
- `src/privilege/sandbox_macos.rs` — macOS Sandbox framework integration
- `src/privilege/capabilities_linux.rs` — Linux capability detection and dropping via `caps` crate
- `tests/privilege_drop.rs` — Integration tests for privilege dropping

### Modified files
- `src/main.rs` — Restructure `run_server()` into privileged init → drop → unprivileged run phases; enhance `Capabilities` subcommand with runtime checks; add `--drop-privileges`, `--drop-user`, `--drop-uid`, `--drop-gid`, `--chroot`, `--sandbox-profile` CLI flags
- `src/implementations/server/mod.rs` — Refactor `ServerRuntime` to support pre-created socket and TUN (split init from run); add `from_prepared()` constructor
- `src/implementations/client/mod.rs` — Apply privilege dropping to client startup (after TUN + kill switch setup)
- `Cargo.toml` — Add `nix = { version = "0.29", features = ["user", "process", "fs", "sched"] }`, `caps = "0.5"` (Linux only, `#[cfg(target_os = "linux")]`)
- `src/lib.rs` — Add `pub mod privilege;`

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| iptables/routing changes needed after privilege drop (e.g., per-client rules in TODO-438) | All firewall rules must be set up BEFORE dropping. For dynamic per-client rules (TODO-438), use a privileged helper process or pre-create a ruleset with iptables-restore that references ipsets, then only modify the ipset contents (which requires CAP_NET_ADMIN). Alternative: keep a privileged thread for firewall modifications. |
| Kill switch needs to modify iptables after VPN disconnect | Kill switch rules must be pre-installed before privilege drop. On disconnect, only need to re-enable blocking (which is the default state). If rules need to change, use the pre-installed rule set with conditional matching. |
| TUN interface destroyed and needs recreation | If TUN is destroyed (crash, OOM), recreation requires root. Mitigation: supervise the process with systemd (restart as root). The TUN fd is kept open for the process lifetime. |
| `quicfuscate` user doesn't exist | Detect at startup. If `--drop-user` is specified but user doesn't exist, fail with clear error. Document user creation in setup guide: `useradd -r -s /usr/sbin/nologin quicfuscate`. |
| chroot breaks TUN access | TUN fd is already open (survives chroot). But `/dev/net/tun` won't exist in chroot for re-opening. Bind-mount `/dev/net/tun` into chroot, or ensure TUN fd is never closed. |
| macOS: no capabilities, must use root for TUN | On macOS, always start as root, create TUN, set up pf, then apply sandbox. No setuid to non-root (macOS TUN requires root for fd operations in some configurations). Use Sandbox framework for isolation instead. |
| Windows: no setuid/capabilities | On Windows, use Windows Service with limited token. Run the service as `NetworkService` account. Use `AdjustTokenPrivileges` to drop privileges after init. Lower priority — Linux is the primary server platform. |
| Audit log file not writable after privilege drop | Open audit log file before dropping privileges. The fd remains valid. Or: set file ownership to `quicfuscate` user before drop. |
| Hot-reload of certs (TODO-434) fails after privilege drop | Cert files must be readable by the `quicfuscate` user. Set file permissions `0644` for certs, `0600` for keys owned by `quicfuscate`. |

## Completion Criteria

- [ ] `CapabilityChecker::check()` detects root/non-root, Linux capabilities, and target user existence at startup
- [ ] `drop_privileges()` performs setgid → setuid → capability drop in correct order
- [ ] Supplementary groups are cleared before setgid
- [ ] `PR_SET_NO_NEW_PRIVS` is set to prevent future privilege escalation
- [ ] All capabilities are cleared from effective, permitted, and inheritable sets
- [ ] Post-drop verification: `getuid() != 0`, `geteuid() != 0`
- [ ] Server startup is restructured: privileged init → drop → unprivileged run
- [ ] TUN fd and UDP socket remain valid after privilege drop
- [ ] Server accepts connections and processes traffic normally after privilege drop
- [ ] `quicfuscate capabilities` subcommand shows runtime capability report (not just compile-time features)
- [ ] `--drop-privileges` / `--drop-user` / `--drop-uid` / `--drop-gid` CLI flags work
- [ ] `--chroot` option creates chroot jail after privilege drop
- [ ] macOS sandbox profile support via `--sandbox-profile`
- [ ] All firewall/routing/TUN setup happens BEFORE privilege drop
- [ ] Audit event logged on privilege drop (TODO-439)
- [ ] Clear error messages when required capabilities are missing
- [ ] Documentation: setup guide for creating `quicfuscate` user, `setcap` instructions
- [ ] All unit, integration, and E2E tests pass
