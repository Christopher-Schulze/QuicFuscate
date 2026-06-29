---
id: TODO-441
title: "Privilege dropping after initialization"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: [TODO-440]
---

# TODO-441: Privilege dropping after initialization

## Problem

The QuicFuscate server runs with full root privileges for its entire
lifetime. While the systemd service file
(`scripts/install/quicfuscate-server.service`) specifies
`User=quicfuscate` and `Group=quicfuscate`, this is a systemd-level
directive that drops privileges **before** the process starts — which
means the process cannot perform privileged initialization (bind to
port 443, create TUN devices, modify iptables). In practice, the
server must be started as root to function, and once initialized, it
retains root privileges for the entire session.

### 1. No app-level privilege dropping

A grep for `setuid`, `setgid`, `chroot`, or `drop_priv` across the
entire `src/` tree returns zero results. There is no code that drops
privileges after the initialization phase. The server process runs
as root (or as the systemd-configured user) for its entire lifetime,
including the main event loop where it processes untrusted network
data from clients.

### 2. systemd User= is insufficient

The systemd service file
(`scripts/install/quicfuscate-server.service`):
```ini
[Service]
Type=simple
User=quicfuscate
Group=quicfuscate
```

If the service runs as `User=quicfuscate`, the process cannot:
- Bind to privileged ports (< 1024) — the default listen address is
  `0.0.0.0:4433` (port 4433 > 1024, so this works, but if the user
  configures port 443 it fails).
- Create TUN devices (`/dev/net/tun` requires `CAP_NET_ADMIN`).
- Modify iptables / ip6tables (requires `CAP_NET_ADMIN`).
- Modify `/proc/sys/net/ipv4/ip_forward` (requires `CAP_SYS_ADMIN`).

So either the service must run as root (defeating the `User=`
directive), or the user must manually configure capabilities
(`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN`),
which is complex and error-prone.

The correct pattern is: **start as root, perform privileged init,
then drop to an unprivileged user via `setuid`/`setgid`**. This is
the standard approach for network servers (OpenSSH, nginx, Apache,
OpenVPN all do this).

### 3. No chroot

There is no `chroot` call. The server process has access to the entire
filesystem. If the server process is compromised (e.g. via a buffer
overflow in QUIC packet parsing), the attacker has full filesystem
access as root. A `chroot` to `/var/lib/quicfuscate` would limit the
attack surface to the chroot jail.

### 4. No capability bounding

After dropping to an unprivileged user, the process may still retain
Linux capabilities (e.g. `CAP_NET_ADMIN`, `CAP_NET_RAW`) that were
present at startup. Without explicitly dropping all capabilities via
`prctl(PR_SET_NO_NEW_PRIVS)` and clearing the bounding set, the
process retains unnecessary privileges.

## Goal

- The server starts as root, performs privileged initialization (bind
  socket, create TUN, setup iptables/routing), then drops to an
  unprivileged user via `setgid` + `setuid`.
- The process is `chroot`ed to `/var/lib/quicfuscate` after
  initialization.
- All Linux capabilities are dropped after initialization.
- `PR_SET_NO_NEW_PRIVS` is set to prevent gaining new privileges via
  `execve`.
- Configuration: `drop_privileges = true`, `run_user =
  "quicfuscate"`, `run_group = "quicfuscate"`, `chroot_path =
  "/var/lib/quicfuscate"`.
- Tests verify that the process runs as the unprivileged user after
  init and has no remaining capabilities.

## Implementation Plan

### Step 1: Add privilege-dropping configuration

**File:** `src/engine/config.rs`, `src/implementations/server/mod.rs`

- Add to `ServerConfig` (`src/implementations/server/mod.rs:104`):
  ```rust
  pub drop_privileges: bool,          // default: true
  pub run_user: String,               // default: "quicfuscate"
  pub run_group: String,              // default: "quicfuscate"
  pub chroot_path: Option<PathBuf>,   // default: Some("/var/lib/quicfuscate")
  pub chroot_enabled: bool,           // default: true
  ```
- Add parsing in the config loader for `[security]` section:
  ```toml
  [security]
  drop_privileges = true
  run_user = "quicfuscate"
  run_group = "quicfuscate"
  chroot_path = "/var/lib/quicfuscate"
  chroot_enabled = true
  ```

### Step 2: Implement the privilege-dropping function

**File:** `src/implementations/server/privdrop.rs` (new)

- Create a `PrivilegeDropper` struct:
  ```rust
  pub struct PrivilegeDropper {
      target_uid: u32,
      target_gid: u32,
      chroot_path: Option<PathBuf>,
  }
  ```
- `PrivilegeDropper::resolve(user: &str, group: &str) ->
  Result<Self, PrivDropError>`:
  - Look up the UID for `user` via `libc::getpwnam` (or the `nix`
    crate's `User::from_name`).
  - Look up the GID for `group` via `libc::getgrnam` (or `nix`'s
    `Group::from_name`).
  - Return an error if the user or group does not exist.
- `PrivilegeDropper::drop(&self) -> Result<(), PrivDropError>`:
  1. **chroot** (if configured):
     ```rust
     if let Some(ref path) = self.chroot_path {
         // Ensure the path exists and is owned by root
         std::fs::create_dir_all(path)?;
         // chdir to the path first so relative paths still work after chroot
         std::env::set_current_dir(path)?;
         // SAFETY: chroot requires CAP_SYS_CHROOT; we are still root here
         let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())?;
         if unsafe { libc::chroot(c_path.as_ptr()) } != 0 {
             return Err(PrivDropError::ChrootFailed(std::io::Error::last_os_error()));
         }
         // chdir to "/" inside the chroot
         std::env::set_current_dir("/")?;
     }
     ```
  2. **Set NO_NEW_PRIVS**:
     ```rust
     // SAFETY: PR_SET_NO_NEW_PRIVS is a safe, well-defined prctl operation
     if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
         return Err(PrivDropError::NoNewPrivsFailed(std::io::Error::last_os_error()));
     }
     ```
  3. **Drop capabilities** (Linux):
     ```rust
     // Clear the capability bounding set
     for cap in 0..=libc::CAP_LAST_CAP {
         if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
             // Some caps may not exist; ignore EINVAL
             let err = std::io::Error::last_os_error();
             if err.raw_os_error() != Some(libc::EINVAL) {
                 return Err(PrivDropError::CapDropFailed(err));
             }
         }
     }
     ```
  4. **setgid**:
     ```rust
     // SAFETY: setgid requires CAP_SETGID; we are still root here
     if unsafe { libc::setgid(self.target_gid) } != 0 {
         return Err(PrivDropError::SetgidFailed(std::io::Error::last_os_error()));
     }
     // Also set the supplementary groups to only the target group
     if unsafe { libc::setgroups(1, &[self.target_gid].as_ptr() as *const _) } != 0 {
         return Err(PrivDropError::SetGroupsFailed(std::io::Error::last_os_error()));
     }
     ```
  5. **setuid** (must be last, after setgid, because setuid loses the
     privilege to call setgid):
     ```rust
     // SAFETY: setuid requires CAP_SETUID; we are still root here
     if unsafe { libc::setuid(self.target_uid) } != 0 {
         return Err(PrivDropError::SetuidFailed(std::io::Error::last_os_error()));
     }
     ```
  6. **Verify**: Check that `getuid() != 0` and `geteuid() != 0`:
     ```rust
     let uid = unsafe { libc::getuid() };
     let euid = unsafe { libc::geteuid() };
     if uid == 0 || euid == 0 {
         return Err(PrivDropError::StillRoot);
     }
     ```

### Step 3: Call privilege dropping after server initialization

**File:** `src/implementations/server/mod.rs`

- In the server startup sequence, after the following operations are
  complete:
  1. UDP socket bind (`src/implementations/server/mod.rs` — the
     `TokioRuntimeBuilder` + `UdpSocket::bind` path)
  2. TUN interface creation (`ServerHostResources::start` at line 834
     — `open_server_tun`)
  3. Routing / iptables setup (`RoutingManager::setup` at line 857)
  4. `mlockall` (TODO-440 Step 7)
  5. QKey registry load (line 676)
  6. TLS certificate / key load
  7. Audit log file open + `chattr +a` (TODO-439)

  ...call `PrivilegeDropper::drop()`:
  ```rust
  if server_config.drop_privileges {
      let dropper = PrivilegeDropper::resolve(
          &server_config.run_user,
          &server_config.run_group,
      )?;
      dropper.drop()?;
      log::info!("Privileges dropped to user '{}', group '{}'",
          server_config.run_user, server_config.run_group);
  }
  ```
- This must happen **before** the server enters the main event loop
  (the `runtime.block_on(async move { ... })` at line 760) so that
  all untrusted network processing occurs with reduced privileges.

### Step 4: Prepare the chroot environment

**File:** `scripts/install/setup-chroot.sh` (new)

- Create a script that sets up the chroot jail at
  `/var/lib/quicfuscate`:
  ```bash
  #!/bin/bash
  set -euo pipefail
  CHROOT=/var/lib/quicfuscate
  mkdir -p "$CHROOT"/{dev,etc,proc,run,tmp,var/log}
  # Create /dev/net/tun inside the chroot (if TUN is opened after chroot)
  # Note: TUN must be opened BEFORE chroot, so this may not be needed
  mknod "$CHROOT/dev/net/tun" c 10 200 2>/dev/null || true
  chmod 666 "$CHROOT/dev/net/tun"
  # Copy necessary libraries (if the binary is dynamically linked)
  ldd /usr/local/bin/quicfuscate | awk '{print $3}' | xargs -I{} cp --parents {} "$CHROOT"
  # Copy the binary itself
  cp /usr/local/bin/quicfuscate "$CHROOT/usr/local/bin/"
  # Copy config files
  cp -r /etc/quicfuscate "$CHROOT/etc/"
  # Set ownership
  chown -R root:root "$CHROOT"
  chmod 700 "$CHROOT"
  ```
- Note: If the TUN device is opened before chroot (as per Step 3),
  `/dev/net/tun` does not need to exist inside the chroot. The TUN
  file descriptor remains valid after chroot.

### Step 5: Update systemd service file

**File:** `scripts/install/quicfuscate-server.service`

- Update the service file to start as root (so the app can perform
  privileged init and then drop privileges itself):
  ```ini
  [Service]
  Type=simple
  # Start as root; the app drops privileges after init
  # User= and Group= are removed; the app handles this via setuid/setgid
  EnvironmentFile=/etc/quicfuscate/quicfuscate.env

  ExecStart=/usr/local/bin/quicfuscate server \
    --listen ${QUICFUSCATE_LISTEN} \
    --cert ${QUICFUSCATE_CERT} \
    --key ${QUICFUSCATE_KEY} \
    --config ${QUICFUSCATE_CONFIG} \
    --admin-web ${QUICFUSCATE_ADMIN_WEB} \
    --admin-web-root ${QUICFUSCATE_ADMIN_WEB_ROOT} \
    --qkey-store ${QUICFUSCATE_QKEY_STORE} \
    --qkey-ttl-secs ${QUICFUSCATE_QKEY_TTL_SECS}

  Restart=on-failure
  RestartSec=2

  # Hardening
  NoNewPrivileges=false   # App sets PR_SET_NO_NEW_PRIVS itself
  PrivateTmp=true
  ProtectSystem=full
  ProtectHome=true
  ReadWritePaths=/etc/quicfuscate /var/lib/quicfuscate /var/log/quicfuscate
  LimitNOFILE=1048576
  LimitMEMLOCK=infinity    # For mlockall (TODO-440)
  ```
- Note: `NoNewPrivileges=true` in systemd would prevent the app from
  calling `setuid` (since `setuid` is a privilege change). Setting it
  to `false` allows the app to manage its own privilege dropping.
  Alternatively, use `AmbientCapabilities` + `User=quicfuscate` and
  skip app-level dropping — but the app-level approach is more
  portable (works without systemd) and is the requested design.

### Step 6: Handle post-drop file access

**File:** `src/implementations/server/mod.rs`, `src/implementations/server/qkey_registry.rs`

- After privilege dropping, the process runs as `quicfuscate` and can
  only access files owned by / readable by that user. Ensure:
  - QKey store file (`qkeys.json`) is owned by `quicfuscate:quicfuscate`
    and writable by the group.
  - Audit log file (`/var/log/quicfuscate/audit.log`) is owned by
    `quicfuscate:quicfuscate`.
  - Config file is readable by `quicfuscate`.
  - The chroot directory contains all necessary files.
- The `setup-chroot.sh` script (Step 4) handles file ownership.
- For non-chroot mode, document that the admin must `chown` the
  relevant files to the `quicfuscate` user.

### Step 7: Tests

**File:** `src/implementations/server/privdrop.rs` (inline tests),
`tests/privilege_drop_test.rs` (new)

- Unit test: `PrivilegeDropper::resolve("nobody", "nogroup")`
  returns a dropper with the correct UID/GID (lookup `nobody` /
  `nogroup` which exist on all Unix systems).
- Unit test: `PrivilegeDropper::resolve("nonexistent_user_12345",
  "nogroup")` returns an error.
- Integration test (Linux, requires root): Start the server as root
  with `drop_privileges = true`. After init, verify:
  - `ps -o user= -p <pid>` returns `quicfuscate` (not `root`).
  - `cat /proc/<pid>/status | grep Uid` shows the real and effective
    UID as the `quicfuscate` user's UID (not 0).
  - `capsh --print --pid=<pid>` shows no capabilities (or only
    `cap_net_bind_service` if port 443 is used).
  - `readlink /proc/<pid>/root` shows `/var/lib/quicfuscate` (if
    chroot is enabled).
- Integration test: Start the server with `drop_privileges = false`.
  Verify the process still runs as root.
- Integration test: Start the server as a non-root user with
  `drop_privileges = true`. Verify the server starts successfully
  (the `setuid` call is a no-op if already running as the target
  user) or fails gracefully if the user lacks privileges for TUN /
  iptables setup.

## Files to Modify/Create

- `src/implementations/server/privdrop.rs` — **new**:
  `PrivilegeDropper` struct, `resolve()`, `drop()` (chroot,
  NO_NEW_PRIVS, cap bounding set drop, setgid, setuid)
- `src/implementations/server/mod.rs` — call `PrivilegeDropper::drop()`
  after initialization, add config fields to `ServerConfig`
- `src/engine/config.rs` — add `drop_privileges`, `run_user`,
  `run_group`, `chroot_path`, `chroot_enabled` to config
- `scripts/install/quicfuscate-server.service` — update to start as
  root, add `LimitMEMLOCK=infinity`, adjust `NoNewPrivileges`
- `scripts/install/setup-chroot.sh` — **new**: chroot jail setup
  script
- `tests/privilege_drop_test.rs` — **new**: integration tests

## Acceptance Criteria

- [ ] `PrivilegeDropper::resolve()` looks up UID/GID by username /
      groupname.
- [ ] `PrivilegeDropper::drop()` performs chroot (if configured),
      sets `PR_SET_NO_NEW_PRIVS`, clears the capability bounding set,
      calls `setgid` + `setgroups` + `setuid`, and verifies the
      process is no longer root.
- [ ] The server calls `PrivilegeDropper::drop()` after socket bind,
      TUN creation, routing/iptables setup, `mlockall`, QKey load,
      and TLS load — before entering the main event loop.
- [ ] After privilege dropping, the process runs as the configured
      `run_user` / `run_group` (verified via `/proc/<pid>/status`).
- [ ] `capsh --print --pid=<pid>` shows no remaining capabilities
      after the drop.
- [ ] `chroot` to `/var/lib/quicfuscate` is applied (verified via
      `readlink /proc/<pid>/root`).
- [ ] `drop_privileges`, `run_user`, `run_group`, `chroot_path` are
      configurable.
- [ ] `scripts/install/setup-chroot.sh` creates the chroot jail with
      correct permissions.
- [ ] `scripts/install/quicfuscate-server.service` starts as root and
      includes `LimitMEMLOCK=infinity`.
- [ ] Integration test verifies the process runs as `quicfuscate`
      after init with no capabilities.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| `PrivilegeDropper::drop()` | < 5 ms | getpwnam/getgrnam (cached) + chroot + prctl + setgid + setuid |
| `chroot` syscall | < 1 ms | Single syscall; path must exist |
| Capability bounding set drop | < 1 ms | ~40 `prctl(PR_CAPBSET_DROP)` calls (one per capability) |
| Post-drop filesystem access | No overhead | Files must be pre-owned by `quicfuscate` user |
| Memory (chroot jail) | ~10 MB | Binary + libraries + config inside chroot |
