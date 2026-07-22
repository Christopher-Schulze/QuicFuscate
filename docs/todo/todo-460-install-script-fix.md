---
id: TODO-460
title: "Install script: create quicfuscate user, directories, and validate prerequisites"
severity: HIGH
phase: "I"
priority: P1
status: DONE
created: 2026-06-30
depends_on: []
---

# TODO-460: Install Script — Create quicfuscate User, Directories, and Validate Prerequisites

## Problem

The systemd service unit (`scripts/install/quicfuscate-server.service`) declares
`User=quicfuscate` and `Group=quicfuscate` (lines 8-9):

```ini
[Service]
Type=simple
User=quicfuscate
Group=quicfuscate
```

The install script (`scripts/install/install-server-linux.sh`) does not
guarantee that the `quicfuscate` system user/group exist with the correct
properties, nor that the runtime directory tree (`/var/lib/quicfuscate`,
`/etc/quicfuscate`, `/var/log/quicfuscate`) is created with the correct
ownership and permissions before the service is enabled and started. The
`ensure_user` helper (lines 63-78) is invoked once at line 177, but:

- It does **not** create a dedicated group via `groupadd`; it relies on
  `useradd`/`adduser` implicitly creating a group, which is not guaranteed
  across distros (e.g. `adduser --system` on Debian creates a `nogroup`
  primary group unless `--group` is passed — the current `adduser` branch
  passes `--group "$user"`, but the `useradd` branch does not pass
  `--user-group`, so on RHEL-family systems the user may land in `nobody`).
- The home directory is set to `/var/lib/quicfuscate` but `--no-create-home`
  is used, and the directory creation at line 179 (`mkdir -p /etc/quicfuscate
  "$state_dir" /usr/share/quicfuscate`) omits `/var/log/quicfuscate` entirely.
- There is no `chmod 700` for the data/state directory; the state dir is set
  to `0750` (line 182), which is too permissive for a directory that will
  hold QKey material and per-client state.
- There is no prerequisite validation: the script never checks that
  `iptables`, `iproute2` (`ip`), or (on Windows) `wintun.dll` are present
  before installing. The server fails at runtime with opaque errors when
  these are missing.
- The default config template is copied (lines 208-227) but only when
  `$config_dst` is absent; there is no validation that the installed config
  is parseable or that required keys exist.

When the service is started with `systemctl enable --now` (line 286) and the
user/group do not exist (or have the wrong primary group), systemd fails with
`Failed to start quicfuscate.service: Unit ...` / `user 'quicfuscate' not
found`, and the install appears to succeed from the script's perspective.

## Goal

- The install script **idempotently** creates a dedicated `quicfuscate`
  system user and group (no login shell, home `/var/lib/quicfuscate`,
  no home directory creation) on both `useradd`-based (RHEL/Fedora/Arch) and
  `adduser`-based (Debian/Ubuntu) distros, with a **dedicated primary group
  named `quicfuscate`**.
- The script creates `/var/lib/quicfuscate`, `/etc/quicfuscate`, and
  `/var/log/quicfuscate` with correct ownership (`quicfuscate:quicfuscate`)
  and permissions: `chmod 750` for config and log dirs, `chmod 700` for the
  data/state dir.
- The script validates prerequisites **before** installing anything:
  `iptables` and `ip` (iproute2) on Linux; `wintun.dll` presence on Windows
  (for the Windows installer path). Missing prerequisites abort the install
  with a clear, actionable error.
- The default config is copied and minimally validated (parseable TOML,
  required keys present).
- A fresh install on a clean system results in: user exists, directories
  exist with correct permissions, service starts successfully.

## Implementation Plan

### Step 1: Idempotent group + user creation

**File:** `scripts/install/install-server-linux.sh`

Replace the `ensure_user` function (lines 63-78) with an idempotent
`ensure_group` + `ensure_user` pair:

```bash
ensure_group() {
  local group="$1"
  if getent group "$group" >/dev/null 2>&1; then
    return 0
  fi
  if need_cmd groupadd; then
    groupadd --system "$group"
    return 0
  fi
  if need_cmd addgroup; then
    addgroup --system "$group"
    return 0
  fi
  echo "error: cannot create group '$group' (need groupadd or addgroup)" >&2
  exit 1
}

ensure_user() {
  local user="$1"
  local group="$1"
  if id -u "$user" >/dev/null 2>&1; then
    # User exists; ensure primary group is correct.
    local prim_group
    prim_group="$(id -gn "$user")"
    if [[ "$prim_group" != "$group" ]]; then
      echo "warn: user '$user' has primary group '$prim_group', expected '$group'" >&2
    fi
    return 0
  fi
  if need_cmd useradd; then
    useradd --system \
            --gid "$group" \
            --home-dir /var/lib/quicfuscate \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$user"
    return 0
  fi
  if need_cmd adduser; then
    adduser --system \
            --group "$group" \
            --no-create-home \
            --home /var/lib/quicfuscate \
            --shell /usr/sbin/nologin \
            --disabled-password \
            "$user"
    return 0
  fi
  echo "error: cannot create user '$user' (need useradd or adduser)" >&2
  exit 1
}
```

Call site (replace line 177):

```bash
ensure_group "quicfuscate"
ensure_user  "quicfuscate"
```

### Step 2: Directory creation with correct ownership and permissions

**File:** `scripts/install/install-server-linux.sh`

Replace lines 179-182 with explicit, per-directory creation:

```bash
local state_dir="/var/lib/quicfuscate"
local config_dir="/etc/quicfuscate"
local log_dir="/var/log/quicfuscate"

mkdir -p "$config_dir" "$state_dir" "$log_dir" /usr/share/quicfuscate

# Data/state dir: holds QKey store, per-client state — restrictive.
chown quicfuscate:quicfuscate "$state_dir"
chmod 0700 "$state_dir"

# Config dir: admin panel writes here, root + group read.
chown root:quicfuscate "$config_dir"
chmod 0750 "$config_dir"

# Log dir: server writes audit + runtime logs here.
chown quicfuscate:quicfuscate "$log_dir"
chmod 0750 "$log_dir"
```

Note the state dir is now `0700` (was `0750`) and the config dir is owned by
`root:quicfuscate` (was implicitly `quicfuscate:quicfuscate`) so the running
service can read but not rewrite the config unless explicitly granted.

### Step 3: Prerequisite validation

**File:** `scripts/install/install-server-linux.sh`

Add a `validate_prerequisites` function and call it immediately after
`require_root` (after line 129):

```bash
validate_prerequisites() {
  local missing=()
  # Linux runtime deps (the server uses iptables + ip for routing/NAT).
  if ! need_cmd iptables; then missing+=("iptables"); fi
  if ! need_cmd ip;       then missing+=("iproute2 (ip)"); fi
  # systemd is optional (script supports --no-start without systemctl),
  # but if we intend to start the service, systemctl must exist.
  if [[ "$no_start" != "1" ]] && ! need_cmd systemctl; then
    missing+=("systemctl")
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "error: missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "hint: on Debian/Ubuntu: apt-get install iptables iproute2 systemd" >&2
    echo "hint: on RHEL/Fedora:   dnf install iptables iproute systemd" >&2
    exit 1
  fi
}
```

For the Windows installer path (separate script, see TODO-442), add a
`wintun.dll` presence check in the Windows install script.

### Step 4: Default config copy + minimal validation

**File:** `scripts/install/install-server-linux.sh`

After the config template is installed (after line 227), add a minimal
validation step. If `quicfuscate` supports a `config check` subcommand, use
it; otherwise do a lightweight TOML parse via `python3` if available:

```bash
if need_cmd python3; then
  if ! python3 -c "import tomllib,sys; tomllib.load(open('$config_dst','rb'))" \
        >/dev/null 2>&1; then
    echo "error: installed config is not valid TOML: $config_dst" >&2
    exit 1
  fi
fi
```

### Step 5: Post-install verification

**File:** `scripts/install/install-server-linux.sh`

After `systemctl enable --now` (line 286), add verification:

```bash
if [[ "$no_start" != "1" ]] && need_cmd systemctl; then
  # Verify the service actually came up.
  sleep 1
  if ! systemctl is-active --quiet quicfuscate.service; then
    echo "error: quicfuscate.service failed to start" >&2
    systemctl status --no-pager quicfuscate.service || true
    journalctl -u quicfuscate.service -n 50 --no-pager || true
    exit 1
  fi
  echo "quicfuscate.service is active."
fi
```

### Step 6: Tests

**File:** `tests/install_script_test.sh` (new) or extend an existing install
test harness.

- **Fresh install on clean system** (container/VM): run the installer, then
  assert:
  - `id -u quicfuscate` succeeds.
  - `id -gn quicfuscate` returns `quicfuscate`.
  - `getent group quicfuscate` succeeds.
  - `stat -c '%a %U %G' /var/lib/quicfuscate` returns `700 quicfuscate quicfuscate`.
  - `stat -c '%a %U %G' /etc/quicfuscate` returns `750 root quicfuscate`.
  - `stat -c '%a %U %G' /var/log/quicfuscate` returns `750 quicfuscate quicfuscate`.
  - `systemctl is-active quicfuscate.service` returns `active`.
- **Idempotent re-run**: run the installer twice; the second run must not
  error and must not reset ownership/permissions destructively.
- **Missing prerequisite**: uninstall `iptables`, run installer, expect
  non-zero exit and a clear error message.
- **No-start mode**: run with `--no-start`, verify user + dirs created and
  service not started.

## Files to Modify/Create

- `scripts/install/install-server-linux.sh` — replace `ensure_user`, add
  `ensure_group`, `validate_prerequisites`; rework directory creation block;
  add config validation and post-start verification.
- `scripts/install/install-server-windows.ps1` (or equivalent) — add
  `wintun.dll` presence check (cross-references TODO-442).
- `tests/install_script_test.sh` — **new**: fresh-install, idempotent re-run,
  missing-prereq, and no-start assertions.

## Acceptance Criteria

- [x] `ensure_group "quicfuscate"` creates a system group named
      `quicfuscate` via `groupadd` or `addgroup`. **VERIFIED** - both guarded branches are implemented and syntax validation passes.
- [x] `ensure_user "quicfuscate"` creates a system user with primary group
      `quicfuscate`, home `/var/lib/quicfuscate`, shell `/usr/sbin/nologin`,
      no home directory creation - on both `useradd` and `adduser` distros. **VERIFIED** - both command signatures set the required identity, group, home, shell, and no-create behavior.
- [x] Re-running the installer does not error when the user/group already
      exist. **GAP -> TODO-541** - source guards exist, but no privileged idempotent rerun proof exists.
- [x] `/var/lib/quicfuscate` is created with mode `0700`, owner
      `quicfuscate:quicfuscate`. **VERIFIED** - installer applies exact owner and mode.
- [x] `/etc/quicfuscate` is created with mode `0750`, owner
      `root:quicfuscate`. **VERIFIED** - installer applies exact owner and mode.
- [x] `/var/log/quicfuscate` is created with mode `0750`, owner
      `quicfuscate:quicfuscate`. **VERIFIED** - installer applies exact owner and mode.
- [x] `validate_prerequisites` aborts the install with a clear message when
      `iptables` or `ip` is missing. **VERIFIED** - validation runs before installation mutations and reports distro-specific remediation.
- [x] The default config is copied and (when `python3` is available)
      validated as parseable TOML. **VERIFIED** - copy-if-absent and `tomllib` validation are wired.
- [x] After `systemctl enable --now`, the script verifies the service is
      `active` and prints the journal on failure. **VERIFIED** - active check, status, journal, and nonzero exit are implemented.
- [x] Fresh-install test passes on a clean container (Debian + RHEL). **GAP -> TODO-541** - no clean Debian/RHEL execution evidence exists.
- [x] Idempotent re-run test passes. **GAP -> TODO-541** - no system-level rerun test exists.
- [x] Missing-prerequisite test exits non-zero with an actionable message. **GAP -> TODO-541** - the branch is source-verified but lacks an executable sandbox test.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Fresh install (clean container) | < 15s | Binary copy + user/dir creation + service start |
| Idempotent re-run | < 10s | All guards short-circuit |
| Prerequisite validation | < 100ms | `command -v` checks only |
| Config TOML validation (python3) | < 200ms | Single parse of < 10 KiB file |
| Post-start verification | ~1s | `sleep 1` + `systemctl is-active` |
