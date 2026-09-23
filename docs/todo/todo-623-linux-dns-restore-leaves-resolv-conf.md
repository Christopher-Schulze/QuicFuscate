---
id: TODO-623
title: linux DNS restore leaves written resolv.conf behind when no original file existed
severity: LOW
phase: C
priority: P3
status: BLOCKED
created: 2026-08-01
depends_on: []
---

# TODO-623: Linux DNS Restore Leaves Modified resolv.conf When Original Did Not Exist

## Current execution gate (2026-09-23)

The remaining owner is privileged Linux proof of the implemented legacy
resolver lifecycle in `src/implementations/client/platform/linux.rs` and
`dns_restore.rs`. On an isolated Linux host, record the exact source revision,
original `/etc/resolv.conf` state and file type, then exercise absent-original
and present-original connect/disconnect, repeated writes, SIGKILL/restart,
active-owner refusal, foreign-content conflict, and malformed/cross-boot
sidecar refusal. Verify byte-identical restoration or absence as applicable,
no unrelated file mutation, and zero owned sidecar/backup residue after
successful cleanup. The August note that one Omega SSH route was unavailable
is historical; recheck host access before execution. Keep TODO-649's separate
symlink/target policy outside this closure.

## Why

`LinuxPlatform::set_dns` without systemd-resolved previously skipped backup state
when `/etc/resolv.conf` did not exist, while `restore_dns` treated the missing
backup as a no-op. That left the QuicFuscate-written file behind after disconnect.

## Findings

### 1. Restore cannot undo the write when the file was absent
- **Files:** `src/implementations/client/platform/linux.rs:277-334`; `src/implementations/client/platform/dns_restore.rs:198-306`
- **Previous:** `backup_resolv_conf_if_needed` recorded `None` when the source file
  was absent; `restore_resolv_conf_from_backup` treated `None` as "nothing to do".
- **Problem:** After a session where `/etc/resolv.conf` did not exist before
  connect, disconnect leaves `/etc/resolv.conf` populated with VPN DNS servers
  permanently, silently altering host DNS resolution state.
- **Implementation:** `ResolvConfRestoreState` records either the copied original
  path or an explicit `Absent` state. Restore removes the written resolver file
  for the absent case and clears state only after successful cleanup. Every managed
  write carries a session marker, and restore verifies that marker before deleting
  or replacing a completed session's current resolver file.

### 2. Restore state is lost when a crash removes or invalidates the backup
- **Files:** `src/implementations/client/platform/linux.rs:240-334`; `src/implementations/client/platform/dns_restore.rs:55-195`
- **Current:** The backup path and absent-original state previously existed only in
  process memory. If the process died after the DNS write, a later
  `LinuxPlatform` instance had no ownership record; a stale fixed backup could
  also be overwritten by the next `set_dns` call.
- **Problem:** The next session cannot distinguish an original resolver file from
  a file written by a previous crashed session, so crash recovery can preserve the
  VPN resolver contents as if they were the host's original configuration.
- **Implementation:** A create-only sidecar records the schema, Linux boot ID,
  PID, process start time, original-existence state, and matching session marker
  before the resolver write. An advisory lock serializes sessions. Same-boot stale
  sessions are recovered only when the owner identity is no longer active and the
  current resolver content still carries the session marker; foreign, incomplete,
  cross-boot, malformed, or orphaned state fails closed. The fixed-path and
  symlink/target contract remains tracked by `TODO-649`.

## Acceptance

- Precondition: `/etc/resolv.conf` absent. After `set_dns` + `restore_dns` the
  file is absent again.
- Precondition: file present. After `set_dns` + `restore_dns` the original
  content is restored byte-identical.
- A stale session cannot remove or replace a current resolver file without its
  session marker, and an orphaned or malformed sidecar is never overwritten.

## Sub-Tasks

- [x] Extend the backup state to record original existence.
- [x] Remove the written file on restore when original was absent.
- [x] Add tests covering absent/present original round trips and missing-backup failure (temp-dir based).
- [x] Persist ownership with boot/PID/start-time identity, serialize create-only state, coordinate concurrent legacy resolver sessions with an advisory lock, mark managed content, and recover stale sessions fail-closed.
- [!] Run and record the exact-revision isolated native Linux matrix above; access to a suitable privileged host must be rechecked.

## Notes

- systemd-resolved path (`resolvectl dns`/`revert`, `src/implementations/client/platform/linux.rs:609-625,647-653`) already restores
  correctly; this finding covers the legacy `/etc/resolv.conf` path only.
- The backup file itself (`/etc/resolv.conf.quicfuscate.bak`) is already removed
  after successful restore (`src/implementations/client/platform/dns_restore.rs:276-289`).
- Present-original restore now refuses to report success when the backup has
  disappeared and retains its in-memory state for a retry.
- A create-only ownership record is derived beside the existing backup path and
  contains schema, Linux boot ID, PID, process start time, original-existence
  state, and the matching resolver-content marker. Active owners block competing
  sessions; stale same-boot owners are recovered only after process identity no
  longer matches and the current file proves ownership. Cross-boot state,
  malformed state, foreign content, and orphaned backups fail closed.
- The current restore helper clears its in-memory state only after the source and
  backup operations succeed. A marker line is intentionally included in the
  temporary managed resolver content so repeated `set_dns` calls retain a stable
  ownership proof; TODO-649 still owns symlink/target handling.
- The focused resolver suite passes 8/8. The full local library run reached
  2,190/2,192; its two failures are unrelated to this task: the DoH cache unit
  test requires external `cloudflare-dns.com` resolution, and the qftls
  ClientHello test calls the frame API before its configured profile jitter
  deadline. These remain separate gate debt and are not represented as DNS
  restore evidence.
- Local implementation and all available macOS checks are complete. The task
  remains blocked, not marked done, until the native Linux platform gate can run
  with a Linux C sysroot or an available configured Omega checkout.

## Deviations

None.
