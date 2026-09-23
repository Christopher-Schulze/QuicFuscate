---
id: TODO-722
title: Clear and verify supplementary groups on non-Linux privilege drop
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-01
depends_on: [TODO-527]
---

# TODO-722: Clear and Verify Supplementary Groups on Non-Linux Privilege Drop

## Why

The Linux privilege path clears supplementary groups before dropping identity, but the non-Linux Unix branch only calls `setgid` and `setuid`. A process can therefore retain supplementary group memberships after the apparent drop.

## Findings

### 1. Non-Linux Unix drops do not clear supplementary groups
- **File:** `src/privilege/drop.rs:398-402`
- **Severity:** HIGH
- **Problem:** The `#[cfg(all(unix, not(target_os = "linux")))]` path sets the primary GID and UID and verifies effective IDs, but does not call a platform-appropriate supplementary-group clearing operation or verify the resulting group set.
- **Impact:** Files and resources accessible through retained supplementary groups remain available after privilege reduction, violating the platform-independent privilege-boundary contract.
- **Boundary:** Every supported Unix privilege drop must clear or explicitly reject retained supplementary groups before reporting success.

## Acceptance

- Every supported non-Linux Unix path clears supplementary groups before `setuid` or returns an explicit unsupported/error result.
- Post-drop verification proves the effective UID, GID, and supplementary-group set match the declared contract.
- Failure of group clearing is propagated and cannot produce a successful drop report.
- Platform-gated tests cover success and group-clear failure paths.
- Local Rust gates and strict Clippy pass.

## Sub-Tasks

- [x] Map the supported non-Linux APIs for clearing supplementary groups.
- [x] Add the operation and propagate failures before the identity change.
- [x] Extend post-drop reports and tests with supplementary-group state.
- [x] Run the available macOS privilege test matrix; the Linux/native limits
      are recorded in the TODO-722 section of `docs/todo.md`.

## Notes

- Linux already has a separate `clear_supplementary_groups()` path; preserve its semantics.
- Related proof owner: TODO-527.

## Current Reconciliation (2026-08-07)

- The non-Linux Unix privilege path sets and verifies effective gid/uid but does not clear or verify supplementary groups. The post-drop identity proof is therefore incomplete outside Linux. No platform implementation or native gate was performed.

## Deviations

None.

## Archive reconciliation (2026-09-23)

Completion evidence and its platform limits are recorded in the TODO-722
section of `docs/todo.md`. This metadata reconciliation did not rerun tests.
