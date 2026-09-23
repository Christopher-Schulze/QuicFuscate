---
id: TODO-723
title: Make PKI writers reject symlinked output paths
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-01
depends_on: [TODO-434, TODO-671]
---

# TODO-723: Make PKI Writers Reject Symlinked Output Paths

## Why

PKI output contains private keys and trust material, and the current writer functions open pathnames directly. A symlink in the PKI directory can redirect a privileged write to an unintended file.

## Findings

### 1. Certificate and key writers follow path symlinks
- **Files:** `src/pki/mod.rs:228,235,259,269,322,342,352`
- **Severity:** HIGH
- **Problem:** `write_key_pem` uses `OpenOptions::open`, while certificate writers use `File::create`; neither rejects a symlink at the target path. `ensure_pki` also uses pathname existence checks before writing.
- **Impact:** A local attacker who can manipulate the PKI directory can redirect certificate or private-key writes, causing data corruption, secret disclosure, or overwrite of an unrelated target.
- **Boundary:** PKI output creation and replacement must be anchored to the intended directory and must not follow symlinks.

## Acceptance

- Existing symlinked key, certificate, and CA paths are rejected without following the link.
- New files are created with restrictive permissions and replacement is atomic without a pathname race.
- The parent directory is validated and all writer errors are propagated.
- Regression tests cover existing symlinks, replacement races where feasible, restrictive modes, and successful normal writes.
- Local Rust gates and strict Clippy pass.

## Sub-Tasks

- [x] Choose the platform-specific no-follow and atomic-replacement strategy.
- [x] Apply it consistently to key, chain, and CA writers.
- [x] Make existing-file detection and replacement use the same safe boundary.
- [x] Add symlink and permission regression tests.

## Notes

- Do not fix this by checking `is_symlink()` and then reopening the same pathname without an atomic no-follow boundary.
- Related file-permission owner: TODO-671.

## Current Reconciliation (2026-08-07)

- The private-key writer requests mode 0600 but does not reject symlinks or use a no-follow creation boundary; certificate and CA writers still use File::create without the same restrictive creation contract. No PKI implementation or filesystem race test was performed.

## Deviations

None.

## Archive reconciliation (2026-09-23)

The implementation, tests and unrun race-test limit are recorded in the
TODO-723 section of `docs/todo.md`. This metadata reconciliation did not
rerun PKI tests.
