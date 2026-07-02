---
id: TODO-513
title: Signed release, install, upgrade, and rollback proof
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-07-02
depends_on: [TODO-448, TODO-460, TODO-461, TODO-509]
---

# TODO-513: Signed Release, Install, Upgrade, and Rollback Proof

## Context

GitHub release builds are green, but production readiness also requires an
operator-grade release story: artifacts, checksums/signatures, install script,
service lifecycle, upgrade, rollback, config/state preservation, and uninstall
behavior.

## Desired Outcome

- Release artifacts are reproducible enough for operator trust.
- Checksums and signatures are generated and documented.
- Linux install, start, stop, restart, upgrade, rollback, and uninstall behavior
  are proven on a real host or clean VM.
- Config, QKey registry, certs, logs, and state are preserved or intentionally
  migrated.

## Implementation Plan

1. Inspect `.github/workflows/release.yml`, `scripts/install/`, config templates,
   and release artifact paths.
2. Define artifact naming and checksum/signature policy.
3. Add or harden release workflow steps for checksum/signature generation.
4. Run install proof on a clean Linux target:
   - install binary,
   - install config,
   - start service,
   - validate logs,
   - stop service,
   - restart service.
5. Run upgrade proof from previous release artifact or simulated previous
   version.
6. Run rollback proof and verify state preservation.
7. Run uninstall/cleanup proof where applicable.
8. Update operator docs with exact commands and verified behavior.

## Acceptance Criteria

- Release workflow publishes binary artifacts plus checksums/signatures.
- Install script exits non-zero on failure and leaves clear diagnostics.
- Service starts and stops cleanly.
- Upgrade preserves config and QKey state.
- Rollback restores previous binary and service health.
- Uninstall removes service/binary while preserving or explicitly archiving state
  according to documented policy.
- No secrets are emitted in logs.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `gh run view <release-run-id>` | release run success |
| checksum verification command | PASS |
| signature verification command | PASS |
| `scripts/install/install-server-linux.sh ...` | PASS on clean Linux target |
| service start/stop/restart commands | PASS |
| upgrade/rollback script or documented command sequence | PASS |

## Non-Goals

- Do not add local Docker dependency.
- Do not change UI.
- Do not publish a public release unless explicitly requested.

