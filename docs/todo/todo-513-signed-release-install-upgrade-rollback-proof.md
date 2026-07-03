---
id: TODO-513
title: Signed release, install, upgrade, and rollback proof
severity: HIGH
phase: S
priority: P1
status: PREPARED
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

## Preparation Evidence (2026-07-03)

**Status: PREPARED — checksum/signature generation added to release workflow, awaiting clean VM execution.**

- `.github/workflows/release.yml` extended with:
  - `Generate checksums and signatures` step: produces `checksums-sha256.txt`
    for all bundle artifacts in `scripts/out/build/`.
  - GPG detached signature of `checksums-sha256.txt` when
    `RELEASE_GPG_KEY_ID` and `RELEASE_GPG_PRIVATE_KEY` secrets are configured.
    Falls back to checksums-only (no signature) when secrets are absent.
  - `Upload checksums` step: uploads `checksums-sha256.txt` and `.sig` as
    a separate artifact.
- `scripts/install/install-server-linux.sh` exists and handles binary
  installation, config placement, and systemd service setup.
- `scripts/install/quicfuscate-server.service` is hardened with:
  `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`,
  `ProtectHome=true`, `ReadWritePaths`, `LimitNOFILE=1048576`,
  `LimitMEMLOCK=infinity` (added during TODO-511/516).

**Remaining for DONE:** Execute install/upgrade/rollback proof on a clean
Linux VM or remote host:
1. Download release artifacts + checksums from GitHub Actions run.
2. Verify checksums: `sha256sum -c checksums-sha256.txt`.
3. Verify signature (if GPG configured): `gpg --verify checksums-sha256.txt.sig`.
4. Run `scripts/install/install-server-linux.sh` on clean Linux.
5. Start/stop/restart service via `systemctl`.
6. Upgrade: install new version over old, verify config/QKey state preserved.
7. Rollback: install previous version, verify service health.
8. Uninstall: remove binary/service, verify state archived or removed per policy.

