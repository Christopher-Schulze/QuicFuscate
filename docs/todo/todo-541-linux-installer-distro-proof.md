---
id: TODO-541
title: Prove Linux installer across clean distro lifecycles
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-460, TODO-527, TODO-530, TODO-531, TODO-542]
---

# TODO-541: Prove Linux Installer Across Clean Distro Lifecycles

## Why

The installer source creates the service identity and directories, validates prerequisites and TOML, and checks systemd startup. No clean Debian/RHEL, idempotent rerun, or missing-dependency execution proves those branches on real distro tool variants.

## Acceptance

- Build a terminating, disposable installer harness for clean Debian-family and RHEL-family environments without weakening the production script.
- Prove user/group identity, shell/home, directory owners/modes, config/env/qkey permissions, unit installation, service activation, and actionable journal failure output.
- Prove second-run idempotence preserves operator-owned config and credentials.
- Prove missing `iptables`, `ip`, and required service-manager paths fail before install mutations with actionable messages.
- Pass shell/static checks, local disposable tests, native CI, Omega clean-host-equivalent proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Clean-install gate: supported Debian-family and RHEL-family disposable environments prove identities, paths, modes, ownership, configuration, credentials, unit state, startup, and actionable journal output.
- Idempotence gate: a second run preserves operator-owned configuration and credentials while converging every installer-owned resource without duplicate or widened permissions.
- Preflight gate: every missing prerequisite and unsupported environment fails before the first persistent mutation, with a test proving the filesystem and service-manager baseline is unchanged.
- Release gate: shell/static checks, disposable tests, native CI, exact-artifact Omega clean-host-equivalent lifecycle, SHA-256, uninstall/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map supported distro commands, installer mutations, and existing release harnesses.
- [ ] Design disposable tests with exact filesystem and systemd assertions.
- [ ] Implement only source fixes exposed by the harness.
- [ ] Execute Debian, RHEL, rerun, missing-prerequisite, and Omega proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-460 reconciliation. Container use for disposable installer tests is authorized by the existing task contract, not introduced as product infrastructure.
- Primary surfaces: `scripts/install/install-server-linux.sh`, `scripts/install/quicfuscate-server.service`, `src/implementations/server/systemd.rs`, `config/server-linux.default.toml`, and the existing release lifecycle harnesses under `scripts/tests/`.
- Scope lock: test the production installer unchanged first and make only source fixes exposed by real distro behavior. Containers or disposable hosts are test substrates, not new product deployment architecture.
- Evidence bundle: retain clean filesystem/service baselines, distro/package-manager versions, mutation journal, owners/modes, preflight negative diffs, rerun preservation hashes, systemd/journal output, exact artifact hash, uninstall state, and residue manifest.

## Deviations

None.
