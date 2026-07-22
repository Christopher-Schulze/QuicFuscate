---
id: TODO-541
title: Prove Linux installer across clean distro lifecycles
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-460, TODO-521]
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

## Sub-Tasks

- [ ] Map supported distro commands, installer mutations, and existing release harnesses.
- [ ] Design disposable tests with exact filesystem and systemd assertions.
- [ ] Implement only source fixes exposed by the harness.
- [ ] Execute Debian, RHEL, rerun, missing-prerequisite, and Omega proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-460 reconciliation. Container use for disposable installer tests is authorized by the existing task contract, not introduced as product infrastructure.

## Deviations

None.
