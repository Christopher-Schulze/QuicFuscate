---
id: TODO-1025
title: Omega E2E ready-hook scripts live only in /tmp - not reproducible
severity: LOW
phase: L
priority: P3
status: OPEN
created: 2026-09-21
depends_on: []
---

# TODO-1025: Persist the E2E ready-hook scripts into scripts/tests/

## Context

The `tun-e2e-netns.sh` validation runs on Omega rely on
`QF_E2E_READY_HOOK=/tmp/hook-udp.sh` (plus sibling hook variants for
TCP/ping evidence). These hook scripts were created ad-hoc on the
Omega host and exist **only in /tmp** - they are lost on reboot, are
not versioned, and cannot be reproduced or reviewed from the repo.

The hooks are what makes the numbers trustworthy: they capture
`qtun0` link counters inside the namespace at the right moment
(the TX-dropped counter that proved the TODO-1017/1021 root cause),
launch the iperf client, and time the measurement window while both
endpoints are up.

## Objective

- Move the hook scripts into `scripts/tests/` (e.g.
  `scripts/tests/tun-e2e-hooks/udp-ready.sh`) with the same contract:
  they run inside the prepared namespaces at readiness, take
  interfaces/rates from env, write evidence to a stable path.
- Make `tun-e2e-netns.sh` (or a sibling wrapper) reference the
  repo-relative path so `QF_E2E_READY_HOOK` is optional.
- Document the env contract (`TAG`, `UDPRATE`, hook stdout ->
  run log) in the e2e script header or `docs/DOCUMENTATION.md`
  testing section.
- Keep Omega's /tmp copies working until the repo versions land
  (deploy via the existing rsync/pull flow).

## Acceptance

- A fresh Omega checkout can run the full UDP evidence flow without
  any hand-created /tmp scripts.
- Hook stdout (qtun0 counters, iperf results) lands in the run log
  or a named evidence file, not lost to `tail` truncation.
- No behavioral change to the e2e script itself.
