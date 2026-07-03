---
id: TODO-512
title: Broderick long-running production soak and chaos proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-02
depends_on: [TODO-473, TODO-474, TODO-509, TODO-511]
---

# TODO-512: Broderick Long-Running Production Soak and Chaos Proof

## Context

Focused E2E and benchmark gates are green, but production VPN readiness needs a
long-running proof that the server/client pair remains stable under sustained
traffic, network adversity, restarts, auth changes, DNS use, and reconnects.

## Desired Outcome

- Multi-hour Broderick soak proves no obvious memory, FD, task, session, DNS,
  FEC, QKey, or tunnel stability regression.
- Failures are captured with logs and minimized repro commands.
- The soak script becomes repeatable and safe to run without corrupting shared
  namespaces or leaving stale processes.

## Test Matrix

| Scenario | Minimum Duration | Required Proof |
|----------|------------------|----------------|
| Clean baseline tunnel | 60 min | stable ping/DNS/throughput, no reconnect churn |
| Loss/jitter adversity | 60 min | FEC adapts, tunnel remains usable |
| Reconnect loop | 30 min | sessions clean up, no leaked clients |
| QKey revoke during traffic | 15 min | revoked session closes, new auth rejects revoked key |
| Server restart | 15 min | clean shutdown/restart, client reconnect path observed |
| DNS leak assertion | full run | no raw port-53 underlay packets during tunnel DNS |
| Resource tracking | full run | RSS/FD/tasks bounded or explained |

## Implementation Plan

1. Inspect existing netns/E2E scripts and reuse their lock discipline.
2. Add a soak runner under `scripts/tests/suites/` or `scripts/tests/utils/`
   only if no existing script can express the matrix.
3. Use explicit output directory under `scripts/out/tests/`.
4. Capture:
   - server/client logs,
   - process RSS,
   - FD counts,
   - packet counters,
   - DNS leak tcpdump counters,
   - FEC mode telemetry,
   - auth/revoke events.
5. Run on Broderick with controlled duration.
6. Document exact commands, duration, host, commit, and result.
7. Update `docs/DOCUMENTATION.md` release-readiness section only with measured
   truth.

## Acceptance Criteria

- Soak runs for the planned duration without unrecovered tunnel failure.
- DNS leak counter remains zero for tunnel DNS.
- No unbounded RSS/FD/task growth across the run.
- Restart/reconnect and QKey revoke scenarios have explicit pass/fail evidence.
- Any failure is converted into a concrete blocking TODO with logs.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| soak runner command on Broderick | PASS |
| `tcpdump`/counter extraction for raw DNS | zero raw tunnel DNS leaks |
| process RSS/FD sampling summary | bounded or explained |
| `git status -sb` after local doc updates | only intentional docs/scripts changes |

## Non-Goals

- Do not fake throughput success when no measurable traffic flows.
- Do not leave remote namespaces/processes running after failure.
- Do not require UI changes.

## Preparation Evidence (2026-07-03)

**Status: OPEN (prepared) — soak script exists, awaiting remote Broderick execution.**

- `scripts/tests/suites/test-runtime-soak-chaos.sh` already exists and
  implements the soak/chaos matrix with configurable iterations,
  admin iterations, fast mode, dry-run mode, and output directory.
- The script supports:
  - `--iterations N` — control loop count for reconnect/restart scenarios
  - `--admin-iterations N` — control QKey revoke/admin action scenarios
  - `--fast` — reduced iterations for quick validation
  - `--dry-run` — validate script structure without executing
  - `--output-dir DIR` — capture logs, RSS, FD counts, packet counters
- Existing E2E scripts (`scripts/tests/suites/test-e2e.sh`,
  `test-fec-e2e-loss.sh`, `test-security.sh`) provide the netns lock
  discipline and cleanup patterns that the soak script reuses.
- DNS leak assertion is already proven by
  `scripts/tests/tun-e2e-dns-leak-netns.sh` (raw_port_53_packets=0).

**Remaining for DONE:** Execute the soak script on Broderick (or equivalent
remote Linux host) for the full test matrix duration:
- 60 min clean baseline tunnel
- 60 min loss/jitter adversity
- 30 min reconnect loop
- 15 min QKey revoke during traffic
- 15 min server restart
- Full run DNS leak + resource tracking

Total minimum duration: ~3 hours. Requires a dedicated remote Linux host
with two network namespaces, root privileges for TUN/iptables, and
sufficient disk space for pcap/log captures.

