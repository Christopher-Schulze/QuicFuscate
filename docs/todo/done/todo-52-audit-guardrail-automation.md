# TODO 52: Audit Guardrail Automation

## Scope
- Automated anti-regression checks for architectural drift:
  - runtime reachability
  - docs/runtime contract consistency
  - suspicious code-shape patterns in production modules

## Problem Statement (Audit Evidence, 2026-03-05)
- Repeated manual audits still left runtime-unused complexity and overlapping paths.
- Current checks focus on compile/tests/lints but not on "feature is claimed but not runtime-used" drift.
- Broad suppression and shadow paths can survive without targeted structural checks.

## Objectives
- Turn high-value forensic checks into repeatable CI gates.
- Catch dead-path reintroduction and docs/runtime contract drift early.
- Reduce dependence on manual deep sweeps for structural quality.

## Work Breakdown
### A. Runtime Reachability Checks
- [x] Add script that scans for declared fastpath modules and verifies runtime call-site reachability. [x] 2026-03-05
- [x] Flag modules that are exported/documented but only referenced by tests. [x] 2026-03-05

### B. Contract Consistency Checks
- [x] Add docs-vs-code checks for key support claims (fastpath, XDP, zerocopy). [x] 2026-03-05
- [x] Fail when feature claim is "active" but runtime capability is hard-disabled. [x] 2026-03-05

### C. Structural Risk Checks
- [x] Add detection for duplicate method definitions in same impl/module. [x] 2026-03-08
- [x] Add checks for broad `allow(dead_code)` in production-critical modules. [x] 2026-03-05
- [x] Add checks for legacy commented shadow implementations in active modules. [x] 2026-03-05

### D. CI Integration
- [x] Integrate checks into existing audit/test runner scripts under `scripts/tests/audits/`. [x] 2026-03-05
- [x] Store artifacts under `scripts/out/audits/` with deterministic naming. [x] 2026-03-05
- [x] Document remediation playbook for failed guardrail checks. [x] 2026-03-08

## Acceptance Criteria
- [x] Guardrail scripts run in CI and fail on structural drift. [x] 2026-03-08
- [x] Reachability and contract checks cover fastpath/XDP/zerocopy surfaces. [x] 2026-03-08
- [x] Audit findings become reproducible from script output. [x] 2026-03-08

## Deliverables
- [x] New guardrail scripts under `scripts/tests/audits/`. [x] 2026-03-05
- [x] CI wiring for guardrail stage. [x] 2026-03-05
- [x] Documentation on interpreting and fixing guardrail failures. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: Added `scripts/tests/audits/audit-runtime-guardrails.sh` and wired it into `scripts/tests/audits/audit-all-comprehensive.sh`. Initial warnings highlighted `BatchProcessor`/`FastPathTransport` runtime reachability gaps and broad dead-code suppression in `src/optimize/udp.rs`.
- 2026-03-05: Guardrail warnings for runtime reachability/dead-code suppression were addressed in code; guardrail currently returns `Critical: 0, Warnings: 0`.
- 2026-03-05: Extended zerocopy threshold wiring guardrail to include `src/transport/xdp.rs` io_uring compatibility send path (`udpfast` + `uring` + `xdp` + `optimize`).
- 2026-03-05: Added RNG policy guardrail for security-sensitive modules (`transport/pn`, `main`, `implementations/server/admin*`): reject direct `OsRng.fill_bytes/getrandom::getrandom/thread_rng.fill_bytes` patterns and require centralized `fill_secure_or_abort` usage.
- 2026-03-05: Extended RNG guardrail to also block direct `optimize::random` / `accelerate::random` usage in security-sensitive modules, preventing accidental non-security RNG imports on auth/token/nonce paths.
- 2026-03-05: Added monitored zero-runtime-reference acceleration export guardrail (warning mode) for dead/shadow candidates in `optimize::{memory,transport,stealth}`.
- 2026-03-05: Refined runtime reachability guardrail classification for `FastPathTransport` to treat xdp/main-only references as compatibility/test surface instead of runtime wiring.
- 2026-03-08: Extended structural drift coverage with duplicate platform-helper guardrails for `udpfast`, shared Linux zerocopy fallback-ladder checks, explicit CI wiring for Linux fastpath guard execution, and a remediation playbook in `docs/DOCUMENTATION.md`.
