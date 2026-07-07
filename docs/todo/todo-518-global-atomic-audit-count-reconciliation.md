---
id: TODO-518
title: Reconcile Global Atomic State Audit counts with code truth
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-07-07
depends_on: [TODO-517]
---

# TODO-518 — Reconcile Global Atomic State Audit Counts with Code Truth

## Context

The "Global Atomic State Audit" table in `docs/DOCUMENTATION.md` claims a total
of 116 atomic statics across the codebase, with per-module counts. A precise
recount after TODO-517 (which converted the 3 brain.rs hint atomics to
`HintChannel<A>` newtypes) revealed three drift sources:

1. **`src/optimize/telemetry.rs`**: Doc says 97, actual 101 (+4). The 6 runtime
   config gates (5 `COLLECT_*_STATS` + `TELEMETRY_ENABLED`) were not counted in
   the table. The actual metrics/counters count is 95, not 97.
2. **`src/optimize/mod.rs`**: Doc says 6, actual 5 (-1). The doc listed 5 items
   (`RR_NODE`, `NUMA_NODES`, `PROFILE_OVERRIDE`, `TLS_LIMIT_RUNTIME`,
   `LOCK_BLOCKS`) but the count column said 6.
3. **`src/qftls.rs`**: Doc says 1, actual 2 (+1). `MAX_EARLY_DATA_SIZE` was
   added after the original audit and not counted.

Net drift: +4. True total: 120, not 116.

The Future Direction section also had inconsistent category counts: it said
"97 of 116" for metrics and "7 across optimize/, crypto/, qftls.rs" for runtime
config, but 97+3+7+2+1 = 110, not 116 — the 6 telemetry config gates were in
the table's telemetry row but not in any Future Direction category.

## Precise Counts (verified 2026-07-07)

### By Module

| Module | Count | Category |
|---|---|---|
| `src/optimize/telemetry.rs` | 101 | 95 Metrics/Counters + 6 Runtime config (5 `COLLECT_*_STATS` + `TELEMETRY_ENABLED`) |
| `src/brain.rs` | 3 | Hint channels (`HintChannel<A>`, TODO-517) |
| `src/optimize/mod.rs` | 5 | Runtime config (`RR_NODE`, `NUMA_NODES`, `PROFILE_OVERRIDE`, `TLS_LIMIT_RUNTIME`, `LOCK_BLOCKS`) |
| `src/transport/batch.rs` | 3 | Metrics |
| `src/crypto/` | 2 | Runtime config (`DATA_AEAD_OVERRIDE_MODE`, `ARM_AES_OK`) |
| `src/fec/` | 1 | Sequencing (`REPAIR_ID_COUNTER`) |
| `src/stealth/` | 1 | Round-robin (`DOH_PROVIDER_INDEX`) |
| `src/qftls.rs` | 2 | Runtime gate (`TLS_OVERRIDE_REQUIRED`, `MAX_EARLY_DATA_SIZE`) |
| `src/main.rs` | 1 | Sequencing (`NEXT_ID`) |
| `src/rng.rs` | 1 | Test gate (`TEST_FORCE_SECURE_ENTROPY_FAILURE`) |
| **Total** | **120** | |

### By Purpose (Future Direction categories)

| Category | Count | Modules |
|---|---|---|
| Metrics/Counters | 98 | telemetry.rs (95) + batch.rs (3) |
| Hint channels | 3 | brain.rs (DONE, TODO-517) |
| Runtime config | 15 | telemetry.rs (6) + optimize/ (5) + crypto/ (2) + qftls.rs (2) |
| Sequencing | 2 | fec/ (1) + main.rs (1) |
| Round-robin | 1 | stealth/ (1) |
| Test gates | 1 | rng.rs (1) |
| **Total** | **120** | |

## Completion Criteria

1. Audit table in `docs/DOCUMENTATION.md` updated with accurate per-module counts.
2. Future Direction category counts updated to sum to 120.
3. `audit-todo-consistency.sh` PASS.
4. Committed.

## Files Touched

- `docs/DOCUMENTATION.md` — audit table + Future Direction.
- `docs/todo.md` — TODO-518 row.
- `docs/todo/todo-518-*.md` — this file.
