# TODO-174: Scripts Redundancy Consolidation

## Status
**PARTIAL**. Phase 1 complete: 6 clearly redundant scripts archived, bridge lib removed,
cross-references updated. 85 -> 83 scripts remaining.

Phase 2 complete (2026-03-21): 3 unified dispatcher scripts created. Original scripts
kept unchanged as implementation backends - no backwards compatibility breakage.
- `scripts/tests/suites/test-fec-all.sh` - unified FEC test dispatcher (6 modes)
- `scripts/benchmarks/suites/bench-fec-all.sh` - unified FEC bench dispatcher (3 modes)
- `scripts/utils/dev.sh` - unified frontend dev launcher (7 subcommands)
- justfile updated with `test-fec`, `bench-fec`, `dev-start`, `dev-stop`, `dev-desktop`, `dev-web`, `dev-status`

Phase 3 candidates (deferred): TLS utils merge, build scripts audit.

## Severity
**LOW**

## Context
The `scripts/` directory contains approximately 88 shell scripts with significant overlap and unclear differentiation between similarly-named scripts. This makes it difficult for developers to know which script to run for a given purpose.

Overlapping script groups:
- `scripts/tests/suites/test-transport.sh` vs `scripts/benchmarks/suites/bench-transport.sh` - unclear boundary between test and benchmark
- `scripts/benchmarks/suites/bench-fec.sh` vs `scripts/benchmarks/suites/bench-fec-simulation.sh` - overlapping FEC benchmarks
- `scripts/utils/util-run-local-ui.sh` vs similar UI startup scripts - redundant launchers
- `scripts/tests/utils/util-tls-*.sh` - 7 TLS utility variants with minimal differences between them

## Root Cause
Scripts were added incrementally for specific needs without auditing existing scripts for overlap. No naming convention or organizational standard was established.

## Fix Plan
1. Inventory all scripts with one-line purpose descriptions
2. Identify exact overlaps and near-duplicates
3. Define clear categories:
   - `test-*`: Run tests, exit with pass/fail
   - `bench-*`: Run benchmarks, output metrics
   - `util-*`: Developer utilities, no pass/fail
   - `build-*`: Build-related tasks
   - `audit-*`: Code quality checks
4. Merge overlapping scripts into consolidated versions with flags/arguments
5. Create meta-wrapper scripts for common workflows:
   - `scripts/test-all.sh`: Runs all test suites
   - `scripts/bench-all.sh`: Runs all benchmarks
6. Remove redundant scripts (archive first)
7. Target: consolidate from ~88 to ~20 scripts
8. Update any CI references to renamed/removed scripts

## Acceptance Criteria
- No overlapping scripts with unclear differentiation
- Clear naming convention applied consistently
- Each script has a header comment explaining its purpose
- Total script count reduced to ~20 focused scripts
- CI pipeline updated for any script renames

## Dependencies
- TODO-175 (central justfile) - may supersede some wrapper scripts

## Affected Files
- `scripts/tests/suites/` (multiple files)
- `scripts/benchmarks/suites/` (multiple files)
- `scripts/utils/` (multiple files)
- `scripts/tests/utils/` (TLS utilities)
- `.github/workflows/ci.yml` (update script references)

## Script Inventory & Identified Redundancies

### Organization (7 categories, ~140 files total)
- `scripts/benchmarks/` - micro (6), smoke (1), suites (12), wrappers (2) = 21
- `scripts/build/` - 3 build scripts
- `scripts/install/` - 1 installer
- `scripts/lib/` - 1 shared lib
- `scripts/tests/` - analysis (4), audits (3), build (6), fast (2), frontend e2e+unit (13), fuzz (6), rust rt-* (50+), smoke (3), suites (20+), utils (11), lib (1)
- `scripts/utils/` - 11 utility scripts

### Key Redundancy Groups
1. **FEC overlap**: bench-fec.sh / bench-fec-simulation.sh / test-fec.sh / test-fec-simulation.sh / test-fec-e2e-loss.sh / test-fec-auto-controller-*.sh - 7 scripts around FEC
2. **Transport overlap**: bench-transport.sh / test-transport.sh / bench-profile-transport-fastpaths.sh - 3+ scripts
3. **Stealth overlap**: bench-stealth.sh / bench-stealth-brain.sh / test-stealth.sh / test-stealth-brain.sh - 4 scripts
4. **UI launchers**: util-run-local-ui.sh / util-stop-local-ui.sh / util-run-local-admin-web.sh / util-stop-local-admin-web.sh / util-dev-uis-start.sh / util-dev-uis-stop.sh - 6 scripts for 2 dev servers
5. **TLS utilities**: 7 tls-related utility scripts (diff, export, generate, list, head, show-active) with overlapping functionality
6. **E2E overlap**: test-e2e.sh / test-e2e-integration.sh / test-e2e-admin-web.sh - unclear boundaries
7. **Build checks**: build-check.sh / build-debug.sh / build-release.sh / build-clippy-matrix.sh / build-dev-tools.sh / build-env-doctor.sh - 6 build scripts

### Consolidation Targets (Phase 2 - deferred)
- Merge FEC scripts into 2 (test-fec-all.sh, bench-fec-all.sh)
- Merge UI launchers into 1 (dev.sh start|stop|web|desktop)
- Merge TLS utils into 1 (tls-tool.sh export|diff|list|head|verify)
- Merge build checks into 2 (build.sh debug|release|check, build-ci.sh)
- Target: ~83 -> ~30 scripts

## Phase 1 Results (2026-03-21)

### Archived to archive/scripts-redundant/:
1. **test-e2e-integration.sh** - Pure delegation wrapper (called test-e2e.sh --integration)
2. **bench-nightly.sh** - Subset of bench-orchestrator.sh --fast
3. **build-debug.sh** - Superseded by `just build` (justfile)
4. **build-release.sh** - Superseded by `just release` + build-pgo-release.sh
5. **build-dev-tools.sh** - Superseded by `just check` + `just lint` + build-clippy-matrix.sh
6. **scripts/lib/lib-common.sh** (bridge) - 7-line redirect to tests/lib/lib-common.sh

### Cross-references updated:
- `scripts/tests/utils/util-run-full-suite.sh` - test-e2e-integration.sh -> test-e2e.sh --integration
- `scripts/tests/suites/test-runtime-soak-chaos.sh` - test-e2e-integration.sh -> test-e2e.sh --integration
- `scripts/utils/util-analyze-codebase.sh` - lib bridge path -> direct tests/lib path
- `scripts/utils/util-check-quality.sh` - lib bridge path -> direct tests/lib path
- `scripts/tests/analysis/analysis-scripts-quality.sh` - removed stale bridge path check

### Kept (not redundant despite initial assessment):
- **UI launchers** (6 scripts): Different use cases (tmux full-stack vs detached dev-only),
  referenced extensively in docs/troubleshooting/DOCUMENTATION; not safe to merge
- **TLS utilities** (6 scripts): Each performs a distinct operation (diff, export, generate,
  list, head, show-env); not truly overlapping
- **build-check.sh / build-clippy-matrix.sh / build-env-doctor.sh**: Each has unique
  functionality not covered by the other or the justfile
- **bench-fec.sh / bench-fec-simulation.sh**: Test different FEC dimensions (unit vs simulation)
- **test-e2e.sh / test-e2e-admin-web.sh**: Different targets (cargo tests vs live HTTP server)

## Phase 2 Results (2026-03-21)

### Strategy
Added unified dispatcher scripts that delegate to existing implementation scripts.
No scripts were deleted, renamed, or moved. Original scripts remain fully functional
for direct invocation and for callers (bench-orchestrator, util-run-full-suite, etc.).

### New files created:

1. **`scripts/tests/suites/test-fec-all.sh`** - Unified FEC test dispatcher
   - `--mode internal` -> test-fec.sh (machine-room tests across 7 FEC modes)
   - `--mode simulation` -> test-fec-simulation.sh (parameter matrix)
   - `--mode e2e-loss` -> test-fec-e2e-loss.sh (fec_sim example loss recovery)
   - `--mode controller` -> test-fec-auto-controller-scenarios.sh (10 named scenarios)
   - `--mode proof` -> test-fec-auto-controller-proof.sh (scenarios + bench iterations)
   - `--mode fast` -> test-fast-fec.sh (quick smoke)
   - Default (no --mode or `--mode all`): runs all 6 modes sequentially

2. **`scripts/benchmarks/suites/bench-fec-all.sh`** - Unified FEC bench dispatcher
   - `--mode unit` -> bench-fec.sh (cargo bench: encoder, decoder, adaptive, XOR)
   - `--mode simulation` -> bench-fec-simulation.sh (timed test matrix)
   - `--mode smoke` -> smoke-fec-quick.sh (quick sanity)
   - Default: runs all 3 modes sequentially

3. **`scripts/utils/dev.sh`** - Unified frontend dev launcher
   - `start` -> util-dev-uis-start.sh (detached background dev servers)
   - `stop` -> util-dev-uis-stop.sh (stop detached servers)
   - `web` -> util-run-local-admin-web.sh (tmux: Rust server + web admin)
   - `desktop` -> util-run-local-ui.sh (tmux: Rust server + admin + desktop)
   - `stop-web` -> util-stop-local-admin-web.sh
   - `stop-all` -> util-stop-local-ui.sh
   - `status` -> shows PID file and tmux session status

### Justfile updates:
- Added: `test-fec`, `bench-fec`, `dev-start`, `dev-stop`, `dev-desktop`, `dev-web`, `dev-status`
- `dev-ui` and `stop-ui` kept as legacy aliases routing through dev.sh

### Build scripts analysis:
All 6 build-related scripts are unique and NOT replaceable by the justfile:
- `scripts/build/build-web-admin.sh` - Svelte build + asset publish (unique pipeline)
- `scripts/build/build-server-bundle.sh` - Server deployment tarball creation (unique)
- `scripts/build/build-pgo-release.sh` - PGO instrumented build pipeline (unique)
- `scripts/tests/build/build-check.sh` - fmt + clippy + cargo check + test compile + bench compile (more than `just check`)
- `scripts/tests/build/build-clippy-matrix.sh` - clippy across 8 feature combinations (unique)
- `scripts/tests/build/build-env-doctor.sh` - CPU/OS/toolchain diagnostics (unique)
