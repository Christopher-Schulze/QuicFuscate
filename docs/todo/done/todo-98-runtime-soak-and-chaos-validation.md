# TODO 98: Runtime Soak and Chaos Validation

## Scope
- long-running runtime validation
- reconnect churn
- loss/jitter chaos
- admin/QKey activity during load

## Problem Statement
- The repository is structurally much cleaner, but it still needs prolonged hostile-condition evidence, not just targeted unit and integration tests.

## Desired End State
- Reproducible soak and chaos suites that answer:
  - does the runtime stay stable for long sessions
  - what fails under churn or pressure
  - how do admin/QKey actions interact with live runtime stress

## Execution Plan

### Phase 1: Soak Matrix
- Define long-run scenarios for:
  - long steady sessions
  - reconnect churn
  - loss/jitter bursts
  - repeated control-plane mutations

### Phase 2: Chaos Harness
- Reuse existing suites where possible and extend them with controlled loops and stress envelopes.
- Implemented first retained entrypoint:
  - `scripts/tests/suites/test-runtime-soak-chaos.sh`
- Current fast-path envelope:
  - repeated `test-e2e-integration.sh --fast`
  - repeated `test-fec-e2e-loss.sh --fast`
  - `test-e2e-admin-web.sh` under `QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1`
- The retained harness now writes:
  - top-level `results.json`
  - top-level `summary.txt` for future runs

### Phase 3: Telemetry and Findings
- Record:
  - failures
  - stalls
  - reconnect behavior
  - controller pathologies
  - runtime counters that explain the outcome

### Phase 4: Fix and Publish
- Tighten runtime behavior where soak/chaos finds real problems.
- Sync the resulting truth to docs.

## Acceptance Criteria
- [x] Reproducible soak and chaos runs exist.
- [x] Findings are either fixed or documented as real constraints.
- [x] The runtime is defended by long-run evidence, not only short tests.

## Validation Status
- `bash -n scripts/tests/suites/test-runtime-soak-chaos.sh`
- `bash scripts/tests/suites/test-runtime-soak-chaos.sh --dry-run --fast`
- `bash scripts/tests/suites/test-runtime-soak-chaos.sh --fast`
- First real fast run result:
  - E2E integration block: green
  - FEC loss chaos block: green
  - admin/QKey control-plane block: green
  - artifacts: `scripts/out/tests/test-runtime-soak-chaos-20260309_132436`
  - note: this first real run predates the later `summary.txt` writer addition and therefore produced top-level `results.json` but no top-level `summary.txt`
- Second real fast run result with the updated harness:
  - E2E integration block: green
  - FEC loss chaos block: green
  - admin/QKey control-plane block: green
  - artifacts: `scripts/out/tests/test-runtime-soak-chaos-20260309_134606`
  - top-level outputs:
    - `results.json`
    - `summary.txt`
  - summary:
    - `ok=3`
    - `failed=0`
- Broader repeated soak run result:
  - steady integration iterations: `2/2` green
  - FEC loss chaos iterations: `2/2` green
  - admin/QKey iterations: `2/2` green
  - artifacts: `scripts/out/tests/test-runtime-soak-chaos-20260309_141016`
  - top-level outputs:
    - `results.json`
    - `summary.txt`
  - summary:
    - `ok=6`
    - `failed=0`
    - `steady_ok=2`
    - `steady_failed=0`
    - `fec_ok=2`
    - `fec_failed=0`
    - `admin_ok=2`
    - `admin_failed=0`
    - `elapsed_seconds=275`

## Validation Matrix
- targeted suite scripts
- longer-running end-to-end / integration / stress runs
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`

## Notes
- Deployment is out of scope.
- This is still local or CI-friendly runtime validation.
- No local instability or control-plane regressions were observed in the broadened retained soak envelope.
