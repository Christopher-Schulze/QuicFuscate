---
id: TODO-892
title: Modularize the FEC internal runner without collapsing proof boundaries
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-14
depends_on: [TODO-890]
---

# TODO-892: Modularize the FEC Internal Runner Without Collapsing Proof Boundaries

## Objective

Give the internal FEC machine-room runner explicit, fail-closed scope selection while preserving the current command identity, mode order, environment contracts, refactor aliases, and the separate FEC simulation, controller, proof, end-to-end, and benchmark boundaries.

The internal runner is `scripts/tests/suites/test-fec.sh`. The aggregate dispatcher `scripts/tests/suites/test-fec-all.sh` already provides coarse `--mode` selection and must remain the single owner of cross-runner orchestration. This task adds fine-grained selection inside the internal runner and makes the aggregate boundary auditable; it does not merge independent FEC proof programs into one giant command.

This is a test-harness and task-documentation change only. It does not authorize FEC algorithm changes, decoder rewrites, wire-format changes, performance tuning, or frontend/Tauri work.

## Why

The internal FEC runner is short at 102 lines but still combines three independent proof responsibilities behind one default invocation:

- Seven initial-mode executions of the broad `fec::` test filter.
- One GF(2^16) SIMD and nibble-table execution.
- Optional refactor validation consisting of nine focused library filters and three structural `rg` checks.

The full-suite utility invokes `test-fec.sh --refactor`, then separately invokes the auto-controller scenarios, auto-controller proof, simulation matrix, and E2E loss matrix. A developer debugging only GF16 or only a visibility/refactor invariant currently has no way to run that dimension without also paying for every internal mode. Conversely, a future implementation could accidentally move simulation or E2E cases into the internal runner and create duplicate or misleading evidence.

The project already has two complementary conventions that must be preserved:

1. `test-fec-all.sh --mode internal|simulation|e2e-loss|controller|proof|fast|all` is the coarse FEC dispatcher.
2. `test-crypto.sh`, `test-stealth.sh`, and `test-security.sh` use validated comma-separated `--only` scopes with explicit omitted-scope JSON records.

The correct design is therefore a two-level contract: `--mode` selects a FEC program, and `test-fec.sh --only` selects a dimension inside the internal program. No second aggregate dispatcher and no duplicated simulation matrix are allowed.

## Verified Current State

The following inventory is source-derived from `scripts/tests/suites/test-fec.sh`, `scripts/tests/suites/test-fec-simulation.sh`, `scripts/tests/suites/test-fec-all.sh`, and `scripts/tests/utils/util-run-full-suite.sh`:

| Current owner | Current behavior | New internal scope or boundary | Must remain separate |
|---|---|---|---|
| Initial FEC modes | Seven ordered `run_cargo_logged` calls with `QUICFUSCATE_FEC_INITIAL_MODE=zero`, `light`, `normal`, `medium`, `strong`, `extreme`, and `streaming`, each using the release `fec::` filter | `modes` | GF16, refactor checks, simulation matrix, E2E loss |
| GF16 path | One release `gf16` filter with `QUICFUSCATE_GF16_SIMD=1` and `QUICFUSCATE_GF16_NIBBLE=1` | `gf16` | Initial modes, simulation matrix, benchmark-only GF16 cells |
| Refactor focused tests | Nine ordered release library filters: `stream_raw_roundtrip`, `test_batch_normal`, `test_batch_extreme_gf16`, `test_streaming_tetrys`, `gf16`, `test_batch_extreme_gf16_coeff_len`, `test_streaming_repairs_have_nonzero_coeffs`, `test_streaming_tetrys_burst_loss_recovery`, and `test_streaming_emit_every_n` | `refactor` | Production mode matrix and E2E proof |
| Refactor structural checks | `rg` checks for the Kalman error covariance shape, `pub mem_pool: Arc<MemoryPool>`, and `impl Drop for FecPacket` | `refactor` result subrecords | Source changes outside the focused internal contract |
| Simulation matrix | `test-fec-simulation.sh` varies mode, loss, Rayon threads, GF16, stream cadence, and adaptive RS while repeatedly running `fec::test_auto_mode_streaming_selection` | Aggregate `--mode simulation` | Must not be silently pulled into `test-fec.sh --only modes` or `--only gf16` |
| E2E loss | `test-fec-e2e-loss.sh` owns model/network loss recovery | Aggregate `--mode e2e-loss` | No internal scope may claim native QUIC/TUN proof |
| Controller scenarios and proof | Separate scenario and proof runners, with proof also owning benchmark iterations | Aggregate `--mode controller` and `--mode proof` | No duplication from internal scope selection |
| Fast FEC smoke | `scripts/tests/fast/test-fast-fec.sh` owns the quick unit plus bench-compile lane | Aggregate `--mode fast` and the full-suite fast lane | Do not move its telemetry/Wiedemann ownership into `test-fec.sh` |

Current flag behavior is also part of the baseline:

- `--refactor` enables the refactor block in addition to modes and GF16.
- `--refactor-only` enables only the refactor block.
- `--output-dir`, `--jobs`, `--features`, and `--verbose` are forwarded through the existing harness validation path.
- Unknown flags exit `2`.
- The current default internal path runs modes and GF16; it does not run the refactor block unless `--refactor` is supplied.

## Canonical Internal Scope Contract

`test-fec.sh` must expose exactly `modes`, `gf16`, and `refactor`, plus `all` as the default. `refactor` is intentionally one auditable scope even though it produces focused test and structural subrecords. This keeps the public vocabulary small while allowing the JSON artifact to distinguish each invariant.

| Scope | Exact owned work | Environment and feature rules | Expected default relation |
|---|---|---|---|
| `modes` | The seven current initial-mode commands in their current order | One `QUICFUSCATE_FEC_INITIAL_MODE` assignment per invocation; existing Cargo feature set and release flags | Included by default and by `--refactor`; omitted by `--refactor-only` |
| `gf16` | The current GF16 SIMD/nibble command | Preserve both GF16 environment assignments and the existing feature set | Included by default and by `--refactor`; omitted by `--refactor-only` |
| `refactor` | Nine focused Cargo filters plus three structural checks | Preserve filter order, `--lib`, release mode, env assignments, and fail-closed `rg` checks | Opt-in through `--refactor`, `--refactor-only`, or explicit `--only refactor` |

`--only` is a new fine-grained selector. Examples:

- `--only modes` runs exactly seven mode invocations.
- `--only gf16` runs exactly the GF16 invocation.
- `--only refactor` runs the complete focused refactor block, including structural checks.
- `--only modes,gf16` runs the normal internal default without relying on legacy aliases.
- `--only all` is equivalent to the current default without `--refactor`.

## Legacy Flag Compatibility

The legacy flags are not removed or reinterpreted silently:

| Invocation | Effective selection | Required compatibility |
|---|---|---|
| no `--only`, no legacy refactor flag | `modes,gf16` | Exact current default |
| `--refactor` | `modes,gf16,refactor` | Exact current full-suite internal call |
| `--refactor-only` | `refactor` | Exact current focused refactor call |
| `--only modes,gf16` | `modes,gf16` | New explicit equivalent of the default |
| `--only refactor` | `refactor` | New explicit equivalent of `--refactor-only` |
| `--only modes --refactor` | Invalid combination unless a documented canonical merge rule is implemented | Never run a surprising superset silently |
| `--only modes --refactor-only` | Invalid combination | Never allow two competing selectors |

The implementation must choose and document one deterministic conflict rule before editing. The preferred rule is to reject conflicting explicit selectors with status `2`, while accepting `--only all --refactor` only if it is normalized to the explicit `modes,gf16,refactor` selection and recorded as such. No last-flag-wins behavior is allowed because it makes shell history and CI logs misleading.

## Cross-Runner Boundary Contract

The following ownership map is mandatory:

| User intent | Canonical entrypoint | Internal `test-fec.sh` scope involved |
|---|---|---|
| Initial mode regressions | `test-fec.sh --only modes` | `modes` |
| GF16 SIMD and nibble path | `test-fec.sh --only gf16` | `gf16` |
| Refactor/API/ownership invariants | `test-fec.sh --only refactor` | `refactor` |
| Configuration robustness across loss/thread/GF16/cadence/RS | `test-fec-all.sh --mode simulation` or direct simulation runner | None beyond its own runner |
| Real loss recovery | `test-fec-all.sh --mode e2e-loss` | None |
| Adaptive controller scenarios | `test-fec-all.sh --mode controller` | None |
| Combined controller evidence and benchmark iterations | `test-fec-all.sh --mode proof` | None |
| Quick FEC smoke | `test-fec-all.sh --mode fast` | None |

The full-suite utility must continue to run one internal FEC command, one controller scenario command, one controller proof command, one simulation command, and one E2E loss command in its existing order. Adding `--only` must not cause any of those independent runners to be invoked twice.

## Implementation Plan

1. Freeze the command inventory above, including the seven mode environment values, the exact GF16 assignments, the nine refactor filters, and the three structural search predicates. Store expected item identities in the new contract fixture before changing dispatch.
2. Add `ONLY=all` and a validated `--only` parser to `test-fec.sh`. Preserve existing argument handling and the current unknown-flag status. Update help text with the exact canonical scope names and legacy alias semantics.
3. Add a single explicit-selection JSON record with requested scopes, effective normalized scopes, legacy alias usage, and mode. Add one scope record per canonical scope with `PASS` for selected or `SKIP` for omitted.
4. Reuse the shared scope-validation and JSON helpers already used by neighboring suites. Do not create a FEC-specific parser, result schema, or ad hoc string-to-shell conversion.
5. Move the seven mode calls behind one `run_modes_scope` owner. Keep their order, filter, release profile, environment assignment, output logging, and failure propagation unchanged.
6. Move the GF16 call behind one `run_gf16_scope` owner. Preserve both `QUICFUSCATE_GF16_SIMD=1` and `QUICFUSCATE_GF16_NIBBLE=1`; do not broaden the production feature set to make the scope discoverable.
7. Move the nine refactor filters and three structural checks behind one `run_refactor_scope` owner. Emit separate result records for each command or check so a failed invariant cannot be hidden behind one aggregate `[OK]` line.
8. Normalize legacy flags before dispatch. Reject conflicting explicit selectors before creating a green result artifact. The normalized selection must be recorded so a legacy full-suite call is distinguishable from a focused call.
9. Add non-vacuity checks using the existing shared cargo output classification. A selected filter that executes zero tests, loses its successful result marker, or fails discovery is `FAIL`, never `PASS`. A selected structural `rg` check that does not find its required current invariant is `FAIL`.
10. Add explicit omitted-scope records with `reason=not_selected_by_scope`. Do not record the aggregate as green when all requested scopes were accidentally skipped.
11. Keep `test-fec-all.sh`'s `--mode` vocabulary unchanged. Add only the minimum pass-through documentation or contract assertions needed to prove that `--mode internal --only ...` reaches the internal runner without leaking `--only` to simulation, E2E, controller, proof, or fast scripts that do not accept it.
12. Reconcile `util-run-full-suite.sh` calls. The scoped `fec` path continues to pass `--refactor`; the default fast path continues to use `test-fast-fec.sh`; the matrix and E2E calls continue to use their own `--fast` profiles.
13. Add a real shell contract fixture under `scripts/tests/fast/` covering default, each individual scope, valid combinations, legacy aliases, conflicting flags, unknown scope, explicit skip rows, positive execution counts, and injected failure propagation. The fixture must inspect actual JSON and actual exit status.
14. Update `docs/DOCUMENTATION.md` and `docs/MAP.md` only after implementation. Document the two-level FEC dispatcher contract and the non-overlap between internal mode tests, simulation robustness, controller evidence, E2E loss, and benchmark proof.
15. Re-read all changed files, run shell syntax and warning-level ShellCheck where available, execute the focused contract fixture, and run the selected internal scopes with isolated output directories. Native Linux, x86 SIMD, privileged E2E, and hosted controller evidence remain explicit availability boundaries.
16. Compare unscoped default and `--refactor` artifacts with the current command inventory. Any removed mode, reordered command, changed environment, duplicate external runner, or silent zero-test path blocks closure.

## Acceptance Criteria

- `test-fec.sh --help` lists exactly `modes,gf16,refactor` for `--only` and documents `--refactor` and `--refactor-only`.
- The no-flag invocation remains modes plus GF16 in the existing order and does not unexpectedly include refactor checks.
- `--refactor` remains the full internal machine-room plus focused refactor contract used by the full runner.
- `--refactor-only` and `--only refactor` are behaviorally equivalent and execute all nine focused filters plus all three structural checks.
- Every selected scope executes only its own commands and every omitted scope is an explicit `SKIP` with a named reason.
- Conflicting legacy and explicit selectors fail before misleading green output; no last-flag-wins ambiguity remains.
- Every selected Cargo filter proves a positive executed-test count and a successful result marker. Structural checks prove their exact current invariants.
- The seven initial modes retain their exact environment assignments and order, including `streaming`.
- GF16 retains both SIMD and nibble environment flags and its existing release test boundary.
- `test-fec-all.sh --mode simulation|e2e-loss|controller|proof|fast` remains unchanged and does not inherit incompatible internal-only flags.
- `util-run-full-suite.sh` does not duplicate internal FEC, simulation, controller, proof, or E2E execution after the change.
- No FEC production source, wire contract, feature ownership, benchmark threshold, frontend source, Tauri host, visual asset, animation, style, layout, copy, or approved Rotate button changes as part of this task.

## Verification Matrix

| Gate | Required evidence | Expected result |
|---|---|---|
| Shell parse | `bash -n scripts/tests/suites/test-fec.sh`, `test-fec-all.sh`, and the new fixture | Exit `0` |
| Static shell quality | Warning-level ShellCheck on changed shell files when installed | No new diagnostics |
| Help and validation | Help, unknown scope, empty scope, malformed list, and conflicting legacy flags | Help `0`; invalid input `2` |
| Default compatibility | Unscoped `test-fec.sh` with isolated output | Modes and GF16 identities/order match baseline |
| Mode scope | `--only modes` | Seven mode invocations, no GF16/refactor records except explicit skips |
| GF16 scope | `--only gf16` | One GF16 invocation with both environment assignments |
| Refactor scope | `--only refactor` and `--refactor-only` | Nine Cargo records plus three structural records, all failable |
| Explicit combination | `--only modes,gf16` and `--refactor` | Correct normalized selection and no duplicates |
| Aggregate boundary | Each `test-fec-all.sh --mode` | Existing downstream runner receives only its supported flags |
| Full-suite consumer | `util-run-full-suite.sh --only fec` with isolated output | One internal, one controller, one proof, one simulation, one E2E path |
| Failure integrity | Controlled failing filter or structural predicate | Nonzero exit, named `FAIL`, no `[OK]` |
| Documentation/diff | `git diff --check`, complete read-back, protected-path diff audit | Clean local diff; no frontend/Tauri visual delta |

## Primary Files and Owners

- `scripts/tests/suites/test-fec.sh`
- `scripts/tests/suites/test-fec-all.sh` only for boundary/contract assertions
- `scripts/tests/suites/test-fec-simulation.sh` only for non-overlap verification
- `scripts/tests/suites/test-fec-e2e-loss.sh` only for non-overlap verification
- `scripts/tests/suites/test-fec-auto-controller-scenarios.sh` only for non-overlap verification
- `scripts/tests/suites/test-fec-auto-controller-proof.sh` only for non-overlap verification
- `scripts/tests/utils/util-run-full-suite.sh`
- `scripts/tests/fast/test-fec-scope-contract.sh` (new contract fixture if needed)
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `docs/todo.md`
- `docs/todo/todo-892-fec-runner-granularity.md`

## Non-Goals

- Replacing the FEC simulation matrix with the internal mode runner.
- Claiming that the simulation matrix proves per-dimension code-path divergence. Its existing proof boundary remains configuration robustness around one focused test.
- Changing FEC mode policy, GF16 kernels, decoder ownership, adaptive controller behavior, loss model, or E2E network setup.
- Removing or renaming `test-fec-all.sh --mode` values.
- Creating a second FEC result schema or a hidden aggregate that hides failed subcommands.
- Touching any frontend or Tauri visual property. The established visual output and approved Rotate control remain frozen.

## Risks and Fail-Closed Rules

- The largest risk is accidentally treating a broad `fec::` filter as proof that every mode path diverged. Preserve the current filter and describe its actual boundary; do not overclaim.
- The second risk is moving simulation or E2E work into an internal scope and doubling runtime. The cross-runner ownership table and full-suite artifact identity check are mandatory.
- A legacy flag conflict must fail closed, not silently select whichever argument appeared last.
- Never use `|| true`, ignore Cargo status, accept `running 0 tests`, or downgrade a missing structural invariant to a skip.
- Keep all environment assignments array-safe and scoped to the intended Cargo process.
- Do not weaken tests, change FEC production code, or alter the frozen frontend to make a runner scope pass.

## Deviations

None.
