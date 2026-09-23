---
id: TODO-730
title: Make the comprehensive audit runner fail closed and measure real scope
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-730: Make the Comprehensive Audit Runner Fail Closed and Measure Real Scope

## Current execution gate (2026-09-23)

The runner's result-integrity work is locally implemented. Its job is to
report each check truthfully; it need not make unrelated product Clippy,
Graphify, native PowerShell, or Omega checks green. The earlier closure loop
was invalid: TODO-730 waited for Omega checkout attribution under TODO-804,
while TODO-804 depends on TODO-730. TODO-804 alone owns the remote proof root.
Historical SSH UID and GitHub DNS failures below are not current blockers for
this local audit-tool task.

Re-run the current strict and advisory result-contract fixtures, scope/dialect
and suite-matrix validators, plus one bounded comprehensive run at one source
revision. Assert every invoked check has command, raw artifact, return code,
and `PASS`/`FAIL`/`UNAVAILABLE` disposition; injected command failure, absent
advisory database, missing parser, and critical finding must remain non-pass in
strict mode. The aggregate may correctly be red for separately owned product
findings, but its machine-readable status and process exit must agree. Record
exact revision, commands, artifact path, and named non-pass owners; close this
task when the runner itself passes those failable contracts. Do not require a
remote push, release publication, or TODO-804 completion to close it.

## Why

`scripts/tests/audits/audit-all-comprehensive.sh` is presented in contributor documentation and the full-suite utility as a static hardening gate, but its command-result handling and heuristic counters do not provide a reliable pass/fail contract. An infrastructure failure can be reported as a clean check, and the default exit code can be zero even after critical findings.

## Findings

### 1. Audit command failures are converted into findings-free output
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:109-112,156-168,185-187,240-251,264-271,285-290`.
- **Problem:** Strict Clippy, dependency audit, clone lint, normal Clippy, documentation generation, and the runtime guardrail invocation use `|| true` or text parsing without retaining a required command-success state. `cargo audit` can fail because its advisory database or network is unavailable and still reach `No known vulnerabilities` when the output contains no literal `Vulnerability` line. `cargo doc` can fail and still report zero missing-doc matches.
- **Impact:** A toolchain, dependency-database, or repository-analysis failure can be mistaken for a clean security or quality result. The report does not distinguish a completed check from an unavailable check.
- **Boundary:** Every required check must record its exit status, preserve its raw artifact, and fail or explicitly report `UNAVAILABLE`; no parser may convert command failure into a pass.

### 2. Default advisory exit status contradicts the documented gate contract
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:11-18,468-480`; `scripts/tests/utils/util-run-full-suite.sh:105-109`; `docs/CONTRIBUTING.md:48-65,100-109,175-183`.
- **Problem:** `STRICT` defaults to `0`, and the script exits `0` after critical findings unless callers add `--strict`. The full-suite utility and contributor gate invoke it without `--strict`, while the contributor checklist calls the audit a required pass gate. The canonical documentation also describes the script as exiting nonzero for policy findings.
- **Impact:** A normal documented full-suite run can return success despite critical audit findings, allowing downstream automation or a developer to treat an unsafe tree as validated.
- **Boundary:** Advisory reporting and blocking release/readiness gates must be separate, explicit modes with matching invocation, output, and documentation contracts.

### 3. Production-scope counters use line-text heuristics instead of parsed source scope
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:100-107,144-149`.
- **Problem:** Unsafe and leak counts are computed by matching raw lines containing `unsafe`, `mem::forget`, `Box::leak`, or `ManuallyDrop`, then excluding lines whose text contains `test` or `bench`. Comments, strings, test helpers in production files, and identifiers can inflate or evade the reported production count; `UNSAFE_COUNT` is computed but unused.
- **Impact:** Security and memory-safety metrics are not reproducible measures of production code and can hide a real runtime occurrence or produce noisy alerts that reviewers learn to ignore.
- **Boundary:** Scope must be defined by parsed Rust items or an explicitly documented file/module allowlist, with test and benchmark configurations classified structurally and every reported match retained with location.

### 4. Security scanning covers only Rust source while the repository ships other executable/configuration surfaces
- **File:** `scripts/tests/audits/audit-all-comprehensive.sh:132-142`.
- **Problem:** The hardcoded-secret scan restricts `rg` to `*.rs` under `src`, excluding shell scripts, Python/PowerShell helpers, TOML/JSON configuration, package manifests, and frontend/Tauri sources. The scan is therefore narrower than the repository's shipped and operational surface.
- **Impact:** A credential or private-key literal outside Rust can pass the advertised hardcoded-secret check, especially in installers, release scripts, configuration, or application packaging paths.
- **Boundary:** Secret scanning must cover every tracked executable and configuration surface, with explicit test-fixture/generated-artifact exclusions and a failable negative fixture.

### 5. Reported test coverage is a file-presence ratio, not executed coverage
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:273-283`.
- **Problem:** `TEST_FILES / TOTAL_FILES` counts Rust files containing the literal `#[test]`; it does not measure lines, branches, executed tests, feature-gated paths, or whether the tests passed. A test module can make an entire large implementation file count as covered, while untested files that are exercised from another module remain invisible.
- **Impact:** The JSON field named `test_coverage_percent` can be consumed as quantitative coverage even though it is only a source-shape heuristic, creating false confidence in security-critical paths.
- **Boundary:** Rename the heuristic or replace it with an actual coverage producer and record tool/version/feature scope. Never publish a source-presence ratio under a coverage metric name.

### 6. Cargo-deny warnings are emitted while the gate still exits successfully
- **Files:** `deny.toml`, the root `cargo deny --locked check` invocation.
- **Evidence:** The locked root check exits 0 but emits seven warnings: three unmatched license allowances (`CC0-1.0`, `MIT-0`, `OpenSSL`) and four unnecessary version-skip entries (`core-foundation`, `crypto-common`, `windows-result`, `windows-strings`).
- **Impact:** A green dependency-policy exit status does not mean the deny configuration is warning-free or that every exception still matches the current graph. Warning output can accumulate unnoticed unless the gate records and classifies it separately from command success.
- **Boundary:** Dependency-policy warnings require an explicit reviewed classification; configuration warnings must not be silently treated as a clean policy result.

### 7. The repository-wide ShellCheck lane records findings but cannot fail on them
- **Files:** `scripts/utils/util-check-quality.sh:69-84`, the 109 tracked `scripts/**/*.sh` files.
- **Evidence:** `shellcheck -x --format=json` reports 331 findings across 78 of the 114 tracked shell scripts: 178 warnings, 147 informational findings, and 6 style findings. The quality helper invokes `shellcheck -S warning` per file but appends `|| true`, counts text matches, and continues without a required pass/fail or structured finding classification.
- **Impact:** The documented quality output can report a number while the command remains green, and the current repository-wide warning lane contains actionable script diagnostics that are not release-blocking or ownership-linked.
- **Boundary:** ShellCheck must retain machine-readable per-file findings and define whether warnings are advisory or blocking; unavailable tooling and suppressed command failures must not be rendered as a clean quality gate.

### 8. The comprehensive runner used a stale source path and aborted before its result was complete
- **File:** `scripts/tests/audits/audit-all-comprehensive.sh:203-223`.
- **Evidence:** `scripts/tests/audits/audit-all-comprehensive.sh --strict` exits 1 during its hot-path allocation probe because it reads `src/transport/connection.rs`, which does not exist in the current checkout; the transport implementation is under `src/transport/connection/mod.rs`. The runner therefore stops before its remaining quality, runtime, complexity, thread-safety, and crypto sections can produce a complete report.
- **Impact:** The advertised comprehensive audit has no trustworthy completed result on the current repository layout, and a missing input is reported as a shell traceback rather than an explicit `UNAVAILABLE`/`FAIL` record.
- **Boundary:** Validate every hardcoded input path before execution and preserve a structured incomplete-run status; source layout changes must not silently invalidate the audit.
- **Current disposition:** The hot-path probe now reads `src/transport/connection/mod.rs`. The 2026-08-01 rerun completed the full runner and reached its summary instead of aborting at this probe.

### 9. The secret heuristic misclassified a deterministic inline test fixture as a Critical finding
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:132-142`, `src/implementations/server/parts/tests_inline.rs:2037`.
- **Evidence:** The strict runner reports one hardcoded secret at `tests_inline.rs:2037`, where the test deliberately uses a repeated `a` token to exercise QKey authentication. The scanner excludes test directories but not inline `#[cfg(test)]` modules or deterministic fixture values.
- **Impact:** A known non-secret test fixture can block strict audit mode and train reviewers to ignore the secret signal, while the scan still lacks coverage for non-Rust shipped surfaces.
- **Boundary:** Classify test code structurally, require explicit fixture markers or bounded allowlists, and retain real secret findings as blocking without turning a heuristic false positive into a product incident.
- **Current disposition:** The deterministic fixture at `src/implementations/server/parts/tests_inline.rs:2037` is now an exact scanner exclusion. The rerun reports no hardcoded-secret finding; broader non-Rust secret-scope work remains open.

### 10. The fail-closed runner now exposes the underlying strict Rust panic surface
- **Files:** `scripts/tests/audits/audit-all-comprehensive.sh:109-116`; `docs/todo/done/todo-757-all-feature-strict-clippy-panic-contract.md`.
- **Evidence:** The repaired command captures and propagates the Clippy exit code. The 2026-08-01 rerun exits 1 with 48 `unwrap()` and 20 `expect()` diagnostics in the strict runtime log, plus the separate `static mut` finding already owned by TODO-676.
- **Impact:** The runner is now truthful, but the comprehensive audit is not green. The product and target-contract findings are registered under TODO-757 and existing linked owners.
- **Boundary:** Do not weaken or swallow the strict result. Remediation and formal invariant classification must be completed before this runner can be a clean blocking gate.

### 11. Supporting analysis helpers are not portable or fail-closed on macOS
- **Files:** `scripts/tests/analysis/analysis-dead-code-report.sh:187-188`; `scripts/tests/analysis/analysis-scripts-quality.sh`; `scripts/tests/audits/verify-audit-completeness.sh`.
- **Evidence:** On the current Darwin host at revision `6b18d373da46242c47283ee5093d359e6a0792a0`, `analysis-dead-code-report.sh` reaches its dependency scan and fails with the BSD `sed` error `bad flag in substitute command: '}'`. Its `results.json` remains unterminated and does not contain a completed summary. The current script-quality report covers 122 scripts and records 10 missing strict-mode cases, 21 missing descriptions, 14 missing help handlers, 24 naming violations, 10 missing usage lines, and 2 unknown-argument handling violations, but exits successfully without a policy result. The completeness verifier is itself reported by that checker because it intentionally has no generic help/description/name contract, so the toolchain currently cannot distinguish intentional audit-tool exceptions from regressions.
- **Additional direct evidence:** `bash scripts/tests/suites/test-graceful-shutdown.sh --help` exits `1` with `FAIL: missing executable .../target/debug/quicfuscate` instead of showing usage. The script creates its temporary proof directory and checks the binary before any argument/help parser, so this live-proof suite is one concrete member of the 14 missing-help cases and cannot be discovered safely through the standard script contract.
- **Impact:** The repository's own analysis layer can produce partial artifacts or green process exits for nonconforming inputs. A maintainer cannot tell whether an analysis result is complete, advisory, or unavailable, and portability failures are hidden behind the same output path used for real findings.
- **Boundary:** Every analysis helper must emit a complete machine-readable `PASS`, `FAIL`, or `UNAVAILABLE` result, use portable shell primitives, and classify intentional helper exceptions explicitly. Tooling-quality findings must have a severity policy and an owner rather than being silently advisory.

### 12. The full-suite utility omits seven declared test suites without an explicit scope contract
- **Files:** `scripts/tests/analysis/analysis-suite-matrix.sh`; `scripts/tests/utils/util-run-full-suite.sh:48-103`; `scripts/tests/suites/`.
- **Evidence:** The current suite matrix on revision `6b18d373da46242c47283ee5093d359e6a0792a0` finds 28 suite scripts, but only 21 are referenced by `util-run-full-suite.sh`; 12 support fast mode and 9 are invoked with the fast flag. The seven unreferenced scripts are `test-ddos-admission.sh`, `test-fec-all.sh`, `test-graceful-shutdown.sh`, `test-linux-installer-guest.sh`, `test-linux-installer.sh`, `test-qkey-auth-policy.sh`, and `test-qkey-registry-encryption.sh`. Some may be deliberate dispatcher, privileged, or long-running boundaries, but neither the matrix nor the full-suite contract records a complete exclusion reason or a separate required lane for each one.
- **Direct exclusion classification:** `test-fec-all.sh` is a dispatcher that maps `internal`, `simulation`, `e2e-loss`, `controller`, `proof`, and `fast` to constituent scripts; those constituent lanes are called directly by the full-suite utility, but the dispatcher itself has no explicit matrix classification. `test-linux-installer.sh` has a dedicated executable `linux-installer-native` job in `.github/workflows/ci.yml`, and it invokes `test-linux-installer-guest.sh` inside systemd-nspawn guests; the guest script is therefore indirect rather than independently scheduled. `test-ddos-admission.sh`, `test-graceful-shutdown.sh`, `test-qkey-auth-policy.sh`, and `test-qkey-registry-encryption.sh` have no executable invocation in the current `.github/workflows` files or `util-run-full-suite.sh`; `test-qkey-auth-policy.sh` appears only as a static path check in `audit-runtime-guardrails.sh`. These four process-real proofs therefore have no evidenced automated execution owner in the current repository snapshot.
- **Impact:** A command named and documented as the full suite can return success while leaving declared security, installer, lifecycle, and encryption proofs unexecuted. The omission is easy to miss because the matrix only reports reachability and does not fail on unowned exclusions.
- **Boundary:** Define the exact suite universe for `util-run-full-suite.sh`; either invoke every safe suite or record each excluded suite with a reason, owning CI lane, prerequisites, and a separate fail-closed status. The matrix must detect newly omitted suites and distinguish dispatchers from required proofs.

### 13. Extension-based syntax checks confuse JSONC and unavailable PowerShell parsing
- **Files:** `apps/svelte-admin/tsconfig.json`, `apps/svelte-desktop/tsconfig.json`, `scripts/utils/provision-wintun.ps1`, `scripts/tests/wintun-omega-e2e.ps1`.
- **Evidence:** A tracked `*.json` parse pass flags both Svelte `tsconfig.json` files because they intentionally contain JSONC comments; `svelte-check --tsconfig ./tsconfig.json` accepts the consumer format and both frontend checks pass. The current host has no `pwsh` executable, so the two tracked PowerShell files cannot receive a local parser result and must remain `UNAVAILABLE` until Windows/native CI evidence exists.
- **Impact:** A generic extension-based syntax gate can report a valid consumer configuration as malformed, while missing native tooling can disappear from the result if the check is skipped. Neither result is safe to collapse into a simple JSON pass or a local PowerShell pass.
- **Boundary:** Maintain a file-dialect manifest and parse each file with its consumer-compatible parser. Unsupported local parsers must produce an explicit `UNAVAILABLE` record with the owning native CI lane and must not be counted as passed.

### 14. Full-suite benchmark preflight hides a declared benchmark failure
- File: scripts/tests/utils/util-run-full-suite.sh:111-120.
- Problem: In the full profile, the utility runs cargo bench --no-run --features benches as a preflight only for the stealth benchmark. Any failure is converted into Skipping stealth benches, while the surrounding full-suite command can continue and finish successfully. Cargo metadata currently declares benchmark targets, so this is not proof that benchmarks are absent.
- Impact: A required full-suite invocation can omit its dedicated benchmark evidence after a compiler, dependency, feature, or toolchain failure without a non-pass result in the aggregate artifact. TODO-735 owns per-suite benchmark command truth; this finding owns the full-suite caller's propagation and scope.
- Boundary: The caller must preserve benchmark preflight status, classify deliberate platform absence separately, and include the skipped or failed benchmark lane in the aggregate result and exit decision.

### 15. Runtime guardrail process-ownership check rejects a valid scoped PID assignment
- **Files:** `scripts/tests/audits/audit-runtime-guardrails.sh:362-378`; `scripts/tests/tun-e2e-netns.sh:252-263`
- **Evidence:** The current guardrail run (`/tmp/quicfuscate-audit-guardrails/results.json`) reports one Critical failure for `tun_e2e_owned_process_cleanup`. Its test requires the exact regular expression `^SERVER_PID=\$!$`, but the valid assignment is intentionally indented inside `start_server()` at `scripts/tests/tun-e2e-netns.sh:262`; the client assignment is top-level. Direct source inspection confirms exact child PID capture, scoped cleanup, the EXIT trap, pre-existing process refusal, and namespace ownership are present.
- **Impact:** The audit infrastructure reports a false Critical failure for a valid harness, so its result cannot distinguish a contract regression from formatting/function scope. The same run also reports the known `src/simd/x86_ack.rs:3` module-wide `dead_code` warning owned by TODO-752; that warning is separate from this false failure.
- **Boundary:** The guardrail must use whitespace-tolerant or syntax-aware matching for shell assignments, add a fixture covering function-scoped child-PID capture, and retain a machine-readable distinction between a real missing cleanup contract and a checker mismatch.

### 16. The 2026-08-03 comprehensive run exposes both real owners and heuristic false positives

- **Command:** `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/quicfuscate-comprehensive-target bash scripts/tests/audits/audit-all-comprehensive.sh --strict --output-dir /tmp/quicfuscate-audit-comprehensive`
- **Evidence:** The run completed on revision `1b91a55f02e5a8f4e70a7d2f4120fc8a747ab523` and retained `audit.log`, `results.json`, `strict-runtime-clippy.log`, `clone-lints.log`, and the nested runtime-guardrail artifacts. It returned `1` with `Critical Issues: 4`, `Warnings: 7`, and `Total Issues: 11`.
- **Critical classification:** The strict runtime Clippy panic and command-status failures belong to TODO-757; the `src/simd/amx.rs:46` `static mut` finding belongs to TODO-676; the runtime guardrail failure is the checker mismatch in Finding 15. The run therefore confirms that the runner is non-green, but does not prove four independent product vulnerabilities.
- **Warning classification:** The `1013` unsafe count is a raw line heuristic covered by Finding 3 and the existing unsafe audit owners. The six leak matches are four intentional fail-closed `mem::forget` calls in `src/optimize/uring_batch.rs:699-702` plus a `ManuallyDrop` comment and operation in `src/transport/batch.rs:396-398`, not six proven leaks. The two redundant clones are current unowned findings in TODO-803. The three commented-code matches are explanatory `while` comments in `src/implementations/client/io_driver.rs:974` and `src/crypto/aes.rs:755,860`, not commented-out code. The 26 timing matches are produced by `grep -rE "if.*secret|if.*key|if.*password"` and include length checks, test assertions, comments, and key-derivation branches rather than a verified secret-dependent timing leak.
- **Additional evidence:** The run reports no hardcoded secret in its Rust-only scan, no known Cargo dependency vulnerability, zero ordinary all-target Clippy warnings, and a `60%` file-presence test metric. The separate frontend Bun audit is non-green under TODO-805. The file-presence metric is not executed coverage and remains covered by Finding 5. The current strict log contains `22` diagnostics in this invocation: one `unwrap`, twenty `expect`, and one `panic`; the older `68`-diagnostic snapshot in TODO-757 is historical scope evidence, not the current count.
- **Boundary:** The runner must retain per-check status and raw locations, distinguish confirmed product findings from heuristic classifications, and publish a complete non-pass result without collapsing either class into a green or unowned result.

### 17. The readiness gate is green only under deny-only dependency-unsafe policy

- **Files:** `scripts/tests/audits/audit-readiness-gates.sh:14-31,159-190`.
- **Evidence:** The default run on 2026-08-03 reported `PASS` for Clippy Strict, Cargo Audit, Cargo Deny, and Cargo Geiger because it did not pass `--strict-geiger`; its Geiger result recorded 31 dependency packages with unsafe usage. The explicit command `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/quicfuscate-readiness-strict-target bash scripts/tests/audits/audit-readiness-gates.sh --strict-geiger --output-dir /tmp/quicfuscate-audit-readiness-strict` on revision `6b18d373da46242c47283ee5093d359e6a0792a0` returned `1`: Clippy, Audit, and Deny passed, while Cargo Geiger failed with `strict mode blocked: dependency unsafe count=31`.
- **Impact:** A plain readiness result can be read as a complete release-quality pass even though the strict dependency-unsafe policy was not evaluated. The current project therefore has a dependency-unsafe boundary that is measured but not green under strict policy.
- **Boundary:** The readiness report must expose whether deny-only or strict Geiger policy ran, retain the dependency package set and count, and prevent a deny-only `PASS` from being presented as a complete strict readiness result.

### 18. The fast full-suite run exposes malformed environment JSON in suite consumers

- **Files:** `scripts/tests/suites/test-optimization.sh:53`; the same default-expansion pattern also occurs in `scripts/tests/suites/test-performance-regression.sh:161` and `scripts/tests/suites/test-security-fuzzing.sh:105`.
- **Evidence:** `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/quicfuscate-full-suite-fast-target bash scripts/tests/utils/util-run-full-suite.sh --fast --output-dir /tmp/quicfuscate-full-suite-fast` passed the build check, 2,144/2,144 library tests, Core Integration, Desktop/Admin validation (370/370 and 285/285 frontend tests plus 17 Rust integration tests), Stealth Fast, and Crypto Fast, then exited `1` in `test-optimization.sh` with `invalid JSON object field: Extra data`. A traced reproduction shows `environment=json:${COMMAND_ENVIRONMENT_JSON:-{}}` passes an extra closing brace when `COMMAND_ENVIRONMENT_JSON` is non-empty, producing `...\"RUSTFLAGS_EXTRA\":\"\"}}` before `qf_json_object_from_pairs` rejects it. The optimization result file remains only an unterminated header, so the otherwise passing test result has no valid machine-readable completion artifact.
- **Impact:** The full-suite dispatcher reports a failure caused by its evidence consumer, while the optimization test itself passed. The same untested pattern can invalidate performance-regression and security-fuzzing result artifacts, and prior TODO-779/TODO-782 verification claims that `test-optimization.sh --fast` passed with valid JSON are stale against the current tree.
- **Boundary:** Reconcile every affected consumer with the shared writer contract, add a regression fixture that exercises non-empty structured environment metadata through each caller, and retain an explicit non-pass artifact when serialization fails. TODO-782 owns the writer-consumer correction; TODO-730 owns the audit classification and aggregate propagation.

### 19. Omega has no singular, inspectable proof checkout

- **Files:** remote `omega:/home/ubuntu/SOFTWARE/QuicFuscate` and `omega:/home/ubuntu/CODE/QuicFuscate`.
- **Evidence:** Read-only inspection on 2026-08-03 found two separate `main` checkouts. `SOFTWARE/QuicFuscate` is at `9b57474197f9f3e14d4b81bc61850c0f85ce6c52`, has zero tracked modifications but 97 untracked status paths and 43,722 untracked files, and contains a running `quicfuscate` server from `runtime-todo528-dc72c84`. `CODE/QuicFuscate` is at `d36652d887c287353f1f953c2c82a58a3ddafcb3`, has 20 tracked modifications, and `git diff --name-only` cannot complete because Git reports a missing object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1`. No remote checkout was modified, cleaned, reset, or stopped.
- **Impact:** An exact Omega result cannot be attributed to one clean, inspectable source/artifact boundary. A proof run may read candidate files, a dirty source tree, or a live server from a different checkout, while the failed diff inspection prevents independent reconstruction of the modified source state.
- **Boundary:** External proof must select one user-approved checkout or an isolated immutable runtime, record source revision and artifact hashes, verify Git readability before execution, and classify protected dirty or live-state surfaces as `UNAVAILABLE`. Cleanup, reset, or process termination remains outside this audit without explicit approval. TODO-804 owns this remote-state reconciliation.

## Current Implementation Evidence (2026-08-04)

- The runner now uses `quicfuscate.audit-result-contract.v1`: every required command retains its raw artifact, command return code, and `PASS`, `FAIL`, or `UNAVAILABLE` status. Strict mode is the default and blocks on any non-pass result; `--advisory` preserves the result while returning success for reporting-only use.
- Structural scope helpers are live and covered by negative fixtures. `audit-rust-scope.py` scans 232 production Rust files and reports 869 `unsafe` locations plus 4 parsed leak-pattern locations. `audit-secret-scope.py` scans 403 executable/configuration surfaces, explicitly excludes 707 generated/test/local surfaces, and reports zero secret findings. The renamed test metric is `test_file_presence_percent`; it is documented as source-marker presence, not executed coverage.
- Dialect validation completed 173 local files using JSON/JSONC, TOML, YAML, Python, and Bash parsers. The two tracked PowerShell files remain explicit `UNAVAILABLE` results because no native PowerShell parser is installed on this macOS host.
- The full strict run `CARGO_BUILD_JOBS=2 bash scripts/tests/audits/audit-all-comprehensive.sh --strict --output-dir /tmp/qf-comprehensive-final.uOPh6F` completed all sections and emitted 32 result objects: 25 `PASS`, 3 `FAIL`, and 3 `UNAVAILABLE`, with exit `1` and summary `FAIL`. The failed checks are strict runtime Clippy (`rc=101`) and runtime guardrails (`rc=1`, the known PMTU contract finding); the unavailable checks are dialect PowerShell parsing plus Cargo Audit and Cargo Deny advisory database access. The remaining critical classifications include the existing `static mut` owner; no product or UI code was changed.
- Supporting lanes now complete machine-readable output. Dead-code analysis returns a `PASS` report with 28 markers, the suite matrix returns `PASS` for all 28 suites with 7 explicit exclusions and zero unowned omissions, and Scripts Quality returns strict `FAIL` with 116 findings. Full-suite benchmark preflight, suite environment JSON, result-contract, Rust-scope, secret-scope, dialect, and runtime-PID negative fixtures all pass.
- Readiness is explicit: the default gate returns `UNAVAILABLE` when Cargo Audit and Cargo Deny cannot fetch the advisory database, while strict Clippy passes and deny-only Geiger records 31 dependency packages with unsafe usage. `--strict-geiger` returns `FAIL` for that dependency-unsafe policy, with the package set retained in `results.json`.
- Remaining boundaries are not silently absorbed: Omega checkout attribution remains TODO-804, product findings remain with their named owners, and local structural completion does not constitute a green release or external-runtime proof.

## Live Recheck (2026-08-07)

The strict runner was rerun after TODO-836 at
`/tmp/quicfuscate-audit-current-20260806.8UshkJ` with serialized Cargo jobs.
It reached the final summary and retained machine-readable artifacts: 38
result objects, `31 PASS`, `3 FAIL`, `2 UNAVAILABLE`, plus the aggregate
`FAIL` record. The failed checks are strict runtime Clippy (`rc=101`),
all-target quality Clippy (`rc=101`), and runtime guardrails (`rc=1`). The
unavailable checks are the two PowerShell dialect parses and the AMX proof
lane on ARM64 macOS. The runner recorded 5 critical classifications and 10
warnings. This confirms result propagation remains fail-closed; it does not
close the named product or external-state owners.

## Acceptance

- Every external audit command records exit status, raw output, and a machine-readable `PASS`, `FAIL`, or `UNAVAILABLE` state; infrastructure failures cannot become a clean result.
- Cargo-deny warning output is parsed and classified independently of its process exit status, and stale license allowances or version skips fail the intended policy lane or have explicit owners.
- The full-suite and contributor gate invoke an explicit blocking mode, while advisory mode is separately named and documented.
- Unsafe, leak, secret, and quality counters have a documented scope that covers production source structurally and all shipped script/configuration surfaces.
- Missing source inputs and false-positive test fixtures produce explicit non-pass classifications with retained evidence rather than aborting or being counted as real production findings.
- Supporting analysis helpers are portable on the supported host platforms and cannot emit incomplete JSON or green exits after internal command failure.
- The full-suite utility has a machine-readable inclusion/exclusion contract for every declared suite; no suite is silently omitted from the repository's primary verification path.
- Any unavailable Omega proof is attributed to TODO-804 and remains a typed
  non-pass input; this runner does not own repair of the remote checkout.
- Syntax validation classifies JSONC, JSON, TOML, YAML, Python, Bash, and PowerShell by actual consumer/parser, and unavailable native tooling is a retained non-pass result.
- The report no longer labels a file-presence heuristic as executed test coverage, or it emits a real coverage artifact with exact tool, feature, and platform scope.
- Negative fixtures prove command failure, missing dependency database, stale secret outside Rust, and critical findings produce the intended non-pass status.
- Existing runtime guardrail behavior and allowlists remain covered without broadening protected UI scope.

## Sub-Tasks

- [x] Define the audit result schema and required command-status propagation.
- [x] Separate advisory reporting from blocking gate invocation and align full-suite/docs callers.
- [x] Replace raw line heuristics with structural scope-aware scans and expand secret-scan coverage.
- [x] Rename or replace the file-presence test metric and document exact coverage scope.
- [x] Add failable negative fixtures for tool failure, secret scope, and gate exit semantics.
- [x] Repair and fail-closed the auxiliary analysis helpers, including portable shell parsing, structured output completion, and explicit intentional exceptions.
- [x] Reconcile the 28-suite matrix with `util-run-full-suite.sh` and record or execute every omitted suite through a required lane.
- [x] Add dialect-aware syntax validation and a fail-closed native-parser result for the PowerShell surfaces.
- [x] Propagate benchmark preflight failure and explicit skip state through util-run-full-suite.sh in coordination with TODO-735.
- [x] Make runtime guardrail source checks whitespace/function-scope tolerant and add a failable fixture for valid scoped PID capture.
- [x] Make the readiness result explicit about deny-only versus strict Geiger policy and retain the dependency-unsafe package set.
- [x] Reconcile malformed environment-JSON default expansion in optimization, performance-regression, and security-fuzzing consumers with TODO-782 and add a failing regression fixture.
- [x] Separate protected Omega checkout and exact-proof attribution under
  TODO-804; this runner consumes its typed result without owning remote repair.
- [x] Repair the stale transport probe path and deterministic inline-test secret false positive.
- [x] Run shell syntax, ShellCheck, audit-runner fixture, and relevant repository gates.
- [ ] Re-run the current strict/advisory, negative-fixture, scope/dialect,
  suite-matrix, and comprehensive-result gates at one revision; prove runner
  status/exit/artifact consistency despite separately owned non-pass checks.

## Notes

- Existing TODO-52 delivered the first runtime guardrail automation; this task owns the comprehensive runner's result integrity and measurement semantics.
- This is an audit-infrastructure implementation task. It does not authorize production Rust or UI changes; the current change set only hardens audit tooling, fixtures, and owning documentation.
- The strict runtime findings are owned by TODO-757 and the linked existing product TODOs; this task owns result propagation and scope truth, not their remediation.
- Activated as a hot-switch from TODO-754 on 2026-08-04. TODO-754's register/schema/Git-scope gate is green; the remaining comprehensive runner boundaries are now the active implementation scope.
- Local implementation and verification are complete in commit `92a05ac`. The remaining Omega checkout attribution gate is blocked by the local SSH client error `No user exists for uid 501`; the local branch is also ahead because GitHub DNS currently cannot resolve `github.com`.

## Current Reconciliation (2026-08-07)

- The audit runner and negative fixtures are implemented and preserve non-pass results for strict findings, unavailable native parsers, and protected external evidence. The current comprehensive report remains non-green at the strict Clippy/runtime-guardrail and Omega attribution boundaries; this task owns result truth, not product remediation. No production implementation was performed in this reconciliation.

## Deviations

None.
