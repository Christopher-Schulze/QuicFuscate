---
id: TODO-749
title: Make CI and release dependency resolution reproducible
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-749: Make CI and Release Dependency Resolution Reproducible

## Current execution gate (2026-09-23)

The local lockfile/tool-version implementation below is historical evidence,
not a current hosted result. Re-run `scripts/audits/verify-reproducible-dependencies.sh`
at one source revision, then inspect the exact CI and release workflow runs
for that revision. Require frozen Bun resolution and non-mutating locked Cargo
metadata/check/Clippy for both root and Tauri graphs, matching resolved tool
versions and lock hashes in two clean runs, and explicit `PASS`/`FAIL`/
`UNAVAILABLE` for every requested platform. A tagged publication or updater
signature is a separate release operation and is not required merely to prove
dependency reproducibility; a packaging lane may run only with its normal
authorization and artifact boundary. The local two-run refresh can start now;
missing hosted toolchain/packaging artifacts block closure, not this step.

## Why

Release and CI gates should resolve the same frontend and packaging toolchain from committed lock and version contracts. The current workflows leave Bun installation unfrozen and install the Tauri CLI from a caret range.

## Findings

### 1. Bun installs do not explicitly enforce the committed lockfile
- **Files:** `.github/workflows/ci.yml:25-26,52-53,108-109,457`; `.github/workflows/release.yml:53,142,201,244,281`; `scripts/build/build-web-admin.sh:53`.
- **Problem:** These gates call `bun install` or `bun install --no-progress` without an explicit frozen-lockfile policy.
- **Impact:** A lockfile or resolver change can alter dependency selection between runs without a corresponding source change or intentional lockfile update.

### 2. Tauri CLI is installed from a moving caret range
- **File:** `.github/workflows/release.yml:199,235,279`.
- **Problem:** `cargo install tauri-cli --version "^2.0.0"` permits a different compatible release on a later run.
- **Impact:** Packaging, updater, and signing behavior can drift independently of the repository revision.

### 3. The committed Tauri lockfile is not compatible with a locked check
- **File:** `apps/tauri/src-tauri/Cargo.lock` against `apps/tauri/src-tauri/Cargo.toml`.
- **Evidence:** `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml --locked` exits before compilation with Cargo's lockfile mismatch error. An unlocked check can rewrite the committed lockfile, which proves that the repository does not currently have a reproducible locked Tauri dependency graph.
- **Impact:** A supposedly read-only verification command can mutate the lockfile, while the locked command cannot verify the checked-in Tauri host at all.

### 4. Several CI toolchain action references are mutable
- **Files:** `.github/workflows/ci.yml:140,355,481`.
- **Evidence:** The feature-matrix, Linux fastpath, and security-audit jobs use `dtolnay/rust-toolchain@master`, while other jobs use `@stable` or `@nightly`. The `master` action reference can change independently of a repository commit, so the action implementation and its toolchain-resolution behavior are not reproducibly selected.
- **Impact:** A green result can depend on a moving action revision even when Cargo manifests, lockfiles, and workflow source are unchanged.

## Acceptance

- CI and release frontend installs use an explicit frozen lockfile mode and fail on lock drift.
- Tauri CLI and other release-critical tools use exact, centrally owned versions with a documented update path.
- All release-critical action and toolchain references use an explicitly owned immutable or intentionally moving policy; any moving reference has a documented reason and a controlled update gate.
- `cargo check`, Clippy, metadata, and release packaging for `apps/tauri/src-tauri` pass with `--locked` against the committed lockfile, and verification commands do not rewrite it.
- A reproducibility probe records resolved versions and proves two clean runs select the same dependency/toolchain set.
- Intentional lockfile/tool updates are visible in review and cannot be introduced by a verification job.

## Sub-Tasks

- [x] Define the lockfile and tool-version owners.
- [x] Apply explicit frozen Bun installation to CI, release, and build helpers.
- [x] Pin Tauri CLI exactly and record the version in the release contract.
- [x] Add a drift/reproducibility gate.
- [ ] Re-run the current local gate and obtain same-revision hosted CI and
      native packaging dependency-resolution evidence; record version/hash
      parity and exact unavailable cells without publishing a release.

## Notes

- This is release and CI infrastructure only; it does not authorize frontend visual changes.
- `config/tool-versions.env` owns Bun `1.3.14`, Rust `1.97.1`, nightly, Tauri CLI `2.11.4`, Cargo Audit `0.22.2`, Cargo Fuzz `0.13.2`, and Critcmp `0.1.8`.
- `apps/tauri/src-tauri/Cargo.lock` was reconciled against its manifest; locked metadata, check, all-target Clippy, and tests pass locally. The native Tauri test target reports 41/41.
- `bash scripts/audits/verify-reproducible-dependencies.sh` passes its workflow scan, two locked Cargo metadata runs per manifest, two frozen Bun dry-runs with identical lock hash, and active tool-version checks.
- Pushed commit: `cba058e` (`TASK 749: Make dependency resolution reproducible`), verified on `origin/main`.

## Implementation Reconciliation

- `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/clippy-matrix.yml`, and `.github/workflows/windows-omega-e2e.yml` no longer use `dtolnay/rust-toolchain@master`, unfrozen Bun installs, caret-ranged Tauri CLI installation, or unqualified release-critical Cargo operations.
- `scripts/build/build-web-admin.sh` and the Linux installer suite consume the source-owned tool-version contract. The release workflow runs locked Tauri metadata/check/Clippy and forwards `--locked` to `cargo tauri build`.
- The gate script itself initially exposed and was corrected for mixed `None`/string sorting in Cargo dependency metadata. The corrected script passes; this self-test is retained as evidence that the gate is executable rather than only statically present.

## External Gate

- **Closure gate:** Same-revision GitHub-hosted CI and applicable Linux/Windows package dependency resolution were not proven by the historical ARM64 macOS run. `cargo tauri build --help` verifies only runner arguments. Updater signing and tagged publication are separate release operations, not this task's acceptance.
- **Scope:** Native release behavior and remote/Omega runtime evidence remain separately owned. No UI source, remote checkout, or release was changed by this task.

## Deviations

None.
