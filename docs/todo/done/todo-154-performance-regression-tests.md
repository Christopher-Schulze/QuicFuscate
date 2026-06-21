# TODO-154: Add Performance Regression Detection to CI

## Status
**DONE** - Criterion benchmarks integrated into CI with two-tier regression thresholds.

## Severity
**MEDIUM**

## Context
Performance regressions in critical paths (crypto operations, transport layer, SIMD-routed
validation) could go undetected until production deployment. A CI benchmark regression gate
now detects these automatically on every pull request.

## Implementation (2026-03-21)

### New files
- `benches/ci_regression.rs` - Criterion benchmark suite covering 9 hotpath groups:
  AES-128 block, GHASH, AES-128-GCM seal, MORUS encrypt/decrypt, varint roundtrip,
  QUIC header validation, popcnt, secure RNG fill. Each group tests multiple buffer
  sizes (64B/1KiB/8KiB) where applicable.

### Modified files
- `Cargo.toml` - Added `criterion = { version = "0.5", features = ["html_reports"] }`
  as dev-dependency. Added `[[bench]] name = "ci_regression" harness = false`.
- `.github/workflows/ci.yml` - New `benchmarks:` job running after `build-test`,
  triggered on PRs only. Uses `continue-on-error: true` so benchmark failures
  do not block the build. Outputs results as GitHub Job Summary.
- `scripts/benchmarks/bench-ci-regression.sh` - Rewritten with two-tier thresholds
  (15% warn / 30% error), `GITHUB_STEP_SUMMARY` integration, and refined critcmp
  output parsing.

### CI job design
- Runs on `ubuntu-latest` after `build-test` succeeds
- Only triggers on `pull_request` events
- Checks out main branch source to build baseline, then compares PR benchmarks
- 15% regression = warning (soft fail, exit 0)
- 30% regression = error (exit 1, but `continue-on-error: true` prevents build block)
- Criterion HTML reports uploaded as artifacts
- Results written to GitHub Job Summary (markdown table + details)

## Acceptance Criteria
- [x] Criterion benchmarks run in CI on every PR
- [x] Benchmark results compared against main branch baseline
- [x] Performance regressions exceeding threshold flagged in job summary
- [x] Two-tier thresholds (15% warn, 30% error)
- [x] Does not block the build (`continue-on-error: true`)
- [x] False positives minimized through criterion statistical analysis

## Affected Files
- `.github/workflows/ci.yml`
- `Cargo.toml`
- `benches/ci_regression.rs` (new)
- `scripts/benchmarks/bench-ci-regression.sh`
- `docs/todo/todo-154-performance-regression-tests.md`
