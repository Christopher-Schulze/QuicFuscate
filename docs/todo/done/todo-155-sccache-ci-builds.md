# TODO-155: Add sccache for CI Compilation Caching

## Status
**COMPLETED** - sccache added to all Rust CI jobs (build-test, feature-matrix, linux-fastpath-gates, e2e-tls) via `mozilla-actions/sccache-action@v0.0.6` with `SCCACHE_GHA_ENABLED` and `RUSTC_WRAPPER` env vars.

## Severity
**LOW**

## Context
The CI pipeline compiles the entire Rust project from scratch on every run. Without compilation caching, Windows and macOS builds are particularly slow due to the large dependency tree and platform-specific compilation overhead. This increases CI feedback time and wastes compute resources.

- `.github/workflows/ci.yml`: No sccache or compilation caching configured
- Cross-platform builds (Linux, macOS, Windows) all compile from scratch

## Root Cause
The CI pipeline uses only basic GitHub Actions caching (if any) for the `~/.cargo` registry. The actual compilation artifacts (`target/`) are not cached between runs. `sccache` was never configured to provide cross-platform compilation caching.

## Fix Plan
1. Add sccache installation to CI:
   ```yaml
   - name: Install sccache
     uses: mozilla-actions/sccache-action@v0.0.4
   - name: Configure sccache
     run: |
       echo "SCCACHE_GH_ACTIONS=true" >> $GITHUB_ENV
       echo "RUSTC_WRAPPER=sccache" >> $GITHUB_ENV
   ```
2. Enable GitHub Actions cache backend for sccache (free, no external storage needed)
3. Add to all Rust build/test/clippy steps across all platform jobs
4. Configure cache key based on: Cargo.lock hash, Rust toolchain version, OS
5. Measure build time before and after:
   - Record current CI build times for Linux, macOS, Windows
   - Compare after sccache integration
6. Alternative: evaluate `cargo-cache` GitHub Action if sccache is too complex

## Acceptance Criteria
- sccache configured for all Rust compilation steps in CI
- Works across Linux, macOS, and Windows CI runners
- CI build times reduced by 30%+ on cache-hit runs
- Cache invalidated properly on Cargo.lock changes
- No false cache hits (verified by test results matching expected behavior)

## Dependencies
- `sccache` binary (installed via GitHub Action)
- GitHub Actions cache storage (included in GitHub plan)

## Affected Files
- `.github/workflows/ci.yml` (add sccache setup and environment variables)
