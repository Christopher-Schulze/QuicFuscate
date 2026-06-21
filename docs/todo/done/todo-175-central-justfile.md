# TODO-175: Central Justfile for Build/Test/Bench Commands

## Status
**COMPLETED** - justfile created at project root with targets: build, release, test, lint, fmt, fmt-check, check, audit, clean, bench, bench-crypto, bench-transport, bench-stealth, build-web-admin, dev-ui, stop-ui, doc.

## Severity
**LOW**

## Context
No central entry point exists for common development commands. Developers must manually locate scripts in the `scripts/` directory tree to perform standard operations like building, testing, benchmarking, or linting.

- No `justfile`, `Makefile`, or equivalent exists at project root
- Build/test/bench commands scattered across 88+ shell scripts
- New contributors must read documentation to discover how to run tests

## Root Cause
Development workflow relied on direct script invocation and developer knowledge rather than a unified command interface.

## Fix Plan
1. Install `just` as the recommended command runner (cross-platform, simple syntax)
2. Create `justfile` at project root with targets:
   - `just build` - Debug build (`cargo build`)
   - `just build-release` - Release build (`cargo build --release`)
   - `just test` - Run all Rust tests (`cargo test`)
   - `just test-unit` - Run unit tests only
   - `just test-integration` - Run integration tests
   - `just test-e2e` - Run E2E tests
   - `just test-frontend` - Run frontend tests (Playwright + Vitest)
   - `just bench` - Run all benchmarks
   - `just bench-crypto` - Crypto-specific benchmarks
   - `just bench-transport` - Transport-specific benchmarks
   - `just lint` - Run `cargo fmt --check && cargo clippy -- -D warnings`
   - `just fmt` - Run `cargo fmt`
   - `just audit` - Run security/quality audits
   - `just dev` - Start development environment
   - `just dev-ui` - Start frontend dev servers
   - `just clean` - Clean build artifacts
   - `just doc` - Generate documentation (`cargo doc --no-deps --open`)
3. Each target delegates to existing scripts or direct commands
4. Add `just --list` friendly descriptions to all targets

## Acceptance Criteria
- `justfile` exists at project root with all listed targets
- `just test` runs the complete test suite
- `just bench` runs all benchmarks
- `just lint` runs formatting and clippy checks
- `just --list` shows all available targets with descriptions
- Documented in README/CONTRIBUTING

## Dependencies
- TODO-174 (scripts consolidation) - justfile targets may reference consolidated scripts

## Affected Files
- `justfile` (new)
- `docs/CONTRIBUTING.md` (document just usage)
- `README.md` (mention just as entry point)
