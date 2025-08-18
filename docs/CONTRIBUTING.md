# Contributing to QuicFuscate

Thank you for your interest in contributing! This document explains how to set up your environment, the development workflow, coding standards, and how to submit high‑quality pull requests that fit the project’s architecture and quality bar.

QuicFuscate is a monolithic Rust crate with a small, carefully curated scripts/ toolchain and a patched quiche vendor workflow. Documentation is centralized in `docs/DOCUMENTATION.md` and must remain the single source of truth.


## Table of Contents
- Project Architecture
- Getting Started
- Local Build & Tests
- Quality Gates (must pass)
- Coding Standards
- Module Boundaries & Layout
- Stealth Profiles & Fingerprints
- Configuration & Docs
- Commit Messages & Branches
- Pull Request Checklist
- Issue Reporting & Repro Steps
- Security & Responsible Disclosure


## Project Architecture
- Single crate under `src/`
  - `src/core.rs` — QUIC session and I/O core
  - `src/crypto.rs` — AEAD, cipher, key exchange glue
  - `src/fec.rs` — fully inlined FEC (encoder/decoder/adaptive/GF tables). No submodules.
  - `src/stealth.rs` — DoH, HTTP/3 masquerading, FakeTLS, fingerprinting, domain fronting, QPACK helpers
  - `src/browser_profiles/*.chlo` — base64-encoded ClientHello profiles (preferred location). Fallback: top-level `browser_profiles/`
- Vendor workflow
  - `libs/patched_quiche` — quiche sources (initialized via build scripts)
  - Build Scripts — fetch/patch/build/export env for cargo: `./scripts/Build/build-quiche-and-check.sh`
- Documentation (English only)
  - `docs/DOCUMENTATION.md` — single file of truth
  - `docs/Changelog.md` — append-only change log

The design favors consolidation and zero duplication. Do not re‑introduce scattered module trees (e.g., `src/fec/*`).


## Getting Started
Prerequisites:
- Rust stable (latest)
- Git, Bash
- C toolchain for building vendored quiche (clang or gcc)

Bootstrap the vendor and build once via the build scripts:
```bash
./scripts/Build/build-quiche-and-check.sh
# Or use other dedicated scripts:
./scripts/Tests/tests-all-release.sh
./scripts/Build/build-fmt-check.sh
./scripts/Audits/audit-code-quality-comprehensive.sh
```
Then build the crate:
```bash
cargo build --release
```


## Local Build & Tests
- Build: `cargo build` or `cargo build --release`
- Tests: `cargo test`
- Lints: `cargo clippy --all-targets -- -D warnings`
- Static hardening audit: run via `./scripts/Audits/audit-static-hardening.sh`

If the workflow fails, check `libs/logs/` and re-run the workflow from the appropriate script.

## Modular Script Architecture
A modular script architecture is provided to streamline common developer tasks (build/test helpers and E2E TLS checks). Dedicated scripts are organized in purpose-specific directories:

- **Build Scripts**: `scripts/Build/` directory contains all build-related scripts
- **Test Scripts**: `scripts/Tests/` directory contains testing workflows
- **Audit Scripts**: `scripts/Audits/` directory contains security and quality audits
- **Benchmark Scripts**: `scripts/Benchmarks/` directory contains performance testing
- **Utility Scripts**: `scripts/Utils/` directory contains helper utilities

```bash
# Build workflows:
./scripts/Build/build-quiche-and-check.sh
./scripts/Build/build-release-macos-only.sh
./scripts/Build/build-release-cross-platform.sh

# Test workflows:
./scripts/Tests/tests-all-release.sh
./scripts/Tests/tests-comprehensive-runner.sh

# Audit workflows:
./scripts/Audits/audit-static-hardening.sh
```

For E2E TLS operations you can use:
- `./scripts/Utils/e2e-decode-all-profiles.sh` - decode ALL profiles
- `./scripts/Utils/e2e-verify-current.sh` - verify current profile (requires .sha256)
- `./scripts/Utils/e2e-verify-all.sh` - verify ALL profiles (requires .sha256)
- `./scripts/Utils/tls-generate-sha256-sidecars.sh` - generate .sha256 sidecars

Note: The modular script architecture replaces the previous TUI-based workflow. Individual scripts provide direct CLI access to all operations. CI and docs are aligned to this script-based approach.


## Quality Gates (must pass)
Before opening a PR, all of the following must be true:
- No panics or stubs in runtime code: no `unwrap/expect/panic!/todo!/unimplemented!`
- No debug prints in runtime code: no `dbg!/println!/eprintln!`
- Proper error handling and logging (`log` macros) with actionable messages
- `cargo clippy` clean with warnings denied
- Static hardening audit passes via `./scripts/Audits/audit-static-hardening.sh`
- CI builds on Linux/macOS/Windows (GitHub Actions)


## Coding Standards
- Rust 2021 edition
- Prefer explicit error types or `anyhow` at boundaries; avoid silent failures
- Never `unwrap/expect` in runtime paths; use `?` and map errors with context
- Panics allowed only in tests and clearly unreachable code paths
- Logging: use `trace/debug/info/warn/error` consistently; no ad-hoc prints
- Public APIs must be documented; keep examples minimal and correct
- Performance-sensitive code paths should include rationale in comments


## Module Boundaries & Layout
- Keep the FEC logic consolidated in `src/fec.rs`. Do not add new submodules
- Stealth functionality belongs in `src/stealth.rs` (DoH, FakeTLS, HTTP/3 masquerading, domain fronting, QPACK)
- QUIC stream/session internals stay in `src/core.rs`
- Browser profile handling belongs to `src/stealth.rs` and `src/browser_profiles/`

When adding new functionality, integrate with the closest primary module. Avoid duplicative helpers; prefer cohesive, well-named internal functions.


## Stealth Profiles & Fingerprints
- Profiles are base64-encoded `.chlo` artifacts in `src/browser_profiles/` (preferred). Fallback `browser_profiles/` is supported
- Additions/updates must include:
  - A minimal description of the fingerprint provenance (e.g., capture source)
  - A short verification note (how it was validated against target servers)
  - An update to `docs/DOCUMENTATION.md` explaining usage and limitations
- Use the CLI to list available fingerprints and verify selection
- Ensure FakeTLS and real TLS fingerprint modes remain consistent with the profile set


## Configuration & Docs
- `docs/DOCUMENTATION.md` is the single source of truth. Update it for any user-facing change:
  - CLI flags, environment variables (`QUICFUSCATE_*`), configuration keys
  - Stealth behavior, profile storage paths, defaults
- Keep `docs/Changelog.md` up to date (prepend newest section). Summarize what changed and why
- Keep `README.md` concise; link to `DOCUMENTATION.md` for deep detail
- Always update `docs/example_config.toml` when adding/removing config keys


## Commit Messages & Branches
- Branch naming: `feature/<short>`, `fix/<short>`, `docs/<short>`, `refactor/<short>`
- Conventional style is appreciated: `feat: …`, `fix: …`, `docs: …`, `refactor: …`, `perf: …`, `test: …`, `ci: …`
- Make logical, small commits; keep messages imperative and focused


## Pull Request Checklist
Please verify before opening a PR:
- [ ] Code compiles on all targets supported by CI
- [ ] `cargo test`, `cargo clippy -D warnings` pass locally
- [ ] Static hardening audit passes via `./scripts/Audits/audit-static-hardening.sh`; no `unwrap/expect/dbg!/println!/panic!/todo!/unimplemented!`
- [ ] `docs/DOCUMENTATION.md` updated (flags, env, config, behavior)
- [ ] `docs/Changelog.md` updated with a brief, precise summary
- [ ] `docs/example_config.toml` updated if config changed
- [ ] `README.md` updated where user entry points changed
- [ ] Added clear rationale in code comments for complex/critical sections

PRs that break the consolidation principles (e.g., re-adding `src/fec/*` trees) will be asked to rework.


## Issue Reporting & Repro Steps
- Use descriptive titles, include platform, CPU arch, and quiche workflow details
- Provide exact commands and configs used (`docs/example_config.toml` snippet or flags)
- Attach logs if possible (sanitize secrets)
- For performance regressions, include throughput/latency numbers and hardware


## Security & Responsible Disclosure
If you believe you’ve found a security issue, please report it privately to the maintainers. Do not open a public issue until coordinated disclosure is agreed.

By submitting a contribution you agree to license your work under the project’s license.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
