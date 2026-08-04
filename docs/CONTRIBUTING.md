# Contributing to QuicFuscate

Thank you for your interest in contributing! This document explains how to set up your environment, the development workflow, coding standards, and how to submit high-quality pull requests that fit the project's architecture and quality bar.

QuicFuscate is a monolithic Rust crate with a small, carefully curated `scripts/` toolchain. Documentation is centralized in `docs/DOCUMENTATION.md` and must remain the single source of truth.


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
  - `src/core.rs` - QUIC session and I/O core
  - `src/crypto/` - AEAD, cipher, key exchange glue (mod.rs + aegis, aes, chacha, morus, hkdf)
  - `src/fec/` - FEC (encoder/decoder/adaptive/GF tables, mod.rs + internal, gf_tables, fountain_codes, etc.)
  - `src/stealth/` - DoH, HTTP/3 masquerading, TLS Cover, fingerprinting, domain fronting, QPACK helpers (mod.rs + tls_cover)
  - TLS fingerprints: deterministic in-memory ClientHello synthesis in `src/stealth/` (no on-disk profiles required). Optional external base64 dumps under top-level `browser_profiles/` are used by the TLS utility scripts for auditing only.
- Script workflow
  - Consolidated build/test/audit/bench scripts under `scripts/{build,benchmarks,tests,utils}/`
  - Audit entrypoints are under `scripts/tests/audits/`
- Documentation (English only)
  - `docs/DOCUMENTATION.md` - single file of truth
  - `docs/todo.md` and `docs/todo/*.md` - task and readiness truth
  - `docs/MAP.md` - repository map and wiring index

The design favors consolidation into well-organized module directories (`src/fec/`, `src/crypto/`, `src/stealth/`, `src/optimize/`, `src/transport/`). Each directory has a `mod.rs` root with focused sub-modules. Do not duplicate logic across modules or introduce parallel implementations.


## Getting Started
Prerequisites:
- Rust stable (selected by `rust-toolchain.toml`)
- Git, Bash
- bun (for frontend apps under `apps/` and shared packages under `packages/`)
- python3 (required by some scripts, for example `scripts/tests/suites/test-e2e-admin-web.sh`)

Bootstrap build & verify via scripts:
```bash
./scripts/tests/build/build-check.sh
./scripts/tests/utils/util-run-full-suite.sh
./scripts/tests/audits/audit-all-comprehensive.sh --strict
```
Build the crate:
```bash
cargo build
```


## Local Build & Tests
- Build: `cargo build` (use `--release` only for final deployment builds)
- Tests: `cargo test --features rust-tests`
- Lints: `cargo clippy --workspace --all-targets -- -D warnings`
- Crypto suite: `./scripts/tests/suites/test-crypto.sh`
- Static hardening audit: run via `./scripts/tests/audits/audit-all-comprehensive.sh --strict`; use `--advisory` only for a non-blocking report.

If a workflow fails, check `scripts/out/` for logs/reports and re-run the appropriate script.

## Modular Script Architecture
A modular script architecture is provided to streamline common developer tasks (build/test helpers and E2E TLS checks). Dedicated scripts are organized in purpose-specific directories:

- **Build Scripts**: `scripts/tests/build/` directory contains build-related scripts
- **Test Scripts**: `scripts/tests/` directory contains testing workflows
- **Audit Scripts**: `scripts/tests/audits/` directory contains security and quality audits
- **Benchmark Scripts**: `scripts/benchmarks/` directory contains performance testing
- **Utility Scripts**: `scripts/tests/utils/` directory contains helper utilities

```bash
# Build workflows:
./scripts/build/build-pgo-release.sh
./scripts/tests/build/build-check.sh

# Test workflows:
./scripts/tests/utils/util-run-full-suite.sh
./scripts/tests/suites/test-crypto.sh

# Audit workflows:
./scripts/tests/audits/audit-all-comprehensive.sh
```

For E2E TLS operations you can use:
- `./scripts/tests/utils/util-e2e-decode-all-profiles.sh` - decode ALL profiles
- `./scripts/tests/utils/util-e2e-verify-current.sh` - verify current profile (requires .sha256)
- `./scripts/tests/utils/util-e2e-verify-all.sh` - verify ALL profiles (requires .sha256)
- `./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh` - generate .sha256 sidecars

Note: The modular script architecture provides direct CLI access to all operations. CI and docs are aligned to this script-based approach.


## Quality Gates (must pass)
Before opening a PR, all of the following must be true:
- No panics or stubs in runtime code: no `unwrap/expect/panic!/todo!/unimplemented!`
- No debug prints in runtime code: no `dbg!/println!/eprintln!`
- Proper error handling and logging (`log` macros) with actionable messages
- `cargo test --features rust-tests` clean
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- Crypto suite: `./scripts/tests/suites/test-crypto.sh`
- Static hardening audit: run via `./scripts/tests/audits/audit-all-comprehensive.sh --strict`; use `--advisory` only for a non-blocking report.
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
- Keep the FEC logic consolidated in `src/fec/`. New submodules only when extracting large inline blocks
- Stealth functionality belongs in `src/stealth/` (DoH, TLS Cover, HTTP/3 masquerading, domain fronting, QPACK)
- QUIC stream/session internals stay in `src/core.rs`
- TLS fingerprint handling belongs to `src/stealth/` (in-memory generation + caching)

When adding new functionality, integrate with the closest primary module. Avoid duplicative helpers; prefer cohesive, well-named internal functions.


## Frontend Development

The Svelte 5 frontends and shared packages use Bun as package manager and runtime:

- **Web Admin**: `cd apps/svelte-admin && bun install && bun run dev --port 1430`
- **Desktop**: `cd apps/svelte-desktop && bun install && bun run dev`
- **Shared UI**: `packages/ui` (Svelte 5 components), `packages/theme` (CSS tokens)

Quality gates (run before PRs):
- `bun run check` - Svelte/TS type checking per app
- `bun run test:unit` - Vitest unit tests per app (test files live under `scripts/tests/frontend/`)
- E2E: `bunx playwright test` via configs in `apps/svelte-admin/playwright.config.ts` and `apps/svelte-desktop/playwright.config.ts`

Component conventions:
- One component per `.svelte` file, PascalCase naming
- Shared presentational components go in `packages/ui/`
- App-specific components in `apps/<app>/src/lib/components/`
- Tests mirror source structure under `scripts/tests/frontend/<app>/unit/`


## Stealth Profiles & Fingerprints
- Runtime fingerprinting uses deterministic in-memory ClientHello synthesis (no on-disk profiles required).
- Server raw-IP fingerprint normalization is connection-frozen with the TLS/H3 persona and runs only after decoded TUN/MASQUE uplink. Preserve disabled byte identity, SYN-only TCP policy, fragments, PMTUD messages, and checksums.
- Changes to network-stack profiles require exact packet vectors, `rt-core-connection-basics`, `rt-stealth-config-toml`, and the `fingerprint_normalizer` allocation/throughput benchmark.
- If you maintain external base64 dumps (`.chlo`/`.chlo.b64`) for auditing, place them under top-level `browser_profiles/` and use the TLS utility scripts to decode/verify and generate sidecars.
- Use the CLI to list available fingerprints and verify selection
- Ensure TLS Cover and real TLS fingerprint modes remain consistent with the profile set


## Configuration & Docs
- `docs/DOCUMENTATION.md` is the single source of truth. Update it for any user-facing change:
  - CLI flags, environment variables (`QUICFUSCATE_*`), configuration keys
  - Stealth behavior, profile storage paths, defaults
- Keep `docs/todo.md`, relevant TODO detail files, and `docs/MAP.md` aligned when task status, release gates, architecture, or wiring truth changes
- Keep `README.md` concise; link to `DOCUMENTATION.md` for deep detail
- Always update `config/quicfuscate.toml` when adding/removing config keys


## Commit Messages & Branches
- Branch naming: `feature/<short>`, `fix/<short>`, `docs/<short>`, `refactor/<short>`
- Conventional style is appreciated: `feat: ...`, `fix: ...`, `docs: ...`, `refactor: ...`, `perf: ...`, `test: ...`, `ci: ...`
- Make logical, small commits; keep messages imperative and focused


## Pull Request Checklist
Please verify before opening a PR:
- [ ] Code compiles on all targets supported by CI
- [ ] `cargo test --features rust-tests` passes locally
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes locally
- [ ] Static hardening audit passes via `./scripts/tests/audits/audit-all-comprehensive.sh --strict`; `--advisory` output is not a gate and must not be treated as one; no `unwrap/expect/dbg!/println!/panic!/todo!/unimplemented!`
  - [ ] `docs/DOCUMENTATION.md` updated (flags, env, config, behavior)
  - [ ] `docs/todo.md`, relevant TODO detail files, and `docs/MAP.md` updated when task status, release gates, architecture, or wiring truth changed
  - [ ] `config/quicfuscate.toml` updated if config changed
  - [ ] `README.md` updated where user entry points changed
  - [ ] Added clear rationale in code comments for complex/critical sections

PRs that break the consolidation principles (e.g., re-adding `src/fec/*` trees) will be asked to rework.


### Issue Reporting & Repro Steps
- Use descriptive titles, include platform, CPU arch, and relevant features/modes (e.g., FEC mode, MASQUE, `io_uring`, internal AF_XDP experimental builds)
- Provide exact commands and configs used (`config/quicfuscate.toml` snippet or flags)
- Attach logs if possible (sanitize secrets)
- For performance regressions, include throughput/latency numbers and hardware


## Security & Responsible Disclosure
If you believe you've found a security issue, please report it privately to the maintainers. Do not open a public issue until coordinated disclosure is agreed.

By submitting a contribution you agree to license your work under the project's license.

## Questions & Contact
For inquiries, open a GitHub issue or write to the public email listed on the repository owner's GitHub profile (christopher.schulze.github@proton.me).

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
