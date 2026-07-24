---
id: TODO-562
title: Refactor single-crate monolith into Cargo workspace sub-crates
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-07-24
depends_on: [TODO-561]
---

# TODO-562: Refactor Single-Crate Monolith into Cargo Workspace Sub-Crates

## Why

The entire Rust core (~136k LoC, 146 files) lives in one crate. This causes:

- Full recompilation of 136k lines on any single-file change (dev iteration >60s cold).
- No isolation of unsafe/SIMD crypto machine room from safe transport/stealth logic.
- Feature flags are global (enabling `io_uring` recompiles stealth, FEC, brain, etc.).
- External consumers (Tauri host, future SDK) must depend on the entire monolith.
- Test parallelism is limited to one compilation unit.
- Cognitive load: no enforced module boundary; any module can reach into any other.

Splitting into a Cargo workspace with focused sub-crates gives incremental compilation,
enforced API boundaries, independent feature gating, and faster CI parallelism.

## Acceptance

- The repository root becomes a Cargo workspace with at least 6 member crates plus the root binary crate.
- Each sub-crate compiles independently with `cargo check -p <crate>`.
- The root binary `quicfuscate` re-exports the same public CLI behavior with zero behavioral regression.
- All existing tests (`cargo test --workspace --all-targets --features rust-tests`) pass unchanged.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
- Incremental rebuild of a single sub-crate (touch one file) completes in under 15 seconds on Apple Silicon dev profile.
- Feature flags are scoped: `io_uring` only recompiles the platform crate, `benches` only the bench crate, etc.
- The Tauri host (`apps/tauri/src-tauri`) depends only on the crates it needs, not the full monolith.
- No `pub` item that was previously crate-internal becomes unnecessarily public; inter-crate APIs are minimal and documented.
- CI workflows updated to leverage workspace parallelism (per-crate check/test where beneficial).
- Documentation (DOCUMENTATION.md, MAP.md) updated to reflect the new crate structure.

## Completion Gates

- Structure gate: workspace layout is committed with clear crate boundaries and a root `Cargo.toml` workspace manifest.
- Compilation gate: `cargo check --workspace` and per-crate `cargo check -p` pass; incremental touch-rebuild measured and recorded.
- Test gate: full workspace test suite passes with `rust-tests` feature; no test removed or weakened.
- Clippy gate: workspace-wide Clippy with `-D warnings` passes on stable.
- Feature gate: feature flags are per-crate; enabling one feature does not force recompilation of unrelated crates.
- Binary gate: `cargo build --release --bin quicfuscate` produces a functionally identical binary (CLI help, server start, client connect all work).
- Tauri gate: `cd apps/tauri/src-tauri && cargo check` passes with narrowed dependency set.
- CI gate: GitHub CI and Clippy Matrix pass on the workspace structure.
- Documentation gate: MAP.md, DOCUMENTATION.md, and AGENTS.md reflect the new crate layout.

## Sub-Tasks

- [ ] Audit current module dependency graph; identify natural seam lines and circular dependencies.
- [ ] Design crate split (proposed: `qf-crypto`, `qf-transport`, `qf-fec`, `qf-stealth`, `qf-core`, `qf-platform`, root `quicfuscate` bin).
- [ ] Break circular dependencies by extracting shared traits/types into a `qf-types` or `qf-common` crate if needed.
- [ ] Move modules into sub-crate directories; update `mod` declarations and `use` paths.
- [ ] Scope feature flags per crate (`io_uring` -> qf-platform, `benches` -> bench targets, SIMD features -> qf-crypto).
- [ ] Update root `Cargo.toml` workspace manifest and binary crate to depend on sub-crates.
- [ ] Update Tauri host `Cargo.toml` to depend only on needed crates.
- [ ] Update CI workflows for workspace-aware check/test/clippy.
- [ ] Run full test suite, Clippy, release build; measure incremental rebuild time.
- [ ] Flush documentation (MAP.md, DOCUMENTATION.md, AGENTS.md) and close with evidence.

## Notes

- Proposed crate boundaries (subject to dependency audit):
  - `qf-crypto`: `src/crypto/`, `src/simd.rs`, `src/simd/` (AEAD ciphers, SIMD dispatch, GF tables used by crypto).
  - `qf-transport`: `src/transport/` (QUIC connection, packets, frames, CC, recovery, H3, version, NAT, path).
  - `qf-fec`: `src/fec/` (adaptive FEC, wire framing, fountain codes, GF arithmetic, interleaving).
  - `qf-stealth`: `src/stealth/`, `src/brain.rs`, `src/qftls.rs`, `src/reality.rs` (stealth stack, brain, TLS cover, reality proxy).
  - `qf-core`: `src/core.rs`, `src/engine/`, `src/compress.rs` (orchestration, engine lifecycle, compression).
  - `qf-platform`: `src/optimize/`, `src/interface/`, `src/firewall/`, `src/privilege/`, `src/dns/`, `src/pki/`, `src/audit/` (OS services, TUN, firewall, privilege, DNS, PKI, audit).
  - `quicfuscate` (root bin): `src/main.rs`, `src/lib.rs`, `src/harness.rs`, `src/implementations/` (CLI entry, server/client runtime wiring).
- Circular dependency risk: `core.rs` orchestrates transport+fec+stealth+crypto. Solution: define trait interfaces in a shared types crate or use dependency inversion.
- The `optimize/` module has cross-cutting helpers (sort, string, iter, random). These may need a small `qf-util` crate or stay in `qf-platform`.
- Existing `[[test]]` and `[[bench]]` targets in root Cargo.toml must be redistributed to owning crates.
- This is a pure structural refactoring: zero behavioral change, zero feature addition, zero feature removal.

## Deviations

None.
