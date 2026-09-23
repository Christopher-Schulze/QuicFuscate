---
id: TODO-755
title: Remediate Tauri dependency advisories and lockfile drift
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-08-01
depends_on: [TODO-270, TODO-749]
---

# TODO-755: Remediate Tauri Dependency Advisories and Lockfile Drift

## Current execution gate (2026-09-23)

The initial ten-vulnerability and twenty-two-warning inventory below is a
historical finding. The later local remediation reported zero vulnerabilities
and a reviewed transitive-warning set. Before closure, refresh the advisory
database and the exact root/Tauri lockfile hashes, run the current
`scripts/audits/verify-tauri-dependencies.sh` plus locked metadata, audit,
deny, check, Clippy, and host tests at one revision, then obtain the matching
hosted macOS/Linux/Windows packaging-security results where those packages
are shipped. A newly reported or newly reachable advisory becomes a separate
exact package/path/fix gate; do not blindly preserve the old warning count.
Tagged publication and updater signing are release operations, not required
to establish this task's dependency-security contract. The local advisory and
lockfile refresh can start now; applicable hosted/native cells block closure
if they remain unavailable.

## Why

The root server dependency graph and the separately excluded Tauri desktop graph have different security and reproducibility states. A green root `cargo audit` result does not cover the Tauri host, whose committed lockfile is not accepted by locked Cargo metadata and whose direct lockfile scan reports actionable RustSec advisories.

## Findings

### 1. The Tauri lockfile contains known vulnerabilities
- **File:** `apps/tauri/src-tauri/Cargo.lock`.
- **Evidence:** `cargo audit --quiet --json --file apps/tauri/src-tauri/Cargo.lock` reports `vulnerabilities_found=True`, `count=10`, and exits 1. The advisory set includes `RUSTSEC-2026-0037`, `RUSTSEC-2026-0067`, `RUSTSEC-2026-0068`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, `RUSTSEC-2026-0104`, `RUSTSEC-2026-0185`, `RUSTSEC-2026-0194`, `RUSTSEC-2026-0195`, and `RUSTSEC-2026-0204`.
- **Impact:** The desktop dependency chain has known denial-of-service, certificate-validation, parsing, archive, and invalid-pointer advisories that are outside the root audit's lockfile scope.

### 2. Tauri advisory enforcement also reports denied warnings
- **File:** `apps/tauri/src-tauri/Cargo.lock`.
- **Evidence:** The same audit reports 22 denied warnings, including unmaintained GTK3 bindings and unsound transitive crates.
- **Impact:** The Tauri release surface cannot claim the repository's documented zero-warning dependency posture.

### 3. Locked Tauri dependency gates cannot inspect the committed graph
- **Files:** `apps/tauri/src-tauri/Cargo.toml`, `apps/tauri/src-tauri/Cargo.lock`.
- **Evidence:** `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml --locked` and `cargo deny --locked --manifest-path apps/tauri/src-tauri/Cargo.toml check` both fail before compilation because Cargo would need to update the lockfile.
- **Impact:** The repository has no passing, non-mutating locked check for the Tauri host. An unlocked check can rewrite the committed lockfile, so a verification run can change dependency truth.

### 4. Root dependency evidence is not sufficient for desktop release claims
- **Files:** `Cargo.lock`, `apps/tauri/src-tauri/Cargo.lock`, `.github/workflows/ci.yml:488-489`, `scripts/tests/audits/audit-readiness-gates.sh:113-149`.
- **Problem:** Root CI and audit helpers scan the root graph, while the Tauri host is built and audited through a separate manifest path with no equivalent locked dependency/security gate.
- **Impact:** Release documentation can remain green for the root graph while the shipped desktop graph is vulnerable or unresolved.

## Resolution

- 2026-09-19 drift remediation: two NEW advisories appeared in both lockfiles and
  were fixed the same day. `aligned_box 0.2.1 -> 0.3.1` (RUSTSEC-2026-0282,
  double-free in `realloc_with_default`; declared in root `Cargo.toml`,
  `qf-fec`, `qf-memory-pool`) and `rustls 0.23.37/0.23.43 -> 0.23.45`
  (RUSTSEC-2026-0285, TLS 1.3 messages accepted across encryption-level
  boundaries; `--precise` needed because conservative update held 0.23.43 in
  the Tauri lockfile). `cargo audit` now reports 0 vulnerabilities on root and
  Tauri lockfiles; `cargo deny check` all four families ok.
- Advisory-DB drift resynced in the warning inventory: the ten GTK3-binding
  unmaintained advisories (RUSTSEC-2024-0411..0420) were withdrawn upstream on
  2026-08-14 and are no longer reported; `paste 1.0.15` (RUSTSEC-2024-0436,
  unmaintained, specta proc-macro chain, no patched release) was newly
  classified. `verify-tauri-dependencies.sh` passes again.
- Pre-existing `darling`/`darling_core`/`darling_macro` 0.21.3 vs 0.23.0
  duplicate (serde_with_macros<-tauri-utils vs tauri-specta-macros) tripped
  `multiple-versions = "deny"`; recorded as reviewed skip entries in
  `config/deny-tauri.toml` with justification - proc-macro internals on
  disjoint major lines cannot be unified without bumping tauri-utils/specta.
- `apps/tauri/src-tauri/Cargo.lock` was reconciled with targeted updates only. The vulnerable `crossbeam-epoch`, `quick-xml`, `quinn-proto`, `rustls-webpki`, and `tar` lines are now patched; `plist` was upgraded to unlock the `quick-xml` patch. The patchable unsound `anyhow` and `rand` 0.8/0.9 lines are also updated.
- The Tauri lock audit returns `vulnerabilities=0`, `returncode=0`, and 10 warnings (was 19 before the 2026-08-14 upstream withdrawal of the GTK3-binding advisories). The warning inventory is exact and transitive: `fxhash 0.2.1`, `paste 1.0.15`, `proc-macro-error 1.0.4`, five URLPattern `unic-*` packages, `glib 0.18.5`, and `rand 0.7.3`. `glib >=0.20.0` is blocked by the pinned GTK3 ABI; `rand >=0.8.6` is blocked for the legacy `phf_generator 0.8` `^0.7` requirement. No advisory is in `deny.toml` `ignore`.
- `scripts/audits/verify-tauri-dependencies.sh` verifies the exact warning set, package versions, blocked patch ranges, reverse paths to `quicfuscate-desktop`, zero direct warning dependencies, zero vulnerabilities, and unchanged lockfile hashes before and after locked metadata and `cargo deny`.
- `config/deny-tauri.toml` scopes unmaintained and unsound findings to transitive dependencies with `workspace`, allows the already reachable `MPL-2.0` license, and records the reviewed Tauri/GTK/legacy version splits without adding Tauri exceptions to the root `deny.toml`. The Tauri binary manifest declares `MIT`; locked Tauri `cargo deny check` reports all four check families `ok` with four non-failing informational diagnostics.
- CI security and release-contract lanes install exact Cargo Audit `0.22.2` and Cargo Deny `0.19.0`, then invoke the Tauri gate. Existing locked Tauri metadata, check, Clippy, test, and packaging steps remain required.
- Local evidence passes on ARM64 macOS: locked Tauri check, all-target strict Clippy, and Tauri host tests `41/41`. The three existing root-library dead-code warnings remain unchanged. An isolated target peaked at 3.8 GiB and was cleaned; the repository target is absent afterward.

## Acceptance

- The committed Tauri lockfile is regenerated intentionally, reviewed, and accepted by `cargo metadata`, `cargo check`, Clippy, `cargo deny`, and `cargo audit` with locked/non-mutating commands.
- Every vulnerability in the current root and Tauri locked graphs is upgraded away or has a source-grounded, reviewed mitigation with an explicit bounded exception; no advisory is silenced only to make a gate pass. The original ten findings are historical.
- Every warning in the current advisory database is classified by reachability and release impact, with unmaintained/unsound dependencies upgraded, isolated, or explicitly documented. The original 22-warning count is historical.
- CI and release run root and Tauri dependency checks against the exact lockfiles used for packaging, and any lockfile drift fails closed.
- Root zero-advisory evidence and Tauri desktop evidence are reported separately in the canonical documentation and TODO ownership register.

## Sub-Tasks

- [x] Regenerate and review the Tauri lockfile without losing the intended manifest constraints.
- [x] Trace every RustSec advisory to the direct dependency and reachable packaged code path.
- [x] Upgrade or isolate vulnerable and unsound Tauri transitive dependencies.
- [x] Add locked Tauri metadata, build, lint, deny, and audit gates to CI/release.
- [x] Refresh documentation claims that currently describe the Tauri audit as informational-only or clean.
- [ ] Refresh current advisory and lockfile evidence, then prove the exact
      hosted/native package dependency graph and warning disposition.

## Notes

- TODO-270 owns the earlier root dependency CVE remediation history; this task owns the current separately locked Tauri graph and its release boundary.
- TODO-749 owns general lockfile/toolchain reproducibility; this task owns the security content and Tauri-specific gate closure.
- The initial audit did not modify either lockfile; this task intentionally changed only the separately owned Tauri lockfile and its audit policy/gates.
- The final local Tauri lock SHA-256 is `3234b8fa29c5c5ee10211d6b3fc0a461e197f41ab1140420155f46be1f11148a`. The verification runner proves that locked metadata and Cargo Deny do not mutate it.
- The local native check/test evidence is not a Linux/Windows packaging proof. Hosted CI and applicable native GTK/WebKit and Windows package dependency graphs remain closure gates; updater signing and tagged publication are separate release tasks.
- Local implementation and verification were committed and pushed in `1048f7eef21f68398c43d062112432aa534c9f96`. This task is OPEN for a current local refresh; later unavailable hosted/native cells may block closure.

## Deviations

None.
