---
id: TODO-805
title: Reconcile frontend dependency security advisories
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-03
depends_on: []
---

# TODO-805: Reconcile Frontend Dependency Security Advisories

## Why

The repository's Rust dependency gates pass their configured checks, but the
2026-08-03 workspace frontend dependency audit failed. The lockfile resolved
multiple packages inside advisory ranges, and the repository had no configured
`bun pm scan` security scanner. This is a separate supply-chain and frontend
runtime boundary from Cargo Audit and must not be represented as a clean whole-
project security result. The implementation below reconciles the locked graph;
hosted CI, native packaging, and browser publication evidence remain external
gates.

## Findings

### 1. Initial Bun audit baseline reports advisories for nine locked packages

- **Command:** `bun audit --json`
- **Evidence:** On 2026-08-03 the command exited `1` and reported `29` advisories affecting nine package keys: `@sveltejs/kit` (`2.55.0`, 5 advisories), `cookie` (`0.6.0`, 1), `devalue` (`5.6.4`, 1), `esbuild` (`0.27.4`, 1), `picomatch` (`4.0.3`, 2), `postcss` (`8.5.8`, 3), `svelte` (`5.53.12`, 4), `undici` (`7.24.3`, 7), and `vite` (`7.3.1`, 5). The report contained high, moderate, and low severity entries, including high-severity advisories for `devalue`, `picomatch`, `postcss`, `undici`, and `vite` ranges.
- **Applicability boundary:** Bun's report groups one `@sveltejs/kit` entry under an `@sveltejs/adapter-node` title, while the lockfile uses `@sveltejs/adapter-static`; each advisory requires package-path and static-build/runtime exposure review before it is treated as an exploitable production issue.
- **Advisory IDs:** `1122155`, `1116432`, `1116433`, `1124300`, `1124301`, `1103907`, `1120448`, `1120680`, `1115551`, `1115554`, `1117015`, `1124252`, `1124288`, `1118900`, `1120446`, `1120447`, `1120449`, `1121187`, `1121241`, `1121244`, `1121247`, `1121249`, `1121254`, `1121428`, `1120785`, `1116230`, `1116232`, `1116235`, and `1123526`.
- **Dependency paths:** `@sveltejs/kit`, `svelte`, and `vite` are direct development dependencies of both Svelte applications; `@sveltejs/kit` and `svelte` are also peer-linked through the shared UI package. `cookie` is transitive through SvelteKit; `devalue` is transitive through SvelteKit and Svelte; `esbuild`, `picomatch`, and `postcss` are transitive through Vite; `undici` is transitive through the development-only `jsdom` path.
- **Static-runtime boundary:** Both applications use `@sveltejs/adapter-static` with `fallback: "index.html"`, and the Admin root layout sets `prerender = true`. The built output is static (`index.html`, `_app/`, and `robots.txt`); no `@sveltejs/adapter-node` or SvelteKit remote-function usage was found. This narrows the production exposure of server-only advisories, but does not clear browser-delivered framework code, build-time tooling, preview/dev servers, or Tauri packaging.
- **Impact:** The current lockfile cannot be treated as advisory-free. Build tooling, static generation, browser-delivered code, and transitive test/runtime packages have different exposure and remediation requirements.
- **Boundary:** Resolve every advisory against the exact lockfile graph, the two SvelteKit static applications, Tauri packaging, development-server exposure, and the generated static output. Record accepted non-runtime findings explicitly; do not suppress IDs without a documented reason.

### 2. Bun's alternate lockfile scanner is unavailable

- **Command:** `bun pm scan`
- **Evidence:** It exits before scanning with `no security scanner configured` and instructs the repository to configure a scanner in `bunfig.toml`.
- **Impact:** The repository has one live advisory result, but no independent Bun lockfile scanner result. A missing scanner must not be reported as a second clean dependency gate.
- **Boundary:** Configure and verify an approved scanner, or document the explicit unavailable state and the authoritative advisory source used by CI.

### 3. Safe-range update candidates existed before implementation

- **Command:** `bun outdated --recursive --no-save --frozen-lockfile`
- **Evidence:** The current registry response reports update candidates `@sveltejs/kit 2.70.2`, `svelte 5.56.8`, and `vite 7.3.6`, which move beyond the currently reported vulnerable ranges. It also reports newer `jsdom`, Vitest, Svelte tooling, and Tauri/plugin versions that require compatibility review. No package manifest or lockfile was changed during this audit.
- **Impact:** The advisory set was not blocked by an absence of candidate versions, but a broad update could affect both frontend applications, shared UI packages, Tauri integration, and test behavior.
- **Boundary:** The approved implementation is recorded in the Resolution section below. The exact advisory scan, lockfile integrity checks, frontend builds, tests, and Tauri validation were re-run after the update.

### 4. The frozen workspace lockfile is internally reproducible

- **Command:** `bun install --dry-run --frozen-lockfile --ignore-scripts`
- **Evidence:** Bun resolves all five workspaces and the recorded lockfile package graph without requesting a lockfile update or running lifecycle scripts. `bun pm untrusted` reports zero untrusted dependencies with scripts.
- **Impact:** Lockfile drift is not the current cause of the advisory result; the security finding is the resolved package set itself and the missing independent scanner.
- **Boundary:** Keep frozen-lockfile verification in the eventual dependency gate and retain the no-lifecycle-script property as a separate supply-chain check.

### 5. Baseline CI had no frontend dependency advisory lane

- **Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/tests/audits/audit-readiness-gates.sh`.
- **Evidence:** CI installs Bun workspaces and runs checks, unit tests, E2E lanes, and builds, while the dependency audit lane invokes only `cargo audit --deny warnings`. No executable workflow or repository gate invokes `bun audit` or a configured `bun pm scan` scanner.
- **Impact:** Before this task, the 29-advisory frontend result was not a required CI failure signal. A lockfile update could reintroduce or preserve the vulnerable package set while Rust dependency gates remained green.
- **Boundary:** The CI and release lane added by this task is described below and has been validated locally. Hosted execution remains an external gate.

## Resolution (2026-08-04)

### Current advisory inventory and exact dispositions

The live `bun audit --json` run on 2026-08-04 reported `35` advisories before remediation across the following nine package keys. The package versions below are the post-remediation locked versions. Each entry retains the advisory ID, severity, affected range, dependency path, exposure surface, and disposition.

| Package and locked version | Advisory ID | Severity and affected range | Dependency path and exposure | Disposition |
| --- | --- | --- | --- | --- |
| `@sveltejs/kit@2.70.2` | `1122155` | moderate, `>=2.38.0 <=2.60.0` | Direct dev dependency of both Svelte apps; static generation, browser bundle, dev server, and Tauri frontend build | Upgraded beyond range; resolved |
| `@sveltejs/kit@2.70.2` | `1116432` | moderate, `<=2.57.0` | Same SvelteKit path; static generation, browser bundle, dev server, and Tauri frontend build | Upgraded beyond range; resolved |
| `@sveltejs/kit@2.70.2` | `1116433` | high, `<=2.57.0`; advisory title references `@sveltejs/adapter-node` BODY_SIZE_LIMIT bypass | Bun reports this under SvelteKit; `@sveltejs/adapter-node` is not installed; static adapter path only | Upgraded beyond range; adapter-node path absent; resolved |
| `@sveltejs/kit@2.70.2` | `1124300` | moderate, `<=2.69.0` | Same SvelteKit path; static generation, browser bundle, dev server, and Tauri frontend build | Upgraded beyond range; resolved |
| `@sveltejs/kit@2.70.2` | `1124301` | moderate, `<=2.69.0` | Same SvelteKit path; static generation, browser bundle, dev server, and Tauri frontend build | Upgraded beyond range; resolved |
| `cookie@0.7.2` | `1103907` | low, `<0.7.0` | `@sveltejs/kit -> cookie`; SvelteKit build/runtime dependency in both static apps | Root override to `0.7.2`; resolved |
| `devalue@5.9.0` | `1120448` | high, `>=5.6.3 <=5.8.0` | `@sveltejs/kit -> devalue` and `svelte -> devalue`; generated static data and framework transforms | Lockfile upgrade through SvelteKit/Svelte update; resolved |
| `esbuild@0.28.1` | `1120680` | low, `>=0.27.3 <0.28.1` | `vite -> esbuild`; frontend build and dev-server tooling | Root override to `0.28.1`; resolved |
| `picomatch@4.0.4` | `1115551` | moderate, `>=4.0.0 <4.0.4` | Vite/fdir/tinyglobby and Vitest paths; build, dev server, and test tooling | Root override to `4.0.4`; resolved |
| `picomatch@4.0.4` | `1115554` | high, `>=4.0.0 <4.0.4` | Vite/fdir/tinyglobby and Vitest paths; build, dev server, and test tooling | Root override to `4.0.4`; resolved |
| `postcss@8.5.23` | `1130709` | moderate, `<=8.5.22` | `vite -> postcss`; frontend build and dev-server tooling | Root override to `8.5.23`; resolved |
| `postcss@8.5.23` | `1117015` | moderate, `<8.5.10` | `vite -> postcss`; frontend build and dev-server tooling | Root override to `8.5.23`; resolved |
| `postcss@8.5.23` | `1124252` | high, `<=8.5.11` | `vite -> postcss`; frontend build and dev-server tooling | Root override to `8.5.23`; resolved |
| `postcss@8.5.23` | `1124288` | high, `<=8.5.17` | `vite -> postcss`; frontend build and dev-server tooling | Root override to `8.5.23`; resolved |
| `svelte@5.56.8` | `1118900` | moderate, `>=5.46.0 <=5.55.6` | Direct dev/peer dependency of both apps and shared UI; compile-time and browser-delivered component code | Upgraded beyond range; resolved |
| `svelte@5.56.8` | `1120446` | moderate, `<=5.55.6` | Same Svelte compiler/component path | Upgraded beyond range; resolved |
| `svelte@5.56.8` | `1120447` | moderate, `>=5.51.5 <=5.55.6` | Same Svelte compiler/component path | Upgraded beyond range; resolved |
| `svelte@5.56.8` | `1120449` | moderate, `<=5.55.6` | Same Svelte compiler/component path | Upgraded beyond range; resolved |
| `undici@7.29.0` | `1130715` | moderate, `>=7.0.0 <7.29.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1130718` | high, `>=7.0.0 <7.29.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1130726` | moderate, `>=7.0.0 <7.29.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1130729` | moderate, `>=7.0.0 <7.29.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1130731` | moderate, `>=7.0.0 <7.29.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121187` | high, `>=7.23.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121241` | moderate, `>=7.0.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121244` | high, `>=7.0.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121247` | high, `>=7.23.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121249` | low, `>=7.0.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121254` | low, `>=7.0.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `undici@7.29.0` | `1121428` | moderate, `>=7.0.0 <7.28.0` | `jsdom -> undici`; test-only Node/jsdom runtime, not generated static output | Root override to `7.29.0`; resolved |
| `vite@7.3.6` | `1120785` | moderate, `>=7.0.0 <=7.3.4` | Direct dev dependency of both apps/shared UI; build and development server | Upgraded beyond range; resolved |
| `vite@7.3.6` | `1116230` | moderate, `>=7.0.0 <=7.3.1` | Same Vite build/dev-server path | Upgraded beyond range; resolved |
| `vite@7.3.6` | `1116232` | high, `>=7.1.0 <=7.3.1` | Same Vite build/dev-server path | Upgraded beyond range; resolved |
| `vite@7.3.6` | `1116235` | high, `>=7.0.0 <=7.3.1` | Same Vite build/dev-server path | Upgraded beyond range; resolved |
| `vite@7.3.6` | `1123526` | high, `>=7.0.0 <=7.3.4` | Same Vite build/dev-server path | Upgraded beyond range; resolved |

The 35 entries are the complete pre-remediation inventory: 5 SvelteKit, 1 cookie, 1 devalue, 1 esbuild, 2 picomatch, 4 postcss, 4 Svelte, 12 undici, and 5 Vite advisories. The post-remediation run reports zero advisories.

### Dependency and runtime boundary

- `@sveltejs/adapter-static` remains the adapter in both applications. No `@sveltejs/adapter-node` package is installed. The generated apps remain static and use the existing `index.html` fallback; the Admin root layout remains prerendered. Server-only adapter-node exposure is therefore not claimed, while build, preview/dev-server, browser bundle, and Tauri packaging paths were revalidated.
- `undici` remains on the `jsdom` test-only path. `jsdom` remains on the compatible `28.x` line because `jsdom@30` requires Node `22.22.2` or newer. The `undici@7.29.0` override satisfies the declared jsdom dependency without forcing that runtime-major change.
- The root overrides are reviewed compatibility pins for `cookie@0.7.2`, `esbuild@0.28.1`, `picomatch@4.0.4`, `postcss@8.5.23`, `undici@7.29.0`, and `vite@7.3.6`. They are checked exactly by the repository gate and are not advisory ignores.
- `bun pm untrusted` reports zero lifecycle-script dependencies. `bun pm scan` remains `UNAVAILABLE` because no scanner is configured; it is not represented as a clean independent result. `bun audit --json` is the authoritative live source for this gate.

### Reproducible gate and CI wiring

- `scripts/audits/verify-frontend-dependencies.sh` validates Bun `1.3.14`, frozen lockfile resolution without lock mutation, zero untrusted lifecycle scripts, zero `bun audit --json` advisories, the approved unavailable state of `bun pm scan`, the exact root overrides, and exact workspace package contracts. It emits machine-readable JSON and exits nonzero on any failed contract.
- `.github/workflows/ci.yml` invokes the gate in a dedicated `frontend-dependency-security` job after frontend checks. `.github/workflows/release.yml` invokes it in the release-version contract before dependency and packaging gates. Frozen Bun installs remain required.
- The local gate result is:

```json
{
  "alternate_scanner": {
    "detail": "bun pm scan has no configured scanner; bun audit --json is authoritative",
    "status": "UNAVAILABLE"
  },
  "audit": {
    "advisories": 0,
    "source": "bun audit --json",
    "status": "PASS"
  },
  "bun_version": "1.3.14",
  "frozen_install": "PASS",
  "lifecycle_scripts": "PASS",
  "lock_sha256": "02c3457fdcc818dafce5248a76da2143bbedd52d33cf841c047dc82b8699bb5e",
  "package_contract": "PASS",
  "result": "PASS"
}
```

### Local Reality Check

- `bun audit --json`: 35 pre-remediation advisories, 0 after remediation.
- Admin `bun run check`: 0 errors, 0 warnings. Desktop `bun run check`: 0 errors, 0 warnings.
- Admin build and Desktop build: pass with Vite `7.3.6`. Existing static-adapter fallback and Vite dynamic-import warnings remain non-failing and are recorded as warnings, not suppressed errors.
- Admin unit tests: 25 files, 285/285. Desktop unit tests: 31 files, 370/370. The combined frontend unit result is 655/655.
- Loopback development-server probes: Admin on `127.0.0.1:1430` and Desktop on `127.0.0.1:4173` both became ready with Vite `7.3.6`; each process was intentionally terminated after the bounded probe.
- Locked Tauri host check, strict all-target Clippy, and tests pass on ARM64 macOS; the host test result is 41/41. The same three pre-existing root-library dead-code warnings remain.
- `git diff --check`, shell syntax, YAML parsing, and the reproducibility dependency gate pass. Build artifacts were kept in isolated temporary targets and cleaned; filesystem free space remained above the 2 GiB minimum and the temporary Tauri target peaked at 3.9 GiB.

### Open external gates

- GitHub-hosted CI execution, Linux/Windows native packaging, updater signing, and tagged publication were not available locally.
- Full Playwright Chromium E2E remains owned by TODO-756 and was not claimed by this dependency task because the required browser runtime is not installed locally.
- No frontend visual/UI source, remote checkout, or Omega state was changed.

## Acceptance

- Every advisory from `bun audit --json` is mapped to an exact package, locked version, dependency path, affected build/runtime surface, severity, and disposition.
- Vulnerable package ranges are upgraded, isolated, or explicitly risk-accepted with evidence; no advisory is hidden through an unreviewed ignore.
- The workspace has a reproducible frontend dependency security gate with a machine-readable result and a clear unavailable state when its data source or scanner cannot run.
- Admin and Desktop static builds, Tauri packaging, unit tests, and the development-server exposure boundary are revalidated after dependency reconciliation.

## Sub-Tasks

- [x] Map all 35 advisories to exact direct and transitive dependency paths in `bun.lock`.
- [x] Determine production, generated-static, Tauri, test-only, and development-server exposure for each affected path.
- [x] Select and configure the authoritative scanner or document the approved unavailable fallback.
- [x] Re-run frontend checks, builds, unit tests, and the dependency gate with retained machine-readable artifacts.

## Notes

- Discovered during the read-only exhaustive audit on 2026-08-03. The remediation changed only dependency manifests, the Bun lockfile, dependency gate script, and CI/release wiring; no frontend visual/UI source was changed.
- `bun pm untrusted` reports zero untrusted dependencies with lifecycle scripts; this does not replace vulnerability scanning.
- 2026-09-19 final remediation: `vitest ^4.1.11` (workspace pins + reviewed-pin contract in `verify-frontend-dependencies.sh`), `smol-toml 1.8.0`, `devalue 5.9.4` via lockfile; `bun audit` reports 0 advisories. CI run `b939f54` green across frontend-checks, frontend-dependency-security, app-backend-checks, build-test, and frontend-e2e - the external CI evidence this task was blocked on.
- Tagged-release Tauri packaging remains an inherent external event owned by TODO-755.

## Deviations

None.
