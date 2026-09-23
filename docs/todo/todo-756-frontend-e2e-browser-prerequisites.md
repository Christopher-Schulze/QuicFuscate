---
id: TODO-756
title: Make frontend E2E browser prerequisites explicit and fail closed
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-08-01
depends_on: [TODO-753]
---

# TODO-756: Make Frontend E2E Browser Prerequisites Explicit and Fail Closed

## Current execution gate (2026-09-23)

The local implementation and 70+23 historical browser runs below are complete
for their recorded revision. Reconfirm the current Playwright version from
`config/tool-versions.env`, both package manifests, and `bun.lock`; run the
preflight's missing-browser negative case and a real Admin/Desktop Chromium
run with discovered test counts at the same revision. Obtain the matching
hosted frontend E2E install and test job results, retaining browser/artifact
versions, exact failures, and preview-process cleanup. The stalled Node 26.6
ZIP extraction is a host-specific historical observation; reproduce it before
treating it as a current blocker. This task is OPEN because its local recheck
can start now; an unavailable hosted run blocks closure, not that work.
TODO-754's whole-repository register is not a browser-suite prerequisite.

## Why

The frontend E2E inventories are present and their preview servers build and start, but the local test commands do not establish or preflight the required Playwright browser runtime. A missing browser therefore produces a full suite of startup failures instead of one actionable environment result.

## Findings

### 1. The local E2E suites cannot execute without the Chromium runtime

- **Files:** `apps/svelte-admin/playwright.config.ts`, `apps/svelte-desktop/playwright.config.ts`, `apps/svelte-admin/package.json:15-17`, `apps/svelte-desktop/package.json:15-17`.
- **Evidence:** `bun run test:e2e -- --list` enumerates 70 Admin tests in five files and 23 Desktop tests in four files. The actual Admin and Desktop runs build and start their preview servers, then fail all 70 and 23 tests before the first assertion because the Playwright Chromium executable is absent at `/Users/christopher/Library/Caches/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-mac-arm64/chrome-headless-shell`.
- **Impact:** The current local E2E command cannot distinguish an unavailable browser environment from a product regression, and it repeats the same prerequisite failure once per test.

### 2. Browser provisioning is defined in CI but not in the package contract

- **Files:** `.github/workflows/ci.yml:59-60`, `apps/svelte-admin/package.json:15-17`, `apps/svelte-desktop/package.json:15-17`.
- **Evidence:** CI runs `bunx playwright install --with-deps chromium` from the Admin workspace before both E2E suites. Neither package's `test:e2e` script performs the same provisioning or a fail-fast browser preflight.
- **Impact:** A fresh local checkout can list the suites and start the application while remaining unable to execute the actual browser contract. CI-only provisioning hides that missing local prerequisite.

## Acceptance

- The Admin and Desktop `test:e2e` entrypoints share an explicit browser prerequisite contract and fail once with an actionable `UNAVAILABLE` diagnostic before launching individual tests when Chromium is absent.
- Local and CI execution use the same documented Playwright browser version, provisioning path, and readiness check.
- With the declared browser runtime available, the E2E commands execute the complete current discovered Admin and Desktop inventories; reconcile changes from the historical 70 and 23 counts against manifests and test source before accepting them.
- Missing browser runtime is reported once as an environment gate failure before any discovered product test starts; the historical 93 repeated failures are not a current inventory target.
- No UI source, component, style, asset, route, or behavior changes are required to close this task.

## Resolution (2026-08-04)

- `config/tool-versions.env` now owns the exact Playwright version `1.58.2`. Both frontend manifests use exact `@playwright/test` `1.58.2`, and `bun.lock` resolves that same version for both workspaces.
- Both frontend packages expose `test:e2e:install` and `test:e2e:preflight`. The `test:e2e`, `test:e2e:ui`, and `test:e2e:debug` entrypoints run the shared preflight before Playwright can start a preview server or individual test.
- `scripts/tests/frontend/verify-playwright-browser.sh` validates the CLI version and launches headless Chromium through the Playwright `channel: "chromium"` path. Missing or non-launchable browser state returns `E2E_BROWSER_STATUS=UNAVAILABLE` with exit code 2 and an actionable install command. A version mismatch returns `FAIL` with exit code 1.
- Both Playwright configs use `channel: "chromium"`, matching the Playwright 1.58.2 Chrome-for-Testing `chromium-1208` artifact. The smoke runner uses the same preflight, and CI provisions through the package-owned install script with `--with-deps`.
- The reproducibility and frontend dependency gates validate the source-owned Playwright version, exact workspace manifests, frozen lockfile, and zero Bun audit advisories. No UI source, component, style, asset, route, or behavior file was changed.

## Reality Check (2026-08-04)

- With an empty browser cache, Admin and Desktop preflight each returned one `E2E_BROWSER_STATUS=UNAVAILABLE` result with exit code 2 and no preview-server or Playwright process. This replaces the former repeated per-test startup failures.
- With the declared full Chromium artifact available, Admin `bun run test:e2e` passed all 70 discovered tests and Desktop `bun run test:e2e` passed all 23 discovered tests. The inventories were not reduced.
- Admin and Desktop `bun run check` each found 0 errors and 0 warnings. The direct unit suites passed 285/285 and 370/370 tests respectively.
- `scripts/audits/verify-frontend-dependencies.sh` passed with zero advisories, exact Playwright version `1.58.2`, frozen install, lifecycle-script, and package-contract checks. `scripts/audits/verify-reproducible-dependencies.sh` passed its two-run dependency and toolchain resolution contract.
- The normal `bunx playwright install chromium` command downloaded the complete artifact on this macOS Node 26.6 host but stalled during Playwright's ZIP extraction. Local runtime proof therefore used that complete exact ZIP to populate the expected Playwright cache and did not claim a normal installer success on this host. CI and other hosts still use the package-owned installer command.

## Open Gates

- Hosted CI execution of the updated package-owned browser installation and both E2E jobs remains external evidence.
- The normal Playwright installer path remains unverified on this specific Node 26.6 host because extraction stalled after the download; the repository contract and the full local browser-run proof are complete.

## Sub-Tasks

- [x] Define the canonical browser version and ownership of local provisioning.
- [x] Add a shared fail-fast browser readiness check to both E2E entrypoints.
- [x] Align CI provisioning and local diagnostics with that contract.
- [x] Run both full E2E suites with the declared browser runtime and reconcile all 93 test results.
- [ ] Re-run current-version local preflight and both real browser suites,
      then record same-revision hosted installation and E2E proof.

## Notes

- The original audit intentionally did not install an external browser runtime. The implementation phase provisioned the exact declared artifact for the local Reality Check.
- Svelte checks, production builds, and unit test inventories are separate gates owned by TODO-753 and do not replace browser execution proof.

## Deviations

The hosted CI and host-specific installer gates cannot be proven from this ARM64 macOS session. The repository contract, fail-fast negative path, full local Admin/Desktop browser suites, and supporting local gates are verified and remain documented as such.
