# TODO-152: Integrate Frontend E2E Playwright Tests into CI

## Status
**DOCUMENTED** - Comment block added to `.github/workflows/ci.yml` noting the gap. Actual Playwright CI jobs deferred until browser infrastructure is ready.

## Severity
**MEDIUM**

## Context
Playwright E2E tests exist for both the web-admin and desktop applications but are not executed in the CI pipeline. Only unit tests and type checks run in CI, leaving end-to-end regressions undetected until manual testing.

- `archive/apps/web-admin-ui/playwright.config.ts`: Playwright config exists for web-admin
- `apps/tauri/playwright.config.ts`: Playwright config exists for desktop
- `scripts/tests/frontend/web-admin/e2e/`: Multiple E2E test files (app.pw.ts, button-semantics.pw.ts, dialog-centering.pw.ts, overlay-notifications.pw.ts, smoke-ui.pw.ts)
- `scripts/tests/frontend/desktop/e2e/`: E2E test files (app.pw.ts, full-ui.pw.ts)
- `.github/workflows/ci.yml`: No Playwright E2E job present

## Root Cause
The CI pipeline was established with Rust-focused build/test steps. Frontend E2E tests were developed locally but never integrated into the automated pipeline, likely due to the complexity of setting up browser environments in CI.

## Fix Plan
1. Add a new CI job for web-admin E2E tests:
   ```yaml
   e2e-web-admin:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - uses: actions/setup-node@v4
         with:
           node-version: '20'
       - run: npx playwright install --with-deps chromium
       - run: cd archive/apps/web-admin-ui && npm ci
       - run: cd archive/apps/web-admin-ui && npx playwright test
   ```
2. Add a separate job for desktop E2E tests (may need Tauri build prerequisites)
3. Configure Playwright to use headless mode (should be default in CI)
4. Add test result artifacts upload for failure screenshots:
   ```yaml
   - uses: actions/upload-artifact@v4
     if: failure()
     with:
       name: playwright-report
       path: archive/apps/web-admin-ui/playwright-report/
   ```
5. Ensure tests run on every PR targeting main
6. Consider running E2E only on changes to `apps/` directory (path filter) for efficiency

## Acceptance Criteria
- Web-admin E2E tests run on every PR in CI
- Desktop E2E tests run on every PR in CI (or documented as blocked with follow-up TODO)
- Failure screenshots uploaded as CI artifacts
- CI pipeline fails if any E2E test fails
- Tests run in headless mode

## Dependencies
- Node.js and Playwright browser binaries available in CI runner
- Web-admin dev server must start successfully in CI
- Desktop E2E may require Tauri build dependencies (system libraries)

## Affected Files
- `.github/workflows/ci.yml` (add E2E jobs)
- `archive/apps/web-admin-ui/playwright.config.ts` (may need CI-specific settings)
- `apps/tauri/playwright.config.ts` (may need CI-specific settings)
