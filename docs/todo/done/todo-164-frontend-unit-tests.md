# TODO-164: Frontend Unit Test Coverage

## Status
**DOCUMENTED**. Priority test targets identified: API sanitization functions (api.ts), type guards (policy-display.ts), format utilities (date/byte/duration formatting), state atoms/stores. Vitest recommended as test runner. Some desktop unit tests already exist under scripts/tests/frontend/desktop/unit/.

## Severity
**MEDIUM**

## Context
Frontend applications have no unit tests for utility functions, type guards, or state logic. Only Playwright E2E tests exist, which are slow and do not provide granular coverage of individual functions.

- `archive/apps/desktop/src/lib/`: Utility modules with no unit tests
- `archive/apps/web-admin-ui/src/`: Business logic with no unit tests
- `scripts/tests/frontend/`: Contains only Playwright E2E test files

## Root Cause
Testing strategy focused exclusively on E2E tests. No Vitest configuration was set up for unit testing during initial development.

## Fix Plan
1. Add Vitest as dev dependency to both frontend apps
2. Configure `vitest.config.ts` for each app (or shared config)
3. Add unit tests for priority targets:
   - API sanitization functions (`api.ts`) - input validation, URL construction, error handling
   - Type guards (`policy-display.ts`) - all type narrowing functions
   - Format utilities - date formatting, byte formatting, duration formatting
   - State atoms/stores - initial state, transitions, derived state
4. Add test scripts to `package.json`: `"test:unit": "vitest run"`
5. Integrate into CI pipeline

## Acceptance Criteria
- Vitest configured and running in both frontend apps
- >80% line coverage on all utility/helper functions
- All type guard functions have positive and negative test cases
- API sanitization tested with malicious inputs
- Unit tests run in CI alongside E2E tests

## Dependencies
- None

## Affected Files
- `apps/tauri/package.json` (add vitest dep)
- `archive/apps/web-admin-ui/package.json` (add vitest dep)
- `apps/tauri/vitest.config.ts` (new)
- `archive/apps/web-admin-ui/vitest.config.ts` (new)
- `archive/apps/desktop/src/lib/*.test.ts` (new test files)
- `archive/apps/web-admin-ui/src/**/*.test.ts` (new test files)
