# TODO-293: Hardcoded ADMIN_PASS="123" in E2E Test

## Problem
E2E test script uses hardcoded `ADMIN_PASS="123"` which, while only in test code, sets a bad example and could be accidentally used as a default.

## Source
AI Model Review (GLM-5) - verified correct.

## Location
- E2E test scripts under `scripts/tests/`

## Fix
Use a clearly test-only password like `TEST_ONLY_DO_NOT_USE_IN_PRODUCTION` or generate a random password for each test run.

## Acceptance Criteria
- No hardcoded weak passwords in test scripts
- Test scripts clearly signal that passwords are test-only
