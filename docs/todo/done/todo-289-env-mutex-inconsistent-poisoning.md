# TODO-289: ENV_MUTEX Duplicated 7x with Inconsistent Poisoning

## Problem
7 separate `ENV_MUTEX` static patterns exist across test files with inconsistent `.unwrap()` vs `.expect()` vs proper poisoning handling. This is a test-code quality issue - a poisoned mutex in one test can cascade failures in others.

## Source
AI Model Review (GLM-5) - verified correct.

## Location
- Various test files under `scripts/tests/rust/`

## Fix
Extract a single `test_env_mutex()` helper or use a consistent pattern across all test files.

## Acceptance Criteria
- Single ENV_MUTEX pattern or consistent handling across all test files
- No inconsistent poisoning behavior
