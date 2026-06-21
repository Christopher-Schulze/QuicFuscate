# TODO-296: Browser Profile Scripts Reference Non-Existent Directory

## Problem
7 scripts under `scripts/tests/utils/` and `scripts/utils/` reference a `browser_profiles/` directory that does not exist in the repository. These scripts will silently fail or error out.

## Source
AI Model Review + previous reality check - verified correct.

## Location
- `scripts/tests/utils/util-e2e-decode-all-profiles.sh`
- `scripts/tests/utils/util-e2e-verify-all.sh`
- `scripts/tests/utils/util-e2e-verify-current.sh`
- `scripts/tests/utils/util-tls-generate-sha256-sidecars.sh`
- Additional scripts referencing `browser_profiles/`

## Fix
Either create the `browser_profiles/` directory with appropriate content, or add existence checks to the scripts with clear error messages, or remove the scripts if the feature is not yet implemented.

## Acceptance Criteria
- Scripts either work correctly or fail with clear error messages
- No silent failures
