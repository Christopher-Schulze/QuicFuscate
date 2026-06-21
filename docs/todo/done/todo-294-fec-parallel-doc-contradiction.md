# TODO-294: DOCUMENTATION.md FEC_PARALLEL Override Contradiction

## Problem
DOCUMENTATION.md claims there is no manual FEC_PARALLEL override, but `main.rs` actually sets it from CLI arguments. The documentation contradicts the actual implementation.

## Source
AI Model Review (GLM-5) - verified correct.

## Location
- `docs/DOCUMENTATION.md` - FEC_PARALLEL section
- `src/main.rs` - CLI argument parsing

## Fix
Update DOCUMENTATION.md to accurately reflect that FEC_PARALLEL can be set via CLI.

## Acceptance Criteria
- DOCUMENTATION.md accurately describes FEC_PARALLEL CLI override
- No doc/code contradiction
